//! Ledger records beyond one row per file: other devices' claims on a shared
//! file, temp-file intents, detached devices, and the bookkeeping of a
//! repaired file.
//!
//! **Claims.** Every device answers for itself: a copy recorded for one phone
//! never confirms anything for another. The `files` row belongs to the device
//! that committed the file first. When a second device delivers the very same
//! bytes to the very same path, the bytes are not stored twice; the second
//! device gets a row in `file_refs` with its own commit sequence number,
//! session and time, as if it had stored its own copy at that moment. Its
//! claim ages on its own clock. A file row cannot be removed while a claim
//! points at it (foreign key), and nothing in the engine removes file rows
//! except a new commit to the same path after the old file has vanished.
//!
//! **Intents.** A temp file is deleted by the clean-up only if a `partials`
//! row says the engine created it. The row is written before the file is
//! created and removed in the same transaction that records the commit, so a
//! committed file never has one.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use super::{
    adjust_usage, adjust_usage_all, append_event, hex, path_key, raise_hwm, raw_file_from_row,
    row_check, to_i64, to_u64, FileRecord, FileState, Ledger, RawFile, Result, FILE_COLUMNS,
};
use crate::hash::ContentHash;

/// The file columns, qualified for use in a join with `file_refs`.
fn qualified_file_columns() -> String {
    FILE_COLUMNS
        .split(',')
        .map(|c| format!("f.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Checksum over the fields of a claim that safety decisions depend on. It
/// binds the claim to the content it was made for, so a claim row cannot be
/// re-pointed at another file.
fn claim_check(
    device: &str,
    file_id: i64,
    hash: &ContentHash,
    size: u64,
    committed_seq: u64,
    committed_session: u64,
    committed_unix_ms: i64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("kiwi-store 2026-11 ledger claim row v1");
    h.update(&(device.len() as u64).to_le_bytes());
    h.update(device.as_bytes());
    h.update(&file_id.to_le_bytes());
    h.update(hash.as_bytes());
    h.update(&size.to_le_bytes());
    h.update(&committed_seq.to_le_bytes());
    h.update(&committed_session.to_le_bytes());
    h.update(&committed_unix_ms.to_le_bytes());
    *h.finalize().as_bytes()
}

struct RawClaim {
    file: RawFile,
    device: String,
    source_name: String,
    committed_seq: i64,
    committed_session: i64,
    committed_unix_ms: i64,
    check: Vec<u8>,
}

fn raw_claim_from_row(r: &Row<'_>) -> rusqlite::Result<RawClaim> {
    Ok(RawClaim {
        file: raw_file_from_row(r)?,
        device: r.get(16)?,
        source_name: r.get(17)?,
        committed_seq: r.get(18)?,
        committed_session: r.get(19)?,
        committed_unix_ms: r.get(20)?,
        check: r.get(21)?,
    })
}

/// Removes the stale row recorded under `path_key`, if any, with everything
/// that depends on it. Called when a file has just been given that path by a
/// no-replace rename: whatever the old row described is no longer there.
pub(super) fn supersede_stale(
    tx: &Transaction<'_>,
    session: u64,
    now_ms: i64,
    key: &str,
    keep_id: Option<i64>,
) -> rusqlite::Result<()> {
    let stale: Option<(i64, String, i64, i64, Vec<u8>)> = tx
        .query_row(
            "SELECT id, device_id, state, size, hash FROM files WHERE path_key = ?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((old_id, old_device, old_state, old_size, old_hash)) = stale else {
        return Ok(());
    };
    if keep_id == Some(old_id) {
        return Ok(());
    }
    let detail = format!("replaced by a new commit; old hash {}", hex(&old_hash));
    append_event(
        tx,
        session,
        now_ms,
        "record_superseded",
        Some(&old_device),
        Some(old_id),
        Some(&detail),
    )?;
    if FileState::from_code(old_state).is_some_and(FileState::occupies_space) {
        adjust_usage_all(tx, old_id, &old_device, -old_size, -1)?;
    }
    // What other devices and the mirrors knew about the vanished file goes
    // with it. Each is logged; a mirror keeps whatever file it has.
    {
        let mut stmt = tx.prepare("SELECT device_id FROM file_refs WHERE file_id = ?1")?;
        let devices: Vec<String> = stmt
            .query_map([old_id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for device in devices {
            append_event(
                tx,
                session,
                now_ms,
                "claim_superseded",
                Some(&device),
                Some(old_id),
                Some(&detail),
            )?;
        }
        let mut stmt =
            tx.prepare("SELECT mirror_id, rel_path FROM mirror_files WHERE file_id = ?1")?;
        let copies: Vec<(i64, String)> = stmt
            .query_map([old_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (mirror_id, rel_path) in copies {
            let detail = format!("mirror {mirror_id}: {rel_path} is no longer tracked");
            append_event(
                tx,
                session,
                now_ms,
                "mirror_record_superseded",
                None,
                Some(old_id),
                Some(&detail),
            )?;
        }
    }
    tx.execute("DELETE FROM file_refs WHERE file_id = ?1", [old_id])?;
    tx.execute("DELETE FROM mirror_files WHERE file_id = ?1", [old_id])?;
    tx.execute("DELETE FROM files WHERE id = ?1", [old_id])?;
    Ok(())
}

/// Re-stamps the claims selected by `where_sql` (over `file_refs r JOIN files
/// f`) as committed at `seq`, in `session`, at `now_ms`. Returns how many.
pub(super) fn restamp_refs(
    tx: &Transaction<'_>,
    where_sql: &str,
    args: &[&dyn rusqlite::ToSql],
    seq: u64,
    session: u64,
    now_ms: i64,
) -> rusqlite::Result<u64> {
    let rows: Vec<(i64, String, i64, Vec<u8>, i64)> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT r.id, r.device_id, r.file_id, f.hash, f.size
             FROM file_refs r JOIN files f ON f.id = r.file_id WHERE {where_sql}"
        ))?;
        let collected = stmt
            .query_map(args, |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        collected
    };
    let mut n = 0;
    for (ref_id, device, file_id, hash, size) in rows {
        let Some(hash) = ContentHash::from_slice(&hash) else {
            continue;
        };
        let check = claim_check(&device, file_id, &hash, to_u64(size), seq, session, now_ms);
        tx.execute(
            "UPDATE file_refs SET committed_seq = ?2, committed_session = ?3, committed_unix_ms = ?4, row_check = ?5 WHERE id = ?1",
            params![ref_id, to_i64(seq), to_i64(session), now_ms, check.as_slice()],
        )?;
        raise_hwm(tx, &device, seq)?;
        n += 1;
    }
    Ok(n)
}

/// What a repaired file is recorded as.
pub(crate) struct Restored<'a> {
    pub rel_path: &'a str,
    pub path_key: &'a str,
    pub dir_synced: bool,
    pub verified_unbuffered: bool,
    pub partial: Option<&'a str>,
    pub detail: &'a str,
}

impl Ledger {
    fn validate_claim(&self, raw: RawClaim) -> Result<FileRecord> {
        let owner = self.validate(raw.file)?;
        if raw.committed_seq < 0 || raw.committed_session < 0 {
            return Err(self.corrupt(format!(
                "a claim on file row {} has negative counters",
                owner.id
            )));
        }
        let expected = claim_check(
            &raw.device,
            owner.id,
            &owner.hash,
            owner.size,
            to_u64(raw.committed_seq),
            to_u64(raw.committed_session),
            raw.committed_unix_ms,
        );
        if raw.check != expected {
            return Err(self.corrupt(format!(
                "the claim of {} on file row {} fails its checksum",
                raw.device, owner.id
            )));
        }
        Ok(FileRecord {
            device: raw.device,
            source_name: raw.source_name,
            committed_seq: to_u64(raw.committed_seq),
            committed_session: to_u64(raw.committed_session),
            committed_unix_ms: raw.committed_unix_ms,
            ..owner
        })
    }

    fn query_claims(
        &self,
        conn: &Connection,
        where_sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<FileRecord>> {
        let sql = format!(
            "SELECT {}, r.device_id, r.source_name, r.committed_seq, r.committed_session, r.committed_unix_ms, r.row_check
             FROM file_refs r JOIN files f ON f.id = r.file_id WHERE {where_sql} ORDER BY r.committed_seq, r.id",
            qualified_file_columns()
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map(args, raw_claim_from_row)
            .map_err(|e| self.map(e))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(self.validate_claim(row.map_err(|e| self.map(e))?)?);
        }
        Ok(out)
    }

    /// Everything `device` can answer for with this content hash: the files
    /// it committed itself and its claims on files another device committed
    /// first. Each record carries the device's own commit sequence number,
    /// session and time. Oldest first.
    pub(crate) fn claims_by_hash(
        &self,
        hash: &ContentHash,
        device: &str,
    ) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE hash = ?1 AND device_id = ?2 ORDER BY committed_seq, id"
        );
        let mut out = self.query_files(&conn, &sql, &[&hash.as_bytes().as_slice(), &device])?;
        out.extend(self.query_claims(
            &conn,
            "f.hash = ?1 AND r.device_id = ?2",
            &[&hash.as_bytes().as_slice(), &device],
        )?);
        out.sort_by_key(|r| (r.committed_seq, r.id));
        Ok(out)
    }

    /// The record `device` holds for this file row, if it holds one.
    pub(crate) fn claim_on_file(&self, file_id: i64, device: &str) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1 AND device_id = ?2");
        if let Some(own) = self
            .query_files(&conn, &sql, &[&file_id, &device])?
            .into_iter()
            .next()
        {
            return Ok(Some(own));
        }
        Ok(self
            .query_claims(
                &conn,
                "r.file_id = ?1 AND r.device_id = ?2",
                &[&file_id, &device],
            )?
            .into_iter()
            .next())
    }

    /// One file row, as its first committer recorded it.
    pub(crate) fn file_by_id(&self, id: i64) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
        Ok(self.query_files(&conn, &sql, &[&id])?.into_iter().next())
    }

    /// Records that `device` delivered the same bytes that `file` (committed
    /// first by another device) already holds at the same path. Returns the
    /// device's own record and whether it is new.
    ///
    /// The caller has just read the file back from disk and compared it with
    /// what the device sent; the ledger only writes that down.
    pub(crate) fn record_claim(
        &self,
        file: &FileRecord,
        device: &str,
        source_name: &str,
        durable: bool,
        now_ms: i64,
    ) -> Result<(FileRecord, bool)> {
        let session = self.session();
        let outcome = self.write(durable, |tx| {
            let existing = self
                .query_claims(
                    tx,
                    "r.file_id = ?1 AND r.device_id = ?2",
                    &[&file.id, &device],
                )?
                .into_iter()
                .next();
            if let Some(existing) = existing {
                return Ok((existing, false));
            }
            let seq = append_event(
                tx,
                session,
                now_ms,
                "claim",
                Some(device),
                Some(file.id),
                Some(&file.rel_path),
            )
            .map_err(|e| self.map(e))?;
            let check = claim_check(device, file.id, &file.hash, file.size, seq, session, now_ms);
            tx.execute(
                "INSERT INTO file_refs(file_id, device_id, source_name, committed_seq, committed_session, committed_unix_ms, row_check)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    file.id,
                    device,
                    source_name,
                    to_i64(seq),
                    to_i64(session),
                    now_ms,
                    check.as_slice()
                ],
            )
            .map_err(|e| self.map(e))?;
            let state: i64 = tx
                .query_row("SELECT state FROM files WHERE id = ?1", [file.id], |r| {
                    r.get(0)
                })
                .map_err(|e| self.map(e))?;
            if FileState::from_code(state).is_some_and(FileState::occupies_space) {
                adjust_usage(tx, device, to_i64(file.size), 1).map_err(|e| self.map(e))?;
            }
            raise_hwm(tx, device, seq).map_err(|e| self.map(e))?;
            Ok((
                FileRecord {
                    device: device.to_owned(),
                    source_name: source_name.to_owned(),
                    committed_seq: seq,
                    committed_session: session,
                    committed_unix_ms: now_ms,
                    ..file.clone()
                },
                true,
            ))
        })?;
        if outcome.1 && !durable {
            self.pending_batched
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(outcome)
    }

    // ----- devices -------------------------------------------------------

    /// Marks a device as unpaired. Nothing is removed: its records, claims
    /// and files stay exactly as they are. Returns false if the device is
    /// unknown or already detached.
    pub(crate) fn detach_device(&self, device_id: &str, note: &str, now_ms: i64) -> Result<bool> {
        let session = self.session();
        self.write(true, |tx| {
            let attached: Option<bool> = tx
                .query_row(
                    "SELECT detached_seq IS NULL FROM devices WHERE device_id = ?1",
                    [device_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| self.map(e))?;
            if attached != Some(true) {
                return Ok(false);
            }
            let seq = append_event(
                tx,
                session,
                now_ms,
                "device_detached",
                Some(device_id),
                None,
                Some(note),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE devices SET detached_seq = ?2 WHERE device_id = ?1",
                params![device_id, to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            Ok(true)
        })
    }

    // ----- temp-file intents ---------------------------------------------

    /// Notes that the engine is about to create the temp file `rel_path` at
    /// `location` (0 for the destination, otherwise a mirror id). Not
    /// flushed: losing the note only means the temp file is never cleaned up
    /// automatically.
    pub(crate) fn add_partial(&self, location: i64, rel_path: &str, now_ms: i64) -> Result<()> {
        let session = self.session();
        self.write(false, |tx| {
            tx.execute(
                "INSERT OR REPLACE INTO partials(location, path_key, rel_path, created_session, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![location, path_key(rel_path), rel_path, to_i64(session), now_ms],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Forgets a temp-file intent.
    pub(crate) fn remove_partial(&self, location: i64, rel_path: &str) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "DELETE FROM partials WHERE location = ?1 AND path_key = ?2",
                params![location, path_key(rel_path)],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Whether the engine noted creating this temp file.
    pub(crate) fn has_partial(&self, location: i64, rel_path: &str) -> Result<bool> {
        let conn = self.lock();
        conn.query_row(
            "SELECT 1 FROM partials WHERE location = ?1 AND path_key = ?2",
            params![location, path_key(rel_path)],
            |_| Ok(()),
        )
        .optional()
        .map(|r| r.is_some())
        .map_err(|e| self.map(e))
    }

    /// The temp files the engine noted creating at `location`.
    pub(crate) fn partials(&self, location: i64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT rel_path FROM partials WHERE location = ?1 ORDER BY path_key")
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([location], |r| r.get::<_, String>(0))
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    // ----- repairs -------------------------------------------------------

    /// Notes that the flush of a file's new name, which had failed at commit
    /// time, has now succeeded.
    pub(crate) fn set_dir_synced(&self, file_id: i64, now_ms: i64) -> Result<()> {
        let session = self.session();
        self.write(true, |tx| {
            append_event(
                tx,
                session,
                now_ms,
                "rename_flushed",
                None,
                Some(file_id),
                None,
            )
            .map_err(|e| self.map(e))?;
            tx.execute("UPDATE files SET dir_synced = 1 WHERE id = ?1", [file_id])
                .map(|_| ())
                .map_err(|e| self.map(e))
        })
    }

    /// Records that a missing or damaged file was written again from a
    /// verified mirror copy. The row now points at the restored file, is
    /// believed intact, and is re-stamped as committed now, in this session,
    /// for its first committer and for every device holding a claim: a
    /// freshly written copy has to age again before it can confirm anything.
    pub(crate) fn record_restored(
        &self,
        file: &FileRecord,
        restored: &Restored<'_>,
        now_ms: i64,
    ) -> Result<FileRecord> {
        let session = self.session();
        self.write(true, |tx| {
            let owner: FileRecord = {
                let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
                self.query_files(tx, &sql, &[&file.id])?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        self.corrupt(format!(
                            "file row {} vanished while it was being repaired",
                            file.id
                        ))
                    })?
            };
            supersede_stale(tx, session, now_ms, restored.path_key, Some(owner.id))
                .map_err(|e| self.map(e))?;
            let seq = append_event(
                tx,
                session,
                now_ms,
                "primary_repaired",
                Some(&owner.device),
                Some(owner.id),
                Some(restored.detail),
            )
            .map_err(|e| self.map(e))?;
            let check = row_check(
                &owner.device,
                restored.rel_path,
                &owner.hash,
                owner.size,
                seq,
                session,
                now_ms,
            );
            tx.execute(
                "UPDATE files SET rel_path = ?2, path_key = ?3, state = 1, state_seq = ?4, committed_seq = ?4,
                                  committed_session = ?5, committed_unix_ms = ?6, dir_synced = ?7,
                                  verified_unbuffered = ?8, row_check = ?9
                 WHERE id = ?1",
                params![
                    owner.id,
                    restored.rel_path,
                    restored.path_key,
                    to_i64(seq),
                    to_i64(session),
                    now_ms,
                    restored.dir_synced,
                    restored.verified_unbuffered,
                    check.as_slice()
                ],
            )
            .map_err(|e| self.map(e))?;
            if !owner.state.occupies_space() {
                adjust_usage_all(tx, owner.id, &owner.device, to_i64(owner.size), 1)
                    .map_err(|e| self.map(e))?;
            }
            raise_hwm(tx, &owner.device, seq).map_err(|e| self.map(e))?;
            restamp_refs(tx, "r.file_id = ?1", &[&owner.id], seq, session, now_ms)
                .map_err(|e| self.map(e))?;
            if let Some(partial) = restored.partial {
                tx.execute(
                    "DELETE FROM partials WHERE location = 0 AND path_key = ?1",
                    [path_key(partial)],
                )
                .map_err(|e| self.map(e))?;
            }
            Ok(FileRecord {
                rel_path: restored.rel_path.to_owned(),
                state: FileState::Committed,
                committed_seq: seq,
                committed_session: session,
                committed_unix_ms: now_ms,
                dir_synced: restored.dir_synced,
                verified_unbuffered: restored.verified_unbuffered,
                ..owner
            })
        })
    }
}
