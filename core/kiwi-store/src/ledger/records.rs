//! Ledger records beyond the plain commit: per-device sessions and commit
//! numbers, the tags of the engine's temp files, unpaired devices, the
//! final-move state of a file, and the bookkeeping of a repaired file.
//!
//! **Per device.** Every device has its own session counter and its own
//! commit numbers. A file row belongs to exactly one device and lies inside
//! that device's folder; nothing recorded for one device is ever used to
//! answer for another.
//!
//! **Temp-file tags.** Each run of the store draws a random tag, writes it
//! here (flushed) before it creates its first temp file, and puts it in the
//! name of every temp file it creates. A file whose name carries a tag this
//! ledger does not know is not the engine's and is never deleted.

use std::collections::HashSet;

use rusqlite::{params, OptionalExtension, Transaction};

use super::{
    adjust_usage, append_event, hex, row_check, to_i64, to_u64, FileRecord, FileState, FmState,
    Ledger, Result, FILE_COLUMNS,
};
use crate::hash::ContentHash;

/// The largest session number a device may be given (2^53 - 1, the protocol's
/// limit).
pub(crate) const MAX_SESSION_SEQ: u64 = (1 << 53) - 1;

/// Removes the stale row recorded under `path_key`, if any, with the mirror
/// records that depend on it. Called when a file has just been given that
/// path by a no-replace rename: whatever the old row described is no longer
/// there.
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
        adjust_usage(tx, &old_device, -old_size, -1)?;
    }
    // What the mirrors knew about the vanished file goes with it. Each is
    // logged; a mirror keeps whatever file it has.
    {
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
    tx.execute("DELETE FROM mirror_files WHERE file_id = ?1", [old_id])?;
    tx.execute("DELETE FROM files WHERE id = ?1", [old_id])?;
    Ok(())
}

/// What a repaired file is recorded as.
pub(crate) struct Restored<'a> {
    pub rel_path: &'a str,
    pub path_key: &'a str,
    pub dir_synced: bool,
    pub verified_unbuffered: bool,
    pub detail: &'a str,
}

impl Ledger {
    // ----- lookups -------------------------------------------------------

    /// One file row.
    pub(crate) fn file_by_id(&self, id: i64) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
        Ok(self.query_files(&conn, &sql, &[&id])?.into_iter().next())
    }

    /// The rows of one device with this content hash, oldest commit first.
    /// Rows of other devices are never returned, whatever they hold.
    pub(crate) fn device_files_by_hash(
        &self,
        device: &str,
        hash: &ContentHash,
    ) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE hash = ?1 AND device_id = ?2 ORDER BY committed_seq, id"
        );
        self.query_files(&conn, &sql, &[&hash.as_bytes().as_slice(), &device])
    }

    /// The row a phone names in a verification request: this device, this
    /// item key, this hash, this size, this commit number. All five must match.
    pub(crate) fn device_record(
        &self,
        device: &str,
        key: &[u8],
        hash: &ContentHash,
        size: u64,
        commit_no: u64,
    ) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files
             WHERE device_id = ?1 AND item_key = ?2 AND hash = ?3 AND size = ?4 AND commit_no = ?5
             ORDER BY id LIMIT 1"
        );
        Ok(self
            .query_files(
                &conn,
                &sql,
                &[
                    &device,
                    &key,
                    &hash.as_bytes().as_slice(),
                    &to_i64(size),
                    &to_i64(commit_no),
                ],
            )?
            .into_iter()
            .next())
    }

    /// Rows (of any device, in any state) whose file has exactly this size.
    /// Used to recognise a temp file that is really a committed file whose
    /// rename was lost.
    pub(crate) fn files_with_size(&self, size: u64) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE size = ?1 ORDER BY id");
        self.query_files(&conn, &sql, &[&to_i64(size)])
    }

    // ----- devices -------------------------------------------------------

    /// Marks a device as unpaired. Nothing is removed: its records and files
    /// stay exactly as they are. Returns false if the device is unknown or
    /// already detached.
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

    /// Begins a new session of one device, durably. `requested` is the
    /// number agreed with the phone; without it the device's own counter is
    /// advanced by one.
    ///
    /// Returns `Ok(None)` for an unknown device, `Ok(Some(Err(current)))` if
    /// the requested number is not above the current one (or out of range),
    /// and otherwise the new session number.
    ///
    /// Being a flushed write, it also makes every batched record durable.
    pub(crate) fn start_device_session(
        &self,
        device_id: &str,
        requested: Option<u64>,
        now_ms: i64,
    ) -> Result<Option<std::result::Result<u64, u64>>> {
        let run = self.session();
        let outcome = self.write(true, |tx| {
            let current: Option<i64> = tx
                .query_row(
                    "SELECT session_seq FROM devices WHERE device_id = ?1",
                    [device_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| self.map(e))?;
            let Some(current) = current.map(to_u64) else {
                return Ok(None);
            };
            let next = match requested {
                None if current < MAX_SESSION_SEQ => current + 1,
                Some(n) if n > current && n <= MAX_SESSION_SEQ => n,
                _ => return Ok(Some(Err(current))),
            };
            let seq = append_event(
                tx,
                run,
                now_ms,
                "device_session_start",
                Some(device_id),
                None,
                Some(&next.to_string()),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE devices SET session_seq = ?2, session_start_seq = ?3 WHERE device_id = ?1",
                params![device_id, to_i64(next), to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            Ok(Some(Ok(next)))
        })?;
        if matches!(outcome, Some(Ok(_))) {
            self.pending_batched
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(outcome)
    }

    /// Raises a device's commit high-water mark to `to` (it never goes
    /// down), so that no commit number a phone has seen is issued twice.
    pub(crate) fn raise_commit_hwm(
        &self,
        device_id: &str,
        to: u64,
        detail: &str,
        now_ms: i64,
    ) -> Result<()> {
        let run = self.session();
        self.write(true, |tx| {
            append_event(
                tx,
                run,
                now_ms,
                "commit_hwm_raised",
                Some(device_id),
                None,
                Some(detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE devices SET commit_hwm = MAX(commit_hwm, ?2) WHERE device_id = ?1",
                params![device_id, to_i64(to)],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    // ----- temp-file tags -------------------------------------------------

    /// Records, flushed, the tag this run will put in its temp-file names.
    pub(crate) fn add_temp_tag(&self, tag: &str, now_ms: i64) -> Result<()> {
        let run = self.session();
        self.write(true, |tx| {
            let seq = append_event(tx, run, now_ms, "temp_tag", None, None, Some(tag))
                .map_err(|e| self.map(e))?;
            tx.execute(
                "INSERT OR IGNORE INTO temp_tags(tag, created_seq, created_unix_ms) VALUES (?1, ?2, ?3)",
                params![tag, to_i64(seq), now_ms],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Every tag this ledger has ever recorded.
    pub(crate) fn temp_tags(&self) -> Result<HashSet<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT tag FROM temp_tags")
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<HashSet<_>>>()
            .map_err(|e| self.map(e))
    }

    // ----- final-move state ----------------------------------------------

    /// Records, in a flushed transaction of its own, that a deletion was
    /// confirmed for a file: it "may be the only copy" from now on. A file
    /// already known as the only copy stays that. Returns the event's
    /// sequence number.
    pub(crate) fn mark_reverified(&self, file_id: i64, device: &str, now_ms: i64) -> Result<u64> {
        let run = self.session();
        self.write(true, |tx| {
            let seq = append_event(
                tx,
                run,
                now_ms,
                "deletion_verified",
                Some(device),
                Some(file_id),
                None,
            )
            .map_err(|e| self.map(e))?;
            let updated = tx
                .execute(
                    "UPDATE files SET last_verified_seq = ?2, last_verified_session = ?3,
                                      fm_state = CASE WHEN fm_state = 0 THEN 1 ELSE fm_state END,
                                      fm_seq = ?2
                     WHERE id = ?1",
                    params![file_id, to_i64(seq), to_i64(run)],
                )
                .map_err(|e| self.map(e))?;
            if updated != 1 {
                return Err(self.corrupt(format!(
                    "file row {file_id} vanished while it was being verified"
                )));
            }
            Ok(seq)
        })
    }

    /// Changes the final-move state of a file. Returns false if there is no
    /// such row.
    pub(crate) fn set_fm_state(
        &self,
        file_id: i64,
        state: FmState,
        expires_unix_ms: Option<i64>,
        detail: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let run = self.session();
        self.write(true, |tx| {
            let device: Option<String> = tx
                .query_row(
                    "SELECT device_id FROM files WHERE id = ?1",
                    [file_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| self.map(e))?;
            let Some(device) = device else {
                return Ok(false);
            };
            let kind = match state {
                FmState::None => "fm_in_place",
                FmState::Reverified => "fm_reverified",
                FmState::SoleCopy => "fm_sole_copy",
                FmState::UserRemoved => "fm_user_removed",
            };
            let seq = append_event(
                tx,
                run,
                now_ms,
                kind,
                Some(&device),
                Some(file_id),
                Some(detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE files SET fm_state = ?2, fm_expires = ?3, fm_seq = ?4 WHERE id = ?1",
                params![file_id, state.code(), expires_unix_ms, to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            Ok(true)
        })
    }

    /// The files of one device in a given final-move state, oldest first.
    pub(crate) fn device_files_in_fm_state(
        &self,
        device: &str,
        state: FmState,
    ) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE device_id = ?1 AND fm_state = ?2 ORDER BY id"
        );
        self.query_files(&conn, &sql, &[&device, &state.code()])
    }

    // ----- repairs -------------------------------------------------------

    /// Notes that the flush of a file's new name, which had not happened at
    /// commit time, has now succeeded.
    pub(crate) fn set_dir_synced(&self, file_id: i64, now_ms: i64) -> Result<()> {
        let run = self.session();
        self.write(true, |tx| {
            append_event(tx, run, now_ms, "rename_flushed", None, Some(file_id), None)
                .map_err(|e| self.map(e))?;
            tx.execute("UPDATE files SET dir_synced = 1 WHERE id = ?1", [file_id])
                .map(|_| ())
                .map_err(|e| self.map(e))
        })
    }

    /// Records that a file found without its final name was given that name
    /// again (its rename had been lost). The row is believed intact again.
    pub(crate) fn record_rename_recreated(
        &self,
        file: &FileRecord,
        detail: &str,
        now_ms: i64,
    ) -> Result<()> {
        let run = self.session();
        self.write(true, |tx| {
            let seq = append_event(
                tx,
                run,
                now_ms,
                "rename_recreated",
                Some(&file.device),
                Some(file.id),
                Some(detail),
            )
            .map_err(|e| self.map(e))?;
            let old: i64 = tx
                .query_row("SELECT state FROM files WHERE id = ?1", [file.id], |r| {
                    r.get(0)
                })
                .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE files SET state = 1, state_seq = ?2, dir_synced = 1 WHERE id = ?1",
                params![file.id, to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            if FileState::from_code(old).is_some_and(|s| !s.occupies_space()) {
                adjust_usage(tx, &file.device, to_i64(file.size), 1).map_err(|e| self.map(e))?;
            }
            Ok(())
        })
    }

    /// Records that a missing or damaged file was written again from a
    /// verified mirror copy. The row now points at the restored file and is
    /// believed intact. It keeps its item key, its hash and its commit
    /// number; the time and the session at which it "was stored" become now
    /// and the device's current session: a freshly written copy has to age
    /// again before it can confirm anything.
    pub(crate) fn record_restored(
        &self,
        file: &FileRecord,
        restored: &Restored<'_>,
        now_ms: i64,
    ) -> Result<FileRecord> {
        let run = self.session();
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
            supersede_stale(tx, run, now_ms, restored.path_key, Some(owner.id))
                .map_err(|e| self.map(e))?;
            let device_session: i64 = tx
                .query_row(
                    "SELECT session_seq FROM devices WHERE device_id = ?1",
                    [&owner.device],
                    |r| r.get(0),
                )
                .map_err(|e| self.map(e))?;
            let device_session = to_u64(device_session);
            let seq = append_event(
                tx,
                run,
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
                device_session,
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
                    to_i64(device_session),
                    now_ms,
                    restored.dir_synced,
                    restored.verified_unbuffered,
                    check.as_slice()
                ],
            )
            .map_err(|e| self.map(e))?;
            if !owner.state.occupies_space() {
                adjust_usage(tx, &owner.device, to_i64(owner.size), 1).map_err(|e| self.map(e))?;
            }
            Ok(FileRecord {
                rel_path: restored.rel_path.to_owned(),
                state: FileState::Committed,
                committed_seq: seq,
                committed_session: device_session,
                committed_unix_ms: now_ms,
                dir_synced: restored.dir_synced,
                verified_unbuffered: restored.verified_unbuffered,
                ..owner
            })
        })
    }
}
