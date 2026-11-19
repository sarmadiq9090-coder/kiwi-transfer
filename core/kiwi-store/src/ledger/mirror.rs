//! Ledger records of the mirrors (second copies on other disks).
//!
//! As everywhere in the ledger, these rows are belief. A mirror copy is used
//! to repair anything only after it has been read back from its disk and
//! matched the hash recorded for the file; the counts derived from these rows
//! describe the last check, not this instant.

use rusqlite::{params, OptionalExtension, Row};

use super::{append_event, to_i64, to_u64, FileRecord, Ledger, Result, FILE_COLUMNS};

/// A mirror destination as the ledger knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRecord {
    /// Row id; what the API calls the mirror's id.
    pub id: i64,
    /// Random identifier, also written to the marker file on the mirror.
    pub uid: String,
    /// The mirror's root folder as last seen.
    pub root: String,
    /// Name shown to the user.
    pub label: String,
    /// Serial number of the volume the mirror was created on.
    pub volume_serial: Option<u64>,
    /// False once the mirror has been removed. The row is kept for the audit
    /// trail; the files on the disk are never touched.
    pub active: bool,
    /// Session in which the mirror was last present with the right identity.
    pub last_seen_session: u64,
    /// Wall-clock time (Unix milliseconds) of that moment.
    pub last_seen_unix_ms: i64,
    /// I/O errors on this mirror since the counters were last reset.
    pub io_errors: u64,
    /// Files on this mirror found different from their record since then.
    pub mismatches: u64,
}

/// What the ledger believes about one file's copy on one mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorFileState {
    /// The copy was read back from the mirror and matched.
    Verified,
    /// A check found the copy gone.
    Missing,
    /// A check found different content where the copy should be.
    Changed,
}

impl MirrorFileState {
    fn code(self) -> i64 {
        match self {
            MirrorFileState::Verified => 1,
            MirrorFileState::Missing => 2,
            MirrorFileState::Changed => 3,
        }
    }

    fn from_code(code: i64) -> Option<MirrorFileState> {
        match code {
            1 => Some(MirrorFileState::Verified),
            2 => Some(MirrorFileState::Missing),
            3 => Some(MirrorFileState::Changed),
            _ => None,
        }
    }
}

/// One file's copy on one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirrorFileRow {
    pub mirror_id: i64,
    pub file_id: i64,
    /// Path relative to the mirror root. Usually the file's own relative
    /// path; different when that name was taken on the mirror.
    pub rel_path: String,
    pub state: MirrorFileState,
}

/// A mirror to register.
pub(crate) struct NewMirror<'a> {
    pub uid: &'a str,
    pub root: &'a str,
    pub label: &'a str,
    pub volume_serial: Option<u64>,
}

/// A copy to record.
pub(crate) struct MirrorCopy<'a> {
    pub mirror_id: i64,
    pub file_id: i64,
    pub rel_path: &'a str,
    pub unbuffered: bool,
    /// Event kind: `mirror_copy`, `mirror_adopt` or `mirror_repaired`.
    pub kind: &'a str,
    pub detail: &'a str,
    pub durable: bool,
}

/// Unmirrored files of one device on one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRow {
    pub mirror_id: i64,
    pub device: String,
    pub files: u64,
    pub bytes: u64,
}

const MIRROR_COLUMNS: &str = "id, uid, root, label, volume_serial, active, last_seen_session, \
     last_seen_unix_ms, io_errors, mismatches";

fn mirror_from_row(r: &Row<'_>) -> rusqlite::Result<MirrorRecord> {
    Ok(MirrorRecord {
        id: r.get(0)?,
        uid: r.get(1)?,
        root: r.get(2)?,
        label: r.get(3)?,
        volume_serial: r
            .get::<_, Option<String>>(4)?
            .and_then(|s| s.parse::<u64>().ok()),
        active: r.get(5)?,
        last_seen_session: to_u64(r.get(6)?),
        last_seen_unix_ms: r.get(7)?,
        io_errors: to_u64(r.get(8)?),
        mismatches: to_u64(r.get(9)?),
    })
}

/// SQL condition: file `f` has a verified copy on some active mirror.
const HAS_MIRROR_COPY: &str =
    "EXISTS (SELECT 1 FROM mirror_files mf JOIN mirrors m ON m.id = mf.mirror_id
             WHERE mf.file_id = f.id AND mf.state = 1 AND m.active = 1)";

impl Ledger {
    /// Registers a mirror. The caller has already written its marker.
    pub(crate) fn add_mirror(&self, new: &NewMirror<'_>, now_ms: i64) -> Result<MirrorRecord> {
        let session = self.session();
        let id = self.write(true, |tx| {
            let detail = format!("{} at {} (id {})", new.label, new.root, new.uid);
            let seq = append_event(
                tx,
                session,
                now_ms,
                "mirror_added",
                None,
                None,
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "INSERT INTO mirrors(uid, root, label, volume_serial, active, added_seq, last_seen_seq, last_seen_session, last_seen_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, ?7)",
                params![
                    new.uid,
                    new.root,
                    new.label,
                    new.volume_serial.map(|s| s.to_string()),
                    to_i64(seq),
                    to_i64(session),
                    now_ms
                ],
            )
            .map_err(|e| self.map(e))?;
            Ok(tx.last_insert_rowid())
        })?;
        self.mirror(id)?
            .ok_or_else(|| self.corrupt("a mirror row vanished right after it was written"))
    }

    /// All mirrors, removed ones included, in the order they were added.
    pub(crate) fn mirrors(&self) -> Result<Vec<MirrorRecord>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!("SELECT {MIRROR_COLUMNS} FROM mirrors ORDER BY id"))
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([], mirror_from_row)
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    pub(crate) fn mirror(&self, id: i64) -> Result<Option<MirrorRecord>> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {MIRROR_COLUMNS} FROM mirrors WHERE id = ?1"),
            [id],
            mirror_from_row,
        )
        .optional()
        .map_err(|e| self.map(e))
    }

    pub(crate) fn mirror_by_uid(&self, uid: &str) -> Result<Option<MirrorRecord>> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {MIRROR_COLUMNS} FROM mirrors WHERE uid = ?1"),
            [uid],
            mirror_from_row,
        )
        .optional()
        .map_err(|e| self.map(e))
    }

    /// Marks a mirror as removed. Its rows stay (they are the audit trail),
    /// but its copies no longer count. Returns false if it was not active.
    pub(crate) fn deactivate_mirror(&self, id: i64, note: &str, now_ms: i64) -> Result<bool> {
        let session = self.session();
        self.write(true, |tx| {
            let active: Option<bool> = tx
                .query_row("SELECT active FROM mirrors WHERE id = ?1", [id], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(|e| self.map(e))?;
            if active != Some(true) {
                return Ok(false);
            }
            let detail = format!("mirror {id}: {note}");
            let seq = append_event(
                tx,
                session,
                now_ms,
                "mirror_removed",
                None,
                None,
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirrors SET active = 0, removed_seq = ?2 WHERE id = ?1",
                params![id, to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            tx.execute("DELETE FROM mirror_scan_state WHERE mirror_id = ?1", [id])
                .map_err(|e| self.map(e))?;
            Ok(true)
        })
    }

    /// Records that a known mirror was found at a new path (or is active
    /// again after having been removed).
    pub(crate) fn reattach_mirror(
        &self,
        id: i64,
        root: &str,
        label: &str,
        now_ms: i64,
    ) -> Result<()> {
        let session = self.session();
        self.write(true, |tx| {
            let detail = format!("mirror {id} is now at {root}");
            let seq = append_event(
                tx,
                session,
                now_ms,
                "mirror_reattached",
                None,
                None,
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirrors SET root = ?2, label = ?3, active = 1, removed_seq = NULL,
                                    last_seen_seq = ?4, last_seen_session = ?5, last_seen_unix_ms = ?6
                 WHERE id = ?1",
                params![id, root, label, to_i64(seq), to_i64(session), now_ms],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Notes that a mirror is present with the right identity.
    pub(crate) fn mirror_seen(&self, id: i64, now_ms: i64) -> Result<()> {
        let session = self.session();
        self.write(false, |tx| {
            let seq = append_event(tx, session, now_ms, "mirror_seen", None, None, None)
                .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirrors SET last_seen_seq = ?2, last_seen_session = ?3, last_seen_unix_ms = ?4 WHERE id = ?1",
                params![id, to_i64(seq), to_i64(session), now_ms],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Adds to a mirror's trouble counters and returns the new totals
    /// (I/O errors, mismatches).
    pub(crate) fn mirror_trouble(
        &self,
        id: i64,
        io_errors: u64,
        mismatches: u64,
        detail: &str,
        now_ms: i64,
    ) -> Result<(u64, u64)> {
        let session = self.session();
        self.write(true, |tx| {
            let detail = format!("mirror {id}: {detail}");
            append_event(
                tx,
                session,
                now_ms,
                "mirror_trouble",
                None,
                None,
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirrors SET io_errors = io_errors + ?2, mismatches = mismatches + ?3 WHERE id = ?1",
                params![id, to_i64(io_errors), to_i64(mismatches)],
            )
            .map_err(|e| self.map(e))?;
            tx.query_row(
                "SELECT io_errors, mismatches FROM mirrors WHERE id = ?1",
                [id],
                |r| Ok((to_u64(r.get(0)?), to_u64(r.get(1)?))),
            )
            .map_err(|e| self.map(e))
        })
    }

    /// Resets a mirror's trouble counters (after a clean pass over it).
    pub(crate) fn mirror_trouble_reset(&self, id: i64) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "UPDATE mirrors SET io_errors = 0, mismatches = 0 WHERE id = ?1",
                [id],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// Up to `limit` files with `id > cursor`, believed intact on the
    /// destination, that have no verified copy on this mirror.
    pub(crate) fn files_pending_for_mirror(
        &self,
        mirror_id: i64,
        cursor: i64,
        limit: u32,
    ) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE id > ?1 AND state = 1
               AND NOT EXISTS (SELECT 1 FROM mirror_files mf
                               WHERE mf.mirror_id = ?2 AND mf.file_id = files.id AND mf.state = 1)
             ORDER BY id LIMIT ?3"
        );
        self.query_files(&conn, &sql, &[&cursor, &mirror_id, &i64::from(limit)])
    }

    /// Up to `limit` files with `id > cursor` that are missing or changed on
    /// the destination and have a copy believed good on some active mirror.
    pub(crate) fn files_repairable(&self, cursor: i64, limit: u32) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files AS f WHERE f.id > ?1 AND f.state <> 1 AND {HAS_MIRROR_COPY}
             ORDER BY f.id LIMIT ?2"
        );
        self.query_files(&conn, &sql, &[&cursor, &i64::from(limit)])
    }

    fn mirror_rows(&self, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<MirrorFileRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(sql).map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map(args, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| self.map(e))?;
        let mut out = Vec::new();
        for row in rows {
            let (mirror_id, file_id, rel_path, state) = row.map_err(|e| self.map(e))?;
            let state = MirrorFileState::from_code(state).ok_or_else(|| {
                self.corrupt(format!(
                    "the mirror record of file row {file_id} has an unknown state"
                ))
            })?;
            out.push(MirrorFileRow {
                mirror_id,
                file_id,
                rel_path,
                state,
            });
        }
        Ok(out)
    }

    /// The copies of one file on the active mirrors.
    pub(crate) fn mirror_rows_for_file(&self, file_id: i64) -> Result<Vec<MirrorFileRow>> {
        self.mirror_rows(
            "SELECT mf.mirror_id, mf.file_id, mf.rel_path, mf.state FROM mirror_files mf
             JOIN mirrors m ON m.id = mf.mirror_id
             WHERE mf.file_id = ?1 AND m.active = 1 ORDER BY mf.mirror_id",
            &[&file_id],
        )
    }

    /// Up to `limit` copies on a mirror with `cursor < file id <= upper`.
    pub(crate) fn mirror_files_after(
        &self,
        mirror_id: i64,
        cursor: i64,
        upper: i64,
        limit: u32,
    ) -> Result<Vec<MirrorFileRow>> {
        self.mirror_rows(
            "SELECT mirror_id, file_id, rel_path, state FROM mirror_files
             WHERE mirror_id = ?1 AND file_id > ?2 AND file_id <= ?3 ORDER BY file_id LIMIT ?4",
            &[&mirror_id, &cursor, &upper, &i64::from(limit)],
        )
    }

    /// Records a verified copy of a file on a mirror. Returns the event's
    /// sequence number. The copy is marked to be read back once more at the
    /// start of a later run: a disk pulled out without "eject" may lose its
    /// last writes.
    pub(crate) fn record_mirror_copy(&self, copy: &MirrorCopy<'_>, now_ms: i64) -> Result<u64> {
        let session = self.session();
        self.write(copy.durable, |tx| {
            let detail = format!(
                "mirror {}: {} {}",
                copy.mirror_id, copy.rel_path, copy.detail
            );
            let seq = append_event(
                tx,
                session,
                now_ms,
                copy.kind,
                None,
                Some(copy.file_id),
                Some(detail.trim_end()),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "INSERT INTO mirror_files(mirror_id, file_id, rel_path, state, copied_seq, copied_run, recheck,
                                          verified_seq, verified_unix_ms, unbuffered)
                 VALUES (?1, ?2, ?3, 1, ?4, (SELECT run_no FROM mirrors WHERE id = ?1), 1, ?4, ?5, ?6)
                 ON CONFLICT(mirror_id, file_id) DO UPDATE SET
                     rel_path = excluded.rel_path, state = 1, copied_seq = excluded.copied_seq,
                     copied_run = excluded.copied_run, recheck = 1,
                     verified_seq = excluded.verified_seq, verified_unix_ms = excluded.verified_unix_ms,
                     unbuffered = excluded.unbuffered",
                params![
                    copy.mirror_id,
                    copy.file_id,
                    copy.rel_path,
                    to_i64(seq),
                    now_ms,
                    copy.unbuffered
                ],
            )
            .map_err(|e| self.map(e))?;
            Ok(seq)
        })
    }

    /// Changes what the ledger believes about a mirror copy. Returns whether
    /// the belief changed (a finding already on record is not logged twice).
    pub(crate) fn set_mirror_file_state(
        &self,
        mirror_id: i64,
        file_id: i64,
        state: MirrorFileState,
        detail: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let session = self.session();
        self.write(true, |tx| {
            let old: Option<i64> = tx
                .query_row(
                    "SELECT state FROM mirror_files WHERE mirror_id = ?1 AND file_id = ?2",
                    params![mirror_id, file_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| self.map(e))?;
            if old.is_none() || old == Some(state.code()) {
                return Ok(false);
            }
            let kind = match state {
                MirrorFileState::Verified => "mirror_file_restored",
                MirrorFileState::Missing => "mirror_file_missing",
                MirrorFileState::Changed => "mirror_file_changed",
            };
            let detail = format!("mirror {mirror_id}: {detail}");
            let seq = append_event(
                tx,
                session,
                now_ms,
                kind,
                None,
                Some(file_id),
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirror_files SET state = ?3, verified_seq = ?4, verified_unix_ms = ?5 WHERE mirror_id = ?1 AND file_id = ?2",
                params![mirror_id, file_id, state.code(), to_i64(seq), now_ms],
            )
            .map_err(|e| self.map(e))?;
            Ok(true)
        })
    }

    /// Notes that a mirror copy was just read back and matched. No event and
    /// no flush: a scan does this for every file.
    pub(crate) fn mirror_file_verified(
        &self,
        mirror_id: i64,
        file_id: i64,
        unbuffered: bool,
        now_ms: i64,
    ) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "UPDATE mirror_files SET verified_unix_ms = ?3, unbuffered = ?4 WHERE mirror_id = ?1 AND file_id = ?2",
                params![mirror_id, file_id, now_ms, unbuffered],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    // ----- scan progress -------------------------------------------------

    /// Saved progress of a mirror scan: (upper file id, cursor).
    pub(crate) fn mirror_scan_state(&self, mirror_id: i64) -> Result<Option<(i64, i64)>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT upper_id, cursor_id FROM mirror_scan_state WHERE mirror_id = ?1",
            [mirror_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| self.map(e))
    }

    pub(crate) fn save_mirror_scan_state(
        &self,
        mirror_id: i64,
        upper: i64,
        cursor: i64,
    ) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "INSERT OR REPLACE INTO mirror_scan_state(mirror_id, upper_id, cursor_id) VALUES (?1, ?2, ?3)",
                params![mirror_id, upper, cursor],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    pub(crate) fn clear_mirror_scan_state(&self, mirror_id: i64) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "DELETE FROM mirror_scan_state WHERE mirror_id = ?1",
                [mirror_id],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    // ----- runs ----------------------------------------------------------

    /// Notes, flushed, that a run or a scan is about to write to a mirror.
    /// Returns the new run number and whether the previous run on this
    /// mirror never reached its end (it may have left temp files behind).
    pub(crate) fn mirror_begin_run(&self, id: i64, now_ms: i64) -> Result<(u64, bool)> {
        let session = self.session();
        self.write(true, |tx| {
            let (run_no, open): (i64, bool) = tx
                .query_row(
                    "SELECT run_no, run_open FROM mirrors WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| self.map(e))?;
            let detail = format!("mirror {id}: run {}", run_no + 1);
            append_event(tx, session, now_ms, "mirror_run", None, None, Some(&detail))
                .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE mirrors SET run_no = ?2, run_open = 1 WHERE id = ?1",
                params![id, run_no + 1],
            )
            .map_err(|e| self.map(e))?;
            Ok((to_u64(run_no + 1), open))
        })
    }

    /// Notes that a run on a mirror reached its end with nothing left behind.
    pub(crate) fn mirror_end_run(&self, id: i64) -> Result<()> {
        self.write(false, |tx| {
            tx.execute("UPDATE mirrors SET run_open = 0 WHERE id = ?1", [id])
                .map(|_| ())
                .map_err(|e| self.map(e))
        })
    }

    /// Up to `limit` copies with `file id > cursor` that an earlier run wrote
    /// and that have not been read back since.
    pub(crate) fn mirror_rows_to_recheck(
        &self,
        mirror_id: i64,
        current_run: u64,
        cursor: i64,
        limit: u32,
    ) -> Result<Vec<MirrorFileRow>> {
        self.mirror_rows(
            "SELECT mirror_id, file_id, rel_path, state FROM mirror_files
             WHERE mirror_id = ?1 AND recheck = 1 AND state = 1 AND copied_run < ?2 AND file_id > ?3
             ORDER BY file_id LIMIT ?4",
            &[&mirror_id, &to_i64(current_run), &cursor, &i64::from(limit)],
        )
    }

    /// Notes that a copy was read back after the run that wrote it.
    pub(crate) fn mirror_recheck_done(&self, mirror_id: i64, file_id: i64) -> Result<()> {
        self.write(false, |tx| {
            tx.execute(
                "UPDATE mirror_files SET recheck = 0 WHERE mirror_id = ?1 AND file_id = ?2",
                params![mirror_id, file_id],
            )
            .map(|_| ())
            .map_err(|e| self.map(e))
        })
    }

    /// The copies on one mirror of files that have exactly this size. Used to
    /// recognise a temp file that is really a recorded copy whose rename was
    /// lost.
    pub(crate) fn mirror_rows_with_size(
        &self,
        mirror_id: i64,
        size: u64,
    ) -> Result<Vec<MirrorFileRow>> {
        self.mirror_rows(
            "SELECT mf.mirror_id, mf.file_id, mf.rel_path, mf.state FROM mirror_files mf
             JOIN files f ON f.id = mf.file_id
             WHERE mf.mirror_id = ?1 AND f.size = ?2 ORDER BY mf.file_id",
            &[&mirror_id, &to_i64(size)],
        )
    }

    /// How many verified copies of a file the active mirrors hold.
    pub(crate) fn mirror_copies_of(&self, file_id: i64) -> Result<u64> {
        let conn = self.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM mirror_files mf JOIN mirrors m ON m.id = mf.mirror_id
             WHERE mf.file_id = ?1 AND mf.state = 1 AND m.active = 1",
            [file_id],
            |r| r.get::<_, i64>(0),
        )
        .map(to_u64)
        .map_err(|e| self.map(e))
    }

    // ----- what is mirrored ---------------------------------------------

    /// Per active mirror and device: the files believed intact on the
    /// destination that have no verified copy on that mirror.
    pub(crate) fn mirror_pending(&self) -> Result<Vec<PendingRow>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT m.id, f.device_id, COUNT(*), COALESCE(SUM(f.size), 0)
                 FROM mirrors m CROSS JOIN files f
                 WHERE m.active = 1 AND f.state = 1
                   AND NOT EXISTS (SELECT 1 FROM mirror_files mf
                                   WHERE mf.mirror_id = m.id AND mf.file_id = f.id AND mf.state = 1)
                 GROUP BY m.id, f.device_id ORDER BY m.id, f.device_id",
            )
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(PendingRow {
                    mirror_id: r.get(0)?,
                    device: r.get(1)?,
                    files: to_u64(r.get(2)?),
                    bytes: to_u64(r.get(3)?),
                })
            })
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    /// For one device: how many of its files have how many copies believed
    /// good (the destination's copy plus one per active mirror). Files the
    /// PC user acknowledged as removed are not counted. Returns pairs of
    /// (number of copies, number of files).
    pub(crate) fn copy_counts(&self, device: &str) -> Result<Vec<(u64, u64)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT copies, COUNT(*) FROM (
                     SELECT (CASE WHEN f.state = 1 THEN 1 ELSE 0 END)
                          + (SELECT COUNT(*) FROM mirror_files mf JOIN mirrors m ON m.id = mf.mirror_id
                             WHERE mf.file_id = f.id AND mf.state = 1 AND m.active = 1) AS copies
                     FROM files f WHERE f.device_id = ?1 AND f.fm_state <> 3)
                 GROUP BY copies ORDER BY copies",
            )
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([device], |r| Ok((to_u64(r.get(0)?), to_u64(r.get(1)?))))
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    /// The device's oldest file (by commit number) that is believed intact
    /// on the destination and has no verified copy on any active mirror.
    pub(crate) fn oldest_unmirrored(&self, device: &str) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files AS f
             WHERE f.device_id = ?1 AND f.state = 1 AND NOT {HAS_MIRROR_COPY}
             ORDER BY f.committed_seq, f.id LIMIT 1"
        );
        Ok(self
            .query_files(&conn, &sql, &[&device])?
            .into_iter()
            .next())
    }

    /// How many mirrors are active.
    pub(crate) fn active_mirror_count(&self) -> Result<u64> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM mirrors WHERE active = 1", [], |r| {
            r.get::<_, i64>(0)
        })
        .map(to_u64)
        .map_err(|e| self.map(e))
    }
}
