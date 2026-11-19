//! The ledger: an SQLite index of what the engine has stored.
//!
//! The ledger is an *index, never the authority*. It says where a file with a
//! given hash should be and when it was committed; whether the file is really
//! there is always decided by reading the file back from the disk. Nothing in
//! this module answers "is it safe?".
//!
//! Durability and integrity measures:
//!
//! * WAL journal with `synchronous=FULL`: a committed transaction survives
//!   power loss (as far as the disk honours flushes).
//! * `PRAGMA integrity_check` and `foreign_key_check` on every open; any
//!   finding makes the open fail with [`LedgerError::Corrupt`].
//! * Every file row carries a BLAKE3 checksum over the fields that decisions
//!   depend on, checked whenever the row is read. SQLite's own check verifies
//!   the b-tree structure, not the cell contents; this closes that gap.
//! * Every change appends an event whose `seq` comes from an `AUTOINCREMENT`
//!   key: strictly increasing, never reused, independent of the clock.
//! * A session counter is incremented durably on every open.
//! * `PRAGMA user_version` carries the schema version; migrations run inside
//!   a transaction; a ledger from a newer build is refused untouched.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::error::LedgerError;
use crate::hash::ContentHash;
use crate::sanitize::{collision_key, SafeName};

/// File name of the database inside the ledger directory.
pub const LEDGER_FILE: &str = "ledger.db";

/// Newest schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 2;

/// SQLite `application_id` of a Kiwi Transfer ledger ("KWST").
const APPLICATION_ID: i64 = 0x4B57_5354;

const MIGRATIONS: &[(u32, &str)] = &[(1, SCHEMA_V1), (2, SCHEMA_V2)];

const SCHEMA_V1: &str = "
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE sessions (
    session         INTEGER PRIMARY KEY,
    started_seq     INTEGER NOT NULL,
    started_unix_ms INTEGER NOT NULL
);

CREATE TABLE events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    session   INTEGER NOT NULL,
    unix_ms   INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    device_id TEXT,
    file_id   INTEGER,
    detail    TEXT
);

CREATE TABLE devices (
    device_id      TEXT PRIMARY KEY NOT NULL,
    display_name   TEXT NOT NULL,
    folder_name    TEXT NOT NULL,
    folder_key     TEXT NOT NULL UNIQUE,
    max_bytes      INTEGER,
    max_files      INTEGER,
    max_file_bytes INTEGER,
    used_bytes     INTEGER NOT NULL DEFAULT 0,
    used_files     INTEGER NOT NULL DEFAULT 0,
    created_seq    INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE files (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id             TEXT NOT NULL REFERENCES devices(device_id),
    rel_path              TEXT NOT NULL,
    path_key              TEXT NOT NULL UNIQUE,
    hash                  BLOB NOT NULL CHECK (length(hash) = 32),
    size                  INTEGER NOT NULL CHECK (size >= 0),
    mtime_unix_ns         INTEGER,
    source_name           TEXT NOT NULL,
    state                 INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    state_seq             INTEGER NOT NULL,
    committed_seq         INTEGER NOT NULL,
    committed_session     INTEGER NOT NULL,
    committed_unix_ms     INTEGER NOT NULL,
    dir_synced            INTEGER NOT NULL,
    verified_unbuffered   INTEGER NOT NULL,
    last_verified_seq     INTEGER,
    last_verified_session INTEGER,
    row_check             BLOB NOT NULL CHECK (length(row_check) = 32)
);
CREATE INDEX files_by_hash ON files(hash);
CREATE INDEX files_by_device ON files(device_id);
";

const SCHEMA_V2: &str = "
CREATE TABLE scan_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    started_seq   INTEGER NOT NULL,
    upper_id      INTEGER NOT NULL,
    cursor_id     INTEGER NOT NULL,
    files_checked INTEGER NOT NULL,
    bytes_checked INTEGER NOT NULL,
    ok            INTEGER NOT NULL,
    missing       INTEGER NOT NULL,
    changed       INTEGER NOT NULL,
    unreadable    INTEGER NOT NULL,
    suspicious    INTEGER NOT NULL,
    restored      INTEGER NOT NULL,
    known_bad     INTEGER NOT NULL
);
";

const EXPECTED_TABLES: &[&str] = &["meta", "sessions", "events", "devices", "files", "scan_state"];

const FILE_COLUMNS: &str = "id, device_id, rel_path, hash, size, mtime_unix_ns, source_name, state, \
     committed_seq, committed_session, committed_unix_ms, dir_synced, verified_unbuffered, \
     last_verified_seq, last_verified_session, row_check";

/// What the ledger believes about a recorded file. Belief only: every answer
/// given to a caller is re-checked against the disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// Committed and, as far as the last check knew, intact.
    Committed,
    /// A check found the file gone.
    Missing,
    /// A check found different content at the recorded path.
    Changed,
}

impl FileState {
    fn code(self) -> i64 {
        match self {
            FileState::Committed => 1,
            FileState::Missing => 2,
            FileState::Changed => 3,
        }
    }

    fn from_code(code: i64) -> Option<FileState> {
        match code {
            1 => Some(FileState::Committed),
            2 => Some(FileState::Missing),
            3 => Some(FileState::Changed),
            _ => None,
        }
    }

    /// Whether a file in this state still occupies space on the destination.
    fn occupies_space(self) -> bool {
        !matches!(self, FileState::Missing)
    }
}

/// One recorded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Row id.
    pub id: i64,
    /// Device that committed it.
    pub device: String,
    /// Path relative to the destination root, `/`-separated.
    pub rel_path: String,
    /// Content hash recorded at commit.
    pub hash: ContentHash,
    /// Size in bytes recorded at commit.
    pub size: u64,
    /// Modification time supplied by the sender (Unix nanoseconds).
    pub mtime_unix_ns: Option<i64>,
    /// The name the peer supplied.
    pub source_name: String,
    /// What the last check believed.
    pub state: FileState,
    /// Sequence number of the commit event.
    pub committed_seq: u64,
    /// Session in which it was committed.
    pub committed_session: u64,
    /// Wall-clock time of the commit (Unix milliseconds).
    pub committed_unix_ms: i64,
    /// Whether the directory flush after the rename succeeded.
    pub dir_synced: bool,
    /// Whether the commit-time read-back bypassed the OS cache.
    pub verified_unbuffered: bool,
    /// Sequence number of the last successful re-verification, if any.
    pub last_verified_seq: Option<u64>,
    /// Session of the last successful re-verification, if any.
    pub last_verified_session: Option<u64>,
}

/// Limits for one paired device. `None` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceLimits {
    /// Total bytes the device may have stored.
    pub max_total_bytes: Option<u64>,
    /// Number of files the device may have stored.
    pub max_files: Option<u64>,
    /// Largest single file accepted from the device.
    pub max_file_bytes: Option<u64>,
}

/// A paired device as the ledger knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Stable identifier chosen by the transfer layer.
    pub device_id: String,
    /// Name shown to the user (peer-supplied; display only).
    pub display_name: String,
    /// The device's folder name (sanitised, unique among devices).
    pub folder_name: String,
    /// Limits in force.
    pub limits: DeviceLimits,
    /// Bytes currently counted against the device.
    pub used_bytes: u64,
    /// Files currently counted against the device.
    pub used_files: u64,
}

/// Why final move is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Recorded files were found missing or changed.
    IntegrityProblems,
    /// Many files changed, vanished or were renamed together (ransomware-like).
    MassChange,
    /// The ledger was damaged and has been reset.
    LedgerReset,
    /// The destination had been used before, but its ledger was empty or gone.
    LedgerLost,
    /// The destination folder lost its identity marker (it may have been replaced).
    MarkerMissing,
    /// Blocked by an explicit call.
    Manual,
}

impl BlockKind {
    fn code(self) -> &'static str {
        match self {
            BlockKind::IntegrityProblems => "integrity",
            BlockKind::MassChange => "mass_change",
            BlockKind::LedgerReset => "ledger_reset",
            BlockKind::LedgerLost => "ledger_lost",
            BlockKind::MarkerMissing => "marker_missing",
            BlockKind::Manual => "manual",
        }
    }

    fn from_code(code: &str) -> Option<BlockKind> {
        Some(match code {
            "integrity" => BlockKind::IntegrityProblems,
            "mass_change" => BlockKind::MassChange,
            "ledger_reset" => BlockKind::LedgerReset,
            "ledger_lost" => BlockKind::LedgerLost,
            "marker_missing" => BlockKind::MarkerMissing,
            "manual" => BlockKind::Manual,
            _ => return None,
        })
    }

    fn severity(self) -> u8 {
        match self {
            BlockKind::Manual => 1,
            BlockKind::IntegrityProblems | BlockKind::LedgerReset | BlockKind::LedgerLost | BlockKind::MarkerMissing => 2,
            BlockKind::MassChange => 3,
        }
    }
}

/// The persistent "final move is blocked" record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    /// Category.
    pub kind: BlockKind,
    /// Human-readable reason.
    pub reason: String,
    /// Sequence number of the event that set it.
    pub set_seq: u64,
    /// Session in which it was set.
    pub set_session: u64,
    /// Wall-clock time it was set (Unix milliseconds; informational).
    pub set_unix_ms: i64,
}

/// One entry of the event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Session that wrote it.
    pub session: u64,
    /// Wall-clock time (Unix milliseconds; informational).
    pub unix_ms: i64,
    /// Event kind, e.g. `commit`, `file_missing`, `block_set`.
    pub kind: String,
    /// Device involved, if any.
    pub device: Option<String>,
    /// File row involved, if any.
    pub file_id: Option<i64>,
    /// Free-form detail.
    pub detail: Option<String>,
}

/// Row counts, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerStats {
    /// Files believed intact.
    pub files_committed: u64,
    /// Files found missing.
    pub files_missing: u64,
    /// Files found changed.
    pub files_changed: u64,
    /// Total size of the files believed intact.
    pub bytes_committed: u64,
    /// Registered devices.
    pub devices: u64,
    /// Events logged.
    pub events: u64,
}

/// A file to record.
pub(crate) struct NewFile<'a> {
    pub device: &'a str,
    pub rel_path: &'a str,
    pub path_key: &'a str,
    pub hash: ContentHash,
    pub size: u64,
    pub mtime_unix_ns: Option<i64>,
    pub source_name: &'a str,
    pub dir_synced: bool,
    pub verified_unbuffered: bool,
    /// The file was already on disk with identical content and is being adopted.
    pub adopted: bool,
}

/// Progress of a resumable integrity scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ScanState {
    pub started_seq: u64,
    pub upper_id: i64,
    pub cursor_id: i64,
    pub files_checked: u64,
    pub bytes_checked: u64,
    pub ok: u64,
    pub missing: u64,
    pub changed: u64,
    pub unreadable: u64,
    pub suspicious: u64,
    pub restored: u64,
    pub known_bad: u64,
}

pub(crate) struct Ledger {
    conn: Mutex<Connection>,
    path: PathBuf,
    session: u64,
    session_start_seq: u64,
    #[cfg(test)]
    fresh: bool,
}

type Result<T> = std::result::Result<T, LedgerError>;

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl Ledger {
    /// Opens (creating if absent) the ledger in `dir`, checks its integrity,
    /// migrates it, and starts a new session.
    pub(crate) fn open(dir: &Path, now_ms: i64) -> Result<Ledger> {
        let path = dir.join(LEDGER_FILE);
        let map = |e: rusqlite::Error| map_sqlite(&path, e);

        let mut conn = Connection::open(&path).map_err(map)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(map)?;

        // The first statement that touches the file is where a file that is
        // not a database (garbled header) is reported.
        let journal: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).map_err(map)?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::Database { message: format!("write-ahead logging is unavailable (journal mode {journal})") });
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA cell_size_check=ON;",
        )
        .map_err(map)?;
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0)).map_err(map)?;
        if synchronous != 2 {
            return Err(LedgerError::Database { message: format!("synchronous=FULL was not applied (got {synchronous})") });
        }

        check_integrity(&conn, &path)?;

        let user_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(map)?;
        let application_id: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0)).map_err(map)?;
        let tables: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'", [], |r| {
                r.get(0)
            })
            .map_err(map)?;

        let fresh = user_version == 0;
        if fresh {
            if tables > 0 || (application_id != 0 && application_id != APPLICATION_ID) {
                return Err(LedgerError::NotALedger { path });
            }
        } else {
            if application_id != APPLICATION_ID {
                return Err(LedgerError::NotALedger { path });
            }
            if user_version < 0 || user_version > i64::from(SCHEMA_VERSION) {
                return Err(LedgerError::TooNew {
                    found: u32::try_from(user_version).unwrap_or(u32::MAX),
                    supported: SCHEMA_VERSION,
                });
            }
        }

        for (version, sql) in MIGRATIONS {
            if i64::from(*version) <= user_version {
                continue;
            }
            let tx = conn.transaction().map_err(map)?;
            tx.execute_batch(sql).map_err(map)?;
            tx.execute_batch(&format!("PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {version};"))
                .map_err(map)?;
            tx.commit().map_err(map)?;
        }

        for table in EXPECTED_TABLES {
            let present: i64 = conn
                .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |r| r.get(0))
                .map_err(map)?;
            if present != 1 {
                return Err(LedgerError::Corrupt { path, detail: format!("table {table} is missing") });
            }
        }

        // Start the session: bump the counter and log it, durably.
        let tx = conn.transaction().map_err(map)?;
        let previous = match meta_get(&tx, "session_counter").map_err(map)? {
            None => 0,
            Some(text) => text.parse::<u64>().map_err(|_| LedgerError::Corrupt {
                path: path.clone(),
                detail: format!("the session counter is not a number ({text:?})"),
            })?,
        };
        let session = previous + 1;
        meta_set(&tx, "session_counter", &session.to_string()).map_err(map)?;
        let seq = append_event(&tx, session, now_ms, "session_start", None, None, None).map_err(map)?;
        tx.execute(
            "INSERT INTO sessions(session, started_seq, started_unix_ms) VALUES (?1, ?2, ?3)",
            params![to_i64(session), to_i64(seq), now_ms],
        )
        .map_err(map)?;
        // Usage counters are derived data; recompute them so they can never drift.
        tx.execute_batch(
            "UPDATE devices SET
                 used_bytes = (SELECT COALESCE(SUM(size), 0) FROM files WHERE files.device_id = devices.device_id AND state <> 2),
                 used_files = (SELECT COUNT(*) FROM files WHERE files.device_id = devices.device_id AND state <> 2);",
        )
        .map_err(map)?;
        tx.commit().map_err(map)?;

        #[cfg(not(test))]
        let _ = fresh;
        Ok(Ledger {
            conn: Mutex::new(conn),
            path,
            session,
            session_start_seq: seq,
            #[cfg(test)]
            fresh,
        })
    }

    /// Moves a damaged ledger (and its journal files) aside so a fresh one
    /// can be created. Nothing is deleted. Returns the new names.
    pub(crate) fn quarantine(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut n = 1u32;
        let suffix = loop {
            let candidate = format!(".corrupt-{n}");
            let taken = ["", "-wal", "-shm"]
                .iter()
                .any(|ext| dir.join(format!("{LEDGER_FILE}{ext}{candidate}")).exists());
            if !taken {
                break candidate;
            }
            n += 1;
        };
        let mut moved = Vec::new();
        for ext in ["", "-wal", "-shm"] {
            let from = dir.join(format!("{LEDGER_FILE}{ext}"));
            if !from.exists() {
                continue;
            }
            let to = dir.join(format!("{LEDGER_FILE}{ext}{suffix}"));
            std::fs::rename(&from, &to).map_err(|source| LedgerError::Io { path: from.clone(), source })?;
            moved.push(to);
        }
        Ok(moved)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves the connection usable: every
        // change is inside a transaction that is rolled back on unwind.
        self.conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn map(&self, e: rusqlite::Error) -> LedgerError {
        map_sqlite(&self.path, e)
    }

    fn corrupt(&self, detail: impl Into<String>) -> LedgerError {
        LedgerError::Corrupt { path: self.path.clone(), detail: detail.into() }
    }

    /// The database file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// This open's session number (1 for the first open of a new ledger).
    pub(crate) fn session(&self) -> u64 {
        self.session
    }

    /// Sequence number of this session's start event.
    pub(crate) fn session_start_seq(&self) -> u64 {
        self.session_start_seq
    }

    /// True if the database had no schema before this open.
    #[cfg(test)]
    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }

    pub(crate) fn destination_id(&self) -> Result<Option<String>> {
        let conn = self.lock();
        meta_get(&conn, "destination_id").map_err(|e| self.map(e))
    }

    pub(crate) fn set_destination_id(&self, id: &str, now_ms: i64) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        meta_set(&tx, "destination_id", id).map_err(|e| self.map(e))?;
        append_event(&tx, self.session, now_ms, "destination_bound", None, None, Some(id)).map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))
    }

    /// Appends a free-standing event and returns its sequence number.
    pub(crate) fn log_event(
        &self,
        kind: &str,
        device: Option<&str>,
        file_id: Option<i64>,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<u64> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let seq = append_event(&tx, self.session, now_ms, kind, device, file_id, detail).map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))?;
        Ok(seq)
    }

    /// The largest wall-clock time any event was written with.
    pub(crate) fn max_seen_unix_ms(&self) -> Result<i64> {
        let conn = self.lock();
        match meta_get(&conn, "max_unix_ms").map_err(|e| self.map(e))? {
            None => Ok(i64::MIN),
            Some(text) => text.parse::<i64>().map_err(|_| self.corrupt("the clock high-water mark is not a number")),
        }
    }

    // ----- devices -------------------------------------------------------

    /// Registers a device or updates its display name and limits. The folder
    /// name is chosen once (unique among devices, case-insensitively) and
    /// never changes afterwards.
    pub(crate) fn upsert_device(
        &self,
        device_id: &str,
        display_name: &str,
        folder_base: &SafeName,
        limits: DeviceLimits,
        now_ms: i64,
    ) -> Result<DeviceRecord> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let exists: bool = tx
            .query_row("SELECT 1 FROM devices WHERE device_id = ?1", [device_id], |_| Ok(()))
            .optional()
            .map_err(|e| self.map(e))?
            .is_some();
        let (max_bytes, max_files, max_file_bytes) =
            (limits.max_total_bytes.map(to_i64), limits.max_files.map(to_i64), limits.max_file_bytes.map(to_i64));
        if exists {
            tx.execute(
                "UPDATE devices SET display_name = ?2, max_bytes = ?3, max_files = ?4, max_file_bytes = ?5 WHERE device_id = ?1",
                params![device_id, display_name, max_bytes, max_files, max_file_bytes],
            )
            .map_err(|e| self.map(e))?;
            append_event(&tx, self.session, now_ms, "device_updated", Some(device_id), None, None)
                .map_err(|e| self.map(e))?;
        } else {
            let mut n = 1u32;
            let folder = loop {
                let candidate = folder_base.with_collision_suffix(n);
                let taken: bool = tx
                    .query_row("SELECT 1 FROM devices WHERE folder_key = ?1", [candidate.collision_key()], |_| Ok(()))
                    .optional()
                    .map_err(|e| self.map(e))?
                    .is_some();
                if !taken {
                    break candidate;
                }
                n += 1;
            };
            let seq = append_event(&tx, self.session, now_ms, "device_registered", Some(device_id), None, Some(folder.as_str()))
                .map_err(|e| self.map(e))?;
            tx.execute(
                "INSERT INTO devices(device_id, display_name, folder_name, folder_key, max_bytes, max_files, max_file_bytes, created_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    device_id,
                    display_name,
                    folder.as_str(),
                    folder.collision_key(),
                    max_bytes,
                    max_files,
                    max_file_bytes,
                    to_i64(seq)
                ],
            )
            .map_err(|e| self.map(e))?;
        }
        let record = read_device(&tx, device_id).map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))?;
        record.ok_or_else(|| self.corrupt("a device row vanished inside its own transaction"))
    }

    pub(crate) fn device(&self, device_id: &str) -> Result<Option<DeviceRecord>> {
        let conn = self.lock();
        read_device(&conn, device_id).map_err(|e| self.map(e))
    }

    pub(crate) fn devices(&self) -> Result<Vec<DeviceRecord>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT device_id, display_name, folder_name, max_bytes, max_files, max_file_bytes, used_bytes, used_files
                 FROM devices ORDER BY device_id",
            )
            .map_err(|e| self.map(e))?;
        let rows = stmt.query_map([], device_from_row).map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| self.map(e))
    }

    // ----- files ---------------------------------------------------------

    /// Records a file that is on disk under its final name and has been
    /// verified. Replaces a stale row for the same path, if there is one (the
    /// file it described is gone: the no-replace rename could not otherwise
    /// have succeeded).
    pub(crate) fn record_commit(&self, new: &NewFile<'_>, now_ms: i64) -> Result<FileRecord> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;

        let stale: Option<(i64, String, i64, i64, Vec<u8>)> = tx
            .query_row("SELECT id, device_id, state, size, hash FROM files WHERE path_key = ?1", [new.path_key], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .optional()
            .map_err(|e| self.map(e))?;
        if let Some((old_id, old_device, old_state, old_size, old_hash)) = stale {
            let detail = format!("replaced by a new commit; old hash {}", hex(&old_hash));
            append_event(&tx, self.session, now_ms, "record_superseded", Some(&old_device), Some(old_id), Some(&detail))
                .map_err(|e| self.map(e))?;
            if FileState::from_code(old_state).is_some_and(FileState::occupies_space) {
                adjust_usage(&tx, &old_device, -old_size, -1).map_err(|e| self.map(e))?;
            }
            tx.execute("DELETE FROM files WHERE id = ?1", [old_id]).map_err(|e| self.map(e))?;
        }

        let kind = if new.adopted { "adopt" } else { "commit" };
        let seq = append_event(&tx, self.session, now_ms, kind, Some(new.device), None, Some(new.rel_path))
            .map_err(|e| self.map(e))?;
        let check = row_check(new.device, new.rel_path, &new.hash, new.size, seq, self.session, now_ms);
        tx.execute(
            "INSERT INTO files(device_id, rel_path, path_key, hash, size, mtime_unix_ns, source_name, state, state_seq,
                               committed_seq, committed_session, committed_unix_ms, dir_synced, verified_unbuffered, row_check)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                new.device,
                new.rel_path,
                new.path_key,
                new.hash.as_bytes().as_slice(),
                to_i64(new.size),
                new.mtime_unix_ns,
                new.source_name,
                to_i64(seq),
                to_i64(self.session),
                now_ms,
                new.dir_synced,
                new.verified_unbuffered,
                check.as_slice(),
            ],
        )
        .map_err(|e| self.map(e))?;
        let id = tx.last_insert_rowid();
        tx.execute("UPDATE events SET file_id = ?1 WHERE seq = ?2", params![id, to_i64(seq)]).map_err(|e| self.map(e))?;
        adjust_usage(&tx, new.device, to_i64(new.size), 1).map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))?;

        Ok(FileRecord {
            id,
            device: new.device.to_owned(),
            rel_path: new.rel_path.to_owned(),
            hash: new.hash,
            size: new.size,
            mtime_unix_ns: new.mtime_unix_ns,
            source_name: new.source_name.to_owned(),
            state: FileState::Committed,
            committed_seq: seq,
            committed_session: self.session,
            committed_unix_ms: now_ms,
            dir_synced: new.dir_synced,
            verified_unbuffered: new.verified_unbuffered,
            last_verified_seq: None,
            last_verified_session: None,
        })
    }

    fn query_files(&self, conn: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<FileRecord>> {
        let mut stmt = conn.prepare(sql).map_err(|e| self.map(e))?;
        let rows = stmt.query_map(args, raw_file_from_row).map_err(|e| self.map(e))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(self.validate(row.map_err(|e| self.map(e))?)?);
        }
        Ok(out)
    }

    fn validate(&self, raw: RawFile) -> Result<FileRecord> {
        let hash = ContentHash::from_slice(&raw.hash)
            .ok_or_else(|| self.corrupt(format!("file row {} has a malformed hash", raw.id)))?;
        let state = FileState::from_code(raw.state)
            .ok_or_else(|| self.corrupt(format!("file row {} has an unknown state", raw.id)))?;
        if raw.size < 0 || raw.committed_seq < 0 || raw.committed_session < 0 {
            return Err(self.corrupt(format!("file row {} has negative counters", raw.id)));
        }
        let record = FileRecord {
            id: raw.id,
            device: raw.device,
            rel_path: raw.rel_path,
            hash,
            size: to_u64(raw.size),
            mtime_unix_ns: raw.mtime_unix_ns,
            source_name: raw.source_name,
            state,
            committed_seq: to_u64(raw.committed_seq),
            committed_session: to_u64(raw.committed_session),
            committed_unix_ms: raw.committed_unix_ms,
            dir_synced: raw.dir_synced,
            verified_unbuffered: raw.verified_unbuffered,
            last_verified_seq: raw.last_verified_seq.map(to_u64),
            last_verified_session: raw.last_verified_session.map(to_u64),
        };
        let expected = row_check(
            &record.device,
            &record.rel_path,
            &record.hash,
            record.size,
            record.committed_seq,
            record.committed_session,
            record.committed_unix_ms,
        );
        if raw.row_check != expected {
            return Err(self.corrupt(format!("file row {} fails its checksum", record.id)));
        }
        Ok(record)
    }

    /// All rows with this content hash, oldest commit first.
    pub(crate) fn files_by_hash(&self, hash: &ContentHash) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE hash = ?1 ORDER BY committed_seq, id");
        self.query_files(&conn, &sql, &[&hash.as_bytes().as_slice()])
    }

    pub(crate) fn file_by_path_key(&self, path_key: &str) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE path_key = ?1");
        Ok(self.query_files(&conn, &sql, &[&path_key])?.into_iter().next())
    }

    #[cfg(test)]
    pub(crate) fn file_by_id(&self, id: i64) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
        Ok(self.query_files(&conn, &sql, &[&id])?.into_iter().next())
    }

    /// Whether any row (in any state) is recorded under this path key.
    pub(crate) fn path_key_exists(&self, path_key: &str) -> Result<bool> {
        let conn = self.lock();
        conn.query_row("SELECT 1 FROM files WHERE path_key = ?1", [path_key], |_| Ok(()))
            .optional()
            .map(|r| r.is_some())
            .map_err(|e| self.map(e))
    }

    /// Up to `limit` rows with `cursor < id <= upper`, in id order.
    pub(crate) fn files_after(&self, cursor: i64, upper: i64, limit: u32) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id > ?1 AND id <= ?2 ORDER BY id LIMIT ?3");
        self.query_files(&conn, &sql, &[&cursor, &upper, &i64::from(limit)])
    }

    pub(crate) fn max_file_id(&self) -> Result<i64> {
        let conn = self.lock();
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM files", [], |r| r.get(0)).map_err(|e| self.map(e))
    }

    /// Paths of rows that were marked missing at or after event `seq`.
    pub(crate) fn missing_since(&self, seq: u64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT rel_path FROM files WHERE state = 2 AND state_seq >= ?1 ORDER BY id")
            .map_err(|e| self.map(e))?;
        let rows = stmt.query_map([to_i64(seq)], |r| r.get::<_, String>(0)).map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| self.map(e))
    }

    /// Changes what the ledger believes about a file. Returns the event's
    /// sequence number, or `None` if the state was already `new_state`.
    pub(crate) fn set_state(&self, file_id: i64, new_state: FileState, detail: &str, now_ms: i64) -> Result<Option<u64>> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let row: Option<(i64, i64, String)> = tx
            .query_row("SELECT state, size, device_id FROM files WHERE id = ?1", [file_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()
            .map_err(|e| self.map(e))?;
        let Some((old_code, size, device)) = row else { return Ok(None) };
        let old = FileState::from_code(old_code).ok_or_else(|| self.corrupt(format!("file row {file_id} has an unknown state")))?;
        if old == new_state {
            return Ok(None);
        }
        let kind = match new_state {
            FileState::Committed => "file_restored",
            FileState::Missing => "file_missing",
            FileState::Changed => "file_changed",
        };
        let seq = append_event(&tx, self.session, now_ms, kind, Some(&device), Some(file_id), Some(detail))
            .map_err(|e| self.map(e))?;
        tx.execute("UPDATE files SET state = ?2, state_seq = ?3 WHERE id = ?1", params![file_id, new_state.code(), to_i64(seq)])
            .map_err(|e| self.map(e))?;
        match (old.occupies_space(), new_state.occupies_space()) {
            (true, false) => adjust_usage(&tx, &device, -size, -1).map_err(|e| self.map(e))?,
            (false, true) => adjust_usage(&tx, &device, size, 1).map_err(|e| self.map(e))?,
            _ => {}
        }
        tx.commit().map_err(|e| self.map(e))?;
        Ok(Some(seq))
    }

    /// Records that a file was re-read from disk and matched. Returns the
    /// event's sequence number.
    pub(crate) fn mark_verified(&self, file_id: i64, kind: &str, device: Option<&str>, now_ms: i64) -> Result<u64> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let seq = append_event(&tx, self.session, now_ms, kind, device, Some(file_id), None).map_err(|e| self.map(e))?;
        let updated = tx
            .execute(
                "UPDATE files SET last_verified_seq = ?2, last_verified_session = ?3 WHERE id = ?1",
                params![file_id, to_i64(seq), to_i64(self.session)],
            )
            .map_err(|e| self.map(e))?;
        if updated != 1 {
            return Err(self.corrupt(format!("file row {file_id} vanished while it was being verified")));
        }
        tx.commit().map_err(|e| self.map(e))?;
        Ok(seq)
    }

    // ----- the final-move block -----------------------------------------

    /// Sets the persistent block. A block that is already set is kept unless
    /// the new one is more severe; either way the event is logged.
    pub(crate) fn block(&self, kind: BlockKind, reason: &str, now_ms: i64) -> Result<BlockInfo> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let existing = read_block(&tx).map_err(|e| self.map(e))?;
        let info = match existing {
            Some(current) if current.kind.severity() >= kind.severity() => {
                append_event(&tx, self.session, now_ms, "block_noted", None, None, Some(reason)).map_err(|e| self.map(e))?;
                current
            }
            _ => {
                let seq = append_event(&tx, self.session, now_ms, "block_set", None, None, Some(reason))
                    .map_err(|e| self.map(e))?;
                meta_set(&tx, "block_kind", kind.code()).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_reason", reason).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_seq", &seq.to_string()).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_session", &self.session.to_string()).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_unix_ms", &now_ms.to_string()).map_err(|e| self.map(e))?;
                BlockInfo { kind, reason: reason.to_owned(), set_seq: seq, set_session: self.session, set_unix_ms: now_ms }
            }
        };
        tx.commit().map_err(|e| self.map(e))?;
        Ok(info)
    }

    pub(crate) fn block_info(&self) -> Result<Option<BlockInfo>> {
        let conn = self.lock();
        read_block(&conn).map_err(|e| self.map(e))
    }

    /// Clears the block. Returns what was cleared, if anything was set.
    pub(crate) fn clear_block(&self, note: &str, now_ms: i64) -> Result<Option<BlockInfo>> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let existing = read_block(&tx).map_err(|e| self.map(e))?;
        if let Some(current) = &existing {
            let detail = format!("{note} (was: {})", current.reason);
            append_event(&tx, self.session, now_ms, "block_cleared", None, None, Some(&detail)).map_err(|e| self.map(e))?;
            tx.execute("DELETE FROM meta WHERE key LIKE 'block\\_%' ESCAPE '\\'", []).map_err(|e| self.map(e))?;
        }
        tx.commit().map_err(|e| self.map(e))?;
        Ok(existing)
    }

    // ----- scan progress -------------------------------------------------

    pub(crate) fn scan_state(&self) -> Result<Option<ScanState>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT started_seq, upper_id, cursor_id, files_checked, bytes_checked, ok, missing, changed, unreadable, suspicious, restored, known_bad
             FROM scan_state WHERE id = 1",
            [],
            |r| {
                Ok(ScanState {
                    started_seq: to_u64(r.get(0)?),
                    upper_id: r.get(1)?,
                    cursor_id: r.get(2)?,
                    files_checked: to_u64(r.get(3)?),
                    bytes_checked: to_u64(r.get(4)?),
                    ok: to_u64(r.get(5)?),
                    missing: to_u64(r.get(6)?),
                    changed: to_u64(r.get(7)?),
                    unreadable: to_u64(r.get(8)?),
                    suspicious: to_u64(r.get(9)?),
                    restored: to_u64(r.get(10)?),
                    known_bad: to_u64(r.get(11)?),
                })
            },
        )
        .optional()
        .map_err(|e| self.map(e))
    }

    pub(crate) fn save_scan_state(&self, s: &ScanState) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR REPLACE INTO scan_state
                 (id, started_seq, upper_id, cursor_id, files_checked, bytes_checked, ok, missing, changed, unreadable, suspicious, restored, known_bad)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                to_i64(s.started_seq),
                s.upper_id,
                s.cursor_id,
                to_i64(s.files_checked),
                to_i64(s.bytes_checked),
                to_i64(s.ok),
                to_i64(s.missing),
                to_i64(s.changed),
                to_i64(s.unreadable),
                to_i64(s.suspicious),
                to_i64(s.restored),
                to_i64(s.known_bad)
            ],
        )
        .map(|_| ())
        .map_err(|e| self.map(e))
    }

    pub(crate) fn clear_scan_state(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM scan_state", []).map(|_| ()).map_err(|e| self.map(e))
    }

    // ----- diagnostics ---------------------------------------------------

    pub(crate) fn stats(&self) -> Result<LedgerStats> {
        let conn = self.lock();
        let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).map(to_u64).map_err(|e| self.map(e));
        Ok(LedgerStats {
            files_committed: count("SELECT COUNT(*) FROM files WHERE state = 1")?,
            files_missing: count("SELECT COUNT(*) FROM files WHERE state = 2")?,
            files_changed: count("SELECT COUNT(*) FROM files WHERE state = 3")?,
            bytes_committed: count("SELECT COALESCE(SUM(size), 0) FROM files WHERE state = 1")?,
            devices: count("SELECT COUNT(*) FROM devices")?,
            events: count("SELECT COUNT(*) FROM events")?,
        })
    }

    /// Up to `limit` events with `seq > after`, oldest first.
    pub(crate) fn events_after(&self, after: u64, limit: u32) -> Result<Vec<EventRecord>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT seq, session, unix_ms, kind, device_id, file_id, detail FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2")
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map(params![to_i64(after), i64::from(limit)], |r| {
                Ok(EventRecord {
                    seq: to_u64(r.get(0)?),
                    session: to_u64(r.get(1)?),
                    unix_ms: r.get(2)?,
                    kind: r.get(3)?,
                    device: r.get(4)?,
                    file_id: r.get(5)?,
                    detail: r.get(6)?,
                })
            })
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| self.map(e))
    }
}

struct RawFile {
    id: i64,
    device: String,
    rel_path: String,
    hash: Vec<u8>,
    size: i64,
    mtime_unix_ns: Option<i64>,
    source_name: String,
    state: i64,
    committed_seq: i64,
    committed_session: i64,
    committed_unix_ms: i64,
    dir_synced: bool,
    verified_unbuffered: bool,
    last_verified_seq: Option<i64>,
    last_verified_session: Option<i64>,
    row_check: Vec<u8>,
}

fn raw_file_from_row(r: &Row<'_>) -> rusqlite::Result<RawFile> {
    Ok(RawFile {
        id: r.get(0)?,
        device: r.get(1)?,
        rel_path: r.get(2)?,
        hash: r.get(3)?,
        size: r.get(4)?,
        mtime_unix_ns: r.get(5)?,
        source_name: r.get(6)?,
        state: r.get(7)?,
        committed_seq: r.get(8)?,
        committed_session: r.get(9)?,
        committed_unix_ms: r.get(10)?,
        dir_synced: r.get(11)?,
        verified_unbuffered: r.get(12)?,
        last_verified_seq: r.get(13)?,
        last_verified_session: r.get(14)?,
        row_check: r.get(15)?,
    })
}

fn device_from_row(r: &Row<'_>) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        device_id: r.get(0)?,
        display_name: r.get(1)?,
        folder_name: r.get(2)?,
        limits: DeviceLimits {
            max_total_bytes: r.get::<_, Option<i64>>(3)?.map(to_u64),
            max_files: r.get::<_, Option<i64>>(4)?.map(to_u64),
            max_file_bytes: r.get::<_, Option<i64>>(5)?.map(to_u64),
        },
        used_bytes: to_u64(r.get(6)?),
        used_files: to_u64(r.get(7)?),
    })
}

fn read_device(conn: &Connection, device_id: &str) -> rusqlite::Result<Option<DeviceRecord>> {
    conn.query_row(
        "SELECT device_id, display_name, folder_name, max_bytes, max_files, max_file_bytes, used_bytes, used_files
         FROM devices WHERE device_id = ?1",
        [device_id],
        device_from_row,
    )
    .optional()
}

fn adjust_usage(tx: &Transaction<'_>, device: &str, bytes: i64, files: i64) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE devices SET used_bytes = MAX(0, used_bytes + ?2), used_files = MAX(0, used_files + ?3) WHERE device_id = ?1",
        params![device, bytes, files],
    )
    .map(|_| ())
}

fn meta_get(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [
        key, value,
    ])
    .map(|_| ())
}

/// Appends an event and advances the clock high-water mark. The returned
/// sequence number is strictly greater than every earlier one.
fn append_event(
    conn: &Connection,
    session: u64,
    now_ms: i64,
    kind: &str,
    device: Option<&str>,
    file_id: Option<i64>,
    detail: Option<&str>,
) -> rusqlite::Result<u64> {
    conn.execute(
        "INSERT INTO events(session, unix_ms, kind, device_id, file_id, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![to_i64(session), now_ms, kind, device, file_id, detail],
    )?;
    let seq = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('max_unix_ms', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE CAST(excluded.value AS INTEGER) > CAST(value AS INTEGER)",
        [now_ms.to_string()],
    )?;
    Ok(to_u64(seq))
}

fn read_block(conn: &Connection) -> rusqlite::Result<Option<BlockInfo>> {
    let Some(kind_code) = meta_get(conn, "block_kind")? else { return Ok(None) };
    let reason = meta_get(conn, "block_reason")?;
    let number = |key: &str| -> rusqlite::Result<Option<i64>> { Ok(meta_get(conn, key)?.and_then(|v| v.parse().ok())) };
    // A block record that cannot be fully read is still a block.
    Ok(Some(BlockInfo {
        kind: BlockKind::from_code(&kind_code).unwrap_or(BlockKind::IntegrityProblems),
        reason: reason.unwrap_or_else(|| "the block record is incomplete".to_owned()),
        set_seq: number("block_seq")?.map(to_u64).unwrap_or(0),
        set_session: number("block_session")?.map(to_u64).unwrap_or(0),
        set_unix_ms: number("block_unix_ms")?.unwrap_or(0),
    }))
}

fn check_integrity(conn: &Connection, path: &Path) -> Result<()> {
    let map = |e: rusqlite::Error| map_sqlite(path, e);
    let mut findings: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("PRAGMA integrity_check(20)").map_err(map)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(map)?;
        for row in rows {
            findings.push(row.map_err(map)?);
        }
    }
    if findings.len() != 1 || findings[0] != "ok" {
        return Err(LedgerError::Corrupt { path: path.to_path_buf(), detail: findings.join("; ") });
    }
    let mut stmt = conn.prepare("PRAGMA foreign_key_check").map_err(map)?;
    let mut rows = stmt.query([]).map_err(map)?;
    if rows.next().map_err(map)?.is_some() {
        return Err(LedgerError::Corrupt { path: path.to_path_buf(), detail: "a file row refers to an unknown device".to_owned() });
    }
    Ok(())
}

fn map_sqlite(path: &Path, e: rusqlite::Error) -> LedgerError {
    use rusqlite::ErrorCode;
    match &e {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(failure.code, ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) =>
        {
            LedgerError::Corrupt { path: path.to_path_buf(), detail: e.to_string() }
        }
        // A column holding the wrong type is damage, not a programming error.
        rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::FromSqlConversionFailure(..) => {
            LedgerError::Corrupt { path: path.to_path_buf(), detail: e.to_string() }
        }
        _ => LedgerError::Database { message: e.to_string() },
    }
}

/// Checksum over the fields of a file row that safety decisions depend on.
fn row_check(
    device: &str,
    rel_path: &str,
    hash: &ContentHash,
    size: u64,
    committed_seq: u64,
    committed_session: u64,
    committed_unix_ms: i64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("kiwi-store 2026-11 ledger file row v1");
    for text in [device, rel_path] {
        h.update(&(text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
    }
    h.update(hash.as_bytes());
    h.update(&size.to_le_bytes());
    h.update(&committed_seq.to_le_bytes());
    h.update(&committed_session.to_le_bytes());
    h.update(&committed_unix_ms.to_le_bytes());
    *h.finalize().as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The collision key of a ledger path.
pub(crate) fn path_key(rel_path: &str) -> String {
    rel_path.split('/').map(collision_key).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize::sanitize_component;

    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("unit-tmp").join("ledger").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn new_file<'a>(device: &'a str, rel: &'a str, key: &'a str, data: &[u8]) -> NewFile<'a> {
        NewFile {
            device,
            rel_path: rel,
            path_key: key,
            hash: ContentHash::of_bytes(data),
            size: data.len() as u64,
            mtime_unix_ns: Some(1_700_000_000_000_000_000),
            source_name: rel,
            dir_synced: true,
            verified_unbuffered: true,
            adopted: false,
        }
    }

    fn device(ledger: &Ledger, id: &str, name: &str) -> DeviceRecord {
        ledger.upsert_device(id, name, &sanitize_component(name).unwrap(), DeviceLimits::default(), 1_000).unwrap()
    }

    #[test]
    fn pragmas_are_in_force() {
        let dir = scratch("pragmas");
        let ledger = Ledger::open(&dir, 1_000).unwrap();
        let conn = ledger.lock();
        let get = |p: &str| conn.query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, rusqlite::types::Value>(0)).unwrap();
        assert_eq!(get("journal_mode"), rusqlite::types::Value::Text("wal".into()));
        assert_eq!(get("synchronous"), rusqlite::types::Value::Integer(2));
        assert_eq!(get("foreign_keys"), rusqlite::types::Value::Integer(1));
        assert_eq!(get("user_version"), rusqlite::types::Value::Integer(i64::from(SCHEMA_VERSION)));
        assert_eq!(get("application_id"), rusqlite::types::Value::Integer(APPLICATION_ID));
    }

    #[test]
    fn sessions_count_up_and_sequence_numbers_never_repeat() {
        let dir = scratch("sessions");
        let mut last_seq = 0;
        for expected in 1..=4u64 {
            // The clock runs backwards on purpose: ordering must not depend on it.
            let ledger = Ledger::open(&dir, 10_000 - expected as i64 * 1_000).unwrap();
            assert_eq!(ledger.session(), expected);
            assert_eq!(ledger.is_fresh(), expected == 1);
            assert!(ledger.session_start_seq() > last_seq);
            let seq = ledger.log_event("test", None, None, None, 5).unwrap();
            assert!(seq > ledger.session_start_seq());
            last_seq = seq;
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        let events = ledger.events_after(0, 1_000).unwrap();
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(seqs, sorted, "sequence numbers must be strictly increasing");
        // The high-water mark remembers the latest wall-clock time ever seen.
        assert_eq!(ledger.max_seen_unix_ms().unwrap(), 9_000);
    }

    #[test]
    fn sequence_numbers_are_not_reused_after_deletion() {
        let dir = scratch("autoincrement");
        let ledger = Ledger::open(&dir, 0).unwrap();
        let a = ledger.log_event("a", None, None, None, 0).unwrap();
        ledger.lock().execute("DELETE FROM events WHERE seq = ?1", [to_i64(a)]).unwrap();
        let b = ledger.log_event("b", None, None, None, 0).unwrap();
        assert!(b > a);
    }

    #[test]
    fn devices_get_unique_folders_and_keep_them() {
        let dir = scratch("devices");
        let ledger = Ledger::open(&dir, 0).unwrap();
        let a = device(&ledger, "dev-a", "Galaxy S23");
        let b = device(&ledger, "dev-b", "Galaxy S23");
        let c = device(&ledger, "dev-c", "GALAXY s23");
        assert_eq!(a.folder_name, "Galaxy S23");
        assert_eq!(b.folder_name, "Galaxy S23 (2)");
        assert_eq!(c.folder_name, "GALAXY s23 (3)");
        // Renaming the device or changing limits does not move its folder.
        let limits = DeviceLimits { max_total_bytes: Some(10), max_files: Some(2), max_file_bytes: Some(5) };
        let a2 = ledger.upsert_device("dev-a", "Renamed", &sanitize_component("Renamed").unwrap(), limits, 0).unwrap();
        assert_eq!(a2.folder_name, "Galaxy S23");
        assert_eq!(a2.display_name, "Renamed");
        assert_eq!(a2.limits, limits);
        assert_eq!(ledger.device("dev-a").unwrap().unwrap(), a2);
        assert_eq!(ledger.device("nobody").unwrap(), None);
        assert_eq!(ledger.devices().unwrap().len(), 3);
    }

    #[test]
    fn commit_lookup_and_usage() {
        let dir = scratch("commit");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "d", "D");
        let rec = ledger.record_commit(&new_file("d", "D/a.jpg", "d/a.jpg", b"aaaa"), 50).unwrap();
        assert_eq!(rec.committed_session, 1);
        assert!(rec.committed_seq > ledger.session_start_seq());
        assert_eq!(ledger.files_by_hash(&ContentHash::of_bytes(b"aaaa")).unwrap(), vec![rec.clone()]);
        assert_eq!(ledger.file_by_path_key("d/a.jpg").unwrap(), Some(rec.clone()));
        assert_eq!(ledger.file_by_id(rec.id).unwrap(), Some(rec.clone()));
        assert!(ledger.path_key_exists("d/a.jpg").unwrap());
        assert!(!ledger.path_key_exists("d/b.jpg").unwrap());
        assert!(ledger.files_by_hash(&ContentHash::of_bytes(b"other")).unwrap().is_empty());
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (4, 1));

        // Missing files stop counting; restored ones count again.
        assert!(ledger.set_state(rec.id, FileState::Missing, "gone", 60).unwrap().is_some());
        assert!(ledger.set_state(rec.id, FileState::Missing, "gone", 60).unwrap().is_none());
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (0, 0));
        assert_eq!(ledger.missing_since(0).unwrap(), vec!["D/a.jpg".to_owned()]);
        ledger.set_state(rec.id, FileState::Changed, "different", 61).unwrap();
        ledger.set_state(rec.id, FileState::Committed, "back", 62).unwrap();
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (4, 1));

        let seq = ledger.mark_verified(rec.id, "verified", Some("d"), 70).unwrap();
        let again = ledger.file_by_id(rec.id).unwrap().unwrap();
        assert_eq!(again.last_verified_seq, Some(seq));
        assert_eq!(again.last_verified_session, Some(1));

        let stats = ledger.stats().unwrap();
        assert_eq!((stats.files_committed, stats.bytes_committed, stats.devices), (1, 4, 1));
    }

    #[test]
    fn a_new_commit_supersedes_a_stale_row_for_the_same_path() {
        let dir = scratch("supersede");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "d", "D");
        let old = ledger.record_commit(&new_file("d", "D/a.jpg", "d/a.jpg", b"old content"), 1).unwrap();
        ledger.set_state(old.id, FileState::Missing, "gone", 2).unwrap();
        let new = ledger.record_commit(&new_file("d", "D/A.JPG", "d/a.jpg", b"new"), 3).unwrap();
        assert_ne!(new.id, old.id);
        assert_eq!(ledger.file_by_id(old.id).unwrap(), None);
        assert_eq!(ledger.file_by_path_key("d/a.jpg").unwrap().unwrap().rel_path, "D/A.JPG");
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (3, 1));
        assert!(ledger.events_after(0, 100).unwrap().iter().any(|e| e.kind == "record_superseded"));
    }

    #[test]
    fn usage_counters_heal_on_open() {
        let dir = scratch("heal");
        {
            let ledger = Ledger::open(&dir, 0).unwrap();
            device(&ledger, "d", "D");
            ledger.record_commit(&new_file("d", "D/a", "d/a", b"12345"), 1).unwrap();
            ledger.lock().execute("UPDATE devices SET used_bytes = 999, used_files = 42", []).unwrap();
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (5, 1));
    }

    #[test]
    fn block_is_persistent_and_escalates_only_upwards() {
        let dir = scratch("block");
        {
            let ledger = Ledger::open(&dir, 0).unwrap();
            assert_eq!(ledger.block_info().unwrap(), None);
            assert_eq!(ledger.clear_block("nothing to clear", 0).unwrap(), None);
            let b = ledger.block(BlockKind::Manual, "by hand", 10).unwrap();
            assert_eq!(b.kind, BlockKind::Manual);
            let b = ledger.block(BlockKind::IntegrityProblems, "one file changed", 11).unwrap();
            assert_eq!(b.kind, BlockKind::IntegrityProblems);
            let b = ledger.block(BlockKind::MassChange, "many files changed", 12).unwrap();
            assert_eq!(b.kind, BlockKind::MassChange);
            // A milder block does not replace a more severe one.
            let b = ledger.block(BlockKind::IntegrityProblems, "another file", 13).unwrap();
            assert_eq!((b.kind, b.reason.as_str()), (BlockKind::MassChange, "many files changed"));
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        let b = ledger.block_info().unwrap().expect("the block must survive a restart");
        assert_eq!((b.kind, b.set_session), (BlockKind::MassChange, 1));
        let cleared = ledger.clear_block("user reviewed", 20).unwrap().unwrap();
        assert_eq!(cleared.kind, BlockKind::MassChange);
        assert_eq!(ledger.block_info().unwrap(), None);
        let kinds: Vec<String> = ledger.events_after(0, 100).unwrap().into_iter().map(|e| e.kind).collect();
        for expected in ["block_set", "block_noted", "block_cleared"] {
            assert!(kinds.iter().any(|k| k == expected), "missing event {expected}");
        }
    }

    #[test]
    fn a_damaged_block_record_still_blocks() {
        let dir = scratch("block-damaged");
        let ledger = Ledger::open(&dir, 0).unwrap();
        ledger.block(BlockKind::Manual, "x", 0).unwrap();
        ledger.lock().execute_batch("UPDATE meta SET value = 'garbage' WHERE key = 'block_kind'; DELETE FROM meta WHERE key = 'block_reason';").unwrap();
        let b = ledger.block_info().unwrap().unwrap();
        assert_eq!(b.kind, BlockKind::IntegrityProblems);
    }

    #[test]
    fn scan_state_round_trips() {
        let dir = scratch("scan-state");
        let ledger = Ledger::open(&dir, 0).unwrap();
        assert_eq!(ledger.scan_state().unwrap(), None);
        let s = ScanState {
            started_seq: 7,
            upper_id: 100,
            cursor_id: 42,
            files_checked: 42,
            bytes_checked: 4_200,
            ok: 40,
            missing: 1,
            changed: 1,
            unreadable: 0,
            suspicious: 0,
            restored: 3,
            known_bad: 2,
        };
        ledger.save_scan_state(&s).unwrap();
        ledger.save_scan_state(&s).unwrap();
        assert_eq!(ledger.scan_state().unwrap(), Some(s));
        ledger.clear_scan_state().unwrap();
        assert_eq!(ledger.scan_state().unwrap(), None);
    }

    #[test]
    fn tampered_rows_fail_their_checksum() {
        let dir = scratch("row-check");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "d", "D");
        let rec = ledger.record_commit(&new_file("d", "D/a", "d/a", b"data"), 1).unwrap();
        // Each of these would make an unsafe answer more likely if believed.
        for tamper in [
            "UPDATE files SET committed_session = 0",
            "UPDATE files SET committed_seq = 0",
            "UPDATE files SET committed_unix_ms = -1",
            "UPDATE files SET size = 5",
            "UPDATE files SET rel_path = 'D/b'",
            "UPDATE files SET hash = zeroblob(32)",
        ] {
            let before: Vec<rusqlite::types::Value> = {
                let conn = ledger.lock();
                let mut stmt = conn.prepare("SELECT committed_session, committed_seq, committed_unix_ms, size, rel_path, hash FROM files").unwrap();
                let v = stmt.query_row([], |r| (0..6).map(|i| r.get(i)).collect()).unwrap();
                v
            };
            ledger.lock().execute(tamper, []).unwrap();
            let err = ledger.file_by_id(rec.id).unwrap_err();
            assert!(err.is_corruption(), "{tamper}: {err}");
            ledger.lock().execute(
                "UPDATE files SET committed_session = ?1, committed_seq = ?2, committed_unix_ms = ?3, size = ?4, rel_path = ?5, hash = ?6",
                rusqlite::params_from_iter(before),
            ).unwrap();
            assert!(ledger.file_by_id(rec.id).is_ok(), "restoring after {tamper}");
        }
    }

    #[test]
    fn migrates_from_version_1_and_keeps_the_data() {
        let dir = scratch("migrate");
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute_batch(&format!("PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = 1;")).unwrap();
            conn.execute("INSERT INTO meta(key, value) VALUES ('session_counter', '41')", []).unwrap();
            conn.execute("INSERT INTO meta(key, value) VALUES ('destination_id', 'abc')", []).unwrap();
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        assert!(!ledger.is_fresh());
        assert_eq!(ledger.session(), 42);
        assert_eq!(ledger.destination_id().unwrap().as_deref(), Some("abc"));
        assert_eq!(ledger.scan_state().unwrap(), None);
        let version: i64 = ledger.lock().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, i64::from(SCHEMA_VERSION));
    }

    #[test]
    fn refuses_a_ledger_from_the_future_without_touching_it() {
        let dir = scratch("too-new");
        drop(Ledger::open(&dir, 0).unwrap());
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1)).unwrap();
        }
        match Ledger::open(&dir, 0) {
            Err(LedgerError::TooNew { found, supported }) => {
                assert_eq!((found, supported), (SCHEMA_VERSION + 1, SCHEMA_VERSION));
            }
            other => panic!("expected TooNew, got {:?}", other.map(|_| ())),
        }
        // The refused open must not have started a session.
        let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
        let counter: String = conn.query_row("SELECT value FROM meta WHERE key = 'session_counter'", [], |r| r.get(0)).unwrap();
        assert_eq!(counter, "1");
    }

    #[test]
    fn refuses_someone_elses_database() {
        let dir = scratch("foreign");
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch("CREATE TABLE notes(text TEXT); INSERT INTO notes VALUES ('hello');").unwrap();
        }
        assert!(matches!(Ledger::open(&dir, 0), Err(LedgerError::NotALedger { .. })));
        // ... and leaves it alone.
        let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM notes", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn quarantine_moves_everything_aside_and_numbers_the_copies() {
        let dir = scratch("quarantine");
        std::fs::write(dir.join(LEDGER_FILE), b"junk").unwrap();
        std::fs::write(dir.join(format!("{LEDGER_FILE}-wal")), b"junk").unwrap();
        let moved = Ledger::quarantine(&dir).unwrap();
        assert_eq!(moved.len(), 2);
        assert!(dir.join("ledger.db.corrupt-1").exists());
        assert!(dir.join("ledger.db-wal.corrupt-1").exists());
        assert!(!dir.join(LEDGER_FILE).exists());
        std::fs::write(dir.join(LEDGER_FILE), b"junk again").unwrap();
        Ledger::quarantine(&dir).unwrap();
        assert!(dir.join("ledger.db.corrupt-2").exists());
        assert_eq!(std::fs::read(dir.join("ledger.db.corrupt-1")).unwrap(), b"junk");
    }

    #[test]
    fn path_keys_fold_each_component() {
        assert_eq!(path_key("DCIM/Camera/IMG.JPG"), "dcim/camera/img.jpg");
        assert_eq!(path_key("a"), "a");
    }
}
