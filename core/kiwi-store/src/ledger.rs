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
//! * A run counter is incremented durably on every open. Each device has
//!   its own session counter, advanced only when the transfer layer says that
//!   device has begun a session.
//! * Commit numbers are counted per device; the per-device high-water mark
//!   (`commit_hwm`) never decreases. A phone holding a receipt above it
//!   proves a rollback.
//! * Records that may be written without an immediate flush (plain copies in a
//!   batch, mirror bookkeeping, temp-file intents) are written with
//!   `synchronous=NORMAL`; the next durable write flushes them too.
//! * `PRAGMA user_version` carries the schema version; migrations run inside
//!   a transaction; a ledger from a newer build is refused untouched.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::error::LedgerError;
use crate::hash::ContentHash;
use crate::sanitize::{collision_key, SafeName};

/// File name of the database inside the ledger directory.
pub const LEDGER_FILE: &str = "ledger.db";

/// Newest schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 3;

/// SQLite `application_id` of a Kiwi Transfer ledger ("KWST").
const APPLICATION_ID: i64 = 0x4B57_5354;

const MIGRATIONS: &[(u32, &str)] = &[(1, SCHEMA_V1), (2, SCHEMA_V2), (3, SCHEMA_V3)];

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

const SCHEMA_V3: &str = "
ALTER TABLE devices ADD COLUMN detached_seq INTEGER;
ALTER TABLE devices ADD COLUMN commit_hwm INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN session_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN session_start_seq INTEGER NOT NULL DEFAULT 0;

ALTER TABLE files ADD COLUMN item_key BLOB;
ALTER TABLE files ADD COLUMN commit_no INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN fm_state INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN fm_expires INTEGER;
ALTER TABLE files ADD COLUMN fm_seq INTEGER;

-- Rows written before commit numbers were counted per device get theirs in
-- the order they were committed, and every device starts in the session the
-- whole store was in: nothing stored so far counts as 'an earlier session'
-- until that device has begun a session of its own.
UPDATE files SET commit_no = (
    SELECT COUNT(*) FROM files AS older
    WHERE older.device_id = files.device_id
      AND (older.committed_seq < files.committed_seq
           OR (older.committed_seq = files.committed_seq AND older.id <= files.id)));
UPDATE devices SET
    commit_hwm = COALESCE((SELECT MAX(commit_no) FROM files WHERE files.device_id = devices.device_id), 0),
    session_seq = COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'session_counter'), 0);
CREATE INDEX files_by_key ON files(device_id, item_key);

CREATE TABLE temp_tags (
    tag             TEXT PRIMARY KEY NOT NULL,
    created_seq     INTEGER NOT NULL,
    created_unix_ms INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE mirrors (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    uid               TEXT NOT NULL UNIQUE,
    root              TEXT NOT NULL,
    label             TEXT NOT NULL,
    volume_serial     TEXT,
    active            INTEGER NOT NULL,
    added_seq         INTEGER NOT NULL,
    removed_seq       INTEGER,
    last_seen_seq     INTEGER NOT NULL,
    last_seen_session INTEGER NOT NULL,
    last_seen_unix_ms INTEGER NOT NULL,
    io_errors         INTEGER NOT NULL DEFAULT 0,
    mismatches        INTEGER NOT NULL DEFAULT 0,
    run_no            INTEGER NOT NULL DEFAULT 0,
    run_open          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE mirror_files (
    mirror_id        INTEGER NOT NULL REFERENCES mirrors(id),
    file_id          INTEGER NOT NULL REFERENCES files(id),
    rel_path         TEXT NOT NULL,
    state            INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    copied_seq       INTEGER NOT NULL,
    copied_run       INTEGER NOT NULL,
    recheck          INTEGER NOT NULL,
    verified_seq     INTEGER NOT NULL,
    verified_unix_ms INTEGER NOT NULL,
    unbuffered       INTEGER NOT NULL,
    PRIMARY KEY (mirror_id, file_id)
) WITHOUT ROWID;
CREATE INDEX mirror_files_by_file ON mirror_files(file_id);

CREATE TABLE mirror_scan_state (
    mirror_id INTEGER PRIMARY KEY REFERENCES mirrors(id),
    upper_id  INTEGER NOT NULL,
    cursor_id INTEGER NOT NULL
);
";

const EXPECTED_TABLES: &[&str] = &[
    "meta",
    "sessions",
    "events",
    "devices",
    "files",
    "scan_state",
    "temp_tags",
    "mirrors",
    "mirror_files",
    "mirror_scan_state",
];

const DEVICE_COLUMNS: &str = "device_id, display_name, folder_name, max_bytes, max_files, \
     max_file_bytes, used_bytes, used_files, detached_seq, commit_hwm, session_seq, \
     session_start_seq";

const FILE_COLUMNS: &str =
    "id, device_id, rel_path, hash, size, mtime_unix_ns, source_name, state, \
     committed_seq, committed_session, committed_unix_ms, dir_synced, verified_unbuffered, \
     last_verified_seq, last_verified_session, row_check, item_key, commit_no, fm_state, \
     fm_expires";

/// Where a stored file stands in a final move, as far as the PC has been told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmState {
    /// Nothing beyond the commit is known: the phone still has its copy.
    None,
    /// A deletion was confirmed for this file. The phone may move its copy
    /// to its trash at any moment, and its report of that can be lost: the
    /// file **may be the only copy**.
    Reverified,
    /// The phone reported that its copy is in its trash or gone: this file is
    /// **the only copy**.
    SoleCopy,
    /// The PC user acknowledged that the file was removed or changed on
    /// purpose. Nothing is confirmed for it any more.
    UserRemoved,
}

impl FmState {
    pub(crate) fn code(self) -> i64 {
        match self {
            FmState::None => 0,
            FmState::Reverified => 1,
            FmState::SoleCopy => 2,
            FmState::UserRemoved => 3,
        }
    }

    fn from_code(code: i64) -> Option<FmState> {
        match code {
            0 => Some(FmState::None),
            1 => Some(FmState::Reverified),
            2 => Some(FmState::SoleCopy),
            3 => Some(FmState::UserRemoved),
            _ => None,
        }
    }
}

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
    /// The device's session in which it was committed.
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
    /// The item key the phone gave the file (opaque; empty for rows written
    /// before keys were recorded).
    pub key: Vec<u8>,
    /// The device's commit number for this file: what a receipt carries.
    pub commit_no: u64,
    /// Where the file stands in a final move.
    pub fm: FmState,
    /// When the phone's trash lets go of its copy, if the phone said
    /// (Unix milliseconds).
    pub fm_expires_unix_ms: Option<i64>,
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
    /// The device was unpaired. Its records and files are kept, scanned and
    /// mirrored like any others; it only cannot receive or confirm anything
    /// until it is registered again.
    pub detached: bool,
    /// Highest commit number ever issued to this device (or named by it:
    /// see `Store::check_peer_commit_seq`). Never decreases.
    pub commit_hwm: u64,
    /// The device's current session number. It advances only with
    /// `Store::new_session` for this device.
    pub session_seq: u64,
    /// Sequence number of the ledger event that began that session.
    pub session_start_seq: u64,
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
    /// A peer holds a receipt the ledger does not know: the ledger was rolled
    /// back (restored from a backup or a system image).
    LedgerRollback,
    /// A disk (the destination or a mirror) returned I/O errors or many
    /// mismatching files.
    DiskFailing,
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
            BlockKind::LedgerRollback => "ledger_rollback",
            BlockKind::DiskFailing => "disk_failing",
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
            "ledger_rollback" => BlockKind::LedgerRollback,
            "disk_failing" => BlockKind::DiskFailing,
            _ => return None,
        })
    }

    fn severity(self) -> u8 {
        match self {
            BlockKind::Manual => 1,
            BlockKind::IntegrityProblems
            | BlockKind::LedgerReset
            | BlockKind::LedgerLost
            | BlockKind::MarkerMissing
            | BlockKind::DiskFailing => 2,
            BlockKind::MassChange | BlockKind::LedgerRollback => 3,
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
    /// The item key the phone gave the file.
    pub key: &'a [u8],
    /// Flush the record to the device before returning. `false` is for plain
    /// copies in a batch: the record becomes durable with the next flush.
    pub durable: bool,
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
    /// Written only while `conn` is locked, so a row and the session it
    /// carries always agree.
    session: AtomicU64,
    session_start_seq: AtomicU64,
    /// Commit records written without a flush since the last durable write.
    pending_batched: AtomicU64,
    /// `synchronous=FULL` could not be restored after a relaxed write. Every
    /// later write is refused: "durable" would no longer mean anything.
    sync_broken: AtomicBool,
    #[cfg(test)]
    fresh: bool,
}

mod mirror;
mod records;

pub(crate) use mirror::{MirrorCopy, MirrorFileRow, NewMirror};
pub use mirror::{MirrorFileState, MirrorRecord};
pub(crate) use records::Restored;

type Result<T> = std::result::Result<T, LedgerError>;

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl Ledger {
    /// Opens the ledger and starts a session in one step.
    #[cfg(test)]
    pub(crate) fn open(dir: &Path, now_ms: i64) -> Result<Ledger> {
        let ledger = Ledger::open_unstarted(dir)?;
        ledger.start_session(now_ms)?;
        Ok(ledger)
    }

    /// Opens (creating if absent) the ledger in `dir`, checks its integrity
    /// and migrates it. No session is started: the caller first decides
    /// whether this ledger belongs to its destination at all, so that a
    /// refused open leaves the session counter alone.
    pub(crate) fn open_unstarted(dir: &Path) -> Result<Ledger> {
        let path = dir.join(LEDGER_FILE);
        let map = |e: rusqlite::Error| map_sqlite(&path, e);

        let mut conn = Connection::open(&path).map_err(map)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(map)?;

        // The first statement that touches the file is where a file that is
        // not a database (garbled header) is reported.
        let journal: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(map)?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::Database {
                message: format!("write-ahead logging is unavailable (journal mode {journal})"),
            });
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA cell_size_check=ON;",
        )
        .map_err(map)?;
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .map_err(map)?;
        if synchronous != 2 {
            return Err(LedgerError::Database {
                message: format!("synchronous=FULL was not applied (got {synchronous})"),
            });
        }

        check_integrity(&conn, &path)?;

        let user_version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(map)?;
        let application_id: i64 = conn
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(map)?;
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
            tx.execute_batch(&format!(
                "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {version};"
            ))
            .map_err(map)?;
            tx.commit().map_err(map)?;
        }

        for table in EXPECTED_TABLES {
            let present: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .map_err(map)?;
            if present != 1 {
                return Err(LedgerError::Corrupt {
                    path,
                    detail: format!("table {table} is missing"),
                });
            }
        }

        #[cfg(not(test))]
        let _ = fresh;
        Ok(Ledger {
            conn: Mutex::new(conn),
            path,
            session: AtomicU64::new(0),
            session_start_seq: AtomicU64::new(0),
            pending_batched: AtomicU64::new(0),
            sync_broken: AtomicBool::new(false),
            #[cfg(test)]
            fresh,
        })
    }

    /// Starts a run of the store: bumps the run counter and logs it, durably.
    /// Called once when the store is opened. Returns the run number. (A
    /// device's sessions are something else: see `start_device_session`.)
    ///
    /// Being a flushed write, it also makes every batched record durable.
    pub(crate) fn start_session(&self, now_ms: i64) -> Result<u64> {
        let mut conn = self.lock();
        self.check_sync()?;
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let previous = match meta_get(&tx, "session_counter").map_err(|e| self.map(e))? {
            None => 0,
            Some(text) => text.parse::<u64>().map_err(|_| {
                self.corrupt(format!("the session counter is not a number ({text:?})"))
            })?,
        };
        // The counter in the file is the authority, but it must never fall
        // behind what this process has already handed out.
        let session = previous.max(self.session.load(Ordering::SeqCst)) + 1;
        meta_set(&tx, "session_counter", &session.to_string()).map_err(|e| self.map(e))?;
        let seq = append_event(&tx, session, now_ms, "session_start", None, None, None)
            .map_err(|e| self.map(e))?;
        tx.execute(
            "INSERT INTO sessions(session, started_seq, started_unix_ms) VALUES (?1, ?2, ?3)",
            params![to_i64(session), to_i64(seq), now_ms],
        )
        .map_err(|e| self.map(e))?;
        // Usage counters are derived data; recompute them so they can never drift.
        tx.execute_batch(
            "UPDATE devices SET
                 used_bytes = (SELECT COALESCE(SUM(size), 0) FROM files WHERE files.device_id = devices.device_id AND state <> 2),
                 used_files = (SELECT COUNT(*) FROM files WHERE files.device_id = devices.device_id AND state <> 2);",
        )
        .map_err(|e| self.map(e))?;
        if meta_get(&tx, "ledger_id")
            .map_err(|e| self.map(e))?
            .is_none()
        {
            meta_set(&tx, "ledger_id", &random_id()).map_err(|e| self.map(e))?;
        }
        tx.commit().map_err(|e| self.map(e))?;
        self.session.store(session, Ordering::SeqCst);
        self.session_start_seq.store(seq, Ordering::SeqCst);
        self.pending_batched.store(0, Ordering::SeqCst);
        Ok(session)
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
            std::fs::rename(&from, &to).map_err(|source| LedgerError::Io {
                path: from.clone(),
                source,
            })?;
            moved.push(to);
        }
        Ok(moved)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves the connection usable: every
        // change is inside a transaction that is rolled back on unwind.
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn map(&self, e: rusqlite::Error) -> LedgerError {
        map_sqlite(&self.path, e)
    }

    fn corrupt(&self, detail: impl Into<String>) -> LedgerError {
        LedgerError::Corrupt {
            path: self.path.clone(),
            detail: detail.into(),
        }
    }

    /// The database file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// This open's session number (1 for the first open of a new ledger).
    pub(crate) fn session(&self) -> u64 {
        self.session.load(Ordering::SeqCst)
    }

    /// Sequence number of this session's start event.
    pub(crate) fn session_start_seq(&self) -> u64 {
        self.session_start_seq.load(Ordering::SeqCst)
    }

    /// Refuses to write once the flush setting could not be restored.
    fn check_sync(&self) -> Result<()> {
        if self.sync_broken.load(Ordering::SeqCst) {
            return Err(LedgerError::Database {
                message: "the ledger could not be switched back to flushed writes".to_owned(),
            });
        }
        Ok(())
    }

    /// Runs `body` in a transaction that is committed **without** a flush
    /// (`synchronous=NORMAL`). The write is atomic and ordered like any
    /// other, but a power loss may undo it together with everything after it;
    /// the next flushed write makes it durable. Used only for records whose
    /// loss costs work, never safety.
    fn relaxed<T>(
        &self,
        conn: &mut Connection,
        body: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.check_sync()?;
        conn.execute_batch("PRAGMA synchronous=NORMAL")
            .map_err(|e| self.map(e))?;
        let outcome = (|| {
            let tx = conn.transaction().map_err(|e| self.map(e))?;
            let value = body(&tx)?;
            tx.commit().map_err(|e| self.map(e))?;
            Ok(value)
        })();
        let restored = conn
            .execute_batch("PRAGMA synchronous=FULL")
            .and_then(|()| conn.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0)));
        if !matches!(restored, Ok(2)) {
            self.sync_broken.store(true, Ordering::SeqCst);
            return Err(LedgerError::Database {
                message: "the ledger could not be switched back to flushed writes".to_owned(),
            });
        }
        outcome
    }

    /// Runs `body` in a transaction that is flushed to the device when it
    /// commits, or in a relaxed one (see [`Ledger::relaxed`]).
    fn write<T>(
        &self,
        durable: bool,
        body: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut conn = self.lock();
        if durable {
            self.check_sync()?;
            let tx = conn.transaction().map_err(|e| self.map(e))?;
            let value = body(&tx)?;
            tx.commit().map_err(|e| self.map(e))?;
            Ok(value)
        } else {
            self.relaxed(&mut conn, body)
        }
    }

    /// Commit records written without a flush since the last flush.
    pub(crate) fn pending_batched(&self) -> u64 {
        self.pending_batched.load(Ordering::SeqCst)
    }

    /// Makes everything written so far durable.
    pub(crate) fn flush(&self, now_ms: i64) -> Result<()> {
        let mut conn = self.lock();
        self.check_sync()?;
        let pending = self.pending_batched.load(Ordering::SeqCst);
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        // A flushed commit syncs the whole write-ahead log, and with it every
        // relaxed transaction before it. The event is what there is to commit.
        let detail = format!("{pending} batched records");
        append_event(
            &tx,
            self.session(),
            now_ms,
            "ledger_flushed",
            None,
            None,
            Some(&detail),
        )
        .map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))?;
        self.pending_batched.store(0, Ordering::SeqCst);
        Ok(())
    }

    /// The random identifier of this ledger. A ledger that was found to have
    /// been restored from an older copy gets a new one.
    pub(crate) fn ledger_id(&self) -> Result<String> {
        let conn = self.lock();
        meta_get(&conn, "ledger_id")
            .map_err(|e| self.map(e))?
            .ok_or_else(|| self.corrupt("the ledger has no identifier"))
    }

    /// Gives the ledger a new identifier (it was found to be a restored
    /// copy), so that every receipt issued under the old one is void.
    pub(crate) fn renew_ledger_id(&self, detail: &str, now_ms: i64) -> Result<String> {
        let id = random_id();
        let run = self.session();
        self.write(true, |tx| {
            append_event(
                tx,
                run,
                now_ms,
                "ledger_id_renewed",
                None,
                None,
                Some(detail),
            )
            .map_err(|e| self.map(e))?;
            meta_set(tx, "ledger_id", &id).map_err(|e| self.map(e))
        })?;
        Ok(id)
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
        append_event(
            &tx,
            self.session(),
            now_ms,
            "destination_bound",
            None,
            None,
            Some(id),
        )
        .map_err(|e| self.map(e))?;
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
        let seq = append_event(&tx, self.session(), now_ms, kind, device, file_id, detail)
            .map_err(|e| self.map(e))?;
        tx.commit().map_err(|e| self.map(e))?;
        Ok(seq)
    }

    /// The largest wall-clock time any event was written with.
    pub(crate) fn max_seen_unix_ms(&self) -> Result<i64> {
        let conn = self.lock();
        match meta_get(&conn, "max_unix_ms").map_err(|e| self.map(e))? {
            None => Ok(i64::MIN),
            Some(text) => text
                .parse::<i64>()
                .map_err(|_| self.corrupt("the clock high-water mark is not a number")),
        }
    }

    /// Accepts the current clock reading as correct after the clock was found
    /// to read earlier than times already in the ledger (it had been set to
    /// the future at some point, and was corrected).
    ///
    /// The high-water mark is lowered to `now_ms`, and every file whose commit
    /// time lies in the future is re-stamped as committed now, in its
    /// device's current session: its age starts over, which can only delay a
    /// confirmation, never hasten one. Returns the number of files re-stamped.
    pub(crate) fn acknowledge_clock(&self, note: &str, now_ms: i64) -> Result<u64> {
        let mut conn = self.lock();
        // Read the affected rows through the validating loader, so that a
        // damaged row is reported rather than given a fresh checksum.
        let sql =
            format!("SELECT {FILE_COLUMNS} FROM files WHERE committed_unix_ms > ?1 ORDER BY id");
        let future = self.query_files(&conn, &sql, &[&now_ms])?;

        let tx = conn.transaction().map_err(|e| self.map(e))?;
        meta_set(&tx, "max_unix_ms", &now_ms.to_string()).map_err(|e| self.map(e))?;
        let detail = format!("{note} ({} files re-stamped)", future.len());
        let seq = append_event(
            &tx,
            self.session(),
            now_ms,
            "clock_acknowledged",
            None,
            None,
            Some(&detail),
        )
        .map_err(|e| self.map(e))?;
        for rec in &future {
            let device_session: i64 = tx
                .query_row(
                    "SELECT session_seq FROM devices WHERE device_id = ?1",
                    [&rec.device],
                    |r| r.get(0),
                )
                .map_err(|e| self.map(e))?;
            let check = row_check(
                &rec.device,
                &rec.rel_path,
                &rec.hash,
                rec.size,
                seq,
                to_u64(device_session),
                now_ms,
            );
            tx.execute(
                "UPDATE files SET committed_seq = ?2, committed_session = ?3, committed_unix_ms = ?4, row_check = ?5 WHERE id = ?1",
                params![rec.id, to_i64(seq), device_session, now_ms, check.as_slice()],
            )
            .map_err(|e| self.map(e))?;
        }
        tx.commit().map_err(|e| self.map(e))?;
        Ok(future.len() as u64)
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
            .query_row(
                "SELECT 1 FROM devices WHERE device_id = ?1",
                [device_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| self.map(e))?
            .is_some();
        let (max_bytes, max_files, max_file_bytes) = (
            limits.max_total_bytes.map(to_i64),
            limits.max_files.map(to_i64),
            limits.max_file_bytes.map(to_i64),
        );
        if exists {
            let was_detached: bool = tx
                .query_row(
                    "SELECT detached_seq IS NOT NULL FROM devices WHERE device_id = ?1",
                    [device_id],
                    |r| r.get(0),
                )
                .map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE devices SET display_name = ?2, max_bytes = ?3, max_files = ?4, max_file_bytes = ?5, detached_seq = NULL WHERE device_id = ?1",
                params![device_id, display_name, max_bytes, max_files, max_file_bytes],
            )
            .map_err(|e| self.map(e))?;
            append_event(
                &tx,
                self.session(),
                now_ms,
                if was_detached {
                    "device_reattached"
                } else {
                    "device_updated"
                },
                Some(device_id),
                None,
                None,
            )
            .map_err(|e| self.map(e))?;
        } else {
            let mut n = 1u32;
            let folder = loop {
                let candidate = folder_base.with_collision_suffix(n);
                let taken: bool = tx
                    .query_row(
                        "SELECT 1 FROM devices WHERE folder_key = ?1",
                        [candidate.collision_key()],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|e| self.map(e))?
                    .is_some();
                if !taken {
                    break candidate;
                }
                n += 1;
            };
            let seq = append_event(
                &tx,
                self.session(),
                now_ms,
                "device_registered",
                Some(device_id),
                None,
                Some(folder.as_str()),
            )
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
            .prepare(&format!(
                "SELECT {DEVICE_COLUMNS} FROM devices ORDER BY device_id"
            ))
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([], device_from_row)
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    // ----- files ---------------------------------------------------------

    /// Records a file that is on disk under its final name and has been
    /// verified. Replaces a stale row for the same path, if there is one (the
    /// file it described is gone: the no-replace rename could not otherwise
    /// have succeeded).
    ///
    /// The file gets the device's next commit number and belongs to the
    /// device's current session.
    pub(crate) fn record_commit(&self, new: &NewFile<'_>, now_ms: i64) -> Result<FileRecord> {
        let run = self.session();
        let (id, seq, commit_no, device_session) = self.write(new.durable, |tx| {
            let device: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT session_seq, commit_hwm FROM devices WHERE device_id = ?1",
                    [new.device],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| self.map(e))?;
            let Some((device_session, hwm)) = device else {
                return Err(self.corrupt(format!(
                    "device {} vanished while one of its files was being recorded",
                    new.device
                )));
            };
            let (device_session, commit_no) = (to_u64(device_session), to_u64(hwm) + 1);

            // A stale row for the same path describes a file that is gone
            // (the no-replace rename could not have succeeded otherwise).
            records::supersede_stale(tx, run, now_ms, new.path_key, None)
                .map_err(|e| self.map(e))?;

            let kind = if new.adopted { "adopt" } else { "commit" };
            let seq = append_event(
                tx,
                run,
                now_ms,
                kind,
                Some(new.device),
                None,
                Some(new.rel_path),
            )
            .map_err(|e| self.map(e))?;
            let check = row_check(
                new.device,
                new.rel_path,
                &new.hash,
                new.size,
                seq,
                device_session,
                now_ms,
            );
            tx.execute(
                "INSERT INTO files(device_id, rel_path, path_key, hash, size, mtime_unix_ns, source_name, state, state_seq,
                                   committed_seq, committed_session, committed_unix_ms, dir_synced, verified_unbuffered,
                                   row_check, item_key, commit_no)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    new.device,
                    new.rel_path,
                    new.path_key,
                    new.hash.as_bytes().as_slice(),
                    to_i64(new.size),
                    new.mtime_unix_ns,
                    new.source_name,
                    to_i64(seq),
                    to_i64(device_session),
                    now_ms,
                    new.dir_synced,
                    new.verified_unbuffered,
                    check.as_slice(),
                    new.key,
                    to_i64(commit_no),
                ],
            )
            .map_err(|e| self.map(e))?;
            let id = tx.last_insert_rowid();
            tx.execute(
                "UPDATE events SET file_id = ?1 WHERE seq = ?2",
                params![id, to_i64(seq)],
            )
            .map_err(|e| self.map(e))?;
            adjust_usage(tx, new.device, to_i64(new.size), 1).map_err(|e| self.map(e))?;
            tx.execute(
                "UPDATE devices SET commit_hwm = ?2 WHERE device_id = ?1",
                params![new.device, to_i64(commit_no)],
            )
            .map_err(|e| self.map(e))?;
            Ok((id, seq, commit_no, device_session))
        })?;
        if !new.durable {
            self.pending_batched.fetch_add(1, Ordering::SeqCst);
        }

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
            committed_session: device_session,
            committed_unix_ms: now_ms,
            dir_synced: new.dir_synced,
            verified_unbuffered: new.verified_unbuffered,
            last_verified_seq: None,
            last_verified_session: None,
            key: new.key.to_vec(),
            commit_no,
            fm: FmState::None,
            fm_expires_unix_ms: None,
        })
    }

    fn query_files(
        &self,
        conn: &Connection,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<FileRecord>> {
        let mut stmt = conn.prepare(sql).map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map(args, raw_file_from_row)
            .map_err(|e| self.map(e))?;
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
        let fm = FmState::from_code(raw.fm_state).ok_or_else(|| {
            self.corrupt(format!(
                "file row {} has an unknown final-move state",
                raw.id
            ))
        })?;
        if raw.size < 0 || raw.committed_seq < 0 || raw.committed_session < 0 || raw.commit_no < 0 {
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
            key: raw.item_key.unwrap_or_default(),
            commit_no: to_u64(raw.commit_no),
            fm,
            fm_expires_unix_ms: raw.fm_expires,
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
    #[cfg(test)]
    pub(crate) fn files_by_hash(&self, hash: &ContentHash) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql =
            format!("SELECT {FILE_COLUMNS} FROM files WHERE hash = ?1 ORDER BY committed_seq, id");
        self.query_files(&conn, &sql, &[&hash.as_bytes().as_slice()])
    }

    pub(crate) fn file_by_path_key(&self, path_key: &str) -> Result<Option<FileRecord>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE path_key = ?1");
        Ok(self
            .query_files(&conn, &sql, &[&path_key])?
            .into_iter()
            .next())
    }

    /// Whether any row (in any state) is recorded under this path key.
    pub(crate) fn path_key_exists(&self, path_key: &str) -> Result<bool> {
        let conn = self.lock();
        conn.query_row(
            "SELECT 1 FROM files WHERE path_key = ?1",
            [path_key],
            |_| Ok(()),
        )
        .optional()
        .map(|r| r.is_some())
        .map_err(|e| self.map(e))
    }

    /// Up to `limit` rows with `cursor < id <= upper`, in id order.
    pub(crate) fn files_after(
        &self,
        cursor: i64,
        upper: i64,
        limit: u32,
    ) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE id > ?1 AND id <= ?2 ORDER BY id LIMIT ?3"
        );
        self.query_files(&conn, &sql, &[&cursor, &upper, &i64::from(limit)])
    }

    pub(crate) fn max_file_id(&self) -> Result<i64> {
        let conn = self.lock();
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM files", [], |r| r.get(0))
            .map_err(|e| self.map(e))
    }

    /// Paths of rows that were marked missing at or after event `seq`.
    pub(crate) fn missing_since(&self, seq: u64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT rel_path FROM files WHERE state = 2 AND state_seq >= ?1 ORDER BY id")
            .map_err(|e| self.map(e))?;
        let rows = stmt
            .query_map([to_i64(seq)], |r| r.get::<_, String>(0))
            .map_err(|e| self.map(e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
    }

    /// Changes what the ledger believes about a file. Returns the event's
    /// sequence number, or `None` if the state was already `new_state`.
    pub(crate) fn set_state(
        &self,
        file_id: i64,
        new_state: FileState,
        detail: &str,
        now_ms: i64,
    ) -> Result<Option<u64>> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let row: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT state, size, device_id FROM files WHERE id = ?1",
                [file_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| self.map(e))?;
        let Some((old_code, size, device)) = row else {
            return Ok(None);
        };
        let old = FileState::from_code(old_code)
            .ok_or_else(|| self.corrupt(format!("file row {file_id} has an unknown state")))?;
        if old == new_state {
            return Ok(None);
        }
        let kind = match new_state {
            FileState::Committed => "file_restored",
            FileState::Missing => "file_missing",
            FileState::Changed => "file_changed",
        };
        let seq = append_event(
            &tx,
            self.session(),
            now_ms,
            kind,
            Some(&device),
            Some(file_id),
            Some(detail),
        )
        .map_err(|e| self.map(e))?;
        tx.execute(
            "UPDATE files SET state = ?2, state_seq = ?3 WHERE id = ?1",
            params![file_id, new_state.code(), to_i64(seq)],
        )
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
    pub(crate) fn mark_verified(
        &self,
        file_id: i64,
        kind: &str,
        device: Option<&str>,
        now_ms: i64,
    ) -> Result<u64> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.map(e))?;
        let seq = append_event(
            &tx,
            self.session(),
            now_ms,
            kind,
            device,
            Some(file_id),
            None,
        )
        .map_err(|e| self.map(e))?;
        let updated = tx
            .execute(
                "UPDATE files SET last_verified_seq = ?2, last_verified_session = ?3 WHERE id = ?1",
                params![file_id, to_i64(seq), to_i64(self.session())],
            )
            .map_err(|e| self.map(e))?;
        if updated != 1 {
            return Err(self.corrupt(format!(
                "file row {file_id} vanished while it was being verified"
            )));
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
                append_event(
                    &tx,
                    self.session(),
                    now_ms,
                    "block_noted",
                    None,
                    None,
                    Some(reason),
                )
                .map_err(|e| self.map(e))?;
                current
            }
            _ => {
                let seq = append_event(
                    &tx,
                    self.session(),
                    now_ms,
                    "block_set",
                    None,
                    None,
                    Some(reason),
                )
                .map_err(|e| self.map(e))?;
                meta_set(&tx, "block_kind", kind.code()).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_reason", reason).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_seq", &seq.to_string()).map_err(|e| self.map(e))?;
                meta_set(&tx, "block_session", &self.session().to_string())
                    .map_err(|e| self.map(e))?;
                meta_set(&tx, "block_unix_ms", &now_ms.to_string()).map_err(|e| self.map(e))?;
                BlockInfo {
                    kind,
                    reason: reason.to_owned(),
                    set_seq: seq,
                    set_session: self.session(),
                    set_unix_ms: now_ms,
                }
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
            append_event(
                &tx,
                self.session(),
                now_ms,
                "block_cleared",
                None,
                None,
                Some(&detail),
            )
            .map_err(|e| self.map(e))?;
            tx.execute(
                "DELETE FROM meta WHERE key LIKE 'block\\_%' ESCAPE '\\'",
                [],
            )
            .map_err(|e| self.map(e))?;
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
        conn.execute("DELETE FROM scan_state", [])
            .map(|_| ())
            .map_err(|e| self.map(e))
    }

    // ----- diagnostics ---------------------------------------------------

    pub(crate) fn stats(&self) -> Result<LedgerStats> {
        let conn = self.lock();
        let count = |sql: &str| {
            conn.query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(to_u64)
                .map_err(|e| self.map(e))
        };
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
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| self.map(e))
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
    item_key: Option<Vec<u8>>,
    commit_no: i64,
    fm_state: i64,
    fm_expires: Option<i64>,
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
        item_key: r.get(16)?,
        commit_no: r.get(17)?,
        fm_state: r.get(18)?,
        fm_expires: r.get(19)?,
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
        detached: r.get::<_, Option<i64>>(8)?.is_some(),
        commit_hwm: to_u64(r.get(9)?),
        session_seq: to_u64(r.get(10)?),
        session_start_seq: to_u64(r.get(11)?),
    })
}

fn read_device(conn: &Connection, device_id: &str) -> rusqlite::Result<Option<DeviceRecord>> {
    conn.query_row(
        &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE device_id = ?1"),
        [device_id],
        device_from_row,
    )
    .optional()
}

fn adjust_usage(
    tx: &Transaction<'_>,
    device: &str,
    bytes: i64,
    files: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE devices SET used_bytes = MAX(0, used_bytes + ?2), used_files = MAX(0, used_files + ?3) WHERE device_id = ?1",
        params![device, bytes, files],
    )
    .map(|_| ())
}

/// 128 random bits as 32 hex digits. Used for identifiers, not for secrets.
fn random_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::with_capacity(32);
    for round in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(round);
        h.write_u32(std::process::id());
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

fn meta_get(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
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
    let Some(kind_code) = meta_get(conn, "block_kind")? else {
        return Ok(None);
    };
    let reason = meta_get(conn, "block_reason")?;
    let number = |key: &str| -> rusqlite::Result<Option<i64>> {
        Ok(meta_get(conn, key)?.and_then(|v| v.parse().ok()))
    };
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
        return Err(LedgerError::Corrupt {
            path: path.to_path_buf(),
            detail: findings.join("; "),
        });
    }
    let mut stmt = conn.prepare("PRAGMA foreign_key_check").map_err(map)?;
    let mut rows = stmt.query([]).map_err(map)?;
    if rows.next().map_err(map)?.is_some() {
        return Err(LedgerError::Corrupt {
            path: path.to_path_buf(),
            detail: "a file row refers to an unknown device".to_owned(),
        });
    }
    Ok(())
}

fn map_sqlite(path: &Path, e: rusqlite::Error) -> LedgerError {
    use rusqlite::ErrorCode;
    match &e {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) =>
        {
            LedgerError::Corrupt {
                path: path.to_path_buf(),
                detail: e.to_string(),
            }
        }
        // A column holding the wrong type is damage, not a programming error.
        rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::FromSqlConversionFailure(..) => {
            LedgerError::Corrupt {
                path: path.to_path_buf(),
                detail: e.to_string(),
            }
        }
        _ => LedgerError::Database {
            message: e.to_string(),
        },
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
    rel_path
        .split('/')
        .map(collision_key)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize::sanitize_component;

    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("unit-tmp")
            .join("ledger")
            .join(name);
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
            key: b"item-key",
            durable: true,
        }
    }

    fn device(ledger: &Ledger, id: &str, name: &str) -> DeviceRecord {
        ledger
            .upsert_device(
                id,
                name,
                &sanitize_component(name).unwrap(),
                DeviceLimits::default(),
                1_000,
            )
            .unwrap()
    }

    #[test]
    fn pragmas_are_in_force() {
        let dir = scratch("pragmas");
        let ledger = Ledger::open(&dir, 1_000).unwrap();
        let conn = ledger.lock();
        let get = |p: &str| {
            conn.query_row(&format!("PRAGMA {p}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .unwrap()
        };
        assert_eq!(
            get("journal_mode"),
            rusqlite::types::Value::Text("wal".into())
        );
        assert_eq!(get("synchronous"), rusqlite::types::Value::Integer(2));
        assert_eq!(get("foreign_keys"), rusqlite::types::Value::Integer(1));
        assert_eq!(
            get("user_version"),
            rusqlite::types::Value::Integer(i64::from(SCHEMA_VERSION))
        );
        assert_eq!(
            get("application_id"),
            rusqlite::types::Value::Integer(APPLICATION_ID)
        );
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
        ledger
            .lock()
            .execute("DELETE FROM events WHERE seq = ?1", [to_i64(a)])
            .unwrap();
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
        let limits = DeviceLimits {
            max_total_bytes: Some(10),
            max_files: Some(2),
            max_file_bytes: Some(5),
        };
        let a2 = ledger
            .upsert_device(
                "dev-a",
                "Renamed",
                &sanitize_component("Renamed").unwrap(),
                limits,
                0,
            )
            .unwrap();
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
        assert_eq!(
            ledger.start_device_session("d", None, 10).unwrap(),
            Some(Ok(1))
        );
        let rec = ledger
            .record_commit(&new_file("d", "D/a.jpg", "d/a.jpg", b"aaaa"), 50)
            .unwrap();
        assert_eq!(rec.committed_session, 1);
        assert_eq!(rec.commit_no, 1);
        assert_eq!(ledger.device("d").unwrap().unwrap().commit_hwm, 1);
        assert!(rec.committed_seq > ledger.session_start_seq());
        assert_eq!(
            ledger
                .files_by_hash(&ContentHash::of_bytes(b"aaaa"))
                .unwrap(),
            vec![rec.clone()]
        );
        assert_eq!(
            ledger.file_by_path_key("d/a.jpg").unwrap(),
            Some(rec.clone())
        );
        assert_eq!(ledger.file_by_id(rec.id).unwrap(), Some(rec.clone()));
        assert!(ledger.path_key_exists("d/a.jpg").unwrap());
        assert!(!ledger.path_key_exists("d/b.jpg").unwrap());
        assert!(ledger
            .files_by_hash(&ContentHash::of_bytes(b"other"))
            .unwrap()
            .is_empty());
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (4, 1));

        // Missing files stop counting; restored ones count again.
        assert!(ledger
            .set_state(rec.id, FileState::Missing, "gone", 60)
            .unwrap()
            .is_some());
        assert!(ledger
            .set_state(rec.id, FileState::Missing, "gone", 60)
            .unwrap()
            .is_none());
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (0, 0));
        assert_eq!(ledger.missing_since(0).unwrap(), vec!["D/a.jpg".to_owned()]);
        ledger
            .set_state(rec.id, FileState::Changed, "different", 61)
            .unwrap();
        ledger
            .set_state(rec.id, FileState::Committed, "back", 62)
            .unwrap();
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (4, 1));

        let seq = ledger
            .mark_verified(rec.id, "verified", Some("d"), 70)
            .unwrap();
        let again = ledger.file_by_id(rec.id).unwrap().unwrap();
        assert_eq!(again.last_verified_seq, Some(seq));
        assert_eq!(again.last_verified_session, Some(1));

        let stats = ledger.stats().unwrap();
        assert_eq!(
            (stats.files_committed, stats.bytes_committed, stats.devices),
            (1, 4, 1)
        );
    }

    #[test]
    fn a_new_commit_supersedes_a_stale_row_for_the_same_path() {
        let dir = scratch("supersede");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "d", "D");
        let old = ledger
            .record_commit(&new_file("d", "D/a.jpg", "d/a.jpg", b"old content"), 1)
            .unwrap();
        ledger
            .set_state(old.id, FileState::Missing, "gone", 2)
            .unwrap();
        let new = ledger
            .record_commit(&new_file("d", "D/A.JPG", "d/a.jpg", b"new"), 3)
            .unwrap();
        assert_ne!(new.id, old.id);
        assert_eq!(ledger.file_by_id(old.id).unwrap(), None);
        assert_eq!(
            ledger
                .file_by_path_key("d/a.jpg")
                .unwrap()
                .unwrap()
                .rel_path,
            "D/A.JPG"
        );
        let d = ledger.device("d").unwrap().unwrap();
        assert_eq!((d.used_bytes, d.used_files), (3, 1));
        assert!(ledger
            .events_after(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind == "record_superseded"));
    }

    #[test]
    fn usage_counters_heal_on_open() {
        let dir = scratch("heal");
        {
            let ledger = Ledger::open(&dir, 0).unwrap();
            device(&ledger, "d", "D");
            ledger
                .record_commit(&new_file("d", "D/a", "d/a", b"12345"), 1)
                .unwrap();
            ledger
                .lock()
                .execute("UPDATE devices SET used_bytes = 999, used_files = 42", [])
                .unwrap();
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
            let b = ledger
                .block(BlockKind::IntegrityProblems, "one file changed", 11)
                .unwrap();
            assert_eq!(b.kind, BlockKind::IntegrityProblems);
            let b = ledger
                .block(BlockKind::MassChange, "many files changed", 12)
                .unwrap();
            assert_eq!(b.kind, BlockKind::MassChange);
            // A milder block does not replace a more severe one.
            let b = ledger
                .block(BlockKind::IntegrityProblems, "another file", 13)
                .unwrap();
            assert_eq!(
                (b.kind, b.reason.as_str()),
                (BlockKind::MassChange, "many files changed")
            );
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        let b = ledger
            .block_info()
            .unwrap()
            .expect("the block must survive a restart");
        assert_eq!((b.kind, b.set_session), (BlockKind::MassChange, 1));
        let cleared = ledger.clear_block("user reviewed", 20).unwrap().unwrap();
        assert_eq!(cleared.kind, BlockKind::MassChange);
        assert_eq!(ledger.block_info().unwrap(), None);
        let kinds: Vec<String> = ledger
            .events_after(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        for expected in ["block_set", "block_noted", "block_cleared"] {
            assert!(
                kinds.iter().any(|k| k == expected),
                "missing event {expected}"
            );
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
        ledger.start_device_session("d", Some(7), 0).unwrap();
        let rec = ledger
            .record_commit(&new_file("d", "D/a", "d/a", b"data"), 1)
            .unwrap();
        assert_eq!(rec.committed_session, 7);
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
                stmt.query_row([], |r| (0..6).map(|i| r.get(i)).collect())
                    .unwrap()
            };
            ledger.lock().execute(tamper, []).unwrap();
            let err = ledger.file_by_id(rec.id).unwrap_err();
            assert!(err.is_corruption(), "{tamper}: {err}");
            ledger.lock().execute(
                "UPDATE files SET committed_session = ?1, committed_seq = ?2, committed_unix_ms = ?3, size = ?4, rel_path = ?5, hash = ?6",
                rusqlite::params_from_iter(before),
            ).unwrap();
            assert!(
                ledger.file_by_id(rec.id).is_ok(),
                "restoring after {tamper}"
            );
        }
    }

    #[test]
    fn migrates_from_version_1_and_keeps_the_data() {
        let dir = scratch("migrate");
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute_batch(&format!(
                "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = 1;"
            ))
            .unwrap();
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('session_counter', '41')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('destination_id', 'abc')",
                [],
            )
            .unwrap();
        }
        let ledger = Ledger::open(&dir, 0).unwrap();
        assert!(!ledger.is_fresh());
        assert_eq!(ledger.session(), 42);
        assert_eq!(ledger.destination_id().unwrap().as_deref(), Some("abc"));
        assert_eq!(ledger.scan_state().unwrap(), None);
        let version: i64 = ledger
            .lock()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, i64::from(SCHEMA_VERSION));
    }

    #[test]
    fn refuses_a_ledger_from_the_future_without_touching_it() {
        let dir = scratch("too-new");
        drop(Ledger::open(&dir, 0).unwrap());
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
                .unwrap();
        }
        match Ledger::open(&dir, 0) {
            Err(LedgerError::TooNew { found, supported }) => {
                assert_eq!((found, supported), (SCHEMA_VERSION + 1, SCHEMA_VERSION));
            }
            other => panic!("expected TooNew, got {:?}", other.map(|_| ())),
        }
        // The refused open must not have started a session.
        let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
        let counter: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'session_counter'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(counter, "1");
    }

    #[test]
    fn refuses_someone_elses_database() {
        let dir = scratch("foreign");
        {
            let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE notes(text TEXT); INSERT INTO notes VALUES ('hello');",
            )
            .unwrap();
        }
        assert!(matches!(
            Ledger::open(&dir, 0),
            Err(LedgerError::NotALedger { .. })
        ));
        // ... and leaves it alone.
        let conn = Connection::open(dir.join(LEDGER_FILE)).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM notes", [], |r| r.get(0))
            .unwrap();
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
        assert_eq!(
            std::fs::read(dir.join("ledger.db.corrupt-1")).unwrap(),
            b"junk"
        );
    }

    #[test]
    fn sessions_and_commit_numbers_are_counted_per_device() {
        let dir = scratch("per-device");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "a", "A");
        device(&ledger, "b", "B");
        // Opening the ledger is nobody's session.
        assert_eq!(ledger.device("a").unwrap().unwrap().session_seq, 0);
        assert_eq!(
            ledger.start_device_session("a", None, 1).unwrap(),
            Some(Ok(1))
        );
        assert_eq!(
            ledger.start_device_session("a", None, 1).unwrap(),
            Some(Ok(2))
        );
        // The number agreed with the phone is taken as it is, if it is newer.
        assert_eq!(
            ledger.start_device_session("a", Some(40), 1).unwrap(),
            Some(Ok(40))
        );
        assert_eq!(
            ledger.start_device_session("a", Some(40), 1).unwrap(),
            Some(Err(40))
        );
        assert_eq!(
            ledger.start_device_session("a", Some(3), 1).unwrap(),
            Some(Err(40))
        );
        assert_eq!(
            ledger
                .start_device_session("a", Some(records::MAX_SESSION_SEQ + 1), 1)
                .unwrap(),
            Some(Err(40))
        );
        assert_eq!(
            ledger.start_device_session("nobody", None, 1).unwrap(),
            None
        );
        // Another device's sessions are its own.
        assert_eq!(ledger.device("b").unwrap().unwrap().session_seq, 0);

        let a1 = ledger
            .record_commit(&new_file("a", "A/1", "a/1", b"1"), 5)
            .unwrap();
        let b1 = ledger
            .record_commit(&new_file("b", "B/1", "b/1", b"1"), 5)
            .unwrap();
        let a2 = ledger
            .record_commit(&new_file("a", "A/2", "a/2", b"2"), 5)
            .unwrap();
        assert_eq!((a1.commit_no, a2.commit_no, b1.commit_no), (1, 2, 1));
        assert_eq!((a1.committed_session, b1.committed_session), (40, 0));
        assert_eq!(ledger.device("a").unwrap().unwrap().commit_hwm, 2);
        assert_eq!(ledger.device("b").unwrap().unwrap().commit_hwm, 1);
        // A raised mark is never handed out again, and never goes down.
        ledger
            .raise_commit_hwm("a", 10, "the phone holds commit 10", 6)
            .unwrap();
        ledger.raise_commit_hwm("a", 4, "lower", 6).unwrap();
        let a3 = ledger
            .record_commit(&new_file("a", "A/3", "a/3", b"3"), 7)
            .unwrap();
        assert_eq!(a3.commit_no, 11);
        // Look-ups never cross devices, even for identical content.
        let hash = ContentHash::of_bytes(b"1");
        assert_eq!(
            ledger.device_files_by_hash("a", &hash).unwrap(),
            vec![a1.clone()]
        );
        assert_eq!(
            ledger.device_files_by_hash("b", &hash).unwrap(),
            vec![b1.clone()]
        );
        assert_eq!(
            ledger.device_record("a", b"item-key", &hash, 1, 1).unwrap(),
            Some(a1)
        );
        for (device, key, size, commit) in [
            ("b", b"item-key".as_slice(), 1, 2),
            ("a", b"other-key".as_slice(), 1, 1),
            ("a", b"item-key".as_slice(), 2, 1),
            ("a", b"item-key".as_slice(), 1, 2),
        ] {
            assert_eq!(
                ledger
                    .device_record(device, key, &hash, size, commit)
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn relaxed_writes_leave_the_ledger_on_flushed_writes() {
        let dir = scratch("relaxed");
        let ledger = Ledger::open(&dir, 0).unwrap();
        device(&ledger, "d", "D");
        let synchronous = |ledger: &Ledger| -> i64 {
            ledger
                .lock()
                .query_row("PRAGMA synchronous", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(synchronous(&ledger), 2);
        let mut batched = new_file("d", "D/a", "d/a", b"a");
        batched.durable = false;
        ledger.record_commit(&batched, 1).unwrap();
        // The relaxed write is over; every later write is flushed again.
        assert_eq!(synchronous(&ledger), 2);
        assert_eq!(ledger.pending_batched(), 1);
        let mut second = new_file("d", "D/b", "d/b", b"b");
        second.durable = false;
        ledger.record_commit(&second, 1).unwrap();
        assert_eq!(ledger.pending_batched(), 2);
        ledger.flush(2).unwrap();
        assert_eq!(ledger.pending_batched(), 0);
        assert_eq!(synchronous(&ledger), 2);
        // A device session is a flushed write too.
        ledger.record_commit(&batched_again(), 3).unwrap();
        assert_eq!(ledger.pending_batched(), 1);
        ledger.start_device_session("d", None, 4).unwrap();
        assert_eq!(ledger.pending_batched(), 0);
        assert!(ledger.events_after(0, 100).unwrap().iter().any(
            |e| e.kind == "ledger_flushed" && e.detail.as_deref() == Some("2 batched records")
        ));
    }

    fn batched_again() -> NewFile<'static> {
        NewFile {
            durable: false,
            ..new_file("d", "D/c", "d/c", b"c")
        }
    }

    #[test]
    fn temp_tags_and_the_ledger_id_persist() {
        let dir = scratch("tags");
        let id = {
            let ledger = Ledger::open(&dir, 0).unwrap();
            assert!(ledger.temp_tags().unwrap().is_empty());
            ledger.add_temp_tag("00112233aabbccdd", 1).unwrap();
            ledger.add_temp_tag("00112233aabbccdd", 1).unwrap();
            ledger.add_temp_tag("ffeeddccbbaa9988", 1).unwrap();
            ledger.ledger_id().unwrap()
        };
        assert_eq!(id.len(), 32);
        let ledger = Ledger::open(&dir, 0).unwrap();
        assert_eq!(ledger.ledger_id().unwrap(), id);
        let tags = ledger.temp_tags().unwrap();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains("00112233aabbccdd") && tags.contains("ffeeddccbbaa9988"));
        let renewed = ledger.renew_ledger_id("restored", 2).unwrap();
        assert_ne!(renewed, id);
        assert_eq!(ledger.ledger_id().unwrap(), renewed);
    }

    #[test]
    fn path_keys_fold_each_component() {
        assert_eq!(path_key("DCIM/Camera/IMG.JPG"), "dcim/camera/img.jpg");
        assert_eq!(path_key("a"), "a");
    }
}
