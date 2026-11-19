//! Error types.

use std::io;
use std::path::PathBuf;

use crate::destination::DestinationError;
use crate::hash::ContentHash;
use crate::sanitize::SanitizeError;
use crate::template::TemplateError;

/// Which per-device limit was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    /// Total bytes stored for the device.
    TotalBytes,
    /// Number of files stored for the device.
    FileCount,
    /// Size of a single file.
    FileBytes,
}

/// Errors from the ledger (the SQLite index).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// The database file is damaged. Nothing in it is trusted; no deletion
    /// can be confirmed until it is reset with
    /// [`Store::reset_corrupt_ledger`](crate::Store::reset_corrupt_ledger).
    #[error("the ledger {path:?} is damaged: {detail}")]
    Corrupt {
        /// The database file.
        path: PathBuf,
        /// What the check found.
        detail: String,
    },
    /// The database was written by a newer version of the engine.
    #[error("the ledger uses schema version {found}; this build understands up to {supported}")]
    TooNew {
        /// Version found in the file.
        found: u32,
        /// Newest version this build can read.
        supported: u32,
    },
    /// The file is an SQLite database, but not one of ours.
    #[error("{path:?} is not a Kiwi Transfer ledger")]
    NotALedger {
        /// The database file.
        path: PathBuf,
    },
    /// The ledger belongs to a different destination folder.
    #[error("the ledger belongs to destination {ledger_id}, but the folder is marked {marker_id}")]
    DestinationMismatch {
        /// Destination id recorded in the ledger.
        ledger_id: String,
        /// Destination id found in the folder's marker file.
        marker_id: String,
    },
    /// The ledger directory is on a network volume, where SQLite's
    /// write-ahead log is not safe.
    #[error("the ledger directory {path:?} is on a network volume")]
    OnNetworkVolume {
        /// The ledger directory.
        path: PathBuf,
    },
    /// File-level I/O around the database failed.
    #[error("ledger I/O failed for {path:?}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Any other database error.
    #[error("ledger database error: {message}")]
    Database {
        /// SQLite's message.
        message: String,
    },
}

impl LedgerError {
    /// True if the error means the ledger's contents cannot be trusted.
    pub fn is_corruption(&self) -> bool {
        matches!(self, LedgerError::Corrupt { .. })
    }
}

/// Errors from the storage engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The destination root is unusable.
    #[error(transparent)]
    Destination(#[from] DestinationError),
    /// A peer-supplied name was refused.
    #[error("the name {name:?} was refused: {source}")]
    UnsafeName {
        /// The name as supplied (lossily truncated for display).
        name: String,
        /// The rule it broke.
        #[source]
        source: SanitizeError,
    },
    /// The organisation template is invalid.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// A device id was not acceptable.
    #[error("the device id {0:?} is not valid")]
    InvalidDeviceId(String),
    /// The device is not registered with this store.
    #[error("the device {0:?} is not registered")]
    UnknownDevice(String),
    /// A file-system operation failed.
    #[error("{op} failed for {path:?}: {source}")]
    Io {
        /// What was being attempted.
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The volume filled up while writing.
    #[error("the destination ran out of space while writing {path:?}: {source}")]
    DiskFull {
        /// The file being written.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The low-space guard refused to start a write.
    #[error("not enough free space: {needed} bytes needed plus a margin of {margin}, {available} available")]
    InsufficientSpace {
        /// Bytes this file and the other files in flight still need.
        needed: u64,
        /// Safety margin that must remain free.
        margin: u64,
        /// Bytes available on the volume.
        available: u64,
    },
    /// A reparse point (junction, symbolic link, mount point) lies between the
    /// root and the target. The engine never follows one.
    #[error("refusing to go through the reparse point {path:?}")]
    ReparsePoint {
        /// The offending path.
        path: PathBuf,
    },
    /// Something that must be a directory is not.
    #[error("{path:?} exists and is not a directory")]
    NotADirectory {
        /// The offending path.
        path: PathBuf,
    },
    /// A directory did not resolve to where the engine put it (8.3 alias,
    /// redirection, or interference).
    #[error("{expected:?} resolves to {resolved:?}")]
    PathMismatch {
        /// Where the engine expected to be.
        expected: PathBuf,
        /// Where the operating system says it is.
        resolved: PathBuf,
    },
    /// The full path would exceed what the file system allows.
    #[error("the path is too long ({utf16_len} UTF-16 units, limit {max})")]
    PathTooLong {
        /// Length of the path that was refused.
        utf16_len: usize,
        /// The limit.
        max: usize,
    },
    /// A per-device limit would be exceeded.
    #[error("device {device:?} would exceed its {kind:?} limit: {requested} requested, {allowed} allowed")]
    QuotaExceeded {
        /// The device.
        device: String,
        /// Which limit.
        kind: QuotaKind,
        /// The limit.
        allowed: u64,
        /// What the request would have brought the total to.
        requested: u64,
    },
    /// The number of bytes received differs from the declared size.
    #[error("{declared} bytes were declared but {received} were received")]
    SizeMismatch {
        /// Size announced by the sender.
        declared: u64,
        /// Bytes actually received (or about to be).
        received: u64,
    },
    /// The sender never said what the file's hash is.
    #[error("the sender supplied no hash for the file")]
    MissingSenderHash,
    /// The sender supplied two different hashes for the same file.
    #[error("the sender supplied two different hashes for the file")]
    ConflictingSenderHashes,
    /// The hash claimed by the sender is not the hash of what arrived.
    #[error("the sender claimed hash {claimed} but the received bytes hash to {received}")]
    SenderHashMismatch {
        /// Hash claimed by the sender.
        claimed: ContentHash,
        /// Hash of the received stream.
        received: ContentHash,
    },
    /// What was read back from the disk is not what was received.
    #[error("read-back from disk does not match: expected {expected} ({expected_size} bytes), found {on_disk} ({on_disk_size} bytes)")]
    DiskVerifyMismatch {
        /// Hash of the received stream.
        expected: ContentHash,
        /// Hash of the bytes read back from the disk.
        on_disk: ContentHash,
        /// Size received.
        expected_size: u64,
        /// Size read back.
        on_disk_size: u64,
    },
    /// No free name was found for the file.
    #[error("too many files named like {name:?} in {dir:?}")]
    TooManyCollisions {
        /// Directory, relative to the root.
        dir: String,
        /// The name that kept colliding.
        name: String,
    },
    /// The incoming file was already finished, aborted, or had failed.
    #[error("this incoming file is already closed")]
    WriterClosed,
    /// The ledger failed.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Another instance has the destination open.
    #[error("the destination is already open in another instance (lock {lock:?})")]
    AlreadyOpen {
        /// The lock file.
        lock: PathBuf,
    },
}

impl StoreError {
    pub(crate) fn io(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> StoreError {
        StoreError::Io { op, path: path.into(), source }
    }

    /// Like [`StoreError::io`], but recognises "no space left".
    pub(crate) fn write(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> StoreError {
        if matches!(source.kind(), io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded) {
            StoreError::DiskFull { path: path.into(), source }
        } else {
            StoreError::Io { op, path: path.into(), source }
        }
    }
}
