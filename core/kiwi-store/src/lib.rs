//! # kiwi-store
//!
//! The PC-side durable storage engine of Kiwi Transfer. It receives files
//! from a paired phone, puts them on disk, proves to itself that they are on
//! disk, and only then lets anyone say so. The phone is allowed to delete its
//! own copy only on the strength of what this crate reports, so the crate is
//! written to say "no" whenever it is not sure.
//!
//! There is no networking and no user interface here. The transfer layer
//! calls [`Store::begin_file`], streams bytes into the returned
//! [`IncomingFile`], and calls [`IncomingFile::finish`]. Later, typically a
//! day later, it calls [`Store::verify_for_deletion`].
//!
//! ```no_run
//! use kiwi_store::{
//!     ContentHash, DeviceId, DeviceLimits, FileRequest, Store, StoreConfig, VerifyRequest,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = Store::open(StoreConfig::new(r"E:\Photos\Kiwi", r"C:\ProgramData\KiwiTransfer\ledger"))?;
//! let phone = DeviceId::new("3f9a6c0e5b7d4a12")?;
//! store.register_device(&phone, "Pixel 8", DeviceLimits::default())?;
//! // Once per connection of this phone:
//! store.new_session(&phone, None)?;
//!
//! let data = b"...jpeg bytes...";
//! let hash = ContentHash::of_bytes(data); // in reality: the hash the phone claims
//!
//! if store.find_duplicate(&phone, &hash)?.is_none() {
//!     let mut incoming = store.begin_file(FileRequest {
//!         device: &phone,
//!         key: b"item-key-from-the-phone",
//!         name: "DCIM/Camera/IMG_0001.jpg",
//!         size: data.len() as u64,
//!         claimed_hash: Some(hash),
//!         capture_time: None,
//!         mtime_unix_ns: None,
//!     })?;
//!     incoming.write(data)?;
//!     let receipt = incoming.finish(None)?;
//!     println!("stored as {} (commit {})", receipt.rel_path, receipt.seq);
//! }
//!
//! // In a later session of this phone (`Store::new_session`), at least 24
//! // hours later, the phone names the record and the key of the proof it
//! // expects:
//! let request = VerifyRequest {
//!     key: b"item-key-from-the-phone",
//!     hash,
//!     size: data.len() as u64,
//!     commit_seq: 1,
//!     proof_key: [7; 32],
//!     min_age_sessions: 1,
//! };
//! match store.verify_for_deletion(&phone, &request) {
//!     Ok(proof) => println!("the phone may delete its copy of {}", proof.file.rel_path),
//!     Err(why) => println!("keep the phone's copy: {why}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See the README for the guarantees in plain words, and for what is *not*
//! guaranteed.

#![warn(missing_docs)]

pub mod destination;
pub mod error;
pub mod fsops;
pub mod hash;
pub mod ledger;
pub mod sanitize;
mod store;
mod sys;
pub mod template;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use destination::{
    CopyOnlyReason, Destination, DestinationError, DestinationWarning, FinalMoveSupport, HazardEnv,
    ManagedFolder, SyncProvider, VolumeClass, VolumeInfo,
};
pub use error::{LedgerError, QuotaKind, StoreError};
pub use hash::ContentHash;
pub use ledger::{
    BlockInfo, BlockKind, DeviceLimits, DeviceRecord, EventRecord, FileState, FmState, LedgerStats,
    MirrorFileState,
};
pub use sanitize::{
    is_shell_active, sanitize_component, sanitize_rel_path, SafeName, SafeRelPath, SanitizeError,
    NEUTRAL_SUFFIX, SHELL_ACTIVE_EXTENSIONS, SHELL_ACTIVE_NAMES,
};
#[cfg(any(test, feature = "test-util"))]
pub use store::Seams;
pub use store::{
    AuditStatus, CancelToken, CommitOutcome, CommitReceipt, CopyCounts, DeletionDenied,
    DeletionProof, DeviceId, FileRequest, FindingKind, IncomingFile, MirrorAbsent, MirrorError,
    MirrorFailure, MirrorId, MirrorInfo, MirrorOptions, MirrorPending, MirrorPresence, MirrorRun,
    MirrorRunReport, MirrorScan, MirrorScanReport, NotVerifiedReason, OpenNote, RecoveryReport,
    Repair, RepairDirection, RollbackCheck, ScanFinding, ScanOptions, ScanPolicy, ScanReport,
    ScanVerdict, Store, StoreConfig, StoredFile, StoredRecord, StoredStatus, UnmirroredCommit,
    VerifyRequest, VolumeProbe, WrongDisk, DEFAULT_SAFETY_MARGIN_BYTES, MAX_LISTED_FINDINGS,
    MAX_MIRRORS, MAX_PATH_UTF16, MIN_WALL_AGE_SECS, MIRROR_MARKER_FILE, STORE_DIR, TEMP_PREFIX,
    TEMP_SUFFIX,
};
pub use template::{CaptureTime, CivilDate, Template, TemplateError};
