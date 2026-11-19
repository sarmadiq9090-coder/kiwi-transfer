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
//! use kiwi_store::{ContentHash, DedupeScope, DeviceId, DeviceLimits, FileRequest, Store, StoreConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = Store::open(StoreConfig::new(r"E:\Photos\Kiwi", r"C:\ProgramData\KiwiTransfer\ledger"))?;
//! let phone = DeviceId::new("3f9a6c0e5b7d4a12")?;
//! store.register_device(&phone, "Pixel 8", DeviceLimits::default())?;
//!
//! let data = b"...jpeg bytes...";
//! let hash = ContentHash::of_bytes(data); // in reality: the hash the phone claims
//!
//! if store.find_duplicate(&hash, DedupeScope::Device(&phone))?.is_none() {
//!     let mut incoming = store.begin_file(FileRequest {
//!         device: &phone,
//!         name: "DCIM/Camera/IMG_0001.jpg",
//!         size: data.len() as u64,
//!         claimed_hash: Some(hash),
//!         capture_time: None,
//!         mtime_unix_ns: None,
//!     })?;
//!     incoming.write(data)?;
//!     let receipt = incoming.finish(None)?;
//!     println!("stored as {}", receipt.rel_path);
//! }
//!
//! // In a later session, at least 24 hours later:
//! match store.verify_for_deletion(&hash, 1) {
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

pub use destination::{CopyOnlyReason, Destination, DestinationError, FinalMoveSupport, VolumeClass, VolumeInfo};
pub use error::{LedgerError, QuotaKind, StoreError};
pub use hash::ContentHash;
pub use ledger::{BlockInfo, BlockKind, DeviceLimits, DeviceRecord, EventRecord, FileState, LedgerStats};
pub use sanitize::{sanitize_component, sanitize_rel_path, SafeName, SafeRelPath, SanitizeError};
#[cfg(any(test, feature = "test-util"))]
pub use store::Seams;
pub use store::{
    CancelToken, CommitOutcome, CommitReceipt, DedupeScope, DeletionDenied, DeletionProof, DeviceId, FileRequest,
    IncomingFile, NotVerifiedReason, OpenNote, RecoveryReport, ScanFinding, ScanOptions, ScanPolicy, ScanReport,
    ScanVerdict, Store, StoreConfig, StoredFile, StoredStatus, DEFAULT_SAFETY_MARGIN_BYTES, MAX_PATH_UTF16,
    MIN_WALL_AGE_SECS, STORE_DIR, TEMP_PREFIX, TEMP_SUFFIX,
};
pub use template::{CaptureTime, CivilDate, Template, TemplateError};
