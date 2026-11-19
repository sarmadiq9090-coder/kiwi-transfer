//! Answers to "is this content safely stored?".
//!
//! The ledger only nominates candidates. Every positive answer in this module
//! comes from reading the candidate file back from the disk and comparing its
//! BLAKE3 hash with the one asked about.
//!
//! Every answer is given **to one device**, from that device's own records,
//! which name files inside that device's own folder. A copy stored by one
//! phone is never used to answer for another, even if it has the same hash.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use super::{lock, DeviceId, Inner, Store, MIN_WALL_AGE_SECS};
use crate::destination::{CopyOnlyReason, FinalMoveSupport};
use crate::error::{LedgerError, StoreError};
use crate::fsops::{is_hard_io_error, EntryKind};
use crate::hash::ContentHash;
use crate::ledger::{BlockInfo, BlockKind, FileRecord, FileState, FmState};
use crate::sanitize::SafeRelPath;

/// A stored file that has just been re-read from disk and matched its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// Ledger row.
    pub file_id: i64,
    /// The device the answer was given to. The commit fields below are that
    /// device's own.
    pub device: String,
    /// Path relative to the destination root, `/`-separated.
    pub rel_path: String,
    /// Absolute path.
    pub abs_path: PathBuf,
    /// Content hash (recorded, and just recomputed from disk).
    pub hash: ContentHash,
    /// Size in bytes.
    pub size: u64,
    /// The device's commit number for the file (what its receipt carried).
    pub commit_seq: u64,
    /// Session of the device's commit.
    pub committed_session: u64,
    /// Wall-clock time of the device's commit (Unix milliseconds).
    pub committed_unix_ms: i64,
    /// Whether this re-read bypassed the operating system's cache.
    pub read_unbuffered: bool,
}

/// Why content is not confirmed as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotVerifiedReason {
    /// The ledger has no record of this content for this device.
    NoRecord,
    /// The recorded file is gone.
    Missing,
    /// The recorded path now holds different content. The text says how.
    Changed(String),
    /// The file could not be read (in use, access denied, I/O error).
    Unreadable(String),
    /// A reparse point (junction, link) lies on the way to the file.
    ReparsePoint(PathBuf),
    /// The file's data is not on the local disk (cloud placeholder).
    NotLocal,
    /// The ledger row does not describe a valid path.
    InvalidRecord,
    /// The file matched, but only through a cached read; that is not good
    /// enough to confirm a deletion.
    BufferedReadOnly,
    /// The file matched, but its name could not be flushed to the device
    /// (neither when it was stored nor now).
    NameNotFlushed(String),
}

impl std::fmt::Display for NotVerifiedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRecord => f.write_str("there is no record of this content for this device"),
            Self::Missing => f.write_str("the stored file is missing"),
            Self::Changed(how) => write!(f, "the stored file was changed ({how})"),
            Self::Unreadable(why) => write!(f, "the stored file could not be read ({why})"),
            Self::ReparsePoint(p) => write!(f, "a link or junction is in the way at {p:?}"),
            Self::NotLocal => f.write_str("the stored file's data is not on the local disk"),
            Self::InvalidRecord => f.write_str("the ledger record is invalid"),
            Self::BufferedReadOnly => f.write_str("the file could only be read through the cache"),
            Self::NameNotFlushed(why) => {
                write!(
                    f,
                    "the file's name could not be flushed to the disk ({why})"
                )
            }
        }
    }
}

/// Answer of [`Store::is_safely_stored`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredStatus {
    /// A file with this content was just read back from disk and matched.
    Verified(StoredFile),
    /// No such confirmation could be made.
    NotVerified(NotVerifiedReason),
}

impl StoredStatus {
    /// True for [`StoredStatus::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, StoredStatus::Verified(_))
    }
}

/// What a phone names when it asks whether it may delete its copy of an item:
/// the record, exactly, and the key of the proof it expects back.
#[derive(Debug, Clone)]
pub struct VerifyRequest<'a> {
    /// The item key the phone gave the file when it sent it.
    pub key: &'a [u8],
    /// The content hash on the phone's receipt.
    pub hash: ContentHash,
    /// The size on the phone's receipt.
    pub size: u64,
    /// The commit number on the phone's receipt ([`CommitReceipt::seq`](super::CommitReceipt)).
    pub commit_seq: u64,
    /// The key of the proof: the answer carries `MAC(proof_key, content)`,
    /// BLAKE3 in keyed mode over the bytes read from the disk. The transfer
    /// layer derives it from a fresh nonce of the phone, so a proof cannot be
    /// replayed or computed from anything but the file's bytes.
    pub proof_key: [u8; 32],
    /// Sessions of this device that must have begun since the one that
    /// recorded the file (never fewer than one).
    pub min_age_sessions: u32,
}

/// Proof returned by [`Store::verify_for_deletion`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a DeletionProof is the only thing that may trigger a deletion on the phone"]
pub struct DeletionProof {
    /// The file that was re-read from disk, unbuffered, just now.
    pub file: StoredFile,
    /// `MAC(proof_key, content)`: BLAKE3 keyed hash of the bytes of that very
    /// read. The phone computes the same over its own copy and compares.
    pub proof: [u8; 32],
    /// How many copies of the file the PC holds: this one, plus one for every
    /// active mirror whose copy was read back and matched when it was last
    /// checked. The proof itself always comes from the destination's file.
    pub copies: u64,
    /// Sessions of the device elapsed since the commit (at least the
    /// requested minimum, at least 1).
    pub sessions_elapsed: u64,
    /// Wall-clock seconds elapsed since the commit (at least 24 hours).
    pub age_secs: u64,
    /// Sequence number of the ledger event recording this verification.
    pub verified_seq: u64,
}

/// Why [`Store::verify_for_deletion`] did not confirm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeletionDenied {
    /// The destination is copy-only.
    #[error("final move is not available: {0}")]
    Unsupported(CopyOnlyReason),
    /// The destination could not be examined right now.
    #[error("the destination cannot be examined: {0}")]
    DestinationUnavailable(String),
    /// The volume behind the destination is not the one the store was opened on.
    #[error("the destination volume changed since the store was opened")]
    VolumeChanged,
    /// Final move is blocked until someone clears the block.
    #[error("final move is blocked: {}", .0.reason)]
    Blocked(BlockInfo),
    /// The ledger failed or is damaged.
    #[error("the ledger cannot be relied on: {0}")]
    Ledger(#[source] LedgerError),
    /// The device is not registered with this store.
    #[error("the device {0:?} is not registered")]
    UnknownDevice(String),
    /// The device was unpaired. Its files are kept, but nothing is confirmed
    /// to it until it is paired again.
    #[error("the device {0:?} is unpaired")]
    DeviceDetached(String),
    /// The clock reads earlier than a time already recorded.
    #[error("the clock went backwards (now {now_unix_ms}, already recorded {last_seen_unix_ms})")]
    ClockWentBackwards {
        /// Current wall-clock time.
        now_unix_ms: i64,
        /// Latest time found in the ledger.
        last_seen_unix_ms: i64,
    },
    /// The wall clock says the file is old enough, but the file was stored
    /// while this program was running and less real time than that has
    /// passed since: the clock was set ahead.
    #[error(
        "the clock says {wall_age_secs} s have passed since the commit, but at most \
         {real_age_at_most_secs} s really have"
    )]
    ClockDisagrees {
        /// Age of the commit by the wall clock.
        wall_age_secs: i64,
        /// The most real time that can have passed since the commit.
        real_age_at_most_secs: u64,
    },
    /// This device has no record with this item key, hash, size and commit
    /// number.
    #[error("this device has no such record")]
    NoRecord,
    /// The PC user acknowledged that this file was removed from the PC. This
    /// is an answer, not an alarm.
    #[error("the file was removed from the PC by its user")]
    RemovedByUser,
    /// The file has not been stored for long enough.
    #[error(
        "stored too recently: committed in session {committed_session} (now {current_session}, {sessions_required} \
         later required), {age_secs} s ago ({age_secs_required} s required)"
    )]
    TooRecent {
        /// Session of the commit.
        committed_session: u64,
        /// The current session.
        current_session: u64,
        /// Sessions that must lie between them.
        sessions_required: u64,
        /// Wall-clock seconds since the commit (negative if the clock is off).
        age_secs: i64,
        /// Wall-clock seconds required.
        age_secs_required: u64,
    },
    /// The stored copy could not be confirmed by reading it back.
    #[error("the stored copy could not be verified: {0}")]
    NotVerified(NotVerifiedReason),
}

/// Result of reading a recorded file back from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe {
    Match {
        unbuffered: bool,
    },
    Missing,
    Changed(String),
    /// Could not be read for a reason that says nothing about the disk (in
    /// use, access denied).
    Unreadable(String),
    /// Could not be read because the disk returned an error.
    IoError(String),
    Reparse(PathBuf),
    NotLocal,
    InvalidRecord,
    Interrupted,
}

impl Probe {
    pub(crate) fn reason(&self) -> NotVerifiedReason {
        match self {
            Probe::Match { .. } => NotVerifiedReason::BufferedReadOnly,
            Probe::Missing => NotVerifiedReason::Missing,
            Probe::Changed(how) => NotVerifiedReason::Changed(how.clone()),
            Probe::Unreadable(why) | Probe::IoError(why) => {
                NotVerifiedReason::Unreadable(why.clone())
            }
            Probe::Reparse(p) => NotVerifiedReason::ReparsePoint(p.clone()),
            Probe::NotLocal => NotVerifiedReason::NotLocal,
            Probe::InvalidRecord => NotVerifiedReason::InvalidRecord,
            Probe::Interrupted => {
                NotVerifiedReason::Unreadable("the read was interrupted".to_owned())
            }
        }
    }

    fn unreadable(e: &std::io::Error) -> Probe {
        if is_hard_io_error(e) {
            Probe::IoError(e.to_string())
        } else {
            Probe::Unreadable(e.to_string())
        }
    }
}

impl Inner {
    /// Reads a recorded file back from the destination and compares it with
    /// its record.
    ///
    /// `on_chunk` is called with the size of each chunk read and may stop the
    /// read (rate limiting and cancellation live there).
    pub(crate) fn probe(
        &self,
        rec: &FileRecord,
        on_chunk: &mut dyn FnMut(usize) -> ControlFlow<()>,
    ) -> Probe {
        self.probe_at(
            self.root(),
            &rec.rel_path,
            rec.size,
            &rec.hash,
            &mut |chunk| on_chunk(chunk.len()),
        )
    }

    /// Reads the file `rel_path` under `root` (the destination or a mirror)
    /// from the device and compares it with the size and hash it should have.
    ///
    /// `on_chunk` receives every chunk as it is read, so the caller can copy
    /// the very bytes that are being verified. What it has received counts
    /// for something only if the result is [`Probe::Match`].
    pub(crate) fn probe_at(
        &self,
        root: &Path,
        rel_path: &str,
        size: u64,
        hash: &ContentHash,
        on_chunk: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Probe {
        // The path comes from the ledger, which is not trusted: it must be
        // exactly what the sanitiser would produce, or it is not used at all.
        let Some(rel) = SafeRelPath::from_stored(rel_path) else {
            return Probe::InvalidRecord;
        };
        let Some(file_name) = rel.file_name() else {
            return Probe::InvalidRecord;
        };

        // Every directory on the way must be a real directory.
        let mut path = root.to_path_buf();
        for part in rel.parent().components() {
            path.push(part.as_str());
            match self.fs.stat(&path) {
                Err(e) => return Probe::unreadable(&e),
                Ok(None) => return Probe::Missing,
                Ok(Some(s)) if s.reparse => return Probe::Reparse(path),
                Ok(Some(s)) if s.kind != EntryKind::Dir => return Probe::Missing,
                Ok(Some(_)) => {}
            }
        }
        path.push(file_name.as_str());
        match self.fs.stat(&path) {
            Err(e) => return Probe::unreadable(&e),
            Ok(None) => return Probe::Missing,
            Ok(Some(s)) if s.reparse => return Probe::Reparse(path),
            Ok(Some(s)) if s.kind != EntryKind::File => {
                return Probe::Changed("the path is no longer a regular file".to_owned())
            }
            Ok(Some(s)) if s.offline => return Probe::NotLocal,
            Ok(Some(s)) if s.size != size => {
                return Probe::Changed(format!("its size is {} bytes instead of {size}", s.size))
            }
            Ok(Some(_)) => {}
        }

        let mut hasher = blake3::Hasher::new();
        let read = self.fs.read_verify(&path, &mut |chunk| {
            hasher.update(chunk);
            on_chunk(chunk)
        });
        match read {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Probe::Missing,
            Err(e) => Probe::unreadable(&e),
            Ok(r) if !r.completed => Probe::Interrupted,
            Ok(r) if r.bytes != size => {
                Probe::Changed(format!("its size is {} bytes instead of {size}", r.bytes))
            }
            Ok(r) => {
                let on_disk = ContentHash::from(hasher.finalize());
                if on_disk != *hash {
                    return Probe::Changed(format!(
                        "its content hashes to {on_disk} instead of {hash}"
                    ));
                }
                // The content is right. Make sure it was read from where the
                // record says it is: ask the operating system where the path
                // really leads. The per-directory check above cannot see a
                // link that was swapped in a moment later, or a short (8.3)
                // name standing in for another folder.
                match self.fs.resolve(&path) {
                    Ok(resolved) if is_where_expected(root, &resolved, &rel) => Probe::Match {
                        unbuffered: r.unbuffered,
                    },
                    Ok(resolved) => Probe::Reparse(resolved),
                    Err(e) => Probe::unreadable(&e),
                }
            }
        }
    }

    /// Brings the ledger in line with what a probe found, and applies the
    /// block policy. Only a *new* finding blocks: a file already known to be
    /// missing or changed does not block again after the block was cleared.
    pub(crate) fn apply_probe(&self, rec: &FileRecord, probe: &Probe) -> Result<(), LedgerError> {
        let now = self.now();
        match probe {
            Probe::Match { .. } => {
                if rec.state != FileState::Committed {
                    self.ledger.set_state(
                        rec.id,
                        FileState::Committed,
                        "found intact again",
                        now,
                    )?;
                }
            }
            Probe::Missing => {
                let newly = self
                    .ledger
                    .set_state(rec.id, FileState::Missing, "the file is gone", now)?
                    .is_some();
                if newly && self.cfg.scan_policy.block_on_missing {
                    let reason = format!("a stored file is missing: {}", rec.rel_path);
                    self.ledger
                        .block(BlockKind::IntegrityProblems, &reason, now)?;
                }
            }
            Probe::Changed(how) => {
                if self
                    .ledger
                    .set_state(rec.id, FileState::Changed, how, now)?
                    .is_some()
                {
                    let reason = format!("a stored file was changed: {} ({how})", rec.rel_path);
                    self.ledger
                        .block(BlockKind::IntegrityProblems, &reason, now)?;
                }
            }
            Probe::Reparse(path) => {
                let reason = format!(
                    "a link or junction was found inside the destination: {}",
                    path.display()
                );
                self.ledger
                    .block(BlockKind::IntegrityProblems, &reason, now)?;
            }
            Probe::InvalidRecord => {
                let reason = format!(
                    "the ledger holds an invalid path for file record {}",
                    rec.id
                );
                self.ledger
                    .block(BlockKind::IntegrityProblems, &reason, now)?;
            }
            // A device error while reading a stored file: the disk is failing.
            Probe::IoError(why) => {
                let reason = format!(
                    "a disk may be failing: reading {} returned an error ({why})",
                    rec.rel_path
                );
                self.ledger.block(BlockKind::DiskFailing, &reason, now)?;
            }
            Probe::Unreadable(_) | Probe::NotLocal | Probe::Interrupted => {}
        }
        Ok(())
    }

    pub(crate) fn stored_file(&self, rec: &FileRecord, unbuffered: bool) -> StoredFile {
        let abs_path = match SafeRelPath::from_stored(&rec.rel_path) {
            Some(rel) => rel.under(self.root()),
            None => PathBuf::new(),
        };
        StoredFile {
            file_id: rec.id,
            device: rec.device.clone(),
            rel_path: rec.rel_path.clone(),
            abs_path,
            hash: rec.hash,
            size: rec.size,
            commit_seq: rec.commit_no,
            committed_session: rec.committed_session,
            committed_unix_ms: rec.committed_unix_ms,
            read_unbuffered: unbuffered,
        }
    }

    /// Looks for a file this device answers for, with this hash, that
    /// verifies from disk.
    ///
    /// A successful check writes nothing to the ledger (this is called once
    /// per file of the phone's library at the start of every transfer; a
    /// synchronous ledger write each time would cost more than the read).
    /// Findings do: a file found missing, changed or restored is recorded.
    fn verify_by_hash(&self, device: &str, hash: &ContentHash) -> Result<StoredStatus, StoreError> {
        // A device the store does not know has no records: the answer is
        // simply "no record".
        let mut candidates = self.ledger.device_files_by_hash(device, hash)?;
        // Try the ones believed intact first.
        candidates.sort_by_key(|r| (r.state != FileState::Committed, r.committed_seq));
        let mut reason = NotVerifiedReason::NoRecord;
        for rec in &candidates {
            let probe = self.probe(rec, &mut |_| ControlFlow::Continue(()));
            self.apply_probe(rec, &probe)?;
            match probe {
                Probe::Match { unbuffered } => {
                    return Ok(StoredStatus::Verified(self.stored_file(rec, unbuffered)));
                }
                other => reason = other.reason(),
            }
        }
        Ok(StoredStatus::NotVerified(reason))
    }

    /// The most real time (in seconds) that can have passed since a commit,
    /// if the commit happened while this process was running. `None` for
    /// commits of earlier runs, about which this process knows nothing.
    fn real_age_at_most_secs(&self, device: &str, committed_seq: u64) -> Option<u64> {
        if committed_seq <= self.open_mark.start_seq {
            return None;
        }
        // The commit came after the start of the device's latest session that
        // began before it (or, failing that, after this process opened the
        // store); no more time than that has passed.
        let begun = lock(&self.device_marks)
            .get(device)
            .and_then(|marks| marks.iter().rev().find(|m| m.start_seq < committed_seq))
            .copied()
            .unwrap_or(self.open_mark);
        let elapsed_ms = self.clock.monotonic_ms().saturating_sub(begun.monotonic_ms);
        Some(elapsed_ms / 1_000)
    }
}

/// Whether a fully resolved path is `root` plus exactly the components of
/// `rel`, compared the way the file system compares names.
fn is_where_expected(root: &Path, resolved: &Path, rel: &SafeRelPath) -> bool {
    let Ok(below) = resolved.strip_prefix(root) else {
        return false;
    };
    let actual: Vec<_> = below.components().collect();
    actual.len() == rel.depth()
        && actual.iter().zip(rel.components()).all(|(got, want)| {
            got.as_os_str()
                .to_str()
                .is_some_and(|name| crate::sanitize::collision_key(name) == want.collision_key())
        })
}

impl Store {
    /// Deduplication: has this device already stored a file with this content?
    ///
    /// Only the device's own records count: the files it committed and its
    /// claims on shared files. What another device stored is not a duplicate
    /// for this one; it sends the file, and if the same bytes land on the
    /// same path they are not stored twice (see
    /// [`CommitOutcome::AlreadyPresent`](super::CommitOutcome::AlreadyPresent)).
    ///
    /// A ledger hit is only a hint. The candidate file is re-read from disk
    /// and re-hashed; `Some` is returned only if that hash matches. A
    /// candidate that turns out to be missing or changed is marked as such
    /// (and blocks final move), and the answer is `None`: the caller should
    /// then transfer the file.
    pub fn find_duplicate(
        &self,
        device: &DeviceId,
        hash: &ContentHash,
    ) -> Result<Option<StoredFile>, StoreError> {
        match self.inner.verify_by_hash(device.as_str(), hash)? {
            StoredStatus::Verified(file) => Ok(Some(file)),
            StoredStatus::NotVerified(_) => Ok(None),
        }
    }

    /// Is a file with this content, stored for this device, safely on disk
    /// right now?
    ///
    /// [`StoredStatus::Verified`] means: a file this device answers for,
    /// recorded with this hash, was just read back from disk in full and its
    /// BLAKE3 hash matched. Anything else (no record for this device, file
    /// gone, file different, file unreadable) is
    /// [`StoredStatus::NotVerified`]. The ledger alone never produces
    /// `Verified`, and neither does another device's copy.
    ///
    /// This is weaker than [`Store::verify_for_deletion`]: it does not look at
    /// the kind of volume, at how long the file has been stored, or at the
    /// final-move block.
    pub fn is_safely_stored(
        &self,
        device: &DeviceId,
        hash: &ContentHash,
    ) -> Result<StoredStatus, StoreError> {
        self.inner.verify_by_hash(device.as_str(), hash)
    }

    /// The delayed second verification that gates deleting the phone's copy.
    ///
    /// Returns a [`DeletionProof`] only if **all** of the following hold:
    ///
    /// 1. the destination, examined again right now, is a fixed internal
    ///    NTFS/ReFS volume, outside any cloud-synced or system-managed
    ///    folder, writable by this account only, and it is the volume the
    ///    store was opened on;
    /// 2. final move is not blocked;
    /// 3. the device is registered and paired;
    /// 4. the clock does not read earlier than a time already in the ledger;
    /// 5. **this device** has a record with exactly this item key, hash, size
    ///    and commit number, the PC user has not acknowledged it as removed,
    ///    and the file it names lies inside this device's own folder;
    /// 6. that record was committed in an **earlier session of this device**:
    ///    at least `min_age_sessions` (and at least 1) sessions of the device
    ///    ago, before the device's current session began by event sequence
    ///    number, **and** at least 24 hours ago by the clock; and if the
    ///    commit happened while this program was running, the time that has
    ///    really passed since does not contradict the clock;
    /// 7. that file, read back from the device just now with an unbuffered
    ///    read, has that size and hashes to that hash, and its name is
    ///    flushed to the device;
    /// 8. the ledger recorded the verification, in a flushed transaction of
    ///    its own, before the answer is given. The file is then marked "may
    ///    be the only copy" ([`FmState::Reverified`]).
    ///
    /// The proof in the answer is `MAC(proof_key, content)` computed from the
    /// bytes of the read in step 7, in the same pass. Nothing is answered
    /// from the ledger, from a cache, from an earlier result, from a mirror,
    /// or from a file of another device.
    ///
    /// A commit number above the device's high-water mark proves that the
    /// ledger was rolled back: final move is blocked (see
    /// [`Store::check_peer_commit_seq`]).
    ///
    /// The store's delay rule is its own. The transfer layer has a second
    /// clock (the link clock, kept with the phone); both must agree before a
    /// phone deletes anything.
    ///
    /// Any doubt is a denial. A denial never deletes or changes anything.
    pub fn verify_for_deletion(
        &self,
        device: &DeviceId,
        req: &VerifyRequest<'_>,
    ) -> Result<DeletionProof, DeletionDenied> {
        let inner = &self.inner;
        let device = device.as_str();

        // 1. The destination, as it is now.
        let current = inner
            .dest
            .reprobe()
            .map_err(|e| DeletionDenied::DestinationUnavailable(e.to_string()))?;
        if let FinalMoveSupport::CopyOnly(reason) = current.final_move_support() {
            return Err(DeletionDenied::Unsupported(reason.clone()));
        }
        if current.volume().serial != inner.dest.volume().serial
            || current.volume().serial.is_none()
        {
            return Err(DeletionDenied::VolumeChanged);
        }

        // Nothing below may rest on a record that a power failure could
        // still take back.
        if inner.ledger.pending_batched() > 0 {
            inner
                .ledger
                .flush(inner.now())
                .map_err(DeletionDenied::Ledger)?;
            inner.write_witness();
        }

        // 2. The block.
        if let Some(block) = inner.ledger.block_info().map_err(DeletionDenied::Ledger)? {
            return Err(DeletionDenied::Blocked(block));
        }

        // 3. The device. (Checked after the block, so that a blocked store
        // says "blocked" to everyone, whoever asks.)
        let owner = match inner
            .ledger
            .device(device)
            .map_err(DeletionDenied::Ledger)?
        {
            None => return Err(DeletionDenied::UnknownDevice(device.to_owned())),
            Some(d) if d.detached => return Err(DeletionDenied::DeviceDetached(d.device_id)),
            Some(d) => d,
        };

        // 4. The clock.
        let now = inner.now();
        let last_seen = inner
            .ledger
            .max_seen_unix_ms()
            .map_err(DeletionDenied::Ledger)?;
        if now < last_seen {
            return Err(DeletionDenied::ClockWentBackwards {
                now_unix_ms: now,
                last_seen_unix_ms: last_seen,
            });
        }

        // 5. The record: this device's, and exactly the one the phone names.
        if req.commit_seq > owner.commit_hwm {
            // The phone holds a receipt this ledger never issued.
            let block = inner
                .rolled_back(device, req.commit_seq, owner.commit_hwm)
                .map_err(DeletionDenied::Ledger)?;
            return Err(DeletionDenied::Blocked(block));
        }
        let Some(rec) = inner
            .ledger
            .device_record(device, req.key, &req.hash, req.size, req.commit_seq)
            .map_err(DeletionDenied::Ledger)?
        else {
            return Err(DeletionDenied::NoRecord);
        };
        if rec.fm == FmState::UserRemoved {
            return Err(DeletionDenied::RemovedByUser);
        }
        // The file must lie inside this device's own folder. A record that
        // says otherwise is damage, and is treated as such.
        let in_own_folder = SafeRelPath::from_stored(&rec.rel_path).is_some_and(|rel| {
            rel.depth() >= 2
                && rel.components()[0].collision_key()
                    == crate::sanitize::collision_key(&owner.folder_name)
        });
        if !in_own_folder {
            inner
                .apply_probe(&rec, &Probe::InvalidRecord)
                .map_err(DeletionDenied::Ledger)?;
            return Err(DeletionDenied::NotVerified(
                NotVerifiedReason::InvalidRecord,
            ));
        }

        // 6. Old enough, by this device's sessions and by the clock.
        let sessions_required = u64::from(req.min_age_sessions.max(1));
        let age_secs_required = inner.cfg.min_wall_age_secs.max(MIN_WALL_AGE_SECS);
        let sessions_elapsed = owner.session_seq.saturating_sub(rec.committed_session);
        let age_secs = now.saturating_sub(rec.committed_unix_ms).div_euclid(1_000);
        let old_enough = rec.committed_session < owner.session_seq
            && sessions_elapsed >= sessions_required
            && rec.committed_seq < owner.session_start_seq
            && age_secs >= 0
            && age_secs as u64 >= age_secs_required;
        if !old_enough {
            return Err(DeletionDenied::TooRecent {
                committed_session: rec.committed_session,
                current_session: owner.session_seq,
                sessions_required,
                age_secs,
                age_secs_required,
            });
        }
        // The wall clock says enough time has passed. If the file was stored
        // while this process was running, the process knows how much time
        // can really have passed, and a clock that was set ahead does not
        // get past that.
        if let Some(at_most) = inner.real_age_at_most_secs(device, rec.committed_seq) {
            if at_most < age_secs_required {
                return Err(DeletionDenied::ClockDisagrees {
                    wall_age_secs: age_secs,
                    real_age_at_most_secs: at_most,
                });
            }
        }

        // 7. One unbuffered pass over the file: the hash that is compared
        // with the record, and the keyed proof, from the same bytes.
        let mut mac = blake3::Hasher::new_keyed(&req.proof_key);
        let probe = inner.probe_at(
            inner.root(),
            &rec.rel_path,
            rec.size,
            &rec.hash,
            &mut |chunk| {
                mac.update(chunk);
                ControlFlow::Continue(())
            },
        );
        inner
            .apply_probe(&rec, &probe)
            .map_err(DeletionDenied::Ledger)?;
        match probe {
            Probe::Match { unbuffered: true } => {}
            other => return Err(DeletionDenied::NotVerified(other.reason())),
        }
        // A problem found a moment ago blocks this file too.
        if let Some(block) = inner.ledger.block_info().map_err(DeletionDenied::Ledger)? {
            return Err(DeletionDenied::Blocked(block));
        }
        // The name the file was read under must be on the device, not only
        // in the cache. If that flush did not succeed when the file was
        // stored, it has to succeed now.
        if !rec.dir_synced {
            if let Err(why) = inner.flush_name(&rec) {
                return Err(DeletionDenied::NotVerified(
                    NotVerifiedReason::NameNotFlushed(why),
                ));
            }
            inner
                .ledger
                .set_dir_synced(rec.id, inner.now())
                .map_err(DeletionDenied::Ledger)?;
        }

        // 8. No flushed record of the verification, no proof. One
        // transaction per confirmation; never batched.
        let verified_seq = inner
            .ledger
            .mark_reverified(rec.id, device, inner.now())
            .map_err(DeletionDenied::Ledger)?;
        let copies = 1 + inner
            .ledger
            .mirror_copies_of(rec.id)
            .map_err(DeletionDenied::Ledger)?;
        Ok(DeletionProof {
            file: inner.stored_file(&rec, true),
            proof: *mac.finalize().as_bytes(),
            copies,
            sessions_elapsed,
            age_secs: age_secs as u64,
            verified_seq,
        })
    }
}

impl Inner {
    /// Flushes a stored file under its recorded name, and its directory.
    fn flush_name(&self, rec: &FileRecord) -> Result<(), String> {
        let rel = SafeRelPath::from_stored(&rec.rel_path)
            .ok_or_else(|| "the ledger record is invalid".to_owned())?;
        let path = rel.under(self.root());
        self.fs.sync_file(&path).map_err(|e| e.to_string())?;
        self.fs
            .sync_dir(&rel.parent().under(self.root()))
            .map_err(|e| e.to_string())
    }
}
