//! Receiving one file from a phone.
//!
//! ```text
//! begin_file   sanitise name -> render layout -> quota -> free space
//!              -> walk/create directories (no reparse points) -> create temp
//! write        temp file  +  incremental BLAKE3 of the bytes received
//! finish       size == declared?            stream hash == sender's hash?
//!              set mtime -> flush to device -> close
//!              reopen UNBUFFERED, re-hash from disk
//!              disk hash == stream hash == sender's hash?   (else delete temp)
//!              rename, no replace                            (collision -> " (2)")
//!              flush the file under its new name -> flush the directory
//!              re-read the file under its new name: there, and still right?
//!              record in ledger -> receipt
//! ```
//!
//! The steps themselves live in [`super::pipeline`], which the mirror uses too.
//!
//! Invariants, whatever fails and wherever:
//!
//! * a file only ever gets its final name after its content has been read
//!   back from the device and matched both hashes;
//! * an existing file is never replaced or modified;
//! * the only files the engine deletes are its own temp files;
//! * an error from `finish` means there is no ledger record.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;

use super::pipeline::{Adoption, PlaceRequest, Placed, TempSlot, PRIMARY};
use super::{lock, DeviceId, Inner, Store, MAX_PATH_UTF16, TEMP_PREFIX};
use crate::error::{QuotaKind, StoreError};
use crate::fsops::Checkpoint;
use crate::hash::ContentHash;
use crate::ledger::{FileState, NewFile};
use crate::sanitize::{sanitize_rel_path, utf16_len, SafeName, SafeRelPath, NEUTRAL_SUFFIX};
use crate::template::{CaptureTime, CivilDate, TemplateContext};

/// One file the peer wants to store.
#[derive(Debug, Clone, Copy)]
pub struct FileRequest<'a> {
    /// The paired device sending the file. Must be registered.
    pub device: &'a DeviceId,
    /// The file's relative path as the peer names it, e.g.
    /// `DCIM/Camera/IMG_0001.jpg`. Untrusted; sanitised here.
    pub name: &'a str,
    /// Exact size in bytes. Writing more or fewer bytes fails the file.
    pub size: u64,
    /// The hash the sender claims, if it is known before the transfer. It may
    /// instead (or also) be given to [`IncomingFile::finish`].
    pub claimed_hash: Option<ContentHash>,
    /// When the photo was taken, if the caller knows (EXIF, MediaStore).
    /// Used only to choose the folder. Falls back to `mtime_unix_ns`.
    pub capture_time: Option<CaptureTime>,
    /// Modification time to give the stored file (Unix nanoseconds).
    pub mtime_unix_ns: Option<i64>,
}

/// How a commit ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The received bytes are now a new file.
    Stored,
    /// A file with exactly this content was already at the target path (it
    /// was re-read from disk to make sure). The received copy was discarded.
    AlreadyPresent,
}

/// Proof that [`IncomingFile::finish`] completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Whether a new file was created.
    pub outcome: CommitOutcome,
    /// Ledger row of the file.
    pub file_id: i64,
    /// Path relative to the destination root, `/`-separated. May differ from
    /// the requested name (sanitising, collision suffix, layout, a
    /// neutralised extension).
    pub rel_path: String,
    /// Absolute path.
    pub abs_path: PathBuf,
    /// Content hash (equal to the sender's claim).
    pub hash: ContentHash,
    /// Size in bytes.
    pub size: u64,
    /// The sending device's commit sequence number for the file: the number
    /// of the ledger event that recorded it for this device.
    pub seq: u64,
    /// Session in which the file was recorded for this device.
    pub session: u64,
    /// The ledger record had been flushed to the device when this receipt was
    /// made. Always true for [`IncomingFile::finish`]. After
    /// [`IncomingFile::finish_batched`] it is false until
    /// [`Store::flush_batch`] returns: do not acknowledge the file to the
    /// phone before that.
    pub durable: bool,
    /// The flush of the file under its final name and of its directory both
    /// succeeded.
    pub dir_synced: bool,
    /// The read-back bypassed the operating system's cache.
    pub verified_unbuffered: bool,
    /// The requested modification time was applied.
    pub mtime_applied: bool,
    /// The file's type is shell-active; it was stored with
    /// [`NEUTRAL_SUFFIX`] appended to its name.
    pub neutralised: bool,
}

/// What a live writer has been promised: released when the writer goes away,
/// on success and on every error path alike.
struct Reservation {
    inner: Arc<Inner>,
    device: String,
    declared: u64,
    written: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.inner.in_flight);
        in_flight.bytes_remaining = in_flight
            .bytes_remaining
            .saturating_sub(self.declared.saturating_sub(self.written));
        if let Some(entry) = in_flight.per_device.get_mut(&self.device) {
            entry.0 = entry.0.saturating_sub(self.declared);
            entry.1 = entry.1.saturating_sub(1);
            if *entry == (0, 0) {
                in_flight.per_device.remove(&self.device);
            }
        }
    }
}

struct ActiveFile {
    // Field order matters: the temp file goes (and with it the bytes on
    // disk) before the reservation that accounted for them is released.
    slot: TempSlot,
    reservation: Reservation,
    claimed: Option<ContentHash>,
    name: SafeName,
    source_name: String,
    mtime_unix_ns: Option<i64>,
}

/// A file being received. Created by [`Store::begin_file`].
///
/// Dropping it without calling [`IncomingFile::finish`] discards everything
/// received so far.
pub struct IncomingFile {
    active: Option<ActiveFile>,
}

impl std::fmt::Debug for IncomingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.active {
            Some(a) => f
                .debug_struct("IncomingFile")
                .field("source_name", &a.source_name)
                .field("written", &a.slot.written())
                .field("declared", &a.reservation.declared)
                .finish(),
            None => f.write_str("IncomingFile(closed)"),
        }
    }
}

impl Store {
    /// Starts receiving one file.
    ///
    /// Nothing is written unless every check passes: the device is paired,
    /// the name is safe, the device is within its limits, the file (plus
    /// everything else in flight plus the safety margin) fits on the volume,
    /// and no reparse point lies between the root and the target directory.
    pub fn begin_file(&self, req: FileRequest<'_>) -> Result<IncomingFile, StoreError> {
        let inner = &self.inner;
        let unsafe_name = |source| StoreError::UnsafeName {
            name: req.name.chars().take(200).collect(),
            source,
        };

        let device = inner
            .ledger
            .device(req.device.as_str())?
            .ok_or_else(|| StoreError::UnknownDevice(req.device.as_str().to_owned()))?;
        if device.detached {
            return Err(StoreError::DeviceDetached(device.device_id));
        }
        let device_folder = SafeName::from_stored(&device.folder_name).ok_or_else(|| {
            StoreError::Ledger(crate::error::LedgerError::Corrupt {
                path: inner.ledger.path().to_path_buf(),
                detail: format!("device {} has an invalid folder name", device.device_id),
            })
        })?;

        // Where it goes.
        let source = sanitize_rel_path(req.name).map_err(unsafe_name)?;
        let name = source
            .file_name()
            .expect("a sanitised path is never empty")
            .clone();
        let phone_dir = source.parent();
        let date = req
            .capture_time
            .or_else(|| {
                req.mtime_unix_ns
                    .map(|ns| CaptureTime::utc(ns.div_euclid(1_000_000_000)))
            })
            .and_then(CivilDate::from_capture_time);
        let dir_rel = inner
            .cfg
            .layout
            .render(&TemplateContext {
                device_folder: &device_folder,
                date,
                phone_dir: &phone_dir,
            })
            .map_err(unsafe_name)?;

        let root_len = utf16_len(&inner.dest.display_root());
        let longest_name =
            (name.utf16_len() + utf16_len(NEUTRAL_SUFFIX)).max(TEMP_PREFIX.len() + 64);
        let path_len = root_len + 1 + dir_rel.utf16_len() + 1 + longest_name;
        if path_len > MAX_PATH_UTF16 {
            return Err(StoreError::PathTooLong {
                utf16_len: path_len,
                max: MAX_PATH_UTF16,
            });
        }

        // Limits. The reservation is taken under the same lock as the check,
        // so concurrent files cannot each pass on their own and overshoot
        // together.
        {
            let mut in_flight = lock(&inner.in_flight);
            let (flying_bytes, flying_files) = in_flight
                .per_device
                .get(&device.device_id)
                .copied()
                .unwrap_or((0, 0));
            let quota = |kind, allowed, requested| StoreError::QuotaExceeded {
                device: device.device_id.clone(),
                kind,
                allowed,
                requested,
            };
            if let Some(max) = device.limits.max_file_bytes {
                if req.size > max {
                    return Err(quota(QuotaKind::FileBytes, max, req.size));
                }
            }
            if let Some(max) = device.limits.max_files {
                let would_be = device
                    .used_files
                    .saturating_add(flying_files)
                    .saturating_add(1);
                if would_be > max {
                    return Err(quota(QuotaKind::FileCount, max, would_be));
                }
            }
            if let Some(max) = device.limits.max_total_bytes {
                let would_be = device
                    .used_bytes
                    .saturating_add(flying_bytes)
                    .saturating_add(req.size);
                if would_be > max {
                    return Err(quota(QuotaKind::TotalBytes, max, would_be));
                }
            }

            // Free space: this file, plus what the other live writers still
            // have to write, plus the margin, must fit.
            let available = inner
                .fs
                .free_space(inner.root())
                .map_err(|e| StoreError::io("measure free space on", inner.root(), e))?;
            let needed = req.size.saturating_add(in_flight.bytes_remaining);
            let margin = inner.cfg.safety_margin_bytes;
            if available < needed.saturating_add(margin) {
                return Err(StoreError::InsufficientSpace {
                    needed,
                    margin,
                    available,
                });
            }

            in_flight.bytes_remaining = in_flight.bytes_remaining.saturating_add(req.size);
            let entry = in_flight
                .per_device
                .entry(device.device_id.clone())
                .or_insert((0, 0));
            entry.0 = entry.0.saturating_add(req.size);
            entry.1 += 1;
        }

        // From here on the reservation is released when it is dropped, on
        // success and on every error path alike.
        let reservation = Reservation {
            inner: Arc::clone(inner),
            device: device.device_id.clone(),
            declared: req.size,
            written: 0,
        };
        let slot = TempSlot::create(inner, PRIMARY, inner.root(), &dir_rel)?;
        Ok(IncomingFile {
            active: Some(ActiveFile {
                slot,
                reservation,
                claimed: req.claimed_hash,
                name,
                source_name: source.to_slash_string(),
                mtime_unix_ns: req.mtime_unix_ns,
            }),
        })
    }
}

impl IncomingFile {
    /// Appends received bytes.
    ///
    /// On any error the file is abandoned: what was received is deleted and
    /// every later call returns [`StoreError::WriterClosed`].
    pub fn write(&mut self, data: &[u8]) -> Result<(), StoreError> {
        let active = self.active.as_mut().ok_or(StoreError::WriterClosed)?;
        let ActiveFile {
            slot, reservation, ..
        } = active;
        let declared = reservation.declared;
        let result = slot.write(data, declared, &mut |n| {
            reservation.written += n;
            let mut in_flight = lock(&reservation.inner.in_flight);
            in_flight.bytes_remaining = in_flight.bytes_remaining.saturating_sub(n);
        });
        if result.is_err() {
            self.active = None;
        }
        result
    }

    /// Bytes received so far.
    pub fn bytes_written(&self) -> u64 {
        self.active.as_ref().map_or(0, |a| a.slot.written())
    }

    /// Discards everything received. Equivalent to dropping the value.
    pub fn abort(self) {}

    /// Leaves the temp file on disk and forgets about it, as a process that
    /// was killed at this point would. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn simulate_crash(mut self) -> Option<PathBuf> {
        let mut active = self.active.take()?;
        Some(active.slot.leak())
    }

    /// Completes the file: verifies it, gives it its final name and records it.
    ///
    /// `claimed_hash` is the hash the sender claims for the file. It is
    /// required either here or in the [`FileRequest`]; if both are given they
    /// must agree.
    ///
    /// On success the file is on disk under [`CommitReceipt::rel_path`], its
    /// content read back from the device matched both the received stream and
    /// the sender's claim (before the rename, and again under the final
    /// name), and the ledger has a flushed record of it. On any error nothing
    /// was recorded.
    ///
    /// An error after the rename can leave the (complete) file behind under
    /// its final name: a failure to confirm it there, or to write the ledger
    /// record. The file is then simply an unrecorded file; sending it again
    /// finds it and, if it is intact, records it
    /// ([`CommitOutcome::AlreadyPresent`]) instead of storing a second copy.
    pub fn finish(self, claimed_hash: Option<ContentHash>) -> Result<CommitReceipt, StoreError> {
        self.finish_with(claimed_hash, true)
    }

    /// Like [`IncomingFile::finish`], except that the ledger record is not
    /// flushed to the device before returning: the next
    /// [`Store::flush_batch`] (or any other flushed ledger write) does that
    /// for the whole batch at once. On a hard disk this saves one flush per
    /// file.
    ///
    /// **For plain copies only.** The file itself is written, flushed and
    /// verified exactly as with `finish`; what is deferred is only the
    /// durability of the ledger row. Until the flush, a power failure may
    /// forget the row (the file stays on disk and is recorded when it is sent
    /// again), so:
    ///
    /// * do not acknowledge the file to the phone before
    ///   [`Store::flush_batch`] has returned;
    /// * nothing the phone deletes may depend on it. The engine itself makes
    ///   sure of that: [`Store::verify_for_deletion`] flushes the ledger
    ///   before it looks, and never confirms a file recorded in the session
    ///   that is still running.
    ///
    /// The receipt has [`CommitReceipt::durable`] set to `false`.
    pub fn finish_batched(
        self,
        claimed_hash: Option<ContentHash>,
    ) -> Result<CommitReceipt, StoreError> {
        self.finish_with(claimed_hash, false)
    }

    fn finish_with(
        mut self,
        claimed_hash: Option<ContentHash>,
        durable: bool,
    ) -> Result<CommitReceipt, StoreError> {
        // `active` cleans up after itself when dropped, which every early
        // return below relies on.
        let mut active = self.active.take().ok_or(StoreError::WriterClosed)?;
        let inner = Arc::clone(active.slot.inner());
        let declared = active.reservation.declared;
        let device = active.reservation.device.clone();

        if active.slot.written() != declared {
            return Err(StoreError::SizeMismatch {
                declared,
                received: active.slot.written(),
            });
        }
        let claimed = match (active.claimed, claimed_hash) {
            (Some(a), Some(b)) if a != b => return Err(StoreError::ConflictingSenderHashes),
            (Some(a), _) => a,
            (None, Some(b)) => b,
            (None, None) => return Err(StoreError::MissingSenderHash),
        };
        let stream_hash = active.slot.stream_hash();
        if stream_hash != claimed {
            return Err(StoreError::SenderHashMismatch {
                claimed,
                received: stream_hash,
            });
        }

        let mtime_applied = active.slot.seal(active.mtime_unix_ns)?;

        // Read it back from the device, not from the cache.
        let (disk_hash, read) = active.slot.read_back(&mut |_| ControlFlow::Continue(()))?;
        if !read.completed
            || read.bytes != declared
            || disk_hash != stream_hash
            || disk_hash != claimed
        {
            return Err(StoreError::DiskVerifyMismatch {
                expected: stream_hash,
                on_disk: disk_hash,
                expected_size: declared,
                on_disk_size: read.bytes,
            });
        }

        let base = active.name.clone();
        let placed = active.slot.place(&PlaceRequest {
            hash: &stream_hash,
            size: declared,
            // The collision suffix goes before the extension, the neutral
            // suffix after it: "a (2).url.kiwi-safe" restores to "a (2).url".
            name_for: &|n| base.with_collision_suffix(n).neutralised().0,
            // An identical file may be used unless the ledger knows the path
            // for other content (or under another spelling).
            may_adopt: &|rel: &SafeRelPath| {
                let record = inner.ledger.file_by_path_key(&rel.collision_key())?;
                Ok(match record {
                    Some(r) if r.hash != stream_hash || r.rel_path != rel.to_slash_string() => {
                        Adoption::No
                    }
                    other => Adoption::Yes(other),
                })
            },
            display_name: active.name.as_str(),
        })?;
        let (name, existing, dir_synced, verified_unbuffered, adopted) = match placed {
            Placed::Stored {
                name,
                dir_synced,
                unbuffered,
            } => (name, None, dir_synced, read.unbuffered && unbuffered, false),
            Placed::Adopted {
                name,
                record,
                unbuffered,
            } => (name, record, false, unbuffered, true),
        };
        let neutralised = active.name.neutralised().1;
        let rel = active.slot.dir_rel().join(name);
        let rel_path = rel.to_slash_string();
        let abs_path = rel.under(inner.root());

        inner
            .fs
            .checkpoint(Checkpoint::BeforeLedgerRecord)
            .map_err(|e| StoreError::io("record", &abs_path, e))?;

        let now = inner.now();
        let (record, record_durable) = match existing {
            Some(existing) => {
                // Already recorded with this content at this path, and just
                // re-read from disk: refresh what the ledger believes.
                if existing.state != FileState::Committed {
                    inner.ledger.set_state(
                        existing.id,
                        FileState::Committed,
                        "found intact while receiving the same content again",
                        now,
                    )?;
                }
                if existing.device == device {
                    inner.ledger.mark_verified(
                        existing.id,
                        "duplicate_received",
                        Some(&device),
                        now,
                    )?;
                    (existing, true)
                } else {
                    // Another device committed this file first. This device
                    // has now delivered the same bytes itself and they were
                    // compared with the file on disk: it gets a record of its
                    // own, which ages from now. Nothing recorded for the
                    // other device is ever used to answer for this one.
                    let (claim, new) = inner.ledger.record_claim(
                        &existing,
                        &device,
                        &active.source_name,
                        durable,
                        now,
                    )?;
                    if !new {
                        inner.ledger.mark_verified(
                            existing.id,
                            "duplicate_received",
                            Some(&device),
                            now,
                        )?;
                    }
                    (claim, durable || !new)
                }
            }
            None => {
                let record = inner.ledger.record_commit(
                    &NewFile {
                        device: &device,
                        rel_path: &rel_path,
                        path_key: &rel.collision_key(),
                        hash: stream_hash,
                        size: declared,
                        mtime_unix_ns: active.mtime_unix_ns,
                        source_name: &active.source_name,
                        dir_synced,
                        verified_unbuffered,
                        adopted,
                        partial: Some(active.slot.temp_rel()),
                        durable,
                    },
                    now,
                )?;
                active.slot.intent_closed();
                (record, durable)
            }
        };
        // The ledger now counts the file; only then is the reservation released.
        drop(active);

        Ok(CommitReceipt {
            outcome: if adopted {
                CommitOutcome::AlreadyPresent
            } else {
                CommitOutcome::Stored
            },
            file_id: record.id,
            rel_path,
            abs_path,
            hash: stream_hash,
            size: record.size,
            seq: record.committed_seq,
            session: record.committed_session,
            durable: record_durable,
            dir_synced,
            verified_unbuffered,
            mtime_applied: mtime_applied && !adopted,
            neutralised,
        })
    }
}
