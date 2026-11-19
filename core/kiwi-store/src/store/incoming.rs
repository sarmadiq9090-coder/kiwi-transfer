//! The durable commit pipeline for one incoming file.
//!
//! ```text
//! begin_file   sanitise name -> render layout -> quota -> free space
//!              -> walk/create directories (no reparse points) -> create temp
//! write        temp file  +  incremental BLAKE3 of the bytes received
//! finish       size == declared?            stream hash == sender's hash?
//!              set mtime -> flush to device -> close
//!              reopen UNBUFFERED, re-hash from disk
//!              disk hash == stream hash == sender's hash?   (else delete temp)
//!              rename, no replace, write-through            (collision -> " (2)")
//!              flush directory -> record in ledger -> receipt
//! ```
//!
//! Invariants, whatever fails and wherever:
//!
//! * a file only ever gets its final name after its content has been read
//!   back from the device and matched both hashes;
//! * an existing file is never replaced or modified;
//! * the only files the engine deletes are its own temp files;
//! * an error from `finish` means there is no ledger record.

use std::io;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::{lock, DeviceId, Inner, Store, MAX_PATH_UTF16, TEMP_PREFIX, TEMP_SUFFIX};
use crate::error::{QuotaKind, StoreError};
use crate::fsops::{Checkpoint, EntryKind, FileStat, TempFile};
use crate::hash::ContentHash;
use crate::ledger::{FileRecord, FileState, NewFile};
use crate::sanitize::{sanitize_rel_path, utf16_len, SafeName, SafeRelPath};
use crate::template::{CaptureTime, CivilDate, TemplateContext};

/// Most alternative names (` (2)`, ` (3)`, ...) tried before giving up.
const MAX_NAME_ATTEMPTS: u32 = 10_000;

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
    /// the requested name (sanitising, collision suffix, layout).
    pub rel_path: String,
    /// Absolute path.
    pub abs_path: PathBuf,
    /// Content hash (equal to the sender's claim).
    pub hash: ContentHash,
    /// Size in bytes.
    pub size: u64,
    /// Sequence number of the ledger event that recorded the file.
    pub seq: u64,
    /// Session in which the file was recorded.
    pub session: u64,
    /// The directory flush after the rename succeeded.
    pub dir_synced: bool,
    /// The read-back bypassed the operating system's cache.
    pub verified_unbuffered: bool,
    /// The requested modification time was applied.
    pub mtime_applied: bool,
}

struct ActiveFile {
    inner: Arc<Inner>,
    temp_path: PathBuf,
    temp: Option<Box<dyn TempFile>>,
    hasher: blake3::Hasher,
    written: u64,
    declared: u64,
    claimed: Option<ContentHash>,
    device: String,
    dir_rel: SafeRelPath,
    dir_abs: PathBuf,
    name: SafeName,
    source_name: String,
    mtime_unix_ns: Option<i64>,
    /// The temp file has been renamed into place and must not be deleted.
    renamed: bool,
    /// Crash simulation: leave the temp file behind.
    leak: bool,
}

impl Drop for ActiveFile {
    fn drop(&mut self) {
        // Close the handle first: an open handle would block the delete.
        self.temp = None;
        if !self.renamed && !self.leak {
            remove_temp(&self.inner, &self.temp_path);
        }
        let mut in_flight = lock(&self.inner.in_flight);
        in_flight.temps.remove(&self.temp_path);
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

/// Deletes one of the engine's own temp files. A scanner may hold the file
/// for a moment, so a refusal is retried briefly; what is left behind is
/// removed by the next recovery pass.
fn remove_temp(inner: &Inner, path: &std::path::Path) {
    debug_assert!(is_temp_name(
        &path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    for attempt in 0..3u64 {
        match inner.fs.remove_file(path) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(Duration::from_millis(30 * (attempt + 1))),
        }
    }
}

/// Whether `name` is one of the engine's temp-file names.
pub(crate) fn is_temp_name(name: &str) -> bool {
    name.len() > TEMP_PREFIX.len() + TEMP_SUFFIX.len()
        && name.starts_with(TEMP_PREFIX)
        && name.ends_with(TEMP_SUFFIX)
}

fn system_time_from_unix_ns(ns: i64) -> Option<SystemTime> {
    let magnitude = Duration::from_nanos(ns.unsigned_abs());
    if ns >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    }
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
                .field("written", &a.written)
                .field("declared", &a.declared)
                .finish(),
            None => f.write_str("IncomingFile(closed)"),
        }
    }
}

enum Placed {
    Stored {
        name: SafeName,
        dir_synced: bool,
    },
    Adopted {
        name: SafeName,
        record: Option<FileRecord>,
        unbuffered: bool,
    },
}

impl Store {
    /// Starts receiving one file.
    ///
    /// Nothing is written unless every check passes: the name is safe, the
    /// device is within its limits, the file (plus everything else in flight
    /// plus the safety margin) fits on the volume, and no reparse point lies
    /// between the root and the target directory.
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
        let path_len =
            root_len + 1 + dir_rel.utf16_len() + 1 + name.utf16_len().max(TEMP_PREFIX.len() + 64);
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

        // From here on the reservation is owned by `active` and is released
        // when it is dropped, on success and on every error path alike.
        let mut active = ActiveFile {
            inner: Arc::clone(inner),
            temp_path: PathBuf::new(),
            temp: None,
            hasher: blake3::Hasher::new(),
            written: 0,
            declared: req.size,
            claimed: req.claimed_hash,
            device: device.device_id.clone(),
            dir_rel: dir_rel.clone(),
            dir_abs: PathBuf::new(),
            name,
            source_name: source.to_slash_string(),
            mtime_unix_ns: req.mtime_unix_ns,
            renamed: true, // nothing to delete yet
            leak: false,
        };

        let (dir_abs, dir_actual) = inner
            .walk_dirs(&dir_rel, true)?
            .expect("walk_dirs(create) returns a path or an error");
        active.dir_abs = dir_abs;
        active.dir_rel = dir_actual;

        // Create the temp file next to the final target, under a fresh name.
        let mut attempts = 0;
        loop {
            let candidate = active.dir_abs.join(inner.temp_name());
            // Register before creating, so a recovery pass running right now
            // cannot mistake the new file for an orphan.
            lock(&inner.in_flight).temps.insert(candidate.clone());
            match inner.fs.create_temp(&candidate) {
                Ok(temp) => {
                    active.temp_path = candidate;
                    active.temp = Some(temp);
                    active.renamed = false;
                    break;
                }
                Err(e) => {
                    lock(&inner.in_flight).temps.remove(&candidate);
                    attempts += 1;
                    if e.kind() != io::ErrorKind::AlreadyExists || attempts >= 8 {
                        return Err(StoreError::write("create the temp file", candidate, e));
                    }
                }
            }
        }

        // The directory was checked before the file was created. Check again
        // through the file itself: it must be exactly where it was put. This
        // closes the window in which a directory on the way could have been
        // swapped for a link between the check and the create.
        let resolved = inner
            .fs
            .resolve(&active.temp_path)
            .map_err(|e| StoreError::io("resolve", &active.temp_path, e))?;
        if resolved != active.temp_path {
            return Err(StoreError::PathMismatch {
                expected: active.temp_path.clone(),
                resolved,
            });
        }
        Ok(IncomingFile {
            active: Some(active),
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
        let result = write_all(active, data);
        if result.is_err() {
            self.active = None;
        }
        result
    }

    /// Bytes received so far.
    pub fn bytes_written(&self) -> u64 {
        self.active.as_ref().map_or(0, |a| a.written)
    }

    /// Discards everything received. Equivalent to dropping the value.
    pub fn abort(self) {}

    /// Leaves the temp file on disk and forgets about it, as a process that
    /// was killed at this point would. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn simulate_crash(mut self) -> Option<PathBuf> {
        let mut active = self.active.take()?;
        active.leak = true;
        Some(active.temp_path.clone())
    }

    /// Completes the file: verifies it, gives it its final name and records it.
    ///
    /// `claimed_hash` is the hash the sender claims for the file. It is
    /// required either here or in the [`FileRequest`]; if both are given they
    /// must agree.
    ///
    /// On success the file is on disk under [`CommitReceipt::rel_path`], its
    /// content read back from the device matched both the received stream and
    /// the sender's claim, and the ledger has a record of it. On any error the
    /// received bytes are deleted and nothing was recorded.
    ///
    /// One error can leave a (complete, verified) file behind: a failure to
    /// write the ledger record after the rename. The file is then simply an
    /// unrecorded file; sending it again finds it and records it
    /// ([`CommitOutcome::AlreadyPresent`]) instead of storing a second copy.
    pub fn finish(
        mut self,
        claimed_hash: Option<ContentHash>,
    ) -> Result<CommitReceipt, StoreError> {
        // `active` cleans up after itself when dropped, which every early
        // return below relies on.
        let mut active = self.active.take().ok_or(StoreError::WriterClosed)?;
        let inner = Arc::clone(&active.inner);

        if active.written != active.declared {
            return Err(StoreError::SizeMismatch {
                declared: active.declared,
                received: active.written,
            });
        }
        let claimed = match (active.claimed, claimed_hash) {
            (Some(a), Some(b)) if a != b => return Err(StoreError::ConflictingSenderHashes),
            (Some(a), _) => a,
            (None, Some(b)) => b,
            (None, None) => return Err(StoreError::MissingSenderHash),
        };
        let stream_hash = ContentHash::from(active.hasher.finalize());
        if stream_hash != claimed {
            return Err(StoreError::SenderHashMismatch {
                claimed,
                received: stream_hash,
            });
        }

        // The modification time is set through the write handle, before the
        // flush: it becomes durable together with the data, and nothing has
        // to touch the file again after it has been verified.
        let mut temp = active
            .temp
            .take()
            .expect("an open incoming file has its handle");
        let mtime_applied = match active.mtime_unix_ns.and_then(system_time_from_unix_ns) {
            Some(mtime) => temp.set_mtime(mtime).is_ok(),
            None => false,
        };
        temp.sync()
            .map_err(|e| StoreError::write("flush", &active.temp_path, e))?;
        drop(temp);

        // Read it back from the device, not from the cache.
        let mut hasher = blake3::Hasher::new();
        let read = inner
            .fs
            .read_verify(&active.temp_path, &mut |chunk| {
                hasher.update(chunk);
                ControlFlow::Continue(())
            })
            .map_err(|e| StoreError::io("read back", &active.temp_path, e))?;
        let disk_hash = ContentHash::from(hasher.finalize());
        if !read.completed
            || read.bytes != active.declared
            || disk_hash != stream_hash
            || disk_hash != claimed
        {
            return Err(StoreError::DiskVerifyMismatch {
                expected: stream_hash,
                on_disk: disk_hash,
                expected_size: active.declared,
                on_disk_size: read.bytes,
            });
        }

        let placed = inner.place(&mut active, &stream_hash)?;
        let (name, existing, dir_synced, verified_unbuffered, adopted) = match placed {
            Placed::Stored { name, dir_synced } => (name, None, dir_synced, read.unbuffered, false),
            Placed::Adopted {
                name,
                record,
                unbuffered,
            } => (name, record, false, unbuffered, true),
        };
        let rel = active.dir_rel.join(name);
        let rel_path = rel.to_slash_string();
        let abs_path = rel.under(inner.root());

        inner
            .fs
            .checkpoint(Checkpoint::BeforeLedgerRecord)
            .map_err(|e| StoreError::io("record", &abs_path, e))?;

        let now = inner.now();
        let record = match existing {
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
                inner.ledger.mark_verified(
                    existing.id,
                    "duplicate_received",
                    Some(&active.device),
                    now,
                )?;
                existing
            }
            None => inner.ledger.record_commit(
                &NewFile {
                    device: &active.device,
                    rel_path: &rel_path,
                    path_key: &rel.collision_key(),
                    hash: stream_hash,
                    size: active.declared,
                    mtime_unix_ns: active.mtime_unix_ns,
                    source_name: &active.source_name,
                    dir_synced,
                    verified_unbuffered,
                    adopted,
                },
                now,
            )?,
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
            dir_synced,
            verified_unbuffered,
            mtime_applied: mtime_applied && !adopted,
        })
    }
}

fn write_all(active: &mut ActiveFile, data: &[u8]) -> Result<(), StoreError> {
    let received = active.written.saturating_add(data.len() as u64);
    if received > active.declared {
        return Err(StoreError::SizeMismatch {
            declared: active.declared,
            received,
        });
    }
    let temp = active
        .temp
        .as_mut()
        .expect("an open incoming file has its handle");
    let mut offset = 0;
    while offset < data.len() {
        let n = match temp.write(&data[offset..]) {
            Ok(0) => {
                let stuck = io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the file system accepted no more bytes",
                );
                return Err(StoreError::write("write", &active.temp_path, stuck));
            }
            Ok(n) => n.min(data.len() - offset),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(StoreError::write("write", &active.temp_path, e)),
        };
        // Only bytes the file system accepted enter the stream hash.
        active.hasher.update(&data[offset..offset + n]);
        offset += n;
        active.written += n as u64;
        let mut in_flight = lock(&active.inner.in_flight);
        in_flight.bytes_remaining = in_flight.bytes_remaining.saturating_sub(n as u64);
    }
    Ok(())
}

impl Inner {
    /// Gives the verified temp file its final name, or finds that an identical
    /// file is already there.
    fn place(&self, active: &mut ActiveFile, hash: &ContentHash) -> Result<Placed, StoreError> {
        let _serialised = lock(&self.commit_lock);
        let dir_key = active.dir_rel.collision_key();
        self.load_dir_names(&dir_key, &active.dir_abs, false)?;

        let mut n = 1u32;
        let mut raced = false;
        // `rounds` bounds the loop even against a file system whose listing,
        // stat and rename disagree with each other indefinitely.
        let mut rounds = 0u32;
        while n <= MAX_NAME_ATTEMPTS && rounds < 4 * MAX_NAME_ATTEMPTS {
            rounds += 1;
            let candidate = active.name.with_collision_suffix(n);
            let key = candidate.collision_key();

            if let Some(existing) = self.cached_name(&dir_key, &key) {
                let existing_path = active.dir_abs.join(&existing);
                match self
                    .fs
                    .stat(&existing_path)
                    .map_err(|e| StoreError::io("examine", &existing_path, e))?
                {
                    // The listing is stale: the name is free again.
                    None => self.forget_name(&dir_key, &key),
                    Some(stat) => {
                        if let Some(adopted) = self.try_adopt(active, &existing, &stat, hash)? {
                            return Ok(adopted);
                        }
                        n += 1;
                        raced = false;
                        continue;
                    }
                }
            } else if raced {
                // The file system insists the name exists although a fresh
                // listing does not show it. Believe the file system.
                n += 1;
                raced = false;
                continue;
            }

            let target = active.dir_abs.join(candidate.as_str());
            match self.fs.rename_noreplace(&active.temp_path, &target) {
                Ok(()) => {
                    active.renamed = true;
                    self.remember_name(&dir_key, key, candidate.as_str());
                    // "Where possible": a file system that cannot flush a
                    // directory does not fail the commit; the receipt and the
                    // ledger say whether it happened.
                    let dir_synced = self.fs.sync_dir(&active.dir_abs).is_ok();
                    return Ok(Placed::Stored {
                        name: candidate,
                        dir_synced,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // Someone created the name after the directory was listed.
                    // Look again and reconsider this same candidate: it may be
                    // the very file we are storing.
                    self.load_dir_names(&dir_key, &active.dir_abs, true)?;
                    raced = true;
                }
                Err(e) => return Err(StoreError::write("rename into place", target, e)),
            }
        }
        Err(StoreError::TooManyCollisions {
            dir: active.dir_rel.to_slash_string(),
            name: active.name.as_str().to_owned(),
        })
    }

    /// If the existing entry is a regular file with exactly the content being
    /// stored, use it instead of creating ` (2)`. The content is compared by
    /// reading the existing file from disk; the ledger's opinion is not enough.
    fn try_adopt(
        &self,
        active: &ActiveFile,
        existing: &str,
        stat: &FileStat,
        hash: &ContentHash,
    ) -> Result<Option<Placed>, StoreError> {
        if stat.kind != EntryKind::File
            || stat.reparse
            || stat.offline
            || stat.size != active.declared
        {
            return Ok(None);
        }
        // A name the sanitiser would not have produced is never recorded.
        let Some(name) = SafeName::from_stored(existing) else {
            return Ok(None);
        };
        let rel = active.dir_rel.join(name.clone());
        let record = self.ledger.file_by_path_key(&rel.collision_key())?;
        if let Some(r) = &record {
            if r.hash != *hash || r.rel_path != rel.to_slash_string() {
                return Ok(None);
            }
        }
        let path = active.dir_abs.join(existing);
        let mut hasher = blake3::Hasher::new();
        let read = self.fs.read_verify(&path, &mut |chunk| {
            hasher.update(chunk);
            ControlFlow::Continue(())
        });
        match read {
            Ok(r)
                if r.completed
                    && r.bytes == active.declared
                    && ContentHash::from(hasher.finalize()) == *hash =>
            {
                Ok(Some(Placed::Adopted {
                    name,
                    record,
                    unbuffered: r.unbuffered,
                }))
            }
            // Different content, or it cannot be read: not ours to adopt.
            _ => Ok(None),
        }
    }
}
