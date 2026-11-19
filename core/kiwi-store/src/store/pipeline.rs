//! The durable write pipeline shared by everything that puts a file on a disk:
//! a file received from a phone, a copy made on a mirror, and a file restored
//! from a mirror.
//!
//! ```text
//! create    walk/create directories (no reparse points) -> create temp
//!           -> note the intent in the ledger -> the temp is where it was put?
//! write     temp file  +  incremental BLAKE3 of the bytes written
//! seal      set mtime -> flush to device -> close
//! read_back reopen UNBUFFERED, re-hash from disk
//! place     rename, no replace (collision -> " (2)"; identical file -> adopt)
//!           -> flush the file under its new name -> flush the directory
//!           -> the file is there, is where it was put, and still hashes right?
//! ```
//!
//! The caller compares the hashes between the steps and records the result.
//!
//! # The only place a file is deleted
//!
//! [`Inner::delete_own_temp`] is the single call site of `Fs::remove_file` in
//! the engine. It refuses any name that is not a temp-file name, and a
//! temp-file name is one no stored file can have: the sanitiser never
//! produces a name starting with `.kiwi-`, and a ledger row carrying one is
//! rejected when it is read. A [`TempSlot`] deletes only the file it created
//! itself, and not after that file was renamed into place.

use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::{lock, Inner, TEMP_PREFIX, TEMP_SUFFIX};
use crate::error::StoreError;
use crate::fsops::{EntryKind, FileStat, TempFile, VerifyRead};
use crate::hash::ContentHash;
use crate::ledger::FileRecord;
use crate::sanitize::{SafeName, SafeRelPath};

/// Most alternative names (` (2)`, ` (3)`, ...) tried before giving up.
const MAX_NAME_ATTEMPTS: u32 = 10_000;

/// The location number of the destination itself. Mirrors use their ledger id.
pub(crate) const PRIMARY: i64 = 0;

/// Whether `name` is exactly the shape of a temp-file name the engine makes:
/// `.kiwi-tmp-<hex>-<hex>-<16 hex>.part`, lower case.
pub(crate) fn is_temp_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix(TEMP_PREFIX)
        .and_then(|rest| rest.strip_suffix(TEMP_SUFFIX))
    else {
        return false;
    };
    let hex = |part: &str| {
        !part.is_empty()
            && part.len() <= 16
            && part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut parts = middle.split('-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(session), Some(counter), Some(random), None) => {
            hex(session) && hex(counter) && hex(random) && random.len() == 16
        }
        _ => false,
    }
}

pub(crate) fn system_time_from_unix_ns(ns: i64) -> Option<SystemTime> {
    let magnitude = Duration::from_nanos(ns.unsigned_abs());
    if ns >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    }
}

/// How a verified temp file got its final name.
pub(crate) enum Placed {
    /// It was renamed into place.
    Stored {
        name: SafeName,
        /// The flush of the file under its new name and of its directory
        /// both succeeded.
        dir_synced: bool,
        /// The read-back under the final name bypassed the cache.
        unbuffered: bool,
    },
    /// A file with identical content was already there (it was read to make
    /// sure); the temp file was not needed.
    Adopted {
        name: SafeName,
        record: Option<FileRecord>,
        unbuffered: bool,
    },
}

/// Whether an existing, identical file may stand in for the one being placed.
pub(crate) enum Adoption {
    No,
    /// Yes; with the ledger record it already has, if any.
    Yes(Option<FileRecord>),
}

/// What [`TempSlot::place`] needs to know.
pub(crate) struct PlaceRequest<'a> {
    pub hash: &'a ContentHash,
    pub size: u64,
    /// The name to try on the n-th attempt (1-based).
    pub name_for: &'a dyn Fn(u32) -> SafeName,
    /// Asked before an existing file is read for comparison.
    pub may_adopt: &'a dyn Fn(&SafeRelPath) -> Result<Adoption, StoreError>,
    /// For the error message when no name is free.
    pub display_name: &'a str,
}

/// A temp file the engine created, with everything registered for it. Dropping
/// the slot deletes the file unless it was renamed into place.
pub(crate) struct TempSlot {
    inner: Arc<Inner>,
    location: i64,
    dir_rel: SafeRelPath,
    dir_abs: PathBuf,
    temp_path: PathBuf,
    temp_rel: String,
    temp: Option<Box<dyn TempFile>>,
    hasher: blake3::Hasher,
    written: u64,
    /// The temp file exists because this slot created it.
    created: bool,
    /// The temp file has been renamed into place and must not be deleted.
    renamed: bool,
    /// The ledger has removed the intent row (together with recording the file).
    intent_closed: bool,
    /// Crash simulation: leave the temp file and its intent row behind.
    leak: bool,
}

impl Drop for TempSlot {
    fn drop(&mut self) {
        // Close the handle first: an open handle would block the delete.
        self.temp = None;
        if self.created && !self.leak {
            let mut gone = self.renamed;
            if !self.renamed {
                gone = self.inner.delete_own_temp(&self.temp_path);
            }
            // A temp file that could not be deleted keeps its intent row, so
            // that the next recovery pass removes it.
            if gone && !self.intent_closed {
                let _ = self
                    .inner
                    .ledger
                    .remove_partial(self.location, &self.temp_rel);
            }
        }
        lock(&self.inner.in_flight).temps.remove(&self.temp_path);
    }
}

impl TempSlot {
    /// Creates a temp file in `dir_rel` under `root`, creating the directory
    /// if needed.
    pub(crate) fn create(
        inner: &Arc<Inner>,
        location: i64,
        root: &Path,
        dir_rel: &SafeRelPath,
    ) -> Result<TempSlot, StoreError> {
        let (dir_abs, dir_actual) = inner
            .walk_dirs(root, dir_rel, true)?
            .expect("walk_dirs(create) returns a path or an error");
        let mut slot = TempSlot {
            inner: Arc::clone(inner),
            location,
            dir_rel: dir_actual,
            dir_abs,
            temp_path: PathBuf::new(),
            temp_rel: String::new(),
            temp: None,
            hasher: blake3::Hasher::new(),
            written: 0,
            created: false,
            renamed: false,
            intent_closed: false,
            leak: false,
        };

        // Create the temp file next to the final target, under a fresh name.
        let mut attempts = 0;
        loop {
            let name = inner.temp_name();
            let candidate = slot.dir_abs.join(&name);
            // Register before creating, so a recovery pass running right now
            // cannot mistake the new file for an orphan.
            lock(&inner.in_flight).temps.insert(candidate.clone());
            match inner.fs.create_temp(&candidate) {
                Ok(temp) => {
                    slot.temp_rel = if slot.dir_rel.is_empty() {
                        name
                    } else {
                        format!("{}/{name}", slot.dir_rel.to_slash_string())
                    };
                    slot.temp_path = candidate;
                    slot.temp = Some(temp);
                    slot.created = true;
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

        // The intent row is written only after the file exists: a row is
        // therefore proof that the engine itself created that file. (If the
        // row cannot be written, the slot is dropped and removes the file it
        // has just made.)
        inner
            .ledger
            .add_partial(location, &slot.temp_rel, inner.now())?;

        // The directory was checked before the file was created. Check again
        // through the file itself: it must be exactly where it was put. This
        // closes the window in which a directory on the way could have been
        // swapped for a link between the check and the create.
        let resolved = inner
            .fs
            .resolve(&slot.temp_path)
            .map_err(|e| StoreError::io("resolve", &slot.temp_path, e))?;
        if resolved != slot.temp_path {
            return Err(StoreError::PathMismatch {
                expected: slot.temp_path.clone(),
                resolved,
            });
        }
        Ok(slot)
    }

    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    /// The temp file's path relative to the root, as noted in the ledger.
    pub(crate) fn temp_rel(&self) -> &str {
        &self.temp_rel
    }

    /// The directory, as it is spelled on disk.
    pub(crate) fn dir_rel(&self) -> &SafeRelPath {
        &self.dir_rel
    }

    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    /// The hash of the bytes written so far.
    pub(crate) fn stream_hash(&self) -> ContentHash {
        ContentHash::from(self.hasher.finalize())
    }

    /// Tells the slot that the ledger has removed the intent row.
    pub(crate) fn intent_closed(&mut self) {
        self.intent_closed = true;
    }

    /// Leaves the temp file and its intent row behind, as a killed process would.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn leak(&mut self) -> PathBuf {
        self.leak = true;
        self.temp_path.clone()
    }

    /// Appends bytes, never more than `limit` in total. `accepted` is told
    /// about every chunk the file system took.
    pub(crate) fn write(
        &mut self,
        data: &[u8],
        limit: u64,
        accepted: &mut dyn FnMut(u64),
    ) -> Result<(), StoreError> {
        let received = self.written.saturating_add(data.len() as u64);
        if received > limit {
            return Err(StoreError::SizeMismatch {
                declared: limit,
                received,
            });
        }
        let temp = self
            .temp
            .as_mut()
            .expect("an open temp slot has its handle");
        let mut offset = 0;
        while offset < data.len() {
            let n = match temp.write(&data[offset..]) {
                Ok(0) => {
                    let stuck = io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the file system accepted no more bytes",
                    );
                    return Err(StoreError::write("write", &self.temp_path, stuck));
                }
                Ok(n) => n.min(data.len() - offset),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(StoreError::write("write", &self.temp_path, e)),
            };
            // Only bytes the file system accepted enter the stream hash.
            self.hasher.update(&data[offset..offset + n]);
            offset += n;
            self.written += n as u64;
            accepted(n as u64);
        }
        Ok(())
    }

    /// Sets the modification time, flushes the file to the device and closes
    /// it. Returns whether the modification time was applied.
    ///
    /// The time is set through the write handle, before the flush: it becomes
    /// durable together with the data, and nothing has to touch the file
    /// again after it has been verified.
    pub(crate) fn seal(&mut self, mtime_unix_ns: Option<i64>) -> Result<bool, StoreError> {
        let mut temp = self.temp.take().expect("an open temp slot has its handle");
        let mtime_applied = match mtime_unix_ns.and_then(system_time_from_unix_ns) {
            Some(mtime) => temp.set_mtime(mtime).is_ok(),
            None => false,
        };
        temp.sync()
            .map_err(|e| StoreError::write("flush", &self.temp_path, e))?;
        drop(temp);
        Ok(mtime_applied)
    }

    /// Reads the sealed temp file back from the device, not from the cache.
    pub(crate) fn read_back(
        &self,
        on_chunk: &mut dyn FnMut(usize) -> ControlFlow<()>,
    ) -> Result<(ContentHash, VerifyRead), StoreError> {
        let mut hasher = blake3::Hasher::new();
        let read = self
            .inner
            .fs
            .read_verify(&self.temp_path, &mut |chunk| {
                hasher.update(chunk);
                on_chunk(chunk.len())
            })
            .map_err(|e| StoreError::io("read back", &self.temp_path, e))?;
        Ok((ContentHash::from(hasher.finalize()), read))
    }

    /// Gives the verified temp file its final name, or finds that an
    /// identical file is already there.
    pub(crate) fn place(&mut self, req: &PlaceRequest<'_>) -> Result<Placed, StoreError> {
        let inner = Arc::clone(&self.inner);
        let _serialised = lock(&inner.commit_lock);
        let dir_key = format!("{}|{}", self.location, self.dir_rel.collision_key());
        inner.load_dir_names(&dir_key, &self.dir_abs, false)?;

        let mut n = 1u32;
        let mut raced = false;
        // `rounds` bounds the loop even against a file system whose listing,
        // stat and rename disagree with each other indefinitely.
        let mut rounds = 0u32;
        while n <= MAX_NAME_ATTEMPTS && rounds < 4 * MAX_NAME_ATTEMPTS {
            rounds += 1;
            let candidate = (req.name_for)(n);
            let key = candidate.collision_key();

            if let Some(existing) = inner.cached_name(&dir_key, &key) {
                let existing_path = self.dir_abs.join(&existing);
                match inner
                    .fs
                    .stat(&existing_path)
                    .map_err(|e| StoreError::io("examine", &existing_path, e))?
                {
                    // The listing is stale: the name is free again.
                    None => inner.forget_name(&dir_key, &key),
                    Some(stat) => {
                        if let Some(adopted) = self.try_adopt(req, &existing, &stat)? {
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

            let target = self.dir_abs.join(candidate.as_str());
            match inner.fs.rename_noreplace(&self.temp_path, &target) {
                Ok(()) => {
                    self.renamed = true;
                    inner.remember_name(&dir_key, key, candidate.as_str());
                    // Make the new name durable. A same-volume rename is a
                    // change to the directory only; it is on the device once
                    // the file and its directory have been flushed. A file
                    // system that cannot do either does not fail the commit;
                    // the receipt and the ledger say whether both happened.
                    let file_synced = inner.fs.sync_file(&target).is_ok();
                    let dir_synced = inner.fs.sync_dir(&self.dir_abs).is_ok();
                    // And look: the file must be there under its new name,
                    // must be where it was put, and must still hash right.
                    // Nothing is recorded for a file that fails this.
                    let unbuffered = inner.confirm_in_place(&target, req.size, req.hash)?;
                    return Ok(Placed::Stored {
                        name: candidate,
                        dir_synced: file_synced && dir_synced,
                        unbuffered,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // Someone created the name after the directory was listed.
                    // Look again and reconsider this same candidate: it may be
                    // the very file we are storing.
                    inner.load_dir_names(&dir_key, &self.dir_abs, true)?;
                    raced = true;
                }
                Err(e) => return Err(StoreError::write("rename into place", target, e)),
            }
        }
        Err(StoreError::TooManyCollisions {
            dir: self.dir_rel.to_slash_string(),
            name: req.display_name.to_owned(),
        })
    }

    /// If the existing entry is a plain, visible, local file with exactly the
    /// content being stored, use it instead of creating ` (2)`. The content
    /// is compared by reading the existing file from disk; the ledger's
    /// opinion is not enough.
    ///
    /// Never adopted: links and other reparse points, cloud placeholders,
    /// hidden and system files, and anything whose name the sanitiser would
    /// not have produced, which includes the engine's own temp files.
    fn try_adopt(
        &self,
        req: &PlaceRequest<'_>,
        existing: &str,
        stat: &FileStat,
    ) -> Result<Option<Placed>, StoreError> {
        if stat.kind != EntryKind::File
            || stat.reparse
            || stat.offline
            || stat.hidden
            || stat.size != req.size
        {
            return Ok(None);
        }
        let Some(name) = SafeName::from_stored(existing) else {
            return Ok(None);
        };
        let rel = self.dir_rel.join(name.clone());
        let record = match (req.may_adopt)(&rel)? {
            Adoption::No => return Ok(None),
            Adoption::Yes(record) => record,
        };
        let path = self.dir_abs.join(existing);
        let mut hasher = blake3::Hasher::new();
        let read = self.inner.fs.read_verify(&path, &mut |chunk| {
            hasher.update(chunk);
            ControlFlow::Continue(())
        });
        match read {
            Ok(r)
                if r.completed
                    && r.bytes == req.size
                    && ContentHash::from(hasher.finalize()) == *req.hash =>
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

impl Inner {
    /// Deletes one of the engine's own temp files: the only way the engine
    /// ever deletes anything. Returns whether the file is gone.
    ///
    /// A name that is not a temp-file name is refused, whoever asks. A
    /// scanner may hold the file for a moment, so a refusal by the file
    /// system is retried briefly; what is left behind is removed by the next
    /// recovery pass.
    pub(crate) fn delete_own_temp(&self, path: &Path) -> bool {
        let is_temp = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_temp_name);
        if !is_temp {
            return false;
        }
        for attempt in 0..3u64 {
            match self.fs.remove_file(path) {
                Ok(()) => return true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
                Err(_) => std::thread::sleep(Duration::from_millis(30 * (attempt + 1))),
            }
        }
        false
    }

    /// After a rename: the file must exist under its new name as a plain file
    /// of the right size, the name must lead where the engine put it, and its
    /// content, read from the device again, must still hash to `hash`.
    /// Returns whether that read bypassed the cache.
    fn confirm_in_place(
        &self,
        target: &Path,
        size: u64,
        hash: &ContentHash,
    ) -> Result<bool, StoreError> {
        let stat = self
            .fs
            .stat(target)
            .map_err(|e| StoreError::io("examine after the rename", target, e))?;
        match stat {
            Some(s) if s.kind == EntryKind::File && !s.reparse && s.size == size => {}
            _ => {
                return Err(StoreError::RenameNotConfirmed {
                    path: target.to_path_buf(),
                })
            }
        }
        let resolved = self
            .fs
            .resolve(target)
            .map_err(|e| StoreError::io("resolve after the rename", target, e))?;
        if resolved != target {
            return Err(StoreError::PathMismatch {
                expected: target.to_path_buf(),
                resolved,
            });
        }
        let mut hasher = blake3::Hasher::new();
        let read = self
            .fs
            .read_verify(target, &mut |chunk| {
                hasher.update(chunk);
                ControlFlow::Continue(())
            })
            .map_err(|e| StoreError::io("read back after the rename", target, e))?;
        let on_disk = ContentHash::from(hasher.finalize());
        if !read.completed || read.bytes != size || on_disk != *hash {
            return Err(StoreError::DiskVerifyMismatch {
                expected: *hash,
                on_disk,
                expected_size: size,
                on_disk_size: read.bytes,
            });
        }
        Ok(read.unbuffered)
    }
}
