//! The file-system seam.
//!
//! Every operation the commit pipeline and the verifiers perform on the
//! destination goes through [`Fs`]. Production code always uses [`RealFs`];
//! tests wrap it to make any single step fail, write short, or be preceded by
//! outside interference (see `testing::FaultFs`, available with the
//! `test-util` feature).

use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::sys;

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// Anything else (device, socket, ...).
    Other,
}

/// Result of looking at a path *without following it* if it is a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    /// Kind of entry. For a reparse point this describes the link itself.
    pub kind: EntryKind,
    /// The entry is a reparse point (junction, symbolic link, mount point, ...).
    pub reparse: bool,
    /// The entry's data is not on the local disk (cloud placeholder, HSM stub).
    pub offline: bool,
    /// Size in bytes.
    pub size: u64,
    /// Last modification time, if the file system has one.
    pub mtime: Option<SystemTime>,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// The entry's name. Names that are not valid Unicode are converted
    /// lossily and `exact` is false.
    pub name: String,
    /// Whether `name` is exactly the on-disk name.
    pub exact: bool,
    /// The entry itself (not what it may link to).
    pub stat: FileStat,
}

/// Outcome of a verification read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyRead {
    /// Bytes delivered to the sink.
    pub bytes: u64,
    /// The read bypassed the operating system's cache.
    pub unbuffered: bool,
    /// The sink let the read run to the end of the file.
    pub completed: bool,
}

/// Points in the commit pipeline that are not file-system calls but where a
/// crash or failure is still worth simulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Checkpoint {
    /// The file has its final name; the ledger has not been told yet.
    BeforeLedgerRecord,
}

/// A file being received.
pub trait TempFile: Send {
    /// Writes some of `buf`, returning how many bytes were accepted.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    /// Sets the modification time through the open handle.
    fn set_mtime(&mut self, mtime: SystemTime) -> io::Result<()>;
    /// Flushes data and metadata to the device (`FlushFileBuffers` / `fsync`).
    fn sync(&mut self) -> io::Result<()>;
}

/// The operations the engine performs on the destination.
pub trait Fs: Send + Sync {
    /// Bytes available to the user on the volume holding `dir`.
    fn free_space(&self, dir: &Path) -> io::Result<u64>;
    /// Looks at `path` without following a final link. `None` if it does not exist.
    fn stat(&self, path: &Path) -> io::Result<Option<FileStat>>;
    /// Lists a directory (entries are not followed).
    fn list_dir(&self, dir: &Path) -> io::Result<Vec<DirEntryInfo>>;
    /// Fully resolves an existing path (links followed, short names expanded).
    fn resolve(&self, path: &Path) -> io::Result<PathBuf>;
    /// Creates one directory; the parent must exist.
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    /// Creates a new file for writing; fails if the name exists.
    fn create_temp(&self, path: &Path) -> io::Result<Box<dyn TempFile>>;
    /// Reads a whole file from the device, bypassing the cache where the
    /// platform allows, feeding it to `sink` until the end or until the sink
    /// breaks.
    fn read_verify(&self, path: &Path, sink: &mut dyn FnMut(&[u8]) -> ControlFlow<()>) -> io::Result<VerifyRead>;
    /// Renames `from` to `to`, failing with `AlreadyExists` rather than
    /// replacing anything, and writes the rename through.
    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Flushes a directory's entries to the device.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
    /// Deletes a file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Called at pipeline points that are not file-system calls.
    fn checkpoint(&self, point: Checkpoint) -> io::Result<()> {
        let _ = point;
        Ok(())
    }
}

/// The real file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

struct RealTemp(std::fs::File);

impl TempFile for RealTemp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.0, buf)
    }

    fn set_mtime(&mut self, mtime: SystemTime) -> io::Result<()> {
        self.0.set_modified(mtime)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}

fn stat_of(meta: &std::fs::Metadata) -> FileStat {
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    FileStat {
        kind,
        reparse: sys::is_reparse(meta),
        offline: sys::is_offline(meta),
        size: meta.len(),
        mtime: meta.modified().ok(),
    }
}

impl Fs for RealFs {
    fn free_space(&self, dir: &Path) -> io::Result<u64> {
        sys::free_space(dir)
    }

    fn stat(&self, path: &Path) -> io::Result<Option<FileStat>> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => Ok(Some(stat_of(&meta))),
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<DirEntryInfo>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = match entry.metadata() {
                Ok(m) => m,
                // Deleted between listing and looking: it is simply not there.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let (name, exact) = match entry.file_name().into_string() {
                Ok(s) => (s, true),
                Err(os) => (os.to_string_lossy().into_owned(), false),
            };
            out.push(DirEntryInfo { name, exact, stat: stat_of(&meta) });
        }
        Ok(out)
    }

    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir(path)
    }

    fn create_temp(&self, path: &Path) -> io::Result<Box<dyn TempFile>> {
        Ok(Box::new(RealTemp(sys::create_temp(path)?)))
    }

    fn read_verify(&self, path: &Path, sink: &mut dyn FnMut(&[u8]) -> ControlFlow<()>) -> io::Result<VerifyRead> {
        let (mut file, unbuffered) = sys::open_for_verify(path)?;
        let mut delivered = false;
        let first = sys::read_to_end_aligned(&mut file, &mut |chunk| {
            delivered = true;
            sink(chunk)
        });
        match first {
            Ok((bytes, completed)) => Ok(VerifyRead { bytes, unbuffered, completed }),
            // The file system accepted the direct-I/O open but refuses the
            // read. Nothing has reached the sink yet, so start over cached.
            Err(e) if unbuffered && !delivered && sys::is_direct_io_unsupported(&e) => {
                drop(file);
                let mut file = sys::open_buffered(path)?;
                let (bytes, completed) = sys::read_to_end_aligned(&mut file, sink)?;
                Ok(VerifyRead { bytes, unbuffered: false, completed })
            }
            Err(e) => Err(e),
        }
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        sys::rename_noreplace(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        sys::sync_dir(dir)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}

/// A source of wall-clock time. Wall-clock time is never the only evidence
/// for a decision (sequence numbers and the session counter are), but the
/// 24-hour rule needs one.
pub trait Clock: Send + Sync {
    /// Milliseconds since 1970-01-01T00:00:00Z.
    fn now_unix_ms(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("unit-tmp").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn hash_file(path: &Path) -> (blake3::Hash, VerifyRead) {
        let mut hasher = blake3::Hasher::new();
        let read = RealFs
            .read_verify(path, &mut |chunk| {
                hasher.update(chunk);
                ControlFlow::Continue(())
            })
            .unwrap();
        (hasher.finalize(), read)
    }

    #[test]
    fn verify_read_handles_every_tail_length() {
        let dir = scratch("verify-read");
        // Sizes around sector and buffer boundaries, including empty.
        let sizes = [0usize, 1, 511, 512, 513, 4095, 4096, 4097, 65_536, 1_048_575, 1_048_576, 1_048_577, 2_500_000];
        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let path = dir.join(format!("f{size}.bin"));
            std::fs::File::create(&path).unwrap().write_all(&data).unwrap();
            let (hash, read) = hash_file(&path);
            assert_eq!(read.bytes, size as u64, "size {size}");
            assert!(read.completed);
            assert_eq!(hash, blake3::hash(&data), "size {size}");
            if cfg!(windows) {
                assert!(read.unbuffered, "NTFS must give an unbuffered read (size {size})");
            }
        }
    }

    #[test]
    fn verify_read_can_be_stopped() {
        let dir = scratch("verify-stop");
        let path = dir.join("big.bin");
        std::fs::write(&path, vec![7u8; 3 * 1_048_576]).unwrap();
        let mut calls = 0;
        let read = RealFs
            .read_verify(&path, &mut |_| {
                calls += 1;
                ControlFlow::Break(())
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert!(!read.completed);
        assert!(read.bytes < 3 * 1_048_576);
    }

    #[test]
    fn verify_read_refuses_directories_and_missing_files() {
        let dir = scratch("verify-refuse");
        assert!(RealFs.read_verify(&dir, &mut |_| ControlFlow::Continue(())).is_err());
        let missing = RealFs.read_verify(&dir.join("nope"), &mut |_| ControlFlow::Continue(())).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn rename_never_replaces() {
        let dir = scratch("rename");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(&b, b"old").unwrap();
        let err = RealFs.rename_noreplace(&a, &b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&a).unwrap(), b"new");
        assert_eq!(std::fs::read(&b).unwrap(), b"old");
        let c = dir.join("c");
        RealFs.rename_noreplace(&a, &c).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&c).unwrap(), b"new");
        // A directory in the way is not replaced either.
        std::fs::create_dir(dir.join("d")).unwrap();
        assert!(RealFs.rename_noreplace(&c, &dir.join("d")).is_err());
        assert_eq!(std::fs::read(&c).unwrap(), b"new");
    }

    #[test]
    fn rename_is_case_insensitive_on_windows() {
        if !cfg!(windows) {
            return;
        }
        let dir = scratch("rename-case");
        std::fs::write(dir.join("Photo.JPG"), b"old").unwrap();
        std::fs::write(dir.join("tmp"), b"new").unwrap();
        let err = RealFs.rename_noreplace(&dir.join("tmp"), &dir.join("photo.jpg")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(dir.join("Photo.JPG")).unwrap(), b"old");
    }

    #[test]
    fn temp_files_are_exclusive_and_keep_their_mtime() {
        let dir = scratch("temp");
        let path = dir.join("t.part");
        let mut t = RealFs.create_temp(&path).unwrap();
        assert_eq!(RealFs.create_temp(&path).err().unwrap().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(t.write(b"hello").unwrap(), 5);
        let when = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_500_000_000);
        t.set_mtime(when).unwrap();
        t.sync().unwrap();
        drop(t);
        // Closing the handle must not bump the time we set.
        let stat = RealFs.stat(&path).unwrap().unwrap();
        assert_eq!(stat.mtime, Some(when));
        assert_eq!(stat.size, 5);
        assert_eq!(stat.kind, EntryKind::File);
        assert!(!stat.reparse);
    }

    #[test]
    fn stat_and_list_do_not_invent_entries() {
        let dir = scratch("stat");
        assert_eq!(RealFs.stat(&dir.join("missing")).unwrap(), None);
        assert_eq!(RealFs.stat(&dir.join("missing").join("deeper")).unwrap(), None);
        std::fs::write(dir.join("file"), b"x").unwrap();
        // A path "through" a file does not exist.
        assert_eq!(RealFs.stat(&dir.join("file").join("child")).unwrap(), None);
        std::fs::create_dir(dir.join("sub")).unwrap();
        let mut names: Vec<_> = RealFs.list_dir(&dir).unwrap().into_iter().map(|e| (e.name, e.stat.kind)).collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(names, vec![("file".to_owned(), EntryKind::File), ("sub".to_owned(), EntryKind::Dir)]);
    }

    #[test]
    fn directory_sync_and_free_space_work_here() {
        let dir = scratch("sync");
        RealFs.sync_dir(&dir).unwrap();
        assert!(RealFs.free_space(&dir).unwrap() > 0);
        assert_eq!(RealFs.resolve(&dir).unwrap(), dir);
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = scratch("lock");
        let path = dir.join("lock");
        let first = sys::acquire_lock(&path).unwrap();
        assert_eq!(sys::acquire_lock(&path).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        drop(first);
        sys::acquire_lock(&path).unwrap();
    }
}
