//! Unix implementation. It exists so that `cargo test` exercises the engine's
//! logic on Linux CI. It is weaker than the Windows implementation in ways
//! that matter, and the engine therefore never reports a Unix destination as
//! supporting final move:
//!
//! * volumes are not classified (fixed / removable / network);
//! * `O_DIRECT` is used for verification reads where the file system offers
//!   it; elsewhere the read is an ordinary cached read and is reported as such;
//! * mount points below the root are not detected the way reparse points are.

// The libc field types (`f_flag`, `f_type`, `f_bavail`, ...) differ between
// Unix flavours; a cast that is needed on one is a no-op on another.
#![allow(clippy::unnecessary_cast)]

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::destination::{DriveKind, VolumeInfo};

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL character"))
}

/// Describes the volume holding `path`. No classification is attempted.
pub(crate) fn probe_volume(path: &Path) -> io::Result<VolumeInfo> {
    let meta = std::fs::metadata(path)?;
    let c = c_path(path)?;
    // SAFETY: `c` is NUL-terminated and `st` is a valid out-pointer.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(VolumeInfo {
        drive: DriveKind::Unknown,
        filesystem: filesystem_name(path),
        serial: Some(meta.dev()),
        read_only: (st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0,
        removable_media: None,
        hot_plug: None,
        bus: None,
        volume_root: String::new(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn filesystem_name(path: &Path) -> String {
    let Ok(c) = c_path(path) else {
        return "unknown".to_owned();
    };
    // SAFETY: `c` is NUL-terminated and `st` is a valid out-pointer.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return "unknown".to_owned();
    }
    let magic = (st.f_type as u64) & 0xffff_ffff;
    match magic {
        0xEF53 => "ext",
        0x9123_683E => "btrfs",
        0x5846_5342 => "xfs",
        0xF2F5_2010 => "f2fs",
        0x2FC1_2FC1 => "zfs",
        0x0102_1994 => "tmpfs",
        0x794C_7630 => "overlayfs",
        0x6573_5546 => "fuse",
        0x6969 => "nfs",
        0xFF53_4D42 | 0xFE53_4D42 | 0x517B => "smb",
        0x5346_544E | 0x7366_746E => "ntfs",
        0x2011_BAB0 => "exfat",
        0x4D44 => "vfat",
        _ => "unknown",
    }
    .to_owned()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn filesystem_name(_path: &Path) -> String {
    "unknown".to_owned()
}

/// Bytes available to the current user on the volume holding `dir`.
pub(crate) fn free_space(dir: &Path) -> io::Result<u64> {
    let c = c_path(dir)?;
    // SAFETY: `c` is NUL-terminated and `st` is a valid out-pointer.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// True for symbolic links (the nearest Unix analogue of a reparse point).
pub(crate) fn is_reparse(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Unix has no portable "data is elsewhere" attribute.
pub(crate) fn is_offline(_meta: &Metadata) -> bool {
    false
}

/// Unix has no placeholder attributes or reparse tags to look at.
pub(crate) fn cloud_evidence(_dir: &Path) -> Option<String> {
    None
}

/// Who besides the owner may write to `path`, judged by its mode bits.
pub(crate) fn other_writers(path: &Path) -> io::Result<Vec<String>> {
    let meta = std::fs::metadata(path)?;
    let mut out = Vec::new();
    if meta.mode() & 0o020 != 0 {
        out.push(format!("group {}", meta.gid()));
    }
    if meta.mode() & 0o002 != 0 {
        out.push("everyone".to_owned());
    }
    Ok(out)
}

/// Unix has no hidden attribute (a leading dot is only a convention).
pub(crate) fn is_hidden(_meta: &Metadata) -> bool {
    false
}

/// Creates a new file for writing; fails if the name exists.
pub(crate) fn create_temp(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Opens a file for a verification read. Returns the handle and whether the
/// read bypasses the page cache (`O_DIRECT`). Where it does not, the page
/// cache is asked to drop the file first, which is advisory only.
pub(crate) fn open_for_verify(path: &Path) -> io::Result<(File, bool)> {
    let (file, unbuffered) = open_direct(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((file, unbuffered))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_direct(path: &Path) -> io::Result<(File, bool)> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => Ok((f, true)),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => open_buffered(path).map(|f| (f, false)),
        Err(e) => Err(e),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_direct(path: &Path) -> io::Result<(File, bool)> {
    open_buffered(path).map(|f| (f, false))
}

/// Opens a file for an ordinary (cached) verification read.
pub(crate) fn open_buffered(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: the descriptor is open. The call is advisory; its result is irrelevant.
        unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the descriptor is open. The call is advisory; its result is irrelevant.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1) };
    }
    Ok(file)
}

/// True if a read error means "this file system cannot do direct I/O", in
/// which case the caller retries with a cached read.
pub(crate) fn is_direct_io_unsupported(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EINVAL)
}

/// Renames without ever replacing an existing file.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        const RENAME_NOREPLACE: libc::c_uint = 1;
        let from_c = c_path(from)?;
        let to_c = c_path(to)?;
        // SAFETY: both strings are NUL-terminated; the syscall takes
        // (olddirfd, oldpath, newdirfd, newpath, flags).
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from_c.as_ptr(),
                libc::AT_FDCWD,
                to_c.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if r == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        // Old kernels and some file systems lack the flag: fall back below.
        if !matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
            return Err(err);
        }
    }
    // Portable no-replace rename: creating a hard link fails if the target
    // exists, and is atomic. Then drop the old name. If dropping it fails the
    // file is nevertheless in place; the leftover temp name is removed by the
    // caller or by the next recovery pass.
    std::fs::hard_link(from, to)?;
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// Flushes a file's data and metadata to disk.
pub(crate) fn sync_file(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    file.sync_all()
}

/// Flushes a directory's entries to disk.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Takes the store's exclusive lock. `WouldBlock` means another instance holds it.
pub(crate) fn acquire_lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    // SAFETY: the descriptor is open.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        return Err(if err.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "the lock is held by another instance",
            )
        } else {
            err
        });
    }
    Ok(file)
}

/// No hidden attribute on Unix; the leading dot already hides the directory.
pub(crate) fn hide(_path: &Path) {}
