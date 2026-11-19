//! Windows implementation (the real target).

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::destination::{BusKind, DriveKind, VolumeInfo};

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_STORAGE_GET_HOTPLUG_INFO: u32 = 0x002D_0C14;

const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_INVALID_PARAMETER: i32 = 87;

// The device-control structures are declared here with `u8` in place of
// BOOLEAN: a driver may return any non-zero byte for "true", and reading such
// a byte as a Rust `bool` would be undefined behaviour.

/// STORAGE_PROPERTY_QUERY for StorageDeviceProperty / PropertyStandardQuery.
#[repr(C)]
struct StoragePropertyQuery {
    property_id: i32,
    query_type: i32,
    additional_parameters: [u8; 4],
}

/// The fixed head of STORAGE_DEVICE_DESCRIPTOR.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct StorageDeviceDescriptor {
    version: u32,
    size: u32,
    device_type: u8,
    device_type_modifier: u8,
    removable_media: u8,
    command_queueing: u8,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    bus_type: i32,
    raw_properties_length: u32,
}

/// STORAGE_HOTPLUG_INFO.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct StorageHotplugInfo {
    size: u32,
    media_removable: u8,
    media_hotplug: u8,
    device_hotplug: u8,
    write_cache_enable_override: u8,
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL character"));
    }
    w.push(0);
    Ok(w)
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Identifies and describes the volume holding `path` (which must exist).
pub(crate) fn probe_volume(path: &Path) -> io::Result<VolumeInfo> {
    let w = wide(path)?;
    // The volume path is never longer than the path it was derived from.
    let mut vol = vec![0u16; w.len() + 8];
    // SAFETY: both pointers are valid NUL-terminated / writable buffers of the stated length.
    if unsafe { GetVolumePathNameW(w.as_ptr(), vol.as_mut_ptr(), vol.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let volume_root = from_wide(&vol);

    // SAFETY: `vol` is NUL-terminated.
    let drive_type = unsafe { GetDriveTypeW(vol.as_ptr()) };
    let is_unc = {
        let upper = volume_root.to_ascii_uppercase();
        upper.starts_with(r"\\?\UNC\")
            || (upper.starts_with(r"\\") && !upper.starts_with(r"\\?\") && !upper.starts_with(r"\\.\"))
    };
    let drive = if is_unc {
        DriveKind::Remote
    } else {
        match drive_type {
            DRIVE_FIXED => DriveKind::Fixed,
            DRIVE_REMOVABLE => DriveKind::Removable,
            DRIVE_REMOTE => DriveKind::Remote,
            DRIVE_CDROM => DriveKind::CdRom,
            DRIVE_RAMDISK => DriveKind::RamDisk,
            _ => DriveKind::Unknown,
        }
    };

    let mut serial = 0u32;
    let mut max_component = 0u32;
    let mut flags = 0u32;
    let mut fs_name = [0u16; 64];
    // SAFETY: all out-pointers are valid for the duration of the call.
    let ok = unsafe {
        GetVolumeInformationW(
            vol.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            &mut max_component,
            &mut flags,
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut info = VolumeInfo {
        drive,
        filesystem: from_wide(&fs_name),
        serial: Some(u64::from(serial)),
        read_only: flags & FILE_READ_ONLY_VOLUME != 0,
        removable_media: None,
        hot_plug: None,
        bus: None,
        volume_root,
    };

    if matches!(drive, DriveKind::Fixed | DriveKind::Removable) {
        // Best effort: when the device cannot be queried the fields stay
        // `None`, and the classifier treats "unknown" as "not proven fixed".
        if let Ok(device) = open_volume_device(&vol) {
            if let Some(d) = query_device_descriptor(&device) {
                info.removable_media = Some(d.removable_media != 0);
                info.bus = Some(bus_kind(d.bus_type));
            }
            if let Some(h) = query_hotplug(&device) {
                info.hot_plug = Some(h.device_hotplug != 0 || h.media_hotplug != 0);
                if h.media_removable != 0 {
                    info.removable_media = Some(true);
                }
            }
        }
    }
    Ok(info)
}

/// Opens the volume device (no access rights: enough for the two property
/// queries, and it needs no elevation).
fn open_volume_device(volume_root: &[u16]) -> io::Result<File> {
    let mut guid = [0u16; 64];
    // SAFETY: `volume_root` is NUL-terminated and `guid` is writable for its length.
    if unsafe { GetVolumeNameForVolumeMountPointW(volume_root.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // `\\?\Volume{GUID}\` names the root directory; without the trailing
    // backslash it names the volume device.
    let name = from_wide(&guid);
    let device = name.trim_end_matches('\\');
    OpenOptions::new().access_mode(0).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).open(device)
}

fn query_device_descriptor(device: &File) -> Option<StorageDeviceDescriptor> {
    let query = StoragePropertyQuery { property_id: 0, query_type: 0, additional_parameters: [0; 4] };
    // The descriptor is followed by variable-length strings; a larger buffer
    // lets drivers that insist on returning them succeed.
    #[repr(C, align(8))]
    struct Out {
        head: StorageDeviceDescriptor,
        tail: [u8; 1024],
    }
    let mut out = Out { head: StorageDeviceDescriptor::default(), tail: [0; 1024] };
    let mut returned = 0u32;
    // SAFETY: the in/out buffers are valid for the stated sizes; the handle is open.
    let ok = unsafe {
        DeviceIoControl(
            device.as_raw_handle() as _,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const StoragePropertyQuery).cast(),
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            (&mut out as *mut Out).cast(),
            std::mem::size_of::<Out>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let _ = out.tail;
    if ok == 0 || (returned as usize) < std::mem::size_of::<StorageDeviceDescriptor>() {
        return None;
    }
    Some(out.head)
}

fn query_hotplug(device: &File) -> Option<StorageHotplugInfo> {
    let mut out = StorageHotplugInfo::default();
    let mut returned = 0u32;
    // SAFETY: the out buffer is valid for the stated size; the handle is open.
    let ok = unsafe {
        DeviceIoControl(
            device.as_raw_handle() as _,
            IOCTL_STORAGE_GET_HOTPLUG_INFO,
            std::ptr::null(),
            0,
            (&mut out as *mut StorageHotplugInfo).cast(),
            std::mem::size_of::<StorageHotplugInfo>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || (returned as usize) < std::mem::size_of::<StorageHotplugInfo>() {
        return None;
    }
    Some(out)
}

fn bus_kind(raw: i32) -> BusKind {
    match raw {
        1 => BusKind::Scsi,
        3 => BusKind::Ata,
        4 => BusKind::Ieee1394,
        7 => BusKind::Usb,
        8 => BusKind::Raid,
        9 => BusKind::IScsi,
        10 => BusKind::Sas,
        11 => BusKind::Sata,
        12 => BusKind::Sd,
        13 => BusKind::Mmc,
        14 => BusKind::Virtual,
        15 => BusKind::FileBackedVirtual,
        16 => BusKind::StorageSpaces,
        17 => BusKind::Nvme,
        other => BusKind::Other(other),
    }
}

/// Bytes available to the current user on the volume holding `dir`.
pub(crate) fn free_space(dir: &Path) -> io::Result<u64> {
    let w = wide(dir)?;
    let mut available = 0u64;
    // SAFETY: `w` is NUL-terminated; the out-pointer is valid; the others may be null.
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut available, std::ptr::null_mut(), std::ptr::null_mut()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(available)
}

/// True for junctions, symbolic links, mount points and every other reparse point.
pub(crate) fn is_reparse(meta: &Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// True when the data is not (or may not be) on the local disk: cloud
/// placeholders and hierarchical-storage stubs. Reading such a file would
/// silently fetch it from somewhere else, which proves nothing about the disk.
pub(crate) fn is_offline(meta: &Metadata) -> bool {
    meta.file_attributes()
        & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

/// Creates a new file for writing; fails if the name exists.
pub(crate) fn create_temp(path: &Path) -> io::Result<File> {
    // Others may read (antivirus, indexer) but not write or delete while the
    // file is being received.
    OpenOptions::new().write(true).create_new(true).share_mode(FILE_SHARE_READ).open(path)
}

/// Opens a file for a verification read that bypasses the operating system's
/// cache. Returns the handle and whether the read is truly unbuffered.
pub(crate) fn open_for_verify(path: &Path) -> io::Result<(File, bool)> {
    match open_checked(path, FILE_FLAG_NO_BUFFERING) {
        Ok(f) => Ok((f, true)),
        // A file system that does not implement unbuffered I/O. The read is
        // still performed, but it is reported as buffered, and nothing that
        // gates deletion accepts a buffered read.
        Err(e) if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER) => open_buffered(path).map(|f| (f, false)),
        Err(e) => Err(e),
    }
}

/// Opens a file for an ordinary (cached) verification read.
pub(crate) fn open_buffered(path: &Path) -> io::Result<File> {
    open_checked(path, 0)
}

fn open_checked(path: &Path, flags: u32) -> io::Result<File> {
    // Nobody may write to the file while it is being hashed. Opening the
    // reparse point itself (rather than its target) means a link that was
    // swapped in at the last moment is detected instead of followed.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(flags | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = file.metadata()?;
    if is_reparse(&meta) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the file is a reparse point"));
    }
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(file)
}

/// Windows reports an unsupported unbuffered open at open time, which
/// [`open_for_verify`] already handles; no read error means "retry buffered".
pub(crate) fn is_direct_io_unsupported(_err: &io::Error) -> bool {
    false
}

/// Renames within a directory without ever replacing an existing file, and
/// does not return until the rename has been written through.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let from_w = wide(from)?;
    let to_w = wide(to)?;
    let mut attempt = 0;
    loop {
        // SAFETY: both strings are NUL-terminated. MOVEFILE_REPLACE_EXISTING
        // and MOVEFILE_COPY_ALLOWED are deliberately absent.
        if unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        // A scanner or indexer may briefly hold the freshly written file.
        let transient = matches!(err.raw_os_error(), Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION));
        attempt += 1;
        if !transient || attempt >= 6 {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(40 * attempt));
    }
}

/// Flushes a directory's metadata to disk.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    let handle = OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?;
    handle.sync_all()
}

/// Takes the store's exclusive lock. `WouldBlock` means another instance holds it.
pub(crate) fn acquire_lock(path: &Path) -> io::Result<File> {
    match OpenOptions::new().read(true).write(true).create(true).truncate(false).share_mode(0).open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "the lock is held by another instance"))
        }
        Err(e) => Err(e),
    }
}

/// Marks the engine's own bookkeeping directory hidden (cosmetic, best effort).
pub(crate) fn hide(path: &Path) {
    if let Ok(w) = wide(path) {
        // SAFETY: `w` is NUL-terminated.
        unsafe { SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_HIDDEN) };
    }
}
