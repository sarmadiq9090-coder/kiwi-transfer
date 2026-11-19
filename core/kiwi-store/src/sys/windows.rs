//! Windows implementation (the real target).

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileW, GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, MoveFileExW, SetFileAttributesW,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_WRITE_THROUGH, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
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
            || (upper.starts_with(r"\\")
                && !upper.starts_with(r"\\?\")
                && !upper.starts_with(r"\\.\"))
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
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            volume_root.as_ptr(),
            guid.as_mut_ptr(),
            guid.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // `\\?\Volume{GUID}\` names the root directory; without the trailing
    // backslash it names the volume device.
    let name = from_wide(&guid);
    let device = name.trim_end_matches('\\');
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(device)
}

fn query_device_descriptor(device: &File) -> Option<StorageDeviceDescriptor> {
    let query = StoragePropertyQuery {
        property_id: 0,
        query_type: 0,
        additional_parameters: [0; 4],
    };
    // The descriptor is followed by variable-length strings; a larger buffer
    // lets drivers that insist on returning them succeed.
    #[repr(C, align(8))]
    struct Out {
        head: StorageDeviceDescriptor,
        tail: [u8; 1024],
    }
    let mut out = Out {
        head: StorageDeviceDescriptor::default(),
        tail: [0; 1024],
    };
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
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            w.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
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
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

const FILE_ATTRIBUTE_PINNED: u32 = 0x0008_0000;
const FILE_ATTRIBUTE_UNPINNED: u32 = 0x0010_0000;

/// Signs that a directory is managed by a cloud-files provider (OneDrive
/// Files On-Demand and the like): placeholder attributes, or a reparse tag
/// from the cloud-files range.
pub(crate) fn cloud_evidence(dir: &Path) -> Option<String> {
    let attrs = std::fs::symlink_metadata(dir).ok()?.file_attributes();
    let placeholder = FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        | FILE_ATTRIBUTE_PINNED
        | FILE_ATTRIBUTE_UNPINNED;
    if attrs & placeholder != 0 {
        return Some(format!(
            "cloud placeholder attributes (0x{:x})",
            attrs & placeholder
        ));
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        let tag = reparse_tag(dir)?;
        // IO_REPARSE_TAG_CLOUD and IO_REPARSE_TAG_CLOUD_1 .. _F.
        if tag & 0xFFFF_0FFF == 0x9000_001A {
            return Some(format!("a cloud-files reparse tag (0x{tag:08x})"));
        }
    }
    None
}

/// The reparse tag of a path that is a reparse point.
fn reparse_tag(path: &Path) -> Option<u32> {
    let w = wide(path).ok()?;
    // SAFETY: WIN32_FIND_DATAW is plain data; all-zero is a valid value.
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: `w` is NUL-terminated and `data` is a valid out-pointer.
    let handle = unsafe { FindFirstFileW(w.as_ptr(), &mut data) };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: the handle came from FindFirstFileW just above.
    unsafe { FindClose(handle) };
    (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(data.dwReserved0)
}

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x08;
/// Rights that let their holder change or remove what is in a folder:
/// FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, DELETE,
/// WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
const WRITE_RIGHTS: u32 =
    0x2 | 0x4 | 0x40 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000 | 0x4000_0000;

/// Accounts that are expected to have full access: SYSTEM, the
/// Administrators group, CREATOR OWNER, OWNER RIGHTS and TrustedInstaller.
const TRUSTED_SIDS: &[&str] = &[
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-3-0",
    "S-1-3-4",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points at a valid SID; `text` receives a LocalAlloc'ed string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `text` is a NUL-terminated string that we own.
    let out = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        s
    };
    Ok(out)
}

fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle is always valid; `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER followed by the SID it points at; 8-byte aligned storage.
    let mut buf = [0u64; 32];
    let mut returned = 0u32;
    // SAFETY: the buffer is valid for its stated size; the token is open.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            std::mem::size_of_val(&buf) as u32,
            &mut returned,
        )
    };
    let err = io::Error::last_os_error();
    // SAFETY: the token handle is open and owned here.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(err);
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
    // pointer points into the same buffer.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_to_string(sid)
}

fn describe_sid(sid: &str) -> String {
    let name = match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-5-4" => "Interactive users",
        "S-1-5-7" => "Anonymous",
        _ => return sid.to_owned(),
    };
    format!("{name} ({sid})")
}

/// Who besides the current user, the system and the administrators may write
/// to (or delete from) `path`, according to its access control list. Deny
/// entries are not evaluated: an account listed here may still be denied,
/// never the other way round.
pub(crate) fn other_writers(path: &Path) -> io::Result<Vec<String>> {
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor was allocated by GetNamedSecurityInfoW.
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    let w = wide(path)?;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `w` is NUL-terminated; the out-pointers are valid; the others may be null.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _descriptor = Descriptor(descriptor);
    if dacl.is_null() {
        return Ok(vec![
            "Everyone (the folder has no access list at all)".to_owned()
        ]);
    }
    let me = current_user_sid()?;
    let mut out = Vec::new();
    // SAFETY: `dacl` points into the descriptor, which lives until the end of this function.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `dacl` is valid and `ace` is a valid out-pointer.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            continue;
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // SAFETY: an ACE of this type is an ACCESS_ALLOWED_ACE.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask & WRITE_RIGHTS == 0 {
            continue;
        }
        // The SID starts where the `SidStart` field is.
        let sid: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        let text = sid_to_string(sid)?;
        if text != me && !TRUSTED_SIDS.contains(&text.as_str()) {
            out.push(describe_sid(&text));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// True for files carrying the hidden or the system attribute.
pub(crate) fn is_hidden(meta: &Metadata) -> bool {
    meta.file_attributes() & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0
}

/// Creates a new file for writing; fails if the name exists.
pub(crate) fn create_temp(path: &Path) -> io::Result<File> {
    // Others may read (antivirus, indexer) but not write or delete while the
    // file is being received.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Opens a file for a verification read that bypasses the operating system's
/// cache. Returns the handle and whether the read is truly unbuffered.
pub(crate) fn open_for_verify(path: &Path) -> io::Result<(File, bool)> {
    match open_checked(path, FILE_FLAG_NO_BUFFERING) {
        Ok(f) => Ok((f, true)),
        // A file system that does not implement unbuffered I/O. The read is
        // still performed, but it is reported as buffered, and nothing that
        // gates deletion accepts a buffered read.
        Err(e) if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER) => {
            open_buffered(path).map(|f| (f, false))
        }
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the file is a reparse point",
        ));
    }
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
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
        let transient = matches!(
            err.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        );
        attempt += 1;
        if !transient || attempt >= 6 {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(40 * attempt));
    }
}

/// Flushes a file under its present name (`FlushFileBuffers`). On NTFS and
/// ReFS this forces the log to disk, and with it the rename that gave the
/// file this name: `MOVEFILE_WRITE_THROUGH` promises that only for a move
/// done as copy and delete, not for a rename within a volume.
pub(crate) fn sync_file(path: &Path) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        // Write access is what FlushFileBuffers asks for; nothing is written.
        let opened = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path);
        match opened {
            Ok(file) => {
                let meta = file.metadata()?;
                if is_reparse(&meta) || !meta.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "not a regular file",
                    ));
                }
                return file.sync_all();
            }
            Err(err) => {
                // A scanner or indexer may briefly hold the freshly renamed file.
                let transient = matches!(
                    err.raw_os_error(),
                    Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                );
                attempt += 1;
                if !transient || attempt >= 6 {
                    return Err(err);
                }
                std::thread::sleep(Duration::from_millis(40 * attempt));
            }
        }
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
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the lock is held by another instance",
        )),
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
