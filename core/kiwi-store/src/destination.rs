//! The destination: the folder files are stored under, and the volume it is on.
//!
//! The one question that matters here is whether the phone may ever be told
//! to delete its copy ("final move"). That is allowed only on a volume the
//! engine can positively identify as a fixed internal disk formatted with a
//! journaling Windows file system (NTFS or ReFS). Everything else (USB disks,
//! memory cards, network shares, FAT/exFAT, virtual disks, anything that
//! cannot be identified) is *copy-only*: files are stored and verified there
//! with the same care, but the engine never confirms a deletion.
//!
//! The folder itself matters too. A folder that a cloud-sync program manages
//! (OneDrive, Dropbox, Google Drive, ...) can turn a stored file into an
//! online-only placeholder or delete it when it is deleted elsewhere; a
//! folder Windows cleans up by itself (Downloads with Storage Sense, the temp
//! folders, the recycle bin) loses files on a schedule. Both are copy-only,
//! with a typed [`DestinationWarning`]. A folder other Windows accounts may
//! write to is reported as a warning as well.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::sys;

/// What `GetDriveTypeW` says about the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveKind {
    /// A fixed disk according to Windows. USB hard disks also report this;
    /// see [`BusKind`].
    Fixed,
    /// Removable media (memory card reader, USB stick, floppy).
    Removable,
    /// A network share.
    Remote,
    /// Optical drive.
    CdRom,
    /// RAM disk.
    RamDisk,
    /// Could not be determined (always the case on non-Windows platforms).
    Unknown,
}

/// The bus the volume's disk is attached through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    /// SATA.
    Sata,
    /// Parallel ATA / legacy IDE.
    Ata,
    /// NVMe.
    Nvme,
    /// SCSI.
    Scsi,
    /// Serial attached SCSI.
    Sas,
    /// Hardware or firmware RAID.
    Raid,
    /// USB (external).
    Usb,
    /// FireWire (external).
    Ieee1394,
    /// SD card.
    Sd,
    /// MMC / eMMC.
    Mmc,
    /// iSCSI (a network disk that looks local).
    IScsi,
    /// A virtual disk.
    Virtual,
    /// A virtual disk backed by a file (VHD/VHDX).
    FileBackedVirtual,
    /// Windows Storage Spaces.
    StorageSpaces,
    /// Any other bus type, with the raw `STORAGE_BUS_TYPE` value.
    Other(i32),
}

/// Facts gathered about the destination's volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Drive type.
    pub drive: DriveKind,
    /// File system name as the operating system reports it (`NTFS`, `exFAT`, ...).
    pub filesystem: String,
    /// Volume serial number (Windows) or device id (Unix), when known.
    pub serial: Option<u64>,
    /// The volume is mounted read-only.
    pub read_only: bool,
    /// The device reports removable media. `None` if it could not be asked.
    pub removable_media: Option<bool>,
    /// The device or its media is flagged hot-pluggable (eSATA, hot-swap
    /// bays, and internal ports whose firmware setting enables hot plug).
    /// `None` if it could not be asked.
    pub hot_plug: Option<bool>,
    /// Bus type. `None` if it could not be asked.
    pub bus: Option<BusKind>,
    /// The volume's mount point as the operating system names it.
    pub volume_root: String,
}

/// Why a destination is copy-only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CopyOnlyReason {
    /// Network share or network disk.
    Network,
    /// Removable media or an external bus (USB, FireWire, SD, MMC).
    Removable,
    /// The disk is flagged hot-pluggable (eSATA, a hot-swap bay, or an
    /// internal port with hot plug enabled in the firmware). It cannot be told
    /// apart from an external disk, so it is treated as one.
    HotPluggable,
    /// The file system is not NTFS or ReFS.
    Filesystem(String),
    /// The volume is read-only.
    ReadOnly,
    /// A virtual or file-backed disk: its durability is that of something else.
    VirtualDisk,
    /// Not a disk the engine recognises (optical, RAM disk, unknown).
    UnrecognisedDrive,
    /// The device would not say what it is. Unknown is not "fixed".
    DeviceUnidentified,
    /// The platform has no volume classification (anything but Windows).
    PlatformUnsupported,
    /// The folder is inside a folder a cloud-sync program manages.
    SyncFolder(SyncProvider),
    /// The folder is inside a folder the system empties by itself.
    ManagedFolder(ManagedFolder),
}

/// A program that keeps a folder in step with a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncProvider {
    /// Microsoft OneDrive.
    OneDrive,
    /// Dropbox.
    Dropbox,
    /// Google Drive.
    GoogleDrive,
    /// Apple iCloud Drive.
    ICloud,
    /// Nextcloud or ownCloud.
    Nextcloud,
    /// Syncthing.
    Syncthing,
    /// Resilio Sync.
    Resilio,
    /// A Windows cloud-files sync root or placeholder of a provider that
    /// could not be named.
    CloudFiles,
}

/// A folder the operating system empties without being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedFolder {
    /// The user's Downloads folder (Windows Storage Sense can delete old
    /// files there).
    Downloads,
    /// A temp folder.
    Temp,
    /// The recycle bin.
    RecycleBin,
}

/// Something about the destination folder the user should be told.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DestinationWarning {
    /// The folder is inside a cloud-synced folder. Files are stored here, but
    /// a deletion is never confirmed.
    SyncFolder {
        /// The program that manages the folder.
        provider: SyncProvider,
        /// What gave it away.
        evidence: String,
    },
    /// The folder is inside a folder the system empties by itself. Files are
    /// stored here, but a deletion is never confirmed.
    ManagedFolder {
        /// Which kind.
        kind: ManagedFolder,
        /// The folder in question.
        folder: PathBuf,
    },
    /// Accounts other than the current user, the system and the
    /// administrators may write to (and so delete from) the folder.
    WritableByOthers {
        /// Who, as far as they could be named.
        principals: Vec<String>,
    },
    /// The folder's access list could not be read, so nothing is known about
    /// who else may write to it.
    AccessListUnreadable(String),
}

impl fmt::Display for DestinationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyncFolder { provider, evidence } => write!(
                f,
                "the destination is inside a folder synced by {provider:?} ({evidence})"
            ),
            Self::ManagedFolder { kind, folder } => write!(
                f,
                "the destination is inside {folder:?}, which the system empties by itself ({kind:?})"
            ),
            Self::WritableByOthers { principals } => write!(
                f,
                "other accounts may change or delete files in the destination: {}",
                principals.join(", ")
            ),
            Self::AccessListUnreadable(why) => {
                write!(f, "the destination's access list could not be read ({why})")
            }
        }
    }
}

/// Marker files and folders sync programs leave in the folders they manage.
const SYNC_MARKERS: &[(SyncProvider, &str)] = &[
    (SyncProvider::Dropbox, ".dropbox"),
    (SyncProvider::Dropbox, ".dropbox.cache"),
    (SyncProvider::GoogleDrive, ".tmp.driveupload"),
    (SyncProvider::GoogleDrive, ".tmp.drivedownload"),
    (SyncProvider::Nextcloud, ".owncloudsync.log"),
    (SyncProvider::Nextcloud, ".nextcloudsync.log"),
    (SyncProvider::Nextcloud, ".sync-exclude.lst"),
    (SyncProvider::Syncthing, ".stfolder"),
    (SyncProvider::Syncthing, ".stignore"),
    (SyncProvider::Resilio, ".sync/ID"),
];

/// Where the known dangerous folders are. Taken from the environment by
/// [`HazardEnv::from_system`]; tests supply their own.
#[derive(Debug, Clone, Default)]
pub struct HazardEnv {
    /// Roots of cloud-synced folders known from the environment.
    pub sync_roots: Vec<(SyncProvider, PathBuf)>,
    /// Folders the system empties by itself.
    pub managed: Vec<(ManagedFolder, PathBuf)>,
    /// Sync markers are looked for in the destination and every folder above
    /// it, up to and including this one (`None`: up to the volume root).
    pub ceiling: Option<PathBuf>,
    /// Read the destination's access list.
    pub check_access: bool,
}

impl HazardEnv {
    /// What this machine's environment says.
    pub fn from_system() -> HazardEnv {
        let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
        let resolved = |p: PathBuf| std::fs::canonicalize(&p).unwrap_or(p);
        let mut env = HazardEnv {
            check_access: true,
            ..HazardEnv::default()
        };
        for name in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Some(root) = var(name) {
                env.sync_roots
                    .push((SyncProvider::OneDrive, resolved(root)));
            }
        }
        let home = var("USERPROFILE").or_else(|| var("HOME"));
        if let Some(home) = &home {
            for name in ["iCloudDrive", "iCloud Drive"] {
                env.sync_roots
                    .push((SyncProvider::ICloud, resolved(home.join(name))));
            }
            env.managed
                .push((ManagedFolder::Downloads, resolved(home.join("Downloads"))));
        }
        let mut temps = vec![std::env::temp_dir()];
        temps.extend(var("TEMP"));
        temps.extend(var("TMP"));
        temps.extend(var("LOCALAPPDATA").map(|p| p.join("Temp")));
        temps.extend(var("SystemRoot").map(|p| p.join("Temp")));
        if cfg!(unix) {
            temps.push(PathBuf::from("/tmp"));
            temps.push(PathBuf::from("/var/tmp"));
        }
        for temp in temps {
            env.managed.push((ManagedFolder::Temp, resolved(temp)));
        }
        env
    }
}

/// The components of a path, folded the way a case-insensitive file system
/// compares names, without the verbatim prefix.
fn folded_components(path: &Path) -> Vec<String> {
    display_path(path)
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .map(crate::sanitize::collision_key)
        .collect()
}

/// Whether `child` is `parent` or lies below it.
fn is_same_or_under(child: &Path, parent: &Path) -> bool {
    let (child, parent) = (folded_components(child), folded_components(parent));
    !parent.is_empty() && child.len() >= parent.len() && child[..parent.len()] == parent[..]
}

/// Looks for the reasons a folder should not hold anybody's only copy.
fn detect_hazards(root: &Path, env: &HazardEnv) -> Vec<DestinationWarning> {
    let mut out: Vec<DestinationWarning> = Vec::new();
    let mut seen: Vec<SyncProvider> = Vec::new();
    let mut sync = |out: &mut Vec<DestinationWarning>, provider: SyncProvider, evidence: String| {
        if !seen.contains(&provider) {
            seen.push(provider);
            out.push(DestinationWarning::SyncFolder { provider, evidence });
        }
    };

    for (provider, sync_root) in &env.sync_roots {
        if is_same_or_under(root, sync_root) {
            let evidence = format!("it is inside {}", display_path(sync_root));
            sync(&mut out, *provider, evidence);
        }
    }
    let mut dir = Some(root);
    while let Some(d) = dir {
        if let Some(ceiling) = &env.ceiling {
            if !is_same_or_under(d, ceiling) {
                break;
            }
        }
        for (provider, marker) in SYNC_MARKERS {
            let mut path = d.to_path_buf();
            for part in marker.split('/') {
                path.push(part);
            }
            if std::fs::symlink_metadata(&path).is_ok() {
                let evidence = format!("{marker} exists in {}", display_path(d));
                sync(&mut out, *provider, evidence);
            }
        }
        if let Some(evidence) = sys::cloud_evidence(d) {
            let evidence = format!("{} has {evidence}", display_path(d));
            sync(&mut out, SyncProvider::CloudFiles, evidence);
        }
        dir = d.parent();
    }

    for (kind, folder) in &env.managed {
        if is_same_or_under(root, folder) {
            out.push(DestinationWarning::ManagedFolder {
                kind: *kind,
                folder: folder.clone(),
            });
            break;
        }
    }
    let in_bin = folded_components(root)
        .iter()
        .any(|part| part == "$recycle.bin" || part == "recycler");
    if in_bin {
        out.push(DestinationWarning::ManagedFolder {
            kind: ManagedFolder::RecycleBin,
            folder: root.to_path_buf(),
        });
    }
    out
}

/// Who else may write to the folder, as a warning (or nothing).
fn access_warning(root: &Path) -> Option<DestinationWarning> {
    match sys::other_writers(root) {
        Ok(principals) if principals.is_empty() => None,
        Ok(principals) => Some(DestinationWarning::WritableByOthers { principals }),
        Err(e) => Some(DestinationWarning::AccessListUnreadable(e.to_string())),
    }
}

/// The volume's verdict, narrowed by what is known about the folder.
fn narrow(volume_verdict: FinalMoveSupport, warnings: &[DestinationWarning]) -> FinalMoveSupport {
    if volume_verdict != FinalMoveSupport::Supported {
        return volume_verdict;
    }
    for warning in warnings {
        match warning {
            DestinationWarning::SyncFolder { provider, .. } => {
                return FinalMoveSupport::CopyOnly(CopyOnlyReason::SyncFolder(*provider))
            }
            DestinationWarning::ManagedFolder { kind, .. } => {
                return FinalMoveSupport::CopyOnly(CopyOnlyReason::ManagedFolder(*kind))
            }
            _ => {}
        }
    }
    FinalMoveSupport::Supported
}

impl fmt::Display for CopyOnlyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => f.write_str("the destination is on a network volume"),
            Self::Removable => f.write_str("the destination is on a removable or external disk"),
            Self::HotPluggable => f.write_str(
                "the destination's disk is flagged hot-pluggable, like an external disk",
            ),
            Self::Filesystem(fs) => {
                write!(f, "the destination's file system is {fs}, not NTFS or ReFS")
            }
            Self::ReadOnly => f.write_str("the destination volume is read-only"),
            Self::VirtualDisk => f.write_str("the destination is on a virtual disk"),
            Self::UnrecognisedDrive => {
                f.write_str("the destination is not on a recognised fixed disk")
            }
            Self::DeviceUnidentified => {
                f.write_str("the destination's disk could not be identified")
            }
            Self::PlatformUnsupported => {
                f.write_str("volume classification is only implemented on Windows")
            }
            Self::SyncFolder(provider) => write!(
                f,
                "the destination is inside a folder synced by {provider:?}"
            ),
            Self::ManagedFolder(kind) => write!(
                f,
                "the destination is inside a folder the system empties by itself ({kind:?})"
            ),
        }
    }
}

/// Whether the phone may ever be told that deleting its copy is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalMoveSupport {
    /// Fixed internal disk with NTFS or ReFS.
    Supported,
    /// Files can be stored here but deletion is never confirmed.
    CopyOnly(CopyOnlyReason),
}

/// Broad class of the destination volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeClass {
    /// Fixed internal disk with NTFS or ReFS.
    FixedNtfsOrRefs,
    /// Removable media or an external disk.
    Removable,
    /// Network share or network disk.
    Network,
    /// Anything else: another file system, a virtual disk, an unidentified device.
    Other,
}

/// Applies the final-move policy to the facts about a volume.
///
/// This is a pure function so the policy can be tested without the hardware.
pub fn classify(info: &VolumeInfo) -> (VolumeClass, FinalMoveSupport) {
    use CopyOnlyReason as R;
    let copy_only = |class, reason| (class, FinalMoveSupport::CopyOnly(reason));

    match info.drive {
        DriveKind::Remote => return copy_only(VolumeClass::Network, R::Network),
        DriveKind::Removable => return copy_only(VolumeClass::Removable, R::Removable),
        DriveKind::CdRom | DriveKind::RamDisk => {
            return copy_only(VolumeClass::Other, R::UnrecognisedDrive)
        }
        DriveKind::Unknown => {
            let reason = if cfg!(windows) {
                R::UnrecognisedDrive
            } else {
                R::PlatformUnsupported
            };
            return copy_only(VolumeClass::Other, reason);
        }
        DriveKind::Fixed => {}
    }
    match info.bus {
        Some(BusKind::Usb | BusKind::Ieee1394 | BusKind::Sd | BusKind::Mmc) => {
            return copy_only(VolumeClass::Removable, R::Removable)
        }
        Some(BusKind::IScsi) => return copy_only(VolumeClass::Network, R::Network),
        Some(BusKind::Virtual | BusKind::FileBackedVirtual) => {
            return copy_only(VolumeClass::Other, R::VirtualDisk)
        }
        Some(BusKind::Other(_)) | None => {
            return copy_only(VolumeClass::Other, R::DeviceUnidentified)
        }
        Some(
            BusKind::Sata
            | BusKind::Ata
            | BusKind::Nvme
            | BusKind::Scsi
            | BusKind::Sas
            | BusKind::Raid
            | BusKind::StorageSpaces,
        ) => {}
    }
    match info.removable_media {
        Some(false) => {}
        Some(true) => return copy_only(VolumeClass::Removable, R::Removable),
        None => return copy_only(VolumeClass::Other, R::DeviceUnidentified),
    }
    match info.hot_plug {
        Some(false) => {}
        Some(true) => return copy_only(VolumeClass::Removable, R::HotPluggable),
        None => return copy_only(VolumeClass::Other, R::DeviceUnidentified),
    }
    let fs = info.filesystem.to_ascii_uppercase();
    if fs != "NTFS" && fs != "REFS" {
        return copy_only(VolumeClass::Other, R::Filesystem(info.filesystem.clone()));
    }
    if info.read_only {
        return copy_only(VolumeClass::Other, R::ReadOnly);
    }
    (VolumeClass::FixedNtfsOrRefs, FinalMoveSupport::Supported)
}

/// Why a destination could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DestinationError {
    /// The root path is not absolute.
    #[error("the destination {0:?} is not an absolute path")]
    NotAbsolute(PathBuf),
    /// The root does not exist or cannot be resolved.
    #[error("the destination {path:?} cannot be opened: {source}")]
    Unavailable {
        /// The path as given.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The root exists but is not a directory.
    #[error("the destination {0:?} is not a directory")]
    NotADirectory(PathBuf),
    /// The volume could not be examined.
    #[error("the volume of {path:?} cannot be examined: {source}")]
    Probe {
        /// The resolved root.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A validated destination root and what is known about its volume.
#[derive(Debug, Clone)]
pub struct Destination {
    root: PathBuf,
    volume: VolumeInfo,
    class: VolumeClass,
    final_move: FinalMoveSupport,
    warnings: Vec<DestinationWarning>,
    env: HazardEnv,
    /// The volume facts were supplied by a test and are not re-read.
    volume_forced: bool,
}

impl Destination {
    /// Validates `root` and classifies its volume.
    ///
    /// The root must be an existing directory given as an absolute path. It is
    /// resolved once (symbolic links and junctions *above* the root are the
    /// user's own choice and are followed here); everything the engine does
    /// afterwards happens strictly below the resolved root, where no reparse
    /// point is ever followed.
    pub fn open(root: &Path) -> Result<Destination, DestinationError> {
        if !root.is_absolute() {
            return Err(DestinationError::NotAbsolute(root.to_path_buf()));
        }
        let resolved =
            std::fs::canonicalize(root).map_err(|source| DestinationError::Unavailable {
                path: root.to_path_buf(),
                source,
            })?;
        let meta = std::fs::symlink_metadata(&resolved).map_err(|source| {
            DestinationError::Unavailable {
                path: root.to_path_buf(),
                source,
            }
        })?;
        if !meta.is_dir() {
            return Err(DestinationError::NotADirectory(root.to_path_buf()));
        }
        let volume = sys::probe_volume(&resolved).map_err(|source| DestinationError::Probe {
            path: resolved.clone(),
            source,
        })?;
        let (class, volume_verdict) = classify(&volume);
        let env = HazardEnv::from_system();
        let mut warnings = detect_hazards(&resolved, &env);
        if env.check_access {
            warnings.extend(access_warning(&resolved));
        }
        Ok(Destination {
            final_move: narrow(volume_verdict, &warnings),
            root: resolved,
            volume,
            class,
            warnings,
            env,
            volume_forced: false,
        })
    }

    /// Replaces what the platform said about the volume. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_volume_for_testing(mut self, volume: VolumeInfo) -> Destination {
        let (class, volume_verdict) = classify(&volume);
        self.volume = volume;
        self.class = class;
        self.final_move = narrow(volume_verdict, &self.warnings);
        self.volume_forced = true;
        self
    }

    /// Replaces where the dangerous folders are looked for, and looks again.
    pub(crate) fn with_hazard_env(mut self, env: HazardEnv) -> Destination {
        let mut warnings = detect_hazards(&self.root, &env);
        if env.check_access {
            warnings.extend(access_warning(&self.root));
        }
        self.final_move = narrow(classify(&self.volume).1, &warnings);
        self.warnings = warnings;
        self.env = env;
        self
    }

    /// What the user should be told about this folder: it is cloud-synced, it
    /// is emptied by the system, or other accounts may write to it.
    pub fn warnings(&self) -> &[DestinationWarning] {
        &self.warnings
    }

    /// The resolved root. On Windows this is a verbatim (`\\?\`) path, which
    /// is what makes long paths work; use [`Destination::display_root`] for
    /// anything shown to a person.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The root in the form people expect to read (`E:\Photos`, `\\server\share\Photos`).
    pub fn display_root(&self) -> String {
        display_path(&self.root)
    }

    /// What is known about the volume.
    pub fn volume(&self) -> &VolumeInfo {
        &self.volume
    }

    /// Broad class of the volume.
    pub fn class(&self) -> VolumeClass {
        self.class
    }

    /// Whether, and if not why not, deletions may be confirmed here.
    pub fn final_move_support(&self) -> &FinalMoveSupport {
        &self.final_move
    }

    /// True only for a fixed internal NTFS or ReFS volume.
    pub fn supports_final_move(&self) -> bool {
        self.final_move == FinalMoveSupport::Supported
    }

    /// Bytes currently available to the user on the destination volume.
    pub fn free_space(&self) -> std::io::Result<u64> {
        sys::free_space(&self.root)
    }

    /// Examines the root again. Used before confirming a deletion: the disk
    /// behind a drive letter can change while the program is running.
    pub fn reprobe(&self) -> Result<Destination, DestinationError> {
        let meta = std::fs::symlink_metadata(&self.root).map_err(|source| {
            DestinationError::Unavailable {
                path: self.root.clone(),
                source,
            }
        })?;
        if !meta.is_dir() || sys::is_reparse(&meta) {
            return Err(DestinationError::NotADirectory(self.root.clone()));
        }
        let volume = if self.volume_forced {
            self.volume.clone()
        } else {
            sys::probe_volume(&self.root).map_err(|source| DestinationError::Probe {
                path: self.root.clone(),
                source,
            })?
        };
        let (class, volume_verdict) = classify(&volume);
        // The folder is looked at again as well: a sync program may have been
        // pointed at it since. The access list is not read again; who may
        // write is a note for the user, not part of the verdict.
        let mut warnings = detect_hazards(&self.root, &self.env);
        warnings.extend(
            self.warnings
                .iter()
                .filter(|w| {
                    matches!(
                        w,
                        DestinationWarning::WritableByOthers { .. }
                            | DestinationWarning::AccessListUnreadable(_)
                    )
                })
                .cloned(),
        );
        Ok(Destination {
            root: self.root.clone(),
            final_move: narrow(volume_verdict, &warnings),
            volume,
            class,
            warnings,
            env: self.env.clone(),
            volume_forced: self.volume_forced,
        })
    }
}

/// Strips the verbatim prefix from a Windows path for display.
pub(crate) fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        s.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_ntfs() -> VolumeInfo {
        VolumeInfo {
            drive: DriveKind::Fixed,
            filesystem: "NTFS".into(),
            serial: Some(1),
            read_only: false,
            removable_media: Some(false),
            hot_plug: Some(false),
            bus: Some(BusKind::Sata),
            volume_root: r"\\?\E:\".into(),
        }
    }

    fn reason(info: &VolumeInfo) -> CopyOnlyReason {
        match classify(info).1 {
            FinalMoveSupport::CopyOnly(r) => r,
            FinalMoveSupport::Supported => panic!("{info:?} must be copy-only"),
        }
    }

    #[test]
    fn fixed_internal_ntfs_and_refs_support_final_move() {
        for bus in [
            BusKind::Sata,
            BusKind::Ata,
            BusKind::Nvme,
            BusKind::Scsi,
            BusKind::Sas,
            BusKind::Raid,
            BusKind::StorageSpaces,
        ] {
            for fs in ["NTFS", "ntfs", "ReFS", "REFS"] {
                let info = VolumeInfo {
                    bus: Some(bus),
                    filesystem: fs.into(),
                    ..fixed_ntfs()
                };
                assert_eq!(
                    classify(&info),
                    (VolumeClass::FixedNtfsOrRefs, FinalMoveSupport::Supported),
                    "{bus:?} {fs}"
                );
            }
        }
    }

    #[test]
    fn everything_else_is_copy_only() {
        use CopyOnlyReason as R;
        let v = fixed_ntfs;
        let cases: Vec<(VolumeInfo, VolumeClass, CopyOnlyReason)> = vec![
            (
                VolumeInfo {
                    drive: DriveKind::Remote,
                    ..v()
                },
                VolumeClass::Network,
                R::Network,
            ),
            (
                VolumeInfo {
                    drive: DriveKind::Removable,
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            (
                VolumeInfo {
                    drive: DriveKind::CdRom,
                    ..v()
                },
                VolumeClass::Other,
                R::UnrecognisedDrive,
            ),
            (
                VolumeInfo {
                    drive: DriveKind::RamDisk,
                    ..v()
                },
                VolumeClass::Other,
                R::UnrecognisedDrive,
            ),
            // A USB hard disk reports DRIVE_FIXED; the bus gives it away.
            (
                VolumeInfo {
                    bus: Some(BusKind::Usb),
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::Ieee1394),
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::Sd),
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::Mmc),
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::IScsi),
                    ..v()
                },
                VolumeClass::Network,
                R::Network,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::Virtual),
                    ..v()
                },
                VolumeClass::Other,
                R::VirtualDisk,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::FileBackedVirtual),
                    ..v()
                },
                VolumeClass::Other,
                R::VirtualDisk,
            ),
            (
                VolumeInfo {
                    bus: Some(BusKind::Other(99)),
                    ..v()
                },
                VolumeClass::Other,
                R::DeviceUnidentified,
            ),
            // Unknown is never treated as fixed.
            (
                VolumeInfo { bus: None, ..v() },
                VolumeClass::Other,
                R::DeviceUnidentified,
            ),
            (
                VolumeInfo {
                    removable_media: None,
                    ..v()
                },
                VolumeClass::Other,
                R::DeviceUnidentified,
            ),
            (
                VolumeInfo {
                    removable_media: Some(true),
                    ..v()
                },
                VolumeClass::Removable,
                R::Removable,
            ),
            // eSATA and hot-swap bays look like internal SATA except for this flag.
            (
                VolumeInfo {
                    hot_plug: Some(true),
                    ..v()
                },
                VolumeClass::Removable,
                R::HotPluggable,
            ),
            (
                VolumeInfo {
                    hot_plug: None,
                    ..v()
                },
                VolumeClass::Other,
                R::DeviceUnidentified,
            ),
            (
                VolumeInfo {
                    filesystem: "exFAT".into(),
                    ..v()
                },
                VolumeClass::Other,
                R::Filesystem("exFAT".into()),
            ),
            (
                VolumeInfo {
                    filesystem: "FAT32".into(),
                    ..v()
                },
                VolumeClass::Other,
                R::Filesystem("FAT32".into()),
            ),
            (
                VolumeInfo {
                    filesystem: String::new(),
                    ..v()
                },
                VolumeClass::Other,
                R::Filesystem(String::new()),
            ),
            (
                VolumeInfo {
                    read_only: true,
                    ..v()
                },
                VolumeClass::Other,
                R::ReadOnly,
            ),
        ];
        for (info, class, why) in cases {
            assert_eq!(classify(&info).0, class, "{info:?}");
            assert_eq!(reason(&info), why, "{info:?}");
        }
        // Network wins over everything else that might look reassuring.
        let info = VolumeInfo {
            drive: DriveKind::Remote,
            filesystem: "NTFS".into(),
            ..v()
        };
        assert_eq!(reason(&info), R::Network);
    }

    #[test]
    fn unknown_drive_kind_is_copy_only() {
        let info = VolumeInfo {
            drive: DriveKind::Unknown,
            ..fixed_ntfs()
        };
        let expected = if cfg!(windows) {
            CopyOnlyReason::UnrecognisedDrive
        } else {
            CopyOnlyReason::PlatformUnsupported
        };
        assert_eq!(reason(&info), expected);
    }

    #[test]
    fn display_strips_the_verbatim_prefix() {
        assert_eq!(
            display_path(Path::new(r"\\?\E:\Photos\Kiwi")),
            r"E:\Photos\Kiwi"
        );
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\nas\share\Photos")),
            r"\\nas\share\Photos"
        );
        assert_eq!(display_path(Path::new("/srv/photos")), "/srv/photos");
    }

    #[test]
    fn open_rejects_bad_roots() {
        assert!(matches!(
            Destination::open(Path::new("relative/dir")),
            Err(DestinationError::NotAbsolute(_))
        ));
        let missing = std::env::temp_dir().join("kiwi-store-definitely-missing-4c1f9a");
        assert!(matches!(
            Destination::open(&missing),
            Err(DestinationError::Unavailable { .. })
        ));
        let exe = std::env::current_exe().unwrap();
        assert!(matches!(
            Destination::open(&exe),
            Err(DestinationError::NotADirectory(_))
        ));
    }

    #[test]
    fn open_probes_the_real_volume() {
        // The crate's own directory: read-only use, nothing is written.
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dest = Destination::open(here).unwrap();
        println!("volume of {}: {:?}", dest.display_root(), dest.volume());
        println!(
            "class {:?}, final move {:?}",
            dest.class(),
            dest.final_move_support()
        );
        assert!(dest.root().is_absolute());
        assert!(dest.free_space().unwrap() > 0);
        assert_eq!(dest.reprobe().unwrap().volume(), dest.volume());
        if cfg!(windows) {
            assert!(dest.root().to_string_lossy().starts_with(r"\\?\"));
            assert!(!dest.display_root().starts_with(r"\\?\"));
            assert!(dest.volume().serial.is_some());
            assert!(!dest.volume().filesystem.is_empty());
        } else {
            assert!(!dest.supports_final_move());
        }
    }
}
