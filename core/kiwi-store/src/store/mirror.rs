//! The mirror: a second copy of every stored file on a second disk.
//!
//! A mirror is a folder on another volume, internal or external. Several may
//! be registered (two external disks that take turns, for example). Each
//! holds the stored files under the same relative paths as the destination,
//! so it can be browsed, and used to put files back.
//!
//! ```text
//! run_mirror   for every stored file without a verified copy on the mirror:
//!              read the file from the destination (unbuffered), checking the
//!              whole path and hashing as it is read, and write those very
//!              bytes to a temp file on the mirror
//!              -> the hash of what was read == the ledger's hash?
//!              flush -> reopen UNBUFFERED on the mirror, re-hash
//!              -> the hash of what the mirror gives back == the ledger's hash?
//!              rename, no replace -> flush -> re-read under the final name
//!              -> record in the ledger
//! scan_mirror  re-hash every recorded copy on the mirror; write a missing or
//!              damaged copy again from the destination; then write every
//!              file that is missing or damaged on the destination again
//!              from a mirror copy that has just been re-hashed
//! ```
//!
//! Rules that hold whatever happens:
//!
//! * **Nothing is ever overwritten, moved or deleted**, on either disk. A
//!   repaired file is written next to the damaged one (`photo (2).jpg`) and
//!   the ledger is pointed at the good copy; the damaged file stays where it
//!   is, for a person to look at.
//! * **The ledger's hash is the arbiter.** A copy repairs another only after
//!   it has itself been read back from its disk and matched that hash. If
//!   neither disk has a matching copy, nothing is repaired.
//! * **The wrong disk is never written to.** Before every run the mirror's
//!   marker file (a random id) and its volume serial number are compared
//!   with the ledger; a folder that does not carry the marker is left alone.
//! * **An absent disk is normal.** It is reported with the time since it was
//!   last seen, nothing more.
//! * **A failing disk blocks final move, and copying goes on.** I/O errors
//!   or several mismatching files on either disk set the persistent block.
//! * **Final move does not wait for the mirror** (the owner's decision). The
//!   mirror is a second line of defence; what the phone may delete is decided
//!   from the destination alone. [`Store::oldest_unmirrored_commit`] lets the
//!   application warn while the phone's trash still holds the original.

use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::pipeline::{Adoption, PlaceRequest, Placed, TempSlot, PRIMARY};
use super::scan::{CancelToken, Throttle};
use super::verify::Probe;
use super::{lock, new_destination_id, DeviceId, Inner, Store, STORE_DIR};
use crate::error::{LedgerError, StoreError};
use crate::fsops::{is_hard_io_error, Checkpoint, EntryKind};
use crate::ledger::{
    BlockInfo, BlockKind, FileRecord, FileState, MirrorCopy, MirrorFileRow, MirrorFileState,
    MirrorRecord, NewMirror, Restored,
};
use crate::sanitize::{SafeName, SafeRelPath};
use crate::sys;

/// Name of the marker file inside a mirror's `.kiwi-store` folder.
pub const MIRROR_MARKER_FILE: &str = "mirror";

const MARKER_MAX_BYTES: usize = 512;

/// Most failures and repairs listed individually in one report.
const MAX_LISTED: usize = 200;

/// Identifies a mirror within one store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MirrorId(pub i64);

/// When a disk counts as failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorPolicy {
    /// This many I/O errors from one disk (during one run for the
    /// destination; accumulated until the next clean scan for a mirror) block
    /// final move.
    pub io_errors_to_block: u64,
    /// This many files on one mirror found different from what was written
    /// there block final move. (One changed file on the destination always
    /// blocks.)
    pub mismatches_to_block: u64,
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        MirrorPolicy {
            io_errors_to_block: 3,
            mismatches_to_block: 3,
        }
    }
}

/// Why a mirror could not be set up or addressed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MirrorError {
    /// No mirror has this id.
    #[error("there is no mirror with id {0}")]
    Unknown(i64),
    /// The folder cannot be reached or examined.
    #[error("the mirror folder {path:?} cannot be used: {source}")]
    Unavailable {
        /// The folder (or the file inside it) involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The path is not an absolute path to an existing, plain directory.
    #[error("the mirror folder {0:?} is not an absolute path to a directory")]
    NotADirectory(PathBuf),
    /// The path is not valid Unicode.
    #[error("the mirror folder {0:?} is not valid Unicode")]
    NotUnicode(PathBuf),
    /// The folder is the destination, inside it, or around it.
    #[error("the mirror folder {0:?} overlaps the destination")]
    OverlapsDestination(PathBuf),
    /// The folder is on the destination's own volume.
    #[error(
        "the mirror folder {0:?} is on the same volume as the destination; a second copy on \
         the same disk protects nothing"
    )]
    SameVolume(PathBuf),
    /// The folder already carries a mirror marker this store cannot accept.
    #[error("the folder {path:?} carries a mirror marker that is not this store's ({detail})")]
    ForeignMarker {
        /// The folder.
        path: PathBuf,
        /// What is wrong with the marker.
        detail: String,
    },
}

/// A registered mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorInfo {
    /// Its id in this store.
    pub id: MirrorId,
    /// The random identifier written to its marker file.
    pub uid: String,
    /// Its root folder, as last seen.
    pub root: PathBuf,
    /// Name shown to the user.
    pub label: String,
    /// False once it has been removed. Removed mirrors stay listed for the
    /// audit trail; their copies no longer count.
    pub active: bool,
    /// Serial number of the volume it was created on.
    pub volume_serial: Option<u64>,
    /// Session in which it was last present with the right identity.
    pub last_seen_session: u64,
    /// Wall-clock time of that moment (Unix milliseconds).
    pub last_seen_unix_ms: i64,
    /// I/O errors on it since its last clean scan.
    pub io_errors: u64,
    /// Mismatching files on it since its last clean scan.
    pub mismatches: u64,
}

impl From<MirrorRecord> for MirrorInfo {
    fn from(m: MirrorRecord) -> Self {
        MirrorInfo {
            id: MirrorId(m.id),
            uid: m.uid,
            root: PathBuf::from(m.root),
            label: m.label,
            active: m.active,
            volume_serial: m.volume_serial,
            last_seen_session: m.last_seen_session,
            last_seen_unix_ms: m.last_seen_unix_ms,
            io_errors: m.io_errors,
            mismatches: m.mismatches,
        }
    }
}

/// A mirror that is not connected. This is a normal state for an external
/// disk; the numbers are for reminders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorAbsent {
    /// When it was last present with the right identity (Unix milliseconds).
    pub last_seen_unix_ms: i64,
    /// Seconds since then, by the wall clock.
    pub secs_since_seen: u64,
    /// Sessions begun since then.
    pub sessions_since_seen: u64,
    /// What the operating system said.
    pub detail: String,
}

/// Why the folder at a mirror's path is not that mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrongDisk {
    /// The folder exists but has no mirror marker: another disk is mounted
    /// at this path.
    NoMarker,
    /// The marker could not be read or is not a mirror marker.
    MarkerUnreadable(String),
    /// The marker is another mirror's.
    OtherMirror {
        /// The identifier found.
        found_uid: String,
    },
    /// The marker belongs to a mirror of another destination.
    OtherStore,
    /// The marker is right, but the volume is not the one the mirror was
    /// created on (the folder was copied to another disk).
    VolumeChanged {
        /// Serial number recorded when the mirror was created.
        expected: u64,
        /// Serial number of the volume there now.
        found: Option<u64>,
    },
    /// The path is no longer a plain directory.
    NotAFolder,
}

/// Whether a mirror can be used right now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MirrorPresence {
    /// Connected, and it is the right disk.
    Present,
    /// Not connected.
    Absent(MirrorAbsent),
    /// Something is at its path, but it is not this mirror. Nothing is
    /// written to it.
    WrongDisk(WrongDisk),
}

impl MirrorPresence {
    /// True for [`MirrorPresence::Present`].
    pub fn is_present(&self) -> bool {
        matches!(self, MirrorPresence::Present)
    }
}

/// Files of one device that still have to be copied to one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorPending {
    /// The mirror.
    pub mirror: MirrorId,
    /// The device. A file two devices answer for counts for both.
    pub device: String,
    /// Number of files.
    pub files: u64,
    /// Their total size.
    pub bytes: u64,
}

/// How well one device's files are covered, as of the last checks.
///
/// A "copy" is the file on the destination, if the last check found it
/// intact, plus one for every active mirror whose copy was read back and
/// matched. These are the ledger's beliefs; scans keep them honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopyCounts {
    /// Files with no copy believed good anywhere.
    pub no_copy: u64,
    /// Files with exactly one.
    pub one_copy: u64,
    /// Files with two or more.
    pub two_or_more: u64,
}

/// A device's oldest file that exists on the destination only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmirroredCommit {
    /// Ledger row of the file.
    pub file_id: i64,
    /// Path relative to the destination root.
    pub rel_path: String,
    /// Size in bytes.
    pub size: u64,
    /// The device's commit sequence number for it.
    pub committed_seq: u64,
    /// Session of the device's commit.
    pub committed_session: u64,
    /// Wall-clock time of the device's commit (Unix milliseconds).
    pub committed_unix_ms: i64,
    /// Seconds since then, by the wall clock (negative if the clock is off).
    pub age_secs: i64,
}

/// How to run a mirror run or a mirror scan.
#[derive(Debug, Clone)]
pub struct MirrorOptions {
    /// Only this mirror (`None`: every active mirror).
    pub mirror: Option<MirrorId>,
    /// Read at most this many bytes per second (averaged over the call).
    pub max_bytes_per_sec: Option<u64>,
    /// Stop after this many files in this call; the work stays resumable.
    pub max_files: Option<u64>,
    /// In a scan: write missing and damaged copies again from the other
    /// disk. Without it the scan only reports.
    pub repair: bool,
}

impl Default for MirrorOptions {
    fn default() -> Self {
        MirrorOptions {
            mirror: None,
            max_bytes_per_sec: None,
            max_files: None,
            repair: true,
        }
    }
}

/// One file a run or a scan could not deal with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorFailure {
    /// The file, relative to the destination root.
    pub rel_path: String,
    /// What went wrong.
    pub reason: String,
}

/// What a mirror run did with one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRun {
    /// The mirror.
    pub mirror: MirrorId,
    /// Whether it could be used. If not, nothing else in here is set.
    pub presence: MirrorPresence,
    /// Every stored file now has a verified copy on this mirror.
    pub completed: bool,
    /// Files copied.
    pub copied: u64,
    /// Their total size.
    pub bytes_copied: u64,
    /// Files found already on the mirror with identical content (read to
    /// make sure) and recorded without copying.
    pub already_there: u64,
    /// Files not copied because the destination's own copy is missing,
    /// changed, or could not be read.
    pub skipped_source: u64,
    /// Files that could not be copied (including the skipped ones).
    pub failed: u64,
    /// I/O errors from the mirror during this run.
    pub io_errors: u64,
    /// Copies that did not read back from the mirror as written.
    pub mismatches: u64,
    /// The mirror disappeared while the run was working on it.
    pub removed_mid_run: bool,
    /// The mirror is full.
    pub out_of_space: bool,
    /// Left-over temp files of an earlier, interrupted run that were removed.
    pub temps_removed: u64,
    /// The individual failures (at most 200 are listed).
    pub failures: Vec<MirrorFailure>,
}

impl MirrorRun {
    fn new(id: i64) -> Self {
        MirrorRun {
            mirror: MirrorId(id),
            presence: MirrorPresence::Present,
            completed: false,
            copied: 0,
            bytes_copied: 0,
            already_there: 0,
            skipped_source: 0,
            failed: 0,
            io_errors: 0,
            mismatches: 0,
            removed_mid_run: false,
            out_of_space: false,
            temps_removed: 0,
            failures: Vec::new(),
        }
    }
}

/// Result of [`Store::run_mirror`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRunReport {
    /// One entry per mirror the run looked at.
    pub mirrors: Vec<MirrorRun>,
    /// Every mirror looked at is present and complete.
    pub completed: bool,
    /// I/O errors from the destination during this run.
    pub destination_io_errors: u64,
    /// The final-move block in force after the run, if any.
    pub block: Option<BlockInfo>,
}

/// Which way a repair went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairDirection {
    /// The destination's file was written again from this mirror's copy.
    DestinationFromMirror(MirrorId),
    /// This mirror's copy was written again from the destination's file.
    MirrorFromDestination(MirrorId),
}

/// One repair. Also in the ledger's event log (`primary_repaired`,
/// `mirror_repaired`), where it stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    /// The file as it was recorded, relative to the destination root.
    pub rel_path: String,
    /// Which disk was repaired from which.
    pub direction: RepairDirection,
    /// Where the good copy was written, relative to the repaired disk's
    /// root. It differs from the old path when the damaged file is still in
    /// the way: that file is never touched.
    pub new_rel_path: String,
}

/// What a mirror scan found on one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorScan {
    /// The mirror.
    pub mirror: MirrorId,
    /// Whether it could be used. If not, nothing else in here is set.
    pub presence: MirrorPresence,
    /// Every recorded copy on this mirror was looked at.
    pub completed: bool,
    /// This call continued an earlier, interrupted scan.
    pub resumed: bool,
    /// Copies checked in this call.
    pub files_checked: u64,
    /// Copies that read back and matched.
    pub ok: u64,
    /// Copies found gone.
    pub missing: u64,
    /// Copies found with different content.
    pub changed: u64,
    /// Copies that could not be read (in use, access denied).
    pub unreadable: u64,
    /// Copies behind a link, or with an invalid record.
    pub suspicious: u64,
    /// Copies written again from the destination.
    pub repaired: u64,
    /// Missing or changed copies that could not be written again (the
    /// destination's own copy is not intact either, or the write failed).
    pub unrepairable: u64,
    /// I/O errors from the mirror during this scan.
    pub io_errors: u64,
    /// The mirror disappeared while the scan was working on it.
    pub removed_mid_run: bool,
    /// The individual failures (at most 200 are listed).
    pub failures: Vec<MirrorFailure>,
}

impl MirrorScan {
    fn new(id: i64) -> Self {
        MirrorScan {
            mirror: MirrorId(id),
            presence: MirrorPresence::Present,
            completed: false,
            resumed: false,
            files_checked: 0,
            ok: 0,
            missing: 0,
            changed: 0,
            unreadable: 0,
            suspicious: 0,
            repaired: 0,
            unrepairable: 0,
            io_errors: 0,
            removed_mid_run: false,
            failures: Vec::new(),
        }
    }
}

/// Result of [`Store::scan_mirror`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorScanReport {
    /// One entry per mirror the scan looked at.
    pub mirrors: Vec<MirrorScan>,
    /// Every mirror looked at is present and was scanned to the end, and the
    /// repair pass over the destination ran to the end.
    pub completed: bool,
    /// Files missing or damaged on the destination that were written again
    /// from a mirror.
    pub destination_repaired: u64,
    /// Files recorded as missing or damaged on the destination that turned
    /// out to be intact after all.
    pub destination_found_intact: u64,
    /// Files missing or damaged on the destination for which no connected
    /// mirror had a copy that still matched.
    pub destination_unrepairable: u64,
    /// I/O errors from the destination during this scan.
    pub destination_io_errors: u64,
    /// Every repair made, in both directions (at most 200 are listed).
    pub repairs: Vec<Repair>,
    /// Destination files that could not be repaired (at most 200 are listed).
    pub failures: Vec<MirrorFailure>,
    /// The final-move block in force after the scan, if any.
    pub block: Option<BlockInfo>,
}

/// Why one copy did not happen.
enum CopyFail {
    Cancelled,
    /// The source is missing, changed, behind a link or has an invalid record.
    SourceNotIntact(String),
    /// The source could not be read, for a reason that says nothing about its disk.
    SourceUnreadable(String),
    /// The source's disk returned an error.
    SourceIo(String),
    /// The target's disk returned an error (or vanished).
    TargetIo(String),
    /// What the target gave back is not what was written.
    TargetMismatch(String),
    NoSpace,
    /// Something on the target is in the way (a link, an unusable name).
    Obstacle(String),
    /// The ledger failed: the whole operation stops.
    Fatal(StoreError),
}

impl CopyFail {
    fn reason(&self) -> String {
        match self {
            CopyFail::Cancelled => "cancelled".to_owned(),
            CopyFail::SourceNotIntact(why) => format!("the source copy is not intact: {why}"),
            CopyFail::SourceUnreadable(why) => format!("the source copy could not be read: {why}"),
            CopyFail::SourceIo(why) => format!("the source disk returned an error: {why}"),
            CopyFail::TargetIo(why) => format!("the target disk returned an error: {why}"),
            CopyFail::TargetMismatch(why) => format!("the copy did not verify: {why}"),
            CopyFail::NoSpace => "the target disk is full".to_owned(),
            CopyFail::Obstacle(why) => why.clone(),
            CopyFail::Fatal(e) => e.to_string(),
        }
    }
}

impl From<LedgerError> for CopyFail {
    fn from(e: LedgerError) -> Self {
        CopyFail::Fatal(e.into())
    }
}

/// Sorts an error of the write pipeline into what it means for a copy.
fn target_fail(e: StoreError) -> CopyFail {
    match e {
        StoreError::DiskFull { .. } | StoreError::InsufficientSpace { .. } => CopyFail::NoSpace,
        StoreError::Io { op, path, source } => {
            let text = format!("{op} failed for {path:?}: {source}");
            if is_hard_io_error(&source) || source.kind() == io::ErrorKind::NotFound {
                CopyFail::TargetIo(text)
            } else {
                CopyFail::Obstacle(text)
            }
        }
        StoreError::DiskVerifyMismatch { .. } | StoreError::RenameNotConfirmed { .. } => {
            CopyFail::TargetMismatch(e.to_string())
        }
        StoreError::SizeMismatch { .. } => {
            CopyFail::SourceNotIntact("it changed size while it was being copied".to_owned())
        }
        StoreError::Ledger(_) => CopyFail::Fatal(e),
        other => CopyFail::Obstacle(other.to_string()),
    }
}

/// A finished copy.
struct CopyDone {
    /// An identical file was already there; nothing was written.
    adopted: bool,
    /// Where the copy is, relative to the target root.
    rel_path: String,
}

/// What a failure means for the loop over one mirror's files.
enum Next {
    Continue,
    StopMirror,
}

/// Trouble counted across one call.
#[derive(Default)]
struct Trouble {
    destination_io_errors: u64,
}

fn push_failure(list: &mut Vec<MirrorFailure>, rel_path: &str, reason: String) {
    if list.len() < MAX_LISTED {
        list.push(MirrorFailure {
            rel_path: rel_path.to_owned(),
            reason,
        });
    }
}

fn marker_text(uid: &str, destination: &str) -> String {
    format!("kiwi-mirror 1\nuid={uid}\ndestination={destination}\n")
}

fn is_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The mirror id and destination id in a marker file.
fn parse_marker(bytes: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "kiwi-mirror 1" {
        return None;
    }
    let uid = lines.next()?.strip_prefix("uid=")?;
    let destination = lines.next()?.strip_prefix("destination=")?;
    (is_id(uid) && is_id(destination))
        .then(|| (uid.to_ascii_lowercase(), destination.to_ascii_lowercase()))
}

fn unix_ns(time: SystemTime) -> Option<i64> {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).ok(),
        Err(e) => i64::try_from(e.duration().as_nanos()).ok().map(|n| -n),
    }
}

/// Whether one path is the other or lies inside it.
fn overlap(a: &Path, b: &Path) -> bool {
    let fold = |p: &Path| -> Vec<String> {
        crate::destination::display_path(p)
            .split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .map(crate::sanitize::collision_key)
            .collect()
    };
    let (a, b) = (fold(a), fold(b));
    let n = a.len().min(b.len());
    a[..n] == b[..n]
}

impl Inner {
    fn destination_id(&self) -> Result<String, StoreError> {
        self.ledger.destination_id()?.ok_or_else(|| {
            StoreError::Ledger(LedgerError::Corrupt {
                path: self.ledger.path().to_path_buf(),
                detail: "the ledger has no destination id".to_owned(),
            })
        })
    }

    /// Looks at a mirror's path: is the mirror there, and is it the right one?
    /// Reads only; writes nothing to the disk.
    pub(crate) fn mirror_presence(&self, m: &MirrorRecord) -> Result<MirrorPresence, StoreError> {
        let root = PathBuf::from(&m.root);
        let now = self.now();
        let absent = |detail: String| {
            MirrorPresence::Absent(MirrorAbsent {
                last_seen_unix_ms: m.last_seen_unix_ms,
                secs_since_seen: u64::try_from(now.saturating_sub(m.last_seen_unix_ms) / 1_000)
                    .unwrap_or(0),
                sessions_since_seen: self.ledger.session().saturating_sub(m.last_seen_session),
                detail,
            })
        };
        match self.fs.stat(&root) {
            Err(e) => return Ok(absent(e.to_string())),
            Ok(None) => return Ok(absent("the folder is not there".to_owned())),
            Ok(Some(s)) if s.kind != EntryKind::Dir || s.reparse => {
                return Ok(MirrorPresence::WrongDisk(WrongDisk::NotAFolder))
            }
            Ok(Some(_)) => {}
        }
        let marker = root.join(STORE_DIR).join(MIRROR_MARKER_FILE);
        let bytes = match self.fs.read_small(&marker, MARKER_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(e) => {
                // The disk may have gone between the two looks.
                return Ok(match self.fs.stat(&root) {
                    Ok(Some(_)) if e.kind() == io::ErrorKind::NotFound => {
                        MirrorPresence::WrongDisk(WrongDisk::NoMarker)
                    }
                    Ok(Some(_)) => {
                        MirrorPresence::WrongDisk(WrongDisk::MarkerUnreadable(e.to_string()))
                    }
                    _ => absent(e.to_string()),
                });
            }
        };
        let Some((uid, destination)) = parse_marker(&bytes) else {
            return Ok(MirrorPresence::WrongDisk(WrongDisk::MarkerUnreadable(
                "the file is not a mirror marker".to_owned(),
            )));
        };
        if destination != self.destination_id()? {
            return Ok(MirrorPresence::WrongDisk(WrongDisk::OtherStore));
        }
        if uid != m.uid {
            return Ok(MirrorPresence::WrongDisk(WrongDisk::OtherMirror {
                found_uid: uid,
            }));
        }
        let volume = match (self.volume_probe)(&root) {
            Ok(volume) => volume,
            Err(e) => return Ok(absent(e.to_string())),
        };
        match (m.volume_serial, volume.serial) {
            (Some(expected), found) if found != Some(expected) => {
                Ok(MirrorPresence::WrongDisk(WrongDisk::VolumeChanged {
                    expected,
                    found,
                }))
            }
            _ => Ok(MirrorPresence::Present),
        }
    }

    /// Writes a mirror's marker file: temp, flush, rename without replacing.
    fn write_mirror_marker(&self, store_dir: &Path, text: &str) -> io::Result<()> {
        let temp = store_dir.join(self.temp_name());
        let marker = store_dir.join(MIRROR_MARKER_FILE);
        let written = (|| {
            let mut file = self.fs.create_temp(&temp)?;
            let mut rest = text.as_bytes();
            while !rest.is_empty() {
                match file.write(rest)? {
                    0 => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                    n => rest = &rest[n.min(rest.len())..],
                }
            }
            file.sync()?;
            drop(file);
            self.fs.rename_noreplace(&temp, &marker)
        })();
        match written {
            Ok(()) => {
                // Best effort: the marker is read back before it is relied on.
                let _ = self.fs.sync_file(&marker);
                let _ = self.fs.sync_dir(store_dir);
                Ok(())
            }
            Err(e) => {
                self.delete_own_temp(&temp);
                Err(e)
            }
        }
    }

    /// Sets the "a disk is failing" block.
    fn block_failing(&self, what: &str) -> Result<(), StoreError> {
        let reason = format!("a disk may be failing: {what}");
        self.ledger
            .block(BlockKind::DiskFailing, &reason, self.now())?;
        Ok(())
    }

    /// Counts trouble on a mirror and blocks when it has become too much.
    fn mirror_trouble(
        &self,
        m: &MirrorRecord,
        io_errors: u64,
        mismatches: u64,
        detail: &str,
    ) -> Result<(), StoreError> {
        let (total_io, total_mismatch) =
            self.ledger
                .mirror_trouble(m.id, io_errors, mismatches, detail, self.now())?;
        let policy = self.cfg.mirror_policy;
        if io_errors > 0 && total_io >= policy.io_errors_to_block.max(1) {
            self.block_failing(&format!(
                "mirror {} ({}) returned {total_io} I/O errors (last: {detail})",
                m.id, m.label
            ))?;
        }
        if mismatches > 0 && total_mismatch >= policy.mismatches_to_block.max(1) {
            self.block_failing(&format!(
                "{total_mismatch} files on mirror {} ({}) did not match what was written there (last: {detail})",
                m.id, m.label
            ))?;
        }
        Ok(())
    }

    /// Counts an I/O error on the destination and blocks when there have
    /// been too many in this call.
    fn destination_trouble(&self, trouble: &mut Trouble, detail: &str) -> Result<(), StoreError> {
        trouble.destination_io_errors += 1;
        if trouble.destination_io_errors == self.cfg.mirror_policy.io_errors_to_block.max(1) {
            self.block_failing(&format!(
                "the destination returned {} I/O errors (last: {detail})",
                trouble.destination_io_errors
            ))?;
        }
        Ok(())
    }
}

impl Store {
    /// Registers a folder on another volume as a mirror.
    ///
    /// The folder must exist, must not overlap the destination and must not
    /// be on the destination's own volume. It may be on any kind of disk
    /// (a USB disk is the usual case) and may already contain files; nothing
    /// in it is ever overwritten. A marker file with a fresh random id is
    /// written to `<folder>/.kiwi-store/mirror`; the id and the volume's
    /// serial number are what later proves that the disk at this path is
    /// this mirror.
    ///
    /// If the folder already carries the marker of a mirror this store knows
    /// (the disk came back under another drive letter, or the mirror had been
    /// removed), that mirror is attached again at its new path instead.
    ///
    /// Nothing is copied yet: see [`Store::run_mirror`].
    pub fn add_mirror(&self, root: &Path, label: &str) -> Result<MirrorInfo, StoreError> {
        let inner = &self.inner;
        let _one_at_a_time = lock(&inner.mirror_lock);
        let unavailable = |path: &Path, source: io::Error| MirrorError::Unavailable {
            path: path.to_path_buf(),
            source,
        };
        if !root.is_absolute() {
            return Err(MirrorError::NotADirectory(root.to_path_buf()).into());
        }
        let resolved = inner.fs.resolve(root).map_err(|e| unavailable(root, e))?;
        match inner.fs.stat(&resolved) {
            Ok(Some(s)) if s.kind == EntryKind::Dir && !s.reparse => {}
            Ok(_) => return Err(MirrorError::NotADirectory(root.to_path_buf()).into()),
            Err(e) => return Err(unavailable(root, e).into()),
        }
        let Some(root_text) = resolved.to_str().map(str::to_owned) else {
            return Err(MirrorError::NotUnicode(resolved).into());
        };
        if overlap(&resolved, inner.root()) {
            return Err(MirrorError::OverlapsDestination(resolved).into());
        }
        let volume = (inner.volume_probe)(&resolved).map_err(|e| unavailable(&resolved, e))?;
        if volume.serial.is_some() && volume.serial == inner.dest.volume().serial {
            return Err(MirrorError::SameVolume(resolved).into());
        }
        let label: String = label
            .chars()
            .filter(|c| !c.is_control())
            .take(100)
            .collect();
        let destination = inner.destination_id()?;
        let now = inner.now();

        let store_dir = resolved.join(STORE_DIR);
        let foreign = |detail: &str| MirrorError::ForeignMarker {
            path: resolved.clone(),
            detail: detail.to_owned(),
        };
        match inner.fs.stat(&store_dir) {
            Ok(Some(s)) if s.kind == EntryKind::Dir && !s.reparse => {}
            Ok(Some(_)) => {
                return Err(foreign("its .kiwi-store entry is not a plain folder").into())
            }
            Ok(None) => {
                inner
                    .fs
                    .create_dir(&store_dir)
                    .map_err(|e| unavailable(&store_dir, e))?;
                sys::hide(&store_dir);
            }
            Err(e) => return Err(unavailable(&store_dir, e).into()),
        }
        let marker = store_dir.join(MIRROR_MARKER_FILE);
        match inner.fs.read_small(&marker, MARKER_MAX_BYTES) {
            Ok(bytes) => {
                // The folder has been a mirror before. It is taken back only
                // if it is one of this store's own.
                let Some((uid, marked_destination)) = parse_marker(&bytes) else {
                    return Err(foreign("the marker cannot be read").into());
                };
                if marked_destination != destination {
                    return Err(foreign("it mirrors another destination").into());
                }
                let Some(known) = inner.ledger.mirror_by_uid(&uid)? else {
                    return Err(foreign("this store's ledger does not know it").into());
                };
                if known.volume_serial.is_some() && known.volume_serial != volume.serial {
                    return Err(foreign("it is not on the volume the mirror was created on").into());
                }
                inner
                    .ledger
                    .reattach_mirror(known.id, &root_text, &label, now)?;
                let record = inner
                    .ledger
                    .mirror(known.id)?
                    .ok_or(MirrorError::Unknown(known.id))?;
                return Ok(record.into());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(unavailable(&marker, e).into()),
        }

        // The ledger first: if we stop between the two writes, the ledger has
        // a mirror whose folder has no marker, which is reported as the wrong
        // disk and can simply be removed and added again. The other order
        // would leave a marker no ledger knows.
        let uid = new_destination_id();
        let record = inner.ledger.add_mirror(
            &NewMirror {
                uid: &uid,
                root: &root_text,
                label: &label,
                volume_serial: volume.serial,
            },
            now,
        )?;
        if let Err(e) = inner.write_mirror_marker(&store_dir, &marker_text(&uid, &destination)) {
            let _ =
                inner
                    .ledger
                    .deactivate_mirror(record.id, "its marker could not be written", now);
            return Err(unavailable(&marker, e).into());
        }
        Ok(record.into())
    }

    /// Removes a mirror from the store. **Nothing on the disk is touched**:
    /// the files stay, and so does the marker, so the same disk can be added
    /// again later. The mirror's copies stop counting at once. Its ledger
    /// rows are kept as the audit trail. Returns false if it was not active.
    pub fn remove_mirror(&self, id: MirrorId, note: &str) -> Result<bool, StoreError> {
        let inner = &self.inner;
        let _one_at_a_time = lock(&inner.mirror_lock);
        if inner.ledger.mirror(id.0)?.is_none() {
            return Err(MirrorError::Unknown(id.0).into());
        }
        Ok(inner.ledger.deactivate_mirror(id.0, note, inner.now())?)
    }

    /// Every mirror ever registered, removed ones included
    /// ([`MirrorInfo::active`] tells them apart).
    pub fn mirrors(&self) -> Result<Vec<MirrorInfo>, StoreError> {
        Ok(self
            .inner
            .ledger
            .mirrors()?
            .into_iter()
            .map(MirrorInfo::from)
            .collect())
    }

    /// Looks whether a mirror is connected and is the right disk. Reads
    /// only. A mirror found present is noted as seen now.
    pub fn mirror_presence(&self, id: MirrorId) -> Result<MirrorPresence, StoreError> {
        let inner = &self.inner;
        let m = inner
            .ledger
            .mirror(id.0)?
            .ok_or(MirrorError::Unknown(id.0))?;
        let presence = inner.mirror_presence(&m)?;
        if presence.is_present() && m.active {
            inner.ledger.mirror_seen(m.id, inner.now())?;
        }
        Ok(presence)
    }

    /// Per active mirror and device: how many stored files have no verified
    /// copy on that mirror yet. Pairs with nothing pending are not listed.
    pub fn mirror_pending(&self) -> Result<Vec<MirrorPending>, StoreError> {
        Ok(self
            .inner
            .ledger
            .mirror_pending()?
            .into_iter()
            .map(|row| MirrorPending {
                mirror: MirrorId(row.mirror_id),
                device: row.device,
                files: row.files,
                bytes: row.bytes,
            })
            .collect())
    }

    /// How many of a device's files have no, one, or at least two copies
    /// believed good. See [`CopyCounts`] for what counts.
    pub fn copy_counts(&self, device: &DeviceId) -> Result<CopyCounts, StoreError> {
        let mut counts = CopyCounts::default();
        for (copies, files) in self.inner.ledger.copy_counts(device.as_str())? {
            match copies {
                0 => counts.no_copy += files,
                1 => counts.one_copy += files,
                _ => counts.two_or_more += files,
            }
        }
        Ok(counts)
    }

    /// The device's oldest stored file that has no verified copy on any
    /// active mirror, if there is one.
    ///
    /// Final move does not wait for the mirror. This is what lets the
    /// application say "the oldest photo that exists only on this PC's disk
    /// was stored 26 days ago" before the phone's own trash, which still
    /// holds the original, expires. With no mirror registered, every stored
    /// file is unmirrored and the oldest one is returned.
    pub fn oldest_unmirrored_commit(
        &self,
        device: &DeviceId,
    ) -> Result<Option<UnmirroredCommit>, StoreError> {
        let inner = &self.inner;
        let now = inner.now();
        Ok(inner
            .ledger
            .oldest_unmirrored(device.as_str())?
            .map(|rec| UnmirroredCommit {
                file_id: rec.id,
                rel_path: rec.rel_path,
                size: rec.size,
                committed_seq: rec.committed_seq,
                committed_session: rec.committed_session,
                committed_unix_ms: rec.committed_unix_ms,
                age_secs: now.saturating_sub(rec.committed_unix_ms).div_euclid(1_000),
            }))
    }

    /// Copies every stored file that has no verified copy on a mirror yet to
    /// that mirror, for every active mirror that is connected.
    ///
    /// Each copy goes through the same pipeline as a file received from a
    /// phone (see the module documentation). The work is resumable: what a
    /// run did not get to, or could not do, the next run does. A mirror that
    /// is not connected is reported as [`MirrorPresence::Absent`] and
    /// skipped; a folder that is not the mirror is reported as
    /// [`MirrorPresence::WrongDisk`] and not written to.
    pub fn run_mirror(&self, cancel: &CancelToken) -> Result<MirrorRunReport, StoreError> {
        self.run_mirror_with(&MirrorOptions::default(), cancel)
    }

    /// [`Store::run_mirror`] with options: one mirror only, a byte rate, a
    /// file budget.
    pub fn run_mirror_with(
        &self,
        opts: &MirrorOptions,
        cancel: &CancelToken,
    ) -> Result<MirrorRunReport, StoreError> {
        let inner = &self.inner;
        let _one_at_a_time = lock(&inner.mirror_lock);
        let mirrors = self.selected_mirrors(opts)?;
        let mut throttle = Throttle::new(opts.max_bytes_per_sec, cancel);
        let mut budget = opts.max_files;
        let mut trouble = Trouble::default();
        let mut runs = Vec::new();
        for m in &mirrors {
            if cancel.is_cancelled() {
                break;
            }
            runs.push(self.run_one_mirror(m, cancel, &mut throttle, &mut budget, &mut trouble)?);
        }
        // The copies were recorded without a flush each; one flush now.
        if runs.iter().any(|r| r.presence.is_present()) {
            inner.ledger.flush(inner.now())?;
        }
        Ok(MirrorRunReport {
            completed: runs.len() == mirrors.len() && runs.iter().all(|r| r.completed),
            mirrors: runs,
            destination_io_errors: trouble.destination_io_errors,
            block: inner.ledger.block_info()?,
        })
    }

    /// Re-reads the copies on the mirrors and repairs what can be repaired.
    ///
    /// For every active, connected mirror: each recorded copy is read back
    /// from the mirror and compared with the ledger's hash. With
    /// [`MirrorOptions::repair`] (the default), a copy that is gone or
    /// different is written again from the destination, provided the
    /// destination's file is itself intact. Then every file the ledger
    /// records as missing or changed on the destination is written again
    /// from a mirror copy, provided that copy, read back just then, matches
    /// the ledger's hash.
    ///
    /// This scan does not look for damage on the destination; that is
    /// [`Store::integrity_scan`]. Run that first.
    ///
    /// Nothing is overwritten, moved or deleted by a repair, and a repair
    /// never clears the final-move block: the block was set when the damage
    /// was found and stays until a person clears it. A file repaired on the
    /// destination is treated as stored anew: it has to age again before a
    /// deletion can be confirmed by it.
    ///
    /// The scan is resumable per mirror, like the integrity scan.
    pub fn scan_mirror(
        &self,
        opts: &MirrorOptions,
        cancel: &CancelToken,
    ) -> Result<MirrorScanReport, StoreError> {
        let inner = &self.inner;
        let _one_at_a_time = lock(&inner.mirror_lock);
        let mirrors = self.selected_mirrors(opts)?;
        let mut throttle = Throttle::new(opts.max_bytes_per_sec, cancel);
        let mut budget = opts.max_files;
        let mut trouble = Trouble::default();
        let mut report = MirrorScanReport {
            mirrors: Vec::new(),
            completed: false,
            destination_repaired: 0,
            destination_found_intact: 0,
            destination_unrepairable: 0,
            destination_io_errors: 0,
            repairs: Vec::new(),
            failures: Vec::new(),
            block: None,
        };
        let mut present: Vec<&MirrorRecord> = Vec::new();
        for m in &mirrors {
            if cancel.is_cancelled() {
                break;
            }
            let scan = self.scan_one_mirror(
                m,
                opts,
                cancel,
                &mut throttle,
                &mut budget,
                &mut trouble,
                &mut report.repairs,
            )?;
            if scan.presence.is_present() && !scan.removed_mid_run {
                present.push(m);
            }
            report.mirrors.push(scan);
        }
        let mut finished =
            report.mirrors.len() == mirrors.len() && report.mirrors.iter().all(|s| s.completed);
        if opts.repair && !cancel.is_cancelled() && budget != Some(0) {
            finished &= self.repair_destination(
                &present,
                cancel,
                &mut throttle,
                &mut budget,
                &mut trouble,
                &mut report,
            )?;
        } else if opts.repair {
            finished = false;
        }
        if report.mirrors.iter().any(|s| s.presence.is_present()) {
            inner.ledger.flush(inner.now())?;
        }
        report.completed = finished;
        report.destination_io_errors = trouble.destination_io_errors;
        report.block = inner.ledger.block_info()?;
        Ok(report)
    }

    /// Sets up a new mirror in `new_destination` and fills it, for when a
    /// mirror disk has been lost or replaced.
    ///
    /// This is [`Store::add_mirror`], then removing the mirror named by
    /// `replaces` (if any; nothing on that disk is touched), then
    /// [`Store::run_mirror`] for the new mirror only. If the run is
    /// interrupted the new mirror stays registered and later runs finish it.
    pub fn rebuild_mirror(
        &self,
        new_destination: &Path,
        label: &str,
        replaces: Option<MirrorId>,
        cancel: &CancelToken,
    ) -> Result<MirrorRunReport, StoreError> {
        let added = self.add_mirror(new_destination, label)?;
        if let Some(old) = replaces.filter(|old| *old != added.id) {
            let note = format!("replaced by mirror {} ({})", added.id.0, added.label);
            self.remove_mirror(old, &note)?;
        }
        self.run_mirror_with(
            &MirrorOptions {
                mirror: Some(added.id),
                ..MirrorOptions::default()
            },
            cancel,
        )
    }

    fn selected_mirrors(&self, opts: &MirrorOptions) -> Result<Vec<MirrorRecord>, StoreError> {
        let all = self.inner.ledger.mirrors()?;
        if let Some(MirrorId(id)) = opts.mirror {
            if !all.iter().any(|m| m.id == id) {
                return Err(MirrorError::Unknown(id).into());
            }
        }
        Ok(all
            .into_iter()
            .filter(|m| m.active && opts.mirror.is_none_or(|id| id.0 == m.id))
            .collect())
    }

    fn run_one_mirror(
        &self,
        m: &MirrorRecord,
        cancel: &CancelToken,
        throttle: &mut Throttle<'_>,
        budget: &mut Option<u64>,
        trouble: &mut Trouble,
    ) -> Result<MirrorRun, StoreError> {
        let inner = &self.inner;
        let mut run = MirrorRun::new(m.id);
        run.presence = inner.mirror_presence(m)?;
        if !run.presence.is_present() {
            return Ok(run);
        }
        inner.ledger.mirror_seen(m.id, inner.now())?;
        let root = PathBuf::from(&m.root);
        run.temps_removed = inner.clean_partials(m.id, &root)?.removed;

        let mut cursor = 0i64;
        let mut stopped = false;
        'files: loop {
            let batch = inner.ledger.files_pending_for_mirror(m.id, cursor, 64)?;
            if batch.is_empty() {
                break;
            }
            for rec in &batch {
                if cancel.is_cancelled() || *budget == Some(0) {
                    stopped = true;
                    break 'files;
                }
                cursor = rec.id;
                if let Some(left) = budget.as_mut() {
                    *left -= 1;
                }
                match self.copy_to_mirror(m, &root, rec, "mirror_copy", throttle) {
                    Ok(done) if done.adopted => run.already_there += 1,
                    Ok(_) => {
                        run.copied += 1;
                        run.bytes_copied += rec.size;
                    }
                    Err(fail) => {
                        let counters = Counters {
                            failed: &mut run.failed,
                            skipped_source: &mut run.skipped_source,
                            io_errors: &mut run.io_errors,
                            mismatches: &mut run.mismatches,
                            removed_mid_run: &mut run.removed_mid_run,
                            out_of_space: &mut run.out_of_space,
                            presence: &mut run.presence,
                            failures: &mut run.failures,
                        };
                        if let Next::StopMirror =
                            self.after_failure(m, rec, fail, counters, trouble)?
                        {
                            stopped = true;
                            break 'files;
                        }
                    }
                }
            }
        }
        run.completed = !stopped && run.failed == 0;
        Ok(run)
    }

    /// Books a failed copy to or on a mirror and decides how to go on.
    fn after_failure(
        &self,
        m: &MirrorRecord,
        rec: &FileRecord,
        fail: CopyFail,
        c: Counters<'_>,
        trouble: &mut Trouble,
    ) -> Result<Next, StoreError> {
        let inner = &self.inner;
        let reason = fail.reason();
        let next = match fail {
            CopyFail::Fatal(e) => return Err(e),
            CopyFail::Cancelled => return Ok(Next::StopMirror),
            CopyFail::SourceNotIntact(_) | CopyFail::SourceUnreadable(_) => {
                *c.skipped_source += 1;
                Next::Continue
            }
            CopyFail::SourceIo(why) => {
                *c.skipped_source += 1;
                inner.destination_trouble(trouble, &why)?;
                Next::Continue
            }
            CopyFail::TargetIo(why) => {
                // An error from a disk that is no longer there is not a
                // failing disk; it is a disk that was unplugged.
                let presence = inner.mirror_presence(m)?;
                if presence.is_present() {
                    *c.io_errors += 1;
                    inner.mirror_trouble(m, 1, 0, &why)?;
                    Next::Continue
                } else {
                    *c.removed_mid_run = true;
                    *c.presence = presence;
                    Next::StopMirror
                }
            }
            CopyFail::TargetMismatch(why) => {
                *c.mismatches += 1;
                inner.mirror_trouble(m, 0, 1, &why)?;
                Next::Continue
            }
            CopyFail::NoSpace => {
                *c.out_of_space = true;
                Next::StopMirror
            }
            CopyFail::Obstacle(_) => Next::Continue,
        };
        *c.failed += 1;
        push_failure(c.failures, &rec.rel_path, reason);
        Ok(next)
    }

    /// Copies one stored file from the destination to a mirror and records
    /// the copy. `kind` is the event logged for a copy that was written.
    fn copy_to_mirror(
        &self,
        m: &MirrorRecord,
        mirror_root: &Path,
        rec: &FileRecord,
        kind: &str,
        throttle: &mut Throttle<'_>,
    ) -> Result<CopyDone, CopyFail> {
        let inner = &self.inner;
        let Some(rel) = SafeRelPath::from_stored(&rec.rel_path) else {
            inner.apply_probe(rec, &Probe::InvalidRecord)?;
            return Err(CopyFail::SourceNotIntact(
                "its ledger record is invalid".to_owned(),
            ));
        };
        let name = rel
            .file_name()
            .expect("a stored path is never empty")
            .clone();

        let available = inner
            .fs
            .free_space(mirror_root)
            .map_err(|e| CopyFail::TargetIo(e.to_string()))?;
        if available < rec.size.saturating_add(inner.cfg.safety_margin_bytes) {
            return Err(CopyFail::NoSpace);
        }
        let mut slot =
            TempSlot::create(inner, m.id, mirror_root, &rel.parent()).map_err(target_fail)?;

        // Read the destination's file, checking the whole path and hashing
        // as it is read, and write those very bytes to the mirror. Only a
        // read that ends as a match (right size, right hash, right place)
        // lets the copy go on: the bytes on the mirror are then the bytes
        // the ledger's hash stands for.
        let source = self.tee(inner.root(), &rec.rel_path, rec, &mut slot, throttle)?;
        match source {
            Probe::Match { .. } => {}
            Probe::Interrupted => return Err(CopyFail::Cancelled),
            Probe::Unreadable(why) => return Err(CopyFail::SourceUnreadable(why)),
            Probe::IoError(why) => return Err(CopyFail::SourceIo(why)),
            other => {
                // Missing, changed, behind a link: the ledger is told, and
                // final move is blocked, exactly as when a scan finds it.
                inner.apply_probe(rec, &other)?;
                return Err(CopyFail::SourceNotIntact(other.reason().to_string()));
            }
        }

        let source_mtime = inner
            .fs
            .stat(&rel.under(inner.root()))
            .ok()
            .flatten()
            .and_then(|s| s.mtime)
            .and_then(unix_ns);
        let done = self.finish_copy(
            &mut slot,
            rec,
            source_mtime,
            &|n| name.stored_variant(n),
            &|_| Ok(Adoption::Yes(None)),
            name.as_str(),
            throttle,
        )?;
        let (rel_path, dir_synced, unbuffered, adopted) = done;
        let _ = dir_synced;

        inner
            .fs
            .checkpoint(Checkpoint::BeforeMirrorRecord)
            .map_err(|e| CopyFail::Obstacle(format!("stopped before recording the copy: {e}")))?;
        let detail = if adopted {
            "was already there with identical content".to_owned()
        } else {
            format!("{} bytes, hash {}", rec.size, rec.hash)
        };
        inner.ledger.record_mirror_copy(
            &MirrorCopy {
                mirror_id: m.id,
                file_id: rec.id,
                rel_path: &rel_path,
                unbuffered,
                kind: if adopted { "mirror_adopt" } else { kind },
                detail: &detail,
                partial: (!adopted).then(|| slot.temp_rel()),
                // A repair is part of the audit trail and is flushed at
                // once; plain copies are flushed together at the end.
                durable: kind == "mirror_repaired",
            },
            inner.now(),
        )?;
        if !adopted {
            slot.intent_closed();
        }
        Ok(CopyDone { adopted, rel_path })
    }

    /// Reads `rel_path` under `root` as [`Inner::probe_at`] does and writes
    /// every chunk into `slot`.
    fn tee(
        &self,
        root: &Path,
        rel_path: &str,
        rec: &FileRecord,
        slot: &mut TempSlot,
        throttle: &mut Throttle<'_>,
    ) -> Result<Probe, CopyFail> {
        let mut write_error = None;
        let probe = self
            .inner
            .probe_at(root, rel_path, rec.size, &rec.hash, &mut |chunk| {
                if let Err(e) = slot.write(chunk, rec.size, &mut |_| {}) {
                    write_error = Some(e);
                    return ControlFlow::Break(());
                }
                throttle.tick(chunk.len())
            });
        match write_error {
            Some(e) => Err(target_fail(e)),
            None => Ok(probe),
        }
    }

    /// The second half of a copy, the same in both directions: flush the
    /// temp file, read it back from its disk, compare with the ledger's hash,
    /// and give it its final name. Returns the final relative path, whether
    /// the name was flushed, whether the reads bypassed the cache, and
    /// whether an identical file was found there instead.
    #[allow(clippy::too_many_arguments)]
    fn finish_copy(
        &self,
        slot: &mut TempSlot,
        rec: &FileRecord,
        mtime_unix_ns: Option<i64>,
        name_for: &dyn Fn(u32) -> SafeName,
        may_adopt: &dyn Fn(&SafeRelPath) -> Result<Adoption, StoreError>,
        display_name: &str,
        throttle: &mut Throttle<'_>,
    ) -> Result<(String, bool, bool, bool), CopyFail> {
        if slot.written() != rec.size || slot.stream_hash() != rec.hash {
            return Err(CopyFail::SourceNotIntact(
                "what was read does not match its record".to_owned(),
            ));
        }
        slot.seal(mtime_unix_ns).map_err(target_fail)?;
        let (on_disk, read) = slot
            .read_back(&mut |n| throttle.tick(n))
            .map_err(target_fail)?;
        if !read.completed {
            return Err(CopyFail::Cancelled);
        }
        if read.bytes != rec.size || on_disk != rec.hash {
            return Err(CopyFail::TargetMismatch(format!(
                "read back {} bytes hashing to {on_disk} instead of {} bytes hashing to {}",
                read.bytes, rec.size, rec.hash
            )));
        }
        let placed = slot
            .place(&PlaceRequest {
                hash: &rec.hash,
                size: rec.size,
                name_for,
                may_adopt,
                display_name,
            })
            .map_err(target_fail)?;
        Ok(match placed {
            Placed::Stored {
                name,
                dir_synced,
                unbuffered,
            } => (
                slot.dir_rel().join(name).to_slash_string(),
                dir_synced,
                read.unbuffered && unbuffered,
                false,
            ),
            Placed::Adopted {
                name, unbuffered, ..
            } => (
                slot.dir_rel().join(name).to_slash_string(),
                false,
                unbuffered,
                true,
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_one_mirror(
        &self,
        m: &MirrorRecord,
        opts: &MirrorOptions,
        cancel: &CancelToken,
        throttle: &mut Throttle<'_>,
        budget: &mut Option<u64>,
        trouble: &mut Trouble,
        repairs: &mut Vec<Repair>,
    ) -> Result<MirrorScan, StoreError> {
        let inner = &self.inner;
        let ledger = &inner.ledger;
        let mut scan = MirrorScan::new(m.id);
        scan.presence = inner.mirror_presence(m)?;
        if !scan.presence.is_present() {
            return Ok(scan);
        }
        ledger.mirror_seen(m.id, inner.now())?;
        let root = PathBuf::from(&m.root);
        inner.clean_partials(m.id, &root)?;

        let (upper, mut cursor) = match ledger.mirror_scan_state(m.id)? {
            Some(saved) => {
                scan.resumed = true;
                saved
            }
            None => {
                let upper = ledger.max_file_id()?;
                ledger.save_mirror_scan_state(m.id, upper, 0)?;
                (upper, 0)
            }
        };
        let mut stopped = false;
        let mut clean = true;
        'rows: loop {
            let rows = ledger.mirror_files_after(m.id, cursor, upper, 64)?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                if cancel.is_cancelled() || *budget == Some(0) {
                    stopped = true;
                    break 'rows;
                }
                let Some(rec) = ledger.file_by_id(row.file_id)? else {
                    cursor = row.file_id;
                    continue;
                };
                let probe = inner.probe_at(&root, &row.rel_path, rec.size, &rec.hash, &mut |c| {
                    throttle.tick(c.len())
                });
                if probe == Probe::Interrupted {
                    // Not counted and the cursor does not move: the copy is
                    // checked again on resume.
                    stopped = true;
                    break 'rows;
                }
                cursor = row.file_id;
                scan.files_checked += 1;
                if let Some(left) = budget.as_mut() {
                    *left -= 1;
                }
                let finding = match probe {
                    Probe::Match { unbuffered } => {
                        scan.ok += 1;
                        ledger.mirror_file_verified(m.id, rec.id, unbuffered, inner.now())?;
                        if row.state != MirrorFileState::Verified {
                            ledger.set_mirror_file_state(
                                m.id,
                                rec.id,
                                MirrorFileState::Verified,
                                "found intact again",
                                inner.now(),
                            )?;
                        }
                        continue;
                    }
                    Probe::Missing => {
                        scan.missing += 1;
                        (
                            MirrorFileState::Missing,
                            format!("{} is gone", row.rel_path),
                        )
                    }
                    Probe::Changed(how) => {
                        scan.changed += 1;
                        (MirrorFileState::Changed, format!("{}: {how}", row.rel_path))
                    }
                    Probe::Unreadable(why) => {
                        clean = false;
                        scan.unreadable += 1;
                        push_failure(&mut scan.failures, &rec.rel_path, why);
                        continue;
                    }
                    Probe::IoError(why) => {
                        clean = false;
                        let presence = inner.mirror_presence(m)?;
                        if !presence.is_present() {
                            scan.removed_mid_run = true;
                            scan.presence = presence;
                            stopped = true;
                            break 'rows;
                        }
                        scan.io_errors += 1;
                        inner.mirror_trouble(m, 1, 0, &why)?;
                        push_failure(&mut scan.failures, &rec.rel_path, why);
                        continue;
                    }
                    other => {
                        clean = false;
                        scan.suspicious += 1;
                        let why = other.reason().to_string();
                        push_failure(&mut scan.failures, &rec.rel_path, why);
                        continue;
                    }
                };
                clean = false;
                let (state, detail) = finding;
                let new =
                    ledger.set_mirror_file_state(m.id, rec.id, state, &detail, inner.now())?;
                if new && state == MirrorFileState::Changed {
                    inner.mirror_trouble(m, 0, 1, &detail)?;
                }
                if !opts.repair {
                    continue;
                }
                match self.copy_to_mirror(m, &root, &rec, "mirror_repaired", throttle) {
                    Ok(done) => {
                        scan.repaired += 1;
                        if repairs.len() < MAX_LISTED {
                            repairs.push(Repair {
                                rel_path: rec.rel_path.clone(),
                                direction: RepairDirection::MirrorFromDestination(MirrorId(m.id)),
                                new_rel_path: done.rel_path,
                            });
                        }
                    }
                    Err(fail) => {
                        let (mut failed, mut skipped, mut mismatches, mut full) =
                            (0u64, 0u64, 0u64, false);
                        let counters = Counters {
                            failed: &mut failed,
                            skipped_source: &mut skipped,
                            io_errors: &mut scan.io_errors,
                            mismatches: &mut mismatches,
                            removed_mid_run: &mut scan.removed_mid_run,
                            out_of_space: &mut full,
                            presence: &mut scan.presence,
                            failures: &mut scan.failures,
                        };
                        let next = self.after_failure(m, &rec, fail, counters, trouble)?;
                        scan.unrepairable += 1;
                        if let Next::StopMirror = next {
                            stopped = true;
                            break 'rows;
                        }
                    }
                }
            }
            ledger.save_mirror_scan_state(m.id, upper, cursor)?;
        }
        if stopped {
            ledger.save_mirror_scan_state(m.id, upper, cursor)?;
        } else {
            ledger.clear_mirror_scan_state(m.id)?;
            scan.completed = true;
            if clean {
                // A whole pass without a single complaint: the disk's record is clean again.
                ledger.mirror_trouble_reset(m.id)?;
            }
        }
        Ok(scan)
    }

    /// Writes every file the ledger records as missing or changed on the
    /// destination again from a connected mirror's copy. Returns whether the
    /// pass ran to the end.
    fn repair_destination(
        &self,
        present: &[&MirrorRecord],
        cancel: &CancelToken,
        throttle: &mut Throttle<'_>,
        budget: &mut Option<u64>,
        trouble: &mut Trouble,
        report: &mut MirrorScanReport,
    ) -> Result<bool, StoreError> {
        let inner = &self.inner;
        let ledger = &inner.ledger;
        let mut cursor = 0i64;
        loop {
            let batch = ledger.files_repairable(cursor, 64)?;
            if batch.is_empty() {
                return Ok(true);
            }
            for rec in &batch {
                if cancel.is_cancelled() || *budget == Some(0) {
                    return Ok(false);
                }
                cursor = rec.id;
                if let Some(left) = budget.as_mut() {
                    *left -= 1;
                }
                // Is it really still missing or damaged? The record is a belief.
                match inner.probe(rec, &mut |n| throttle.tick(n)) {
                    Probe::Interrupted => return Ok(false),
                    Probe::Match { unbuffered } => {
                        inner.apply_probe(rec, &Probe::Match { unbuffered })?;
                        report.destination_found_intact += 1;
                        continue;
                    }
                    Probe::IoError(why) => {
                        inner.destination_trouble(trouble, &why)?;
                    }
                    _ => {}
                }
                let mut repaired = false;
                let mut last_reason = "no connected mirror has a copy of it".to_owned();
                for row in ledger.mirror_rows_for_file(rec.id)? {
                    if row.state != MirrorFileState::Verified {
                        continue;
                    }
                    let Some(m) = present.iter().find(|m| m.id == row.mirror_id) else {
                        continue;
                    };
                    match self.restore_from_mirror(m, &row, rec, throttle, trouble) {
                        Ok(new_rel_path) => {
                            report.destination_repaired += 1;
                            if report.repairs.len() < MAX_LISTED {
                                report.repairs.push(Repair {
                                    rel_path: rec.rel_path.clone(),
                                    direction: RepairDirection::DestinationFromMirror(MirrorId(
                                        m.id,
                                    )),
                                    new_rel_path,
                                });
                            }
                            repaired = true;
                            break;
                        }
                        Err(CopyFail::Fatal(e)) => return Err(e),
                        Err(CopyFail::Cancelled) => return Ok(false),
                        Err(other) => last_reason = other.reason(),
                    }
                }
                if !repaired {
                    report.destination_unrepairable += 1;
                    push_failure(&mut report.failures, &rec.rel_path, last_reason);
                }
            }
        }
    }

    /// Writes one file on the destination again from a mirror's copy, and
    /// points the ledger at the restored file. Returns its relative path.
    fn restore_from_mirror(
        &self,
        m: &MirrorRecord,
        row: &MirrorFileRow,
        rec: &FileRecord,
        throttle: &mut Throttle<'_>,
        trouble: &mut Trouble,
    ) -> Result<String, CopyFail> {
        let inner = &self.inner;
        let ledger = &inner.ledger;
        let mirror_root = PathBuf::from(&m.root);
        let Some(rel) = SafeRelPath::from_stored(&rec.rel_path) else {
            return Err(CopyFail::Obstacle(
                "its ledger record is invalid".to_owned(),
            ));
        };
        let name = rel
            .file_name()
            .expect("a stored path is never empty")
            .clone();

        let available = inner
            .fs
            .free_space(inner.root())
            .map_err(|e| CopyFail::TargetIo(e.to_string()))?;
        let reserved = lock(&inner.in_flight).bytes_remaining;
        if available
            < rec
                .size
                .saturating_add(reserved)
                .saturating_add(inner.cfg.safety_margin_bytes)
        {
            return Err(CopyFail::NoSpace);
        }
        let mut slot =
            TempSlot::create(inner, PRIMARY, inner.root(), &rel.parent()).map_err(target_fail)?;

        // The mirror's copy is believed good. Believing is not enough: it is
        // read from the mirror now, in full, and only if it matches the
        // ledger's hash do its bytes go any further.
        match self.tee(&mirror_root, &row.rel_path, rec, &mut slot, throttle)? {
            Probe::Match { .. } => {}
            Probe::Interrupted => return Err(CopyFail::Cancelled),
            Probe::Unreadable(why) => return Err(CopyFail::SourceUnreadable(why)),
            Probe::IoError(why) => {
                if inner
                    .mirror_presence(m)
                    .map_err(CopyFail::Fatal)?
                    .is_present()
                {
                    inner
                        .mirror_trouble(m, 1, 0, &why)
                        .map_err(CopyFail::Fatal)?;
                }
                return Err(CopyFail::SourceIo(why));
            }
            other => {
                let (state, mismatch) = match &other {
                    Probe::Missing => (MirrorFileState::Missing, 0),
                    _ => (MirrorFileState::Changed, 1),
                };
                let detail = format!("{}: {}", row.rel_path, other.reason());
                let new =
                    ledger.set_mirror_file_state(m.id, rec.id, state, &detail, inner.now())?;
                if new && mismatch > 0 {
                    inner
                        .mirror_trouble(m, 0, mismatch, &detail)
                        .map_err(CopyFail::Fatal)?;
                }
                return Err(CopyFail::SourceNotIntact(detail));
            }
        }

        let own_id = rec.id;
        let done = self.finish_copy(
            &mut slot,
            rec,
            rec.mtime_unix_ns,
            &|n| name.stored_variant(n),
            // An identical file may be used if the ledger does not know the
            // path, or knows it as this very file.
            &|candidate: &SafeRelPath| {
                Ok(match ledger.file_by_path_key(&candidate.collision_key())? {
                    Some(other) if other.id != own_id => Adoption::No,
                    known => Adoption::Yes(known),
                })
            },
            name.as_str(),
            throttle,
        );
        let (new_rel_path, dir_synced, unbuffered, adopted) = match done {
            Ok(done) => done,
            Err(CopyFail::TargetIo(why)) => {
                inner
                    .destination_trouble(trouble, &why)
                    .map_err(CopyFail::Fatal)?;
                return Err(CopyFail::TargetIo(why));
            }
            Err(other) => return Err(other),
        };
        let Some(new_rel) = SafeRelPath::from_stored(&new_rel_path) else {
            return Err(CopyFail::Obstacle(
                "the restored file has a name that cannot be recorded".to_owned(),
            ));
        };

        inner
            .fs
            .checkpoint(Checkpoint::BeforeRepairRecord)
            .map_err(|e| CopyFail::Obstacle(format!("stopped before recording the repair: {e}")))?;
        let was = match rec.state {
            FileState::Missing => "missing",
            FileState::Changed => "changed",
            FileState::Committed => "believed intact",
        };
        let detail = format!(
            "written again as {new_rel_path} from mirror {} ({}) copy {}; hash {}; the file at {} was {was} and has not been touched",
            m.id, m.uid, row.rel_path, rec.hash, rec.rel_path
        );
        ledger.record_restored(
            rec,
            &Restored {
                rel_path: &new_rel_path,
                path_key: &new_rel.collision_key(),
                dir_synced,
                verified_unbuffered: unbuffered,
                partial: (!adopted).then(|| slot.temp_rel()),
                detail: &detail,
            },
            inner.now(),
        )?;
        if !adopted {
            slot.intent_closed();
        }
        Ok(new_rel_path)
    }
}

/// The counters a failed copy is booked to (a run and a scan keep them in
/// different places).
struct Counters<'a> {
    failed: &'a mut u64,
    skipped_source: &'a mut u64,
    io_errors: &'a mut u64,
    mismatches: &'a mut u64,
    removed_mid_run: &'a mut bool,
    out_of_space: &'a mut bool,
    presence: &'a mut MirrorPresence,
    failures: &'a mut Vec<MirrorFailure>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_round_trip_and_junk_is_refused() {
        let uid = "0123456789abcdef0123456789abcdef";
        let destination = "fedcba9876543210fedcba9876543210";
        let text = marker_text(uid, destination);
        assert_eq!(
            parse_marker(text.as_bytes()),
            Some((uid.to_owned(), destination.to_owned()))
        );
        for junk in [
            "",
            "kiwi-mirror 2\nuid=0123456789abcdef0123456789abcdef\ndestination=fedcba9876543210fedcba9876543210\n",
            "kiwi-mirror 1\nuid=short\ndestination=fedcba9876543210fedcba9876543210\n",
            "kiwi-mirror 1\nuid=0123456789abcdef0123456789abcdef\n",
            "kiwi-mirror 1\ndestination=fedcba9876543210fedcba9876543210\nuid=0123456789abcdef0123456789abcdef\n",
            "0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(parse_marker(junk.as_bytes()), None, "{junk:?}");
        }
        assert_eq!(parse_marker(&[0xff, 0xfe, 0x00]), None);
    }

    #[test]
    fn overlapping_folders_are_recognised() {
        let p = Path::new;
        assert!(overlap(p("/a/b"), p("/a/b")));
        assert!(overlap(p("/a/b/c"), p("/a/b")));
        assert!(overlap(p("/a/b"), p("/a/b/c")));
        assert!(overlap(p("/A/B"), p("/a/b/c")));
        assert!(!overlap(p("/a/b"), p("/a/c")));
        assert!(!overlap(p("/a/bc"), p("/a/b")));
        if cfg!(windows) {
            assert!(overlap(p(r"\\?\E:\Photos\Kiwi"), p(r"E:\photos")));
            assert!(!overlap(p(r"\\?\E:\Photos"), p(r"F:\Photos")));
        }
    }
}
