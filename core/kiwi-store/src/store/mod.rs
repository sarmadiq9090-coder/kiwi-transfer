//! The storage engine: one destination root, one ledger.

mod fm;
mod incoming;
mod mirror;
mod pipeline;
mod recovery;
mod scan;
mod verify;

pub use fm::{AuditStatus, StoredRecord};
pub use incoming::{CommitOutcome, CommitReceipt, FileRequest, IncomingFile};
pub use mirror::{
    CopyCounts, MirrorAbsent, MirrorError, MirrorFailure, MirrorId, MirrorInfo, MirrorOptions,
    MirrorPending, MirrorPresence, MirrorRun, MirrorRunReport, MirrorScan, MirrorScanReport,
    Repair, RepairDirection, UnmirroredCommit, WrongDisk, MAX_MIRRORS, MIRROR_MARKER_FILE,
};
pub use recovery::RecoveryReport;
pub use scan::{
    CancelToken, FindingKind, ScanFinding, ScanOptions, ScanPolicy, ScanReport, ScanVerdict,
    MAX_LISTED_FINDINGS,
};
pub use verify::{
    DeletionDenied, DeletionProof, NotVerifiedReason, StoredFile, StoredStatus, VerifyRequest,
};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::destination::{Destination, DriveKind, HazardEnv, VolumeInfo};
use crate::error::{LedgerError, StoreError};
use crate::fsops::{Clock, EntryKind, Fs, RealFs, SystemClock};
use crate::ledger::{
    BlockInfo, BlockKind, DeviceLimits, DeviceRecord, EventRecord, Ledger, LedgerStats,
};
use crate::sanitize::{collision_key, sanitize_component, SafeName, SafeRelPath};
use crate::sys;
use crate::template::Template;

/// Name of the engine's bookkeeping directory inside the destination root.
pub const STORE_DIR: &str = ".kiwi-store";

/// Temp files are named `<TEMP_PREFIX><unique><TEMP_SUFFIX>`. They are the
/// only files the engine ever deletes.
pub const TEMP_PREFIX: &str = ".kiwi-tmp-";

/// See [`TEMP_PREFIX`].
pub const TEMP_SUFFIX: &str = ".part";

/// Default for [`StoreConfig::safety_margin_bytes`].
pub const DEFAULT_SAFETY_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

/// The shortest wall-clock age [`Store::verify_for_deletion`] ever accepts.
/// [`StoreConfig::min_wall_age_secs`] can raise it, never lower it.
pub const MIN_WALL_AGE_SECS: u64 = 24 * 60 * 60;

/// Longest absolute path the engine will create, in UTF-16 code units. The
/// Windows limit for verbatim paths is 32,767; the difference is headroom for
/// the temp-file name and the verbatim prefix.
pub const MAX_PATH_UTF16: usize = 32_000;

const MARKER_FILE: &str = "id";
const WITNESS_FILE: &str = "commits";
const ROOT_LOCK_FILE: &str = "lock";
const LEDGER_LOCK_FILE: &str = "ledger.lock";

/// Identifier of a paired device, chosen by the transfer layer (for example
/// the hex fingerprint of the device's pinned key). 1 to 128 characters from
/// `A-Z a-z 0-9 . _ -`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Validates and wraps an identifier.
    pub fn new(id: &str) -> Result<DeviceId, StoreError> {
        let ok = !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(DeviceId(id.to_owned()))
        } else {
            Err(StoreError::InvalidDeviceId(id.chars().take(140).collect()))
        }
    }

    /// The identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How to open a store.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// The destination folder. Must exist.
    pub root: PathBuf,
    /// Where the ledger database lives. Created if absent. Put it on a local
    /// disk (SQLite's write-ahead log is not safe on network shares): either
    /// the application's data directory, or `<root>/.kiwi-store`.
    pub ledger_dir: PathBuf,
    /// Where files go under the root.
    pub layout: Template,
    /// Free space that must remain after a file has been written.
    pub safety_margin_bytes: u64,
    /// Wall-clock age required by [`Store::verify_for_deletion`], in seconds.
    /// Values below [`MIN_WALL_AGE_SECS`] are raised to it.
    pub min_wall_age_secs: u64,
    /// Do not run the recovery pass inside [`Store::open`]; the caller runs
    /// [`Store::run_recovery`] itself (typically on a background thread).
    pub defer_recovery: bool,
    /// What the integrity checks treat as alarming.
    pub scan_policy: ScanPolicy,
}

impl StoreConfig {
    /// A configuration with the default layout (`{device}/{phone_dir}`),
    /// margins and policies.
    pub fn new(root: impl Into<PathBuf>, ledger_dir: impl Into<PathBuf>) -> StoreConfig {
        StoreConfig {
            root: root.into(),
            ledger_dir: ledger_dir.into(),
            layout: Template::keep_phone_structure(),
            safety_margin_bytes: DEFAULT_SAFETY_MARGIN_BYTES,
            min_wall_age_secs: MIN_WALL_AGE_SECS,
            defer_recovery: false,
            scan_policy: ScanPolicy::default(),
        }
    }
}

/// Things [`Store::open`] noticed that the application should tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenNote {
    /// A new, empty ledger was created for a destination never used before.
    NewDestination,
    /// The destination had been used before, but the ledger was empty or
    /// missing. Final move has been blocked.
    LedgerLost,
    /// A damaged ledger was moved aside and replaced by an empty one. Final
    /// move has been blocked.
    LedgerReset {
        /// Where the damaged files were moved to.
        quarantined: Vec<PathBuf>,
    },
    /// The destination's identity marker was missing and has been rewritten.
    /// If the ledger had records, final move has been blocked.
    MarkerRecreated,
    /// The ledger is older than the destination folder remembers: it was
    /// restored from a backup or a system image. It has been given a new
    /// identifier (every receipt issued so far is void) and final move has
    /// been blocked.
    LedgerRolledBack {
        /// What gave it away.
        detail: String,
    },
}

/// Asks the platform about the volume holding a path. Replaced in tests to
/// stand in for disks that are not there.
pub type VolumeProbe = Arc<dyn Fn(&Path) -> io::Result<VolumeInfo> + Send + Sync>;

/// Seams for tests. Never available in a shipping build.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default)]
pub struct Seams {
    /// Replaces the real file system.
    pub fs: Option<Arc<dyn Fs>>,
    /// Replaces the system clock.
    pub clock: Option<Arc<dyn Clock>>,
    /// Replaces what the platform says about the destination volume.
    pub volume: Option<VolumeInfo>,
    /// Replaces what the platform says about the volume of a mirror.
    pub volume_probe: Option<VolumeProbe>,
    /// Replaces where cloud-synced and system-managed folders are looked for.
    pub hazards: Option<HazardEnv>,
}

#[cfg(not(any(test, feature = "test-util")))]
#[derive(Default)]
pub(crate) struct Seams {
    pub(crate) fs: Option<Arc<dyn Fs>>,
    pub(crate) clock: Option<Arc<dyn Clock>>,
    pub(crate) volume: Option<VolumeInfo>,
    pub(crate) volume_probe: Option<VolumeProbe>,
    pub(crate) hazards: Option<HazardEnv>,
}

/// When a session began in this process, on the clock that cannot be set.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionMark {
    /// Sequence number of the session's start event.
    pub(crate) start_seq: u64,
    /// [`Clock::monotonic_ms`] at that moment.
    pub(crate) monotonic_ms: u64,
}

/// Answer of [`Store::check_peer_commit_seq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackCheck {
    /// The ledger knows every commit the peer holds a receipt for.
    Consistent {
        /// Highest commit sequence number ever issued to the device.
        device_commit_hwm: u64,
    },
    /// The peer holds a receipt the ledger never issued: the ledger was
    /// rolled back. Final move is now blocked.
    RolledBack {
        /// The highest commit sequence number the peer holds a receipt for.
        peer_commit_seq: u64,
        /// Highest commit sequence number the ledger remembers issuing to it.
        device_commit_hwm: u64,
        /// The block that was set.
        block: BlockInfo,
    },
}

#[derive(Default)]
pub(crate) struct InFlight {
    /// Temp files that belong to live writers (recovery must not touch them).
    temps: HashSet<PathBuf>,
    /// Bytes the live writers have been promised but have not written yet.
    bytes_remaining: u64,
    /// Per device: (bytes declared, files) of the live writers.
    per_device: HashMap<String, (u64, u64)>,
}

pub(crate) struct Inner {
    pub(crate) cfg: StoreConfig,
    pub(crate) dest: Destination,
    pub(crate) fs: Arc<dyn Fs>,
    pub(crate) volume_probe: VolumeProbe,
    /// When this process opened the store.
    pub(crate) open_mark: SessionMark,
    /// The sessions each device has begun in this process, oldest first.
    pub(crate) device_marks: Mutex<HashMap<String, Vec<SessionMark>>>,
    /// The tag in the names of the temp files this run creates.
    temp_tag: String,
    /// Every temp-file tag the ledger has recorded, this run's included.
    pub(crate) known_tags: Mutex<HashSet<String>>,
    /// One mirror run or mirror scan at a time.
    pub(crate) mirror_lock: Mutex<()>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) ledger: Ledger,
    pub(crate) in_flight: Mutex<InFlight>,
    /// Per directory (by collision key): collision key of each entry -> its
    /// actual name. Filled on first use; the no-replace rename remains the
    /// authority for whether a name is free.
    pub(crate) dir_names: Mutex<HashMap<String, HashMap<String, String>>>,
    /// Serialises "choose a name and rename into place".
    pub(crate) commit_lock: Mutex<()>,
    /// One integrity scan at a time: its progress record is a single row.
    pub(crate) scan_lock: Mutex<()>,
    temp_counter: AtomicU64,
    recovery: Mutex<Option<RecoveryReport>>,
    notes: Vec<OpenNote>,
    _root_lock: File,
    _ledger_lock: File,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // None of the guarded structures can be left half-updated by a panic.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The storage engine for one destination.
///
/// Cheap to clone; all clones share the same state. See the crate
/// documentation for the guarantees.
#[derive(Clone)]
pub struct Store {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.inner.dest.display_root())
            .field("session", &self.inner.ledger.session())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the destination and its ledger and starts a new session.
    ///
    /// A long-running program opens the store once and calls
    /// [`Store::new_session`] at the start of every later transfer session.
    ///
    /// Fails with [`LedgerError::Corrupt`] if the ledger is damaged; see
    /// [`Store::reset_corrupt_ledger`]. Unless
    /// [`StoreConfig::defer_recovery`] is set, the recovery pass has run by
    /// the time this returns.
    pub fn open(cfg: StoreConfig) -> Result<Store, StoreError> {
        Self::open_impl(cfg, Seams::default(), None)
    }

    /// Like [`Store::open`], with parts of the world replaced. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn open_with_seams(cfg: StoreConfig, seams: Seams) -> Result<Store, StoreError> {
        Self::open_impl(cfg, seams, None)
    }

    /// Opens the store, replacing a *damaged* ledger by an empty one.
    ///
    /// The damaged database is moved aside (never deleted) and final move is
    /// blocked until [`Store::clear_final_move_block`] is called. The files in
    /// the destination are untouched, but the engine no longer knows them:
    /// nothing committed before the reset can be confirmed for deletion until
    /// it is received (and thereby re-verified) again.
    ///
    /// If the ledger is not damaged this is exactly [`Store::open`]. Other
    /// errors, including "this database is not ours", are returned unchanged.
    pub fn reset_corrupt_ledger(cfg: StoreConfig) -> Result<Store, StoreError> {
        Self::reset_impl(cfg, Seams::default)
    }

    /// Like [`Store::reset_corrupt_ledger`], with seams. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn reset_corrupt_ledger_with_seams(
        cfg: StoreConfig,
        seams: impl Fn() -> Seams,
    ) -> Result<Store, StoreError> {
        Self::reset_impl(cfg, seams)
    }

    fn reset_impl(cfg: StoreConfig, seams: impl Fn() -> Seams) -> Result<Store, StoreError> {
        match Self::open_impl(cfg.clone(), seams(), None) {
            Err(StoreError::Ledger(LedgerError::Corrupt { detail, .. })) => {
                let ledger_dir = std::fs::canonicalize(&cfg.ledger_dir).map_err(|e| {
                    StoreError::io("resolve the ledger directory", &cfg.ledger_dir, e)
                })?;
                // Hold the ledger lock while moving files, so two instances cannot both reset.
                let quarantined = {
                    let lock_path = ledger_dir.join(LEDGER_LOCK_FILE);
                    let _lock = acquire(&lock_path)?;
                    Ledger::quarantine(&ledger_dir)?
                };
                Self::open_impl(cfg, seams(), Some((detail, quarantined)))
            }
            other => other,
        }
    }

    fn open_impl(
        cfg: StoreConfig,
        seams: Seams,
        after_reset: Option<(String, Vec<PathBuf>)>,
    ) -> Result<Store, StoreError> {
        let mut dest = Destination::open(&cfg.root)?;
        if let Some(volume) = seams.volume {
            dest = force_volume(dest, volume);
        }
        if let Some(env) = seams.hazards {
            dest = dest.with_hazard_env(env);
        }
        let fs: Arc<dyn Fs> = seams.fs.unwrap_or_else(|| Arc::new(RealFs));
        let clock: Arc<dyn Clock> = seams.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let volume_probe: VolumeProbe = seams
            .volume_probe
            .unwrap_or_else(|| Arc::new(|path: &Path| sys::probe_volume(path)));

        // The bookkeeping directory inside the root: lock and identity marker.
        let store_dir = dest.root().join(STORE_DIR);
        match std::fs::create_dir(&store_dir) {
            Ok(()) => sys::hide(&store_dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(StoreError::write(
                    "create the bookkeeping directory",
                    &store_dir,
                    e,
                ))
            }
        }
        let meta = std::fs::symlink_metadata(&store_dir)
            .map_err(|e| StoreError::io("examine", &store_dir, e))?;
        if sys::is_reparse(&meta) {
            return Err(StoreError::ReparsePoint { path: store_dir });
        }
        if !meta.is_dir() {
            return Err(StoreError::NotADirectory { path: store_dir });
        }
        let root_lock = acquire(&store_dir.join(ROOT_LOCK_FILE))?;

        // The ledger directory.
        std::fs::create_dir_all(&cfg.ledger_dir)
            .map_err(|e| StoreError::write("create the ledger directory", &cfg.ledger_dir, e))?;
        let ledger_dir = std::fs::canonicalize(&cfg.ledger_dir)
            .map_err(|e| StoreError::io("resolve the ledger directory", &cfg.ledger_dir, e))?;
        let ledger_volume = sys::probe_volume(&ledger_dir)
            .map_err(|e| StoreError::io("examine the volume of", &ledger_dir, e))?;
        if ledger_volume.drive == DriveKind::Remote
            || matches!(ledger_volume.filesystem.as_str(), "nfs" | "smb")
        {
            return Err(LedgerError::OnNetworkVolume { path: ledger_dir }.into());
        }
        let ledger_lock = acquire(&ledger_dir.join(LEDGER_LOCK_FILE))?;

        let now = clock.now_unix_ms();
        let ledger = Ledger::open_unstarted(&ledger_dir)?;

        // Bind the ledger to the destination folder. A ledger that belongs to
        // another folder is refused before a session is started in it.
        let marker_path = store_dir.join(MARKER_FILE);
        let marker = read_marker(&marker_path);
        let ledger_id = ledger.destination_id()?;
        if let (Some(marker), Some(ledger_id)) = (&marker, &ledger_id) {
            if marker != ledger_id {
                return Err(LedgerError::DestinationMismatch {
                    ledger_id: ledger_id.clone(),
                    marker_id: marker.clone(),
                }
                .into());
            }
        }
        let fresh_ledger = ledger.max_file_id()? == 0 && ledger.devices()?.is_empty();
        ledger.start_session(now)?;
        let open_mark = SessionMark {
            start_seq: ledger.session_start_seq(),
            monotonic_ms: clock.monotonic_ms(),
        };
        // This run's temp-file tag is in the ledger, flushed, before any temp
        // file can carry it.
        let temp_tag = format!("{:016x}", random_u64());
        ledger.add_temp_tag(&temp_tag, now)?;
        let known_tags = ledger.temp_tags()?;
        let mut notes = Vec::new();
        match (marker, ledger_id) {
            (None, None) => {
                let id = new_destination_id();
                // Ledger first: if we stop between the two writes, the next
                // open sees "ledger has an id, marker missing, no files" and
                // simply rewrites the marker.
                ledger.set_destination_id(&id, now)?;
                write_marker(&marker_path, &id)?;
                notes.push(OpenNote::NewDestination);
            }
            (Some(_), Some(_)) => {}
            (Some(marker), None) => {
                // The folder was used before, but this ledger knows nothing.
                ledger.set_destination_id(&marker, now)?;
                match &after_reset {
                    Some((detail, quarantined)) => {
                        let reason = format!(
                            "the ledger was damaged ({detail}) and has been reset; files stored before the reset are no longer known"
                        );
                        ledger.block(BlockKind::LedgerReset, &reason, now)?;
                        notes.push(OpenNote::LedgerReset {
                            quarantined: quarantined.clone(),
                        });
                    }
                    None => {
                        ledger.block(
                            BlockKind::LedgerLost,
                            "this destination was used before, but its ledger was empty or missing; files stored earlier are no longer known",
                            now,
                        )?;
                        notes.push(OpenNote::LedgerLost);
                    }
                }
            }
            (None, Some(ledger_id)) => {
                write_marker(&marker_path, &ledger_id)?;
                notes.push(OpenNote::MarkerRecreated);
                if ledger.max_file_id()? > 0 {
                    ledger.block(
                        BlockKind::MarkerMissing,
                        "the destination folder lost its identity marker; the folder may have been replaced or emptied",
                        now,
                    )?;
                }
            }
        }
        if let (Some((detail, quarantined)), true) = (
            &after_reset,
            notes.is_empty() || notes == [OpenNote::NewDestination],
        ) {
            // Reset of a ledger for a folder that had no marker either.
            let reason = format!("the ledger was damaged ({detail}) and has been reset");
            ledger.block(BlockKind::LedgerReset, &reason, now)?;
            notes.push(OpenNote::LedgerReset {
                quarantined: quarantined.clone(),
            });
        }

        // A ledger that is behind what the destination folder remembers was
        // restored from an older copy while the folder was not.
        let witness_path = store_dir.join(WITNESS_FILE);
        if !fresh_ledger {
            if let Some(detail) = rolled_back(&ledger, &witness_path)? {
                for (device, hwm) in read_witness(&witness_path).map(|w| w.1).unwrap_or_default() {
                    ledger.raise_commit_hwm(
                        &device,
                        hwm,
                        "the destination remembers this commit",
                        now,
                    )?;
                }
                ledger.renew_ledger_id(&detail, now)?;
                let reason =
                    format!("the ledger was rolled back (restored from an older copy): {detail}");
                ledger.block(BlockKind::LedgerRollback, &reason, now)?;
                notes.push(OpenNote::LedgerRolledBack { detail });
            }
        }

        let defer_recovery = cfg.defer_recovery;
        let store = Store {
            inner: Arc::new(Inner {
                cfg,
                dest,
                fs,
                volume_probe,
                open_mark,
                device_marks: Mutex::new(HashMap::new()),
                temp_tag,
                known_tags: Mutex::new(known_tags),
                mirror_lock: Mutex::new(()),
                clock,
                ledger,
                in_flight: Mutex::new(InFlight::default()),
                dir_names: Mutex::new(HashMap::new()),
                commit_lock: Mutex::new(()),
                scan_lock: Mutex::new(()),
                temp_counter: AtomicU64::new(0),
                recovery: Mutex::new(None),
                notes,
                _root_lock: root_lock,
                _ledger_lock: ledger_lock,
            }),
        };
        store.inner.write_witness();
        if !defer_recovery {
            store.run_recovery(&CancelToken::new())?;
        }
        Ok(store)
    }

    /// The destination this store writes to.
    pub fn destination(&self) -> &Destination {
        &self.inner.dest
    }

    /// The number of this run of the store: it grows by one every time the
    /// store is opened. It is **not** what "an earlier session" means in
    /// [`Store::verify_for_deletion`]; that is a device's own session, see
    /// [`Store::new_session`].
    pub fn run_number(&self) -> u64 {
        self.inner.ledger.session()
    }

    /// The random identifier of the ledger. Receipts are only good for the
    /// ledger that issued them; a ledger found to have been restored from an
    /// older copy gets a new identifier (see [`OpenNote::LedgerRolledBack`]).
    pub fn ledger_id(&self) -> Result<String, StoreError> {
        Ok(self.inner.ledger.ledger_id()?)
    }

    /// Begins a new session **of one device**. Returns its number.
    ///
    /// A session is one established connection of one phone. The transfer
    /// layer calls this once per connection, when both sides have agreed on
    /// the session number, and passes that number; without a number the
    /// device's own counter is advanced by one. Opening the store, starting
    /// the program, or another phone connecting is **not** a new session for
    /// this phone, and nothing but this call advances its counter.
    ///
    /// The counter is in the ledger and survives restarts. The call does not
    /// return before the new session is on the device, and with it every
    /// batched record (see [`IncomingFile::finish_batched`]).
    ///
    /// What it means for [`Store::verify_for_deletion`]:
    ///
    /// * a file this device stored before the call belongs to an earlier
    ///   session from now on; a file whose transfer began before the call and
    ///   is finished after it belongs to the new session;
    /// * `min_age_sessions = n` is satisfied once the device's session number
    ///   is at least `n` above that of the session that recorded the file;
    /// * calling this again and again buys nothing: the 24 hours are counted
    ///   separately, on the wall clock, and for files stored while this
    ///   process has been running also on a clock that cannot be set, so a
    ///   wall clock that jumps ahead does not shorten the wait.
    ///
    /// Fails if the device is unknown or unpaired, or if `session_seq` is not
    /// above the device's current session number (or above 2^53 - 1).
    pub fn new_session(
        &self,
        device: &DeviceId,
        session_seq: Option<u64>,
    ) -> Result<u64, StoreError> {
        let inner = &self.inner;
        let id = device.as_str();
        match inner.ledger.device(id)? {
            None => return Err(StoreError::UnknownDevice(id.to_owned())),
            Some(d) if d.detached => return Err(StoreError::DeviceDetached(d.device_id)),
            Some(_) => {}
        }
        let outcome = inner
            .ledger
            .start_device_session(id, session_seq, inner.now())?;
        let session = match outcome {
            None => return Err(StoreError::UnknownDevice(id.to_owned())),
            Some(Err(current)) => {
                return Err(StoreError::SessionNotNewer {
                    current,
                    requested: session_seq.unwrap_or(current.saturating_add(1)),
                })
            }
            Some(Ok(session)) => session,
        };
        if let Some(record) = inner.ledger.device(id)? {
            lock(&inner.device_marks)
                .entry(id.to_owned())
                .or_default()
                .push(SessionMark {
                    start_seq: record.session_start_seq,
                    monotonic_ms: inner.clock.monotonic_ms(),
                });
        }
        inner.write_witness();
        Ok(session)
    }

    /// What [`Store::open`] noticed.
    pub fn open_notes(&self) -> &[OpenNote] {
        &self.inner.notes
    }

    /// The report of the most recent recovery pass, if one has run.
    pub fn recovery_report(&self) -> Option<RecoveryReport> {
        lock(&self.inner.recovery).clone()
    }

    /// Registers a paired device, or updates its display name and limits.
    ///
    /// The device's folder name is derived from `display_name` (which is
    /// peer-supplied and is sanitised like any other name) the first time and
    /// never changes afterwards.
    pub fn register_device(
        &self,
        id: &DeviceId,
        display_name: &str,
        limits: DeviceLimits,
    ) -> Result<DeviceRecord, StoreError> {
        let shown: String = display_name
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        let folder = sanitize_component(display_name).or_else(|_| {
            let short: String = id.as_str().chars().take(12).collect();
            sanitize_component(&format!("Device {short}"))
        });
        let folder = folder.map_err(|source| StoreError::UnsafeName {
            name: shown.clone(),
            source,
        })?;
        Ok(self.inner.ledger.upsert_device(
            id.as_str(),
            &shown,
            &folder,
            limits,
            self.inner.now(),
        )?)
    }

    /// A registered device, with its limits and current usage.
    pub fn device(&self, id: &DeviceId) -> Result<Option<DeviceRecord>, StoreError> {
        Ok(self.inner.ledger.device(id.as_str())?)
    }

    /// All registered devices, unpaired ones included.
    pub fn devices(&self) -> Result<Vec<DeviceRecord>, StoreError> {
        Ok(self.inner.ledger.devices()?)
    }

    /// Unpairs a device **without removing anything**.
    ///
    /// The device's ledger records and its files stay exactly as they are:
    /// they may be the only copies of photos the phone has already deleted.
    /// They are still scanned, still mirrored, still counted, and still shown
    /// by [`Store::devices`] with [`DeviceRecord::detached`] set. The device
    /// itself can no longer send files or have a deletion confirmed until it
    /// is registered again ([`Store::register_device`] with the same id),
    /// which brings everything back as it was.
    ///
    /// There is no call that removes a device's records or files.
    ///
    /// Returns false if the device is unknown or already unpaired.
    pub fn detach_device(&self, id: &DeviceId, note: &str) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .ledger
            .detach_device(id.as_str(), note, self.inner.now())?)
    }

    /// A device's commit high-water mark: the highest commit number
    /// ([`CommitReceipt::seq`]) this ledger has ever issued to it. Commit
    /// numbers are counted per device (1, 2, 3, ...); the mark is stored in
    /// the ledger and never decreases.
    ///
    /// The transfer layer sends it to the phone when they connect; the phone
    /// compares it with the highest commit number it holds a receipt for. A
    /// phone that holds a higher one has proof that this ledger was rolled
    /// back (restored from a backup or a system image): see
    /// [`Store::check_peer_commit_seq`].
    pub fn commit_hwm(&self, device: &DeviceId) -> Result<u64, StoreError> {
        self.inner
            .ledger
            .device(device.as_str())?
            .map(|d| d.commit_hwm)
            .ok_or_else(|| StoreError::UnknownDevice(device.as_str().to_owned()))
    }

    /// Checks the highest commit number a phone holds a receipt for against
    /// what the ledger remembers issuing to it.
    ///
    /// If the phone's number is higher, the ledger has lost commits it once
    /// acknowledged: it was rolled back. That is recorded, final move is
    /// blocked ([`BlockKind::LedgerRollback`]), the device's mark is raised
    /// to the phone's number (so that no commit number is ever issued twice)
    /// and [`RollbackCheck::RolledBack`] is returned; the transfer layer
    /// should treat the phone's receipts as void and offer everything again.
    pub fn check_peer_commit_seq(
        &self,
        device: &DeviceId,
        peer_commit_seq: u64,
    ) -> Result<RollbackCheck, StoreError> {
        let inner = &self.inner;
        let record = inner
            .ledger
            .device(device.as_str())?
            .ok_or_else(|| StoreError::UnknownDevice(device.as_str().to_owned()))?;
        if peer_commit_seq <= record.commit_hwm {
            return Ok(RollbackCheck::Consistent {
                device_commit_hwm: record.commit_hwm,
            });
        }
        let block = inner.rolled_back(&record.device_id, peer_commit_seq, record.commit_hwm)?;
        Ok(RollbackCheck::RolledBack {
            peer_commit_seq,
            device_commit_hwm: record.commit_hwm,
            block,
        })
    }

    /// Reports a ledger rollback that the caller detected by other means
    /// (for example a receipt whose hash the ledger does not know). Final
    /// move is blocked until [`Store::clear_final_move_block`].
    pub fn report_rollback(&self, detail: &str) -> Result<BlockInfo, StoreError> {
        let reason = format!("the ledger was rolled back: {detail}");
        Ok(self
            .inner
            .ledger
            .block(BlockKind::LedgerRollback, &reason, self.inner.now())?)
    }

    /// Flushes the ledger: every record written by
    /// [`IncomingFile::finish_batched`] so far is on the device when this
    /// returns, and their receipts may be acknowledged to the phone.
    pub fn flush_batch(&self) -> Result<(), StoreError> {
        self.inner.ledger.flush(self.inner.now())?;
        self.inner.write_witness();
        Ok(())
    }

    /// How many batched records are waiting for [`Store::flush_batch`].
    pub fn pending_batch(&self) -> u64 {
        self.inner.ledger.pending_batched()
    }

    /// The persistent final-move block, if set.
    pub fn final_move_block(&self) -> Result<Option<BlockInfo>, StoreError> {
        Ok(self.inner.ledger.block_info()?)
    }

    /// Blocks final move by hand (for example from a "pause deletions" switch).
    pub fn block_final_move(&self, reason: &str) -> Result<BlockInfo, StoreError> {
        Ok(self
            .inner
            .ledger
            .block(BlockKind::Manual, reason, self.inner.now())?)
    }

    /// Clears the final-move block. This is the only way it is ever cleared.
    ///
    /// `note` is logged (who decided, and why). Clearing does not vouch for
    /// any file: every later confirmation still re-reads the file from disk.
    /// Returns the block that was cleared, if one was set.
    pub fn clear_final_move_block(&self, note: &str) -> Result<Option<BlockInfo>, StoreError> {
        Ok(self.inner.ledger.clear_block(note, self.inner.now())?)
    }

    /// Tells the engine that the clock is right *now*, after it was wrong.
    ///
    /// If the PC's clock was ever ahead (a dead battery, a mistyped year) and
    /// files were stored during that time, the corrected clock reads earlier
    /// than times already in the ledger, and [`Store::verify_for_deletion`]
    /// answers [`DeletionDenied::ClockWentBackwards`] until real time catches
    /// up, which may be years. This call is the way out, and like clearing
    /// the block it must be a person's decision: it accepts the present
    /// reading as the truth. Files whose recorded commit time lies in the
    /// future are treated as committed now, in this session, so they have to
    /// age again before they can be confirmed. Returns how many were affected.
    pub fn acknowledge_clock_change(&self, note: &str) -> Result<u64, StoreError> {
        Ok(self
            .inner
            .ledger
            .acknowledge_clock(note, self.inner.now())?)
    }

    /// Row counts of the ledger, for diagnostics.
    pub fn stats(&self) -> Result<LedgerStats, StoreError> {
        Ok(self.inner.ledger.stats()?)
    }

    /// Up to `limit` ledger events with a sequence number above `after`.
    pub fn events_after(&self, after: u64, limit: u32) -> Result<Vec<EventRecord>, StoreError> {
        Ok(self.inner.ledger.events_after(after, limit)?)
    }

    /// The ledger database file (for backups and support bundles).
    pub fn ledger_path(&self) -> &Path {
        self.inner.ledger.path()
    }
}

impl Inner {
    pub(crate) fn now(&self) -> i64 {
        self.clock.now_unix_ms()
    }

    pub(crate) fn root(&self) -> &Path {
        self.dest.root()
    }

    /// A fresh temp-file name: `.kiwi-tmp-<tag>-<n>-<random>.part`, with the
    /// tag of this run.
    pub(crate) fn temp_name(&self) -> String {
        let n = self.temp_counter.fetch_add(1, Ordering::Relaxed);
        format!(
            "{TEMP_PREFIX}{}-{:x}-{:016x}{TEMP_SUFFIX}",
            self.temp_tag,
            n,
            random_u64()
        )
    }

    /// Records a proven rollback for one device: block, and raise the
    /// device's mark so the numbers the phone has seen are never used again.
    pub(crate) fn rolled_back(
        &self,
        device: &str,
        peer_commit_seq: u64,
        known: u64,
    ) -> Result<BlockInfo, LedgerError> {
        let reason = format!(
            "the ledger was rolled back: device {device} holds a receipt for commit {peer_commit_seq}, \
             but the highest commit the ledger remembers issuing to it is {known}"
        );
        let block = self
            .ledger
            .block(BlockKind::LedgerRollback, &reason, self.now())?;
        self.ledger
            .raise_commit_hwm(device, peer_commit_seq, &reason, self.now())?;
        self.write_witness();
        Ok(block)
    }

    /// Writes down, inside the destination folder, the highest commit number
    /// of every device. Called only when the ledger has just been flushed,
    /// so the note is never ahead of the ledger. A ledger that is later
    /// found behind this note was restored from an older copy. Best effort:
    /// without the note only this one way of noticing is lost.
    pub(crate) fn write_witness(&self) {
        let (Ok(ledger_id), Ok(devices)) = (self.ledger.ledger_id(), self.ledger.devices()) else {
            return;
        };
        let mut text = format!("kiwi-commits 1 {ledger_id}\n");
        for device in devices {
            text.push_str(&format!("{} {}\n", device.device_id, device.commit_hwm));
        }
        let path = self.root().join(STORE_DIR).join(WITNESS_FILE);
        let fresh = path.with_extension("new");
        if std::fs::write(&fresh, text).is_ok() {
            let _ = std::fs::rename(&fresh, &path);
        }
    }

    /// Walks from `root` (the destination or a mirror) down `dir`, refusing reparse points and anything
    /// that is not a directory. With `create`, missing directories are made
    /// (reusing an existing directory whose name differs only by case).
    ///
    /// Returns the absolute path and the directory's path as it is actually
    /// spelled on disk, or `None` if a component is missing and `create` is
    /// false.
    pub(crate) fn walk_dirs(
        &self,
        root: &Path,
        dir: &SafeRelPath,
        create: bool,
    ) -> Result<Option<(PathBuf, SafeRelPath)>, StoreError> {
        let mut path = root.to_path_buf();
        for part in dir.components() {
            let parent = path.clone();
            path.push(part.as_str());
            let mut stat = self
                .fs
                .stat(&path)
                .map_err(|e| StoreError::io("examine", &path, e))?;
            if stat.is_none() {
                if !create {
                    return Ok(None);
                }
                // On a case-sensitive file system an existing "dcim" must be
                // reused for "DCIM", exactly as NTFS would do by itself.
                let key = part.collision_key();
                let twin = self
                    .fs
                    .list_dir(&parent)
                    .map_err(|e| StoreError::io("list", &parent, e))?
                    .into_iter()
                    .find(|e| e.exact && collision_key(&e.name) == key);
                match twin {
                    Some(entry) => {
                        path = parent.join(&entry.name);
                    }
                    None => match self.fs.create_dir(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(StoreError::write("create the directory", &path, e)),
                    },
                }
                stat = self
                    .fs
                    .stat(&path)
                    .map_err(|e| StoreError::io("examine", &path, e))?;
            }
            match stat {
                Some(s) if s.reparse => return Err(StoreError::ReparsePoint { path }),
                Some(s) if s.kind == EntryKind::Dir => {}
                Some(_) => return Err(StoreError::NotADirectory { path }),
                None => {
                    let gone = io::Error::new(
                        io::ErrorKind::NotFound,
                        "the directory vanished while it was being created",
                    );
                    return Err(StoreError::io("examine", &path, gone));
                }
            }
        }

        // Ask the operating system where we really are. This catches what the
        // per-component check cannot: 8.3 short names that alias another
        // directory, and anything that redirected the path after the check.
        let resolved = self
            .fs
            .resolve(&path)
            .map_err(|e| StoreError::io("resolve", &path, e))?;
        let mismatch = || StoreError::PathMismatch {
            expected: path.clone(),
            resolved: resolved.clone(),
        };
        let below = resolved.strip_prefix(root).map_err(|_| mismatch())?;
        let mut actual = Vec::with_capacity(dir.depth());
        for component in below.components() {
            let name = component.as_os_str().to_str().ok_or_else(mismatch)?;
            actual.push(SafeName::from_stored(name).ok_or_else(mismatch)?);
        }
        let same = actual.len() == dir.depth()
            && actual
                .iter()
                .zip(dir.components())
                .all(|(a, want)| a.collision_key() == want.collision_key());
        if !same {
            return Err(mismatch());
        }
        let actual = SafeRelPath::from_components(actual);
        Ok(Some((actual.under(root), actual)))
    }

    /// Loads (or reloads) the names in a directory into the cache.
    pub(crate) fn load_dir_names(
        &self,
        dir_key: &str,
        dir_abs: &Path,
        reload: bool,
    ) -> Result<(), StoreError> {
        if !reload && lock(&self.dir_names).contains_key(dir_key) {
            return Ok(());
        }
        let listing = self
            .fs
            .list_dir(dir_abs)
            .map_err(|e| StoreError::io("list", dir_abs, e))?;
        let mut names = HashMap::with_capacity(listing.len());
        for entry in listing {
            names
                .entry(collision_key(&entry.name))
                .or_insert(entry.name);
        }
        lock(&self.dir_names).insert(dir_key.to_owned(), names);
        Ok(())
    }

    pub(crate) fn cached_name(&self, dir_key: &str, name_key: &str) -> Option<String> {
        lock(&self.dir_names)
            .get(dir_key)
            .and_then(|names| names.get(name_key).cloned())
    }

    pub(crate) fn remember_name(&self, dir_key: &str, name_key: String, actual: &str) {
        if let Some(names) = lock(&self.dir_names).get_mut(dir_key) {
            names.insert(name_key, actual.to_owned());
        }
    }

    pub(crate) fn forget_name(&self, dir_key: &str, name_key: &str) {
        if let Some(names) = lock(&self.dir_names).get_mut(dir_key) {
            names.remove(name_key);
        }
    }

    /// Forgets every cached directory listing (after anything that may have
    /// changed the tree behind the engine's back).
    pub(crate) fn forget_all_names(&self) {
        lock(&self.dir_names).clear();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // A clean shutdown leaves no batched record at the mercy of a power cut.
        if self.ledger.pending_batched() > 0 && self.ledger.flush(self.clock.now_unix_ms()).is_ok()
        {
            self.write_witness();
        }
    }
}

/// The note the destination folder keeps of the ledger's commit numbers: the
/// ledger id it was written for, and each device's highest commit number.
fn read_witness(path: &Path) -> Option<(String, Vec<(String, u64)>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let ledger_id = lines.next()?.strip_prefix("kiwi-commits 1 ")?.to_owned();
    let mut devices = Vec::new();
    for line in lines {
        let (device, hwm) = line.split_once(' ')?;
        devices.push((device.to_owned(), hwm.parse().ok()?));
    }
    Some((ledger_id, devices))
}

/// Compares a ledger that has been used before with the destination's note.
/// Returns what is wrong if the ledger is behind it.
fn rolled_back(ledger: &Ledger, witness_path: &Path) -> Result<Option<String>, StoreError> {
    let Some((noted_id, noted)) = read_witness(witness_path) else {
        return Ok(None);
    };
    if noted_id != ledger.ledger_id()? {
        return Ok(Some(
            "the destination was last used with a later state of this ledger".to_owned(),
        ));
    }
    let known: HashMap<String, u64> = ledger
        .devices()?
        .into_iter()
        .map(|d| (d.device_id, d.commit_hwm))
        .collect();
    for (device, hwm) in noted {
        let have = known.get(&device).copied();
        if hwm > 0 && have.is_none_or(|have| have < hwm) {
            return Ok(Some(format!(
                "the destination remembers commit {hwm} of device {device}; the ledger knows {}",
                have.map_or("nothing of that device".to_owned(), |h| format!(
                    "only up to {h}"
                ))
            )));
        }
    }
    Ok(None)
}

fn acquire(lock_path: &Path) -> Result<File, StoreError> {
    match sys::acquire_lock(lock_path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(StoreError::AlreadyOpen {
            lock: lock_path.to_path_buf(),
        }),
        Err(e) => Err(StoreError::io("lock", lock_path, e)),
    }
}

#[cfg(any(test, feature = "test-util"))]
fn force_volume(dest: Destination, volume: VolumeInfo) -> Destination {
    dest.with_volume_for_testing(volume)
}

#[cfg(not(any(test, feature = "test-util")))]
fn force_volume(dest: Destination, _volume: VolumeInfo) -> Destination {
    dest
}

fn read_marker(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let id = text.trim();
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

fn write_marker(path: &Path, id: &str) -> Result<(), StoreError> {
    let tmp = path.with_extension("new");
    let write = || -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(id.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| StoreError::write("write the destination marker", path, e))
}

pub(crate) fn new_destination_id() -> String {
    format!("{:016x}{:016x}", random_u64(), random_u64())
}

/// 64 bits that differ between calls and between processes. Used for unique
/// names and identifiers, not for secrets.
pub(crate) fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u32(std::process::id());
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_handles_can_cross_threads() {
        fn send_and_sync<T: Send + Sync>() {}
        fn send<T: Send>() {}
        send_and_sync::<Store>();
        send_and_sync::<CancelToken>();
        send::<IncomingFile>();
    }

    #[test]
    fn device_ids_are_plain() {
        assert!(DeviceId::new("abc-DEF_0.9").is_ok());
        for bad in ["", " ", "a b", "a/b", "a:b", "a%b", "a@b"] {
            assert!(DeviceId::new(bad).is_err(), "{bad:?}");
        }
        assert!(DeviceId::new(&"a".repeat(128)).is_ok());
        assert!(DeviceId::new(&"a".repeat(129)).is_err());
    }

    #[test]
    fn markers_are_validated() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("unit-tmp")
            .join("marker");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id");
        assert_eq!(read_marker(&path), None);
        let id = new_destination_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, new_destination_id());
        write_marker(&path, &id).unwrap();
        assert_eq!(read_marker(&path), Some(id.clone()));
        // Rewriting replaces the old marker in one step.
        let other = new_destination_id();
        write_marker(&path, &other).unwrap();
        assert_eq!(read_marker(&path), Some(other));
        // Anything that is not 32 hex digits is "no marker".
        for junk in ["", "xyz", "0123", &"g".repeat(32), &"a".repeat(33)] {
            std::fs::write(&path, junk).unwrap();
            assert_eq!(read_marker(&path), None, "{junk:?}");
        }
    }

    #[test]
    fn temp_names_are_recognised_and_unique() {
        use super::pipeline::is_temp_name;
        assert!(is_temp_name(
            ".kiwi-tmp-00112233aabbccdd-0-0123456789abcdef.part"
        ));
        assert!(is_temp_name(
            ".kiwi-tmp-00112233aabbccdd-1f-0123456789abcdef.part"
        ));
        for not in [
            ".kiwi-tmp-.part",
            ".kiwi-tmp-x",
            "x.kiwi-tmp-1.part",
            "a.part",
            ".KIWI-TMP-1.part",
            ".kiwi-tmp-1.part",
            ".kiwi-tmp-notes.part",
            ".kiwi-tmp-1-0-0123456789abcdef.part",
            ".kiwi-tmp-00112233aabbccdd-0-0123456789abcde.part",
            ".kiwi-tmp-00112233AABBCCDD-0-0123456789abcdef.part",
            ".kiwi-tmp-00112233aabbccdd-0-0123456789abcdef-1.part",
            ".kiwi-tmp-00112233aabbccdd-0-0123456789abcdef.part.jpg",
            "",
        ] {
            assert!(!is_temp_name(not), "{not:?}");
        }
        assert_ne!(random_u64(), random_u64());
    }
}
