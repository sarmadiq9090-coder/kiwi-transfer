//! The storage engine: one destination root, one ledger.

mod incoming;
mod recovery;
mod scan;
mod verify;

pub use incoming::{CommitOutcome, CommitReceipt, FileRequest, IncomingFile};
pub use recovery::RecoveryReport;
pub use scan::{
    CancelToken, FindingKind, ScanFinding, ScanOptions, ScanPolicy, ScanReport, ScanVerdict,
    MAX_LISTED_FINDINGS,
};
pub use verify::{
    DedupeScope, DeletionDenied, DeletionProof, NotVerifiedReason, StoredFile, StoredStatus,
};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::destination::{Destination, DriveKind};
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
}

/// Seams for tests. Never available in a shipping build.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default)]
pub struct Seams {
    /// Replaces the real file system.
    pub fs: Option<Arc<dyn Fs>>,
    /// Replaces the system clock.
    pub clock: Option<Arc<dyn Clock>>,
    /// Replaces what the platform says about the destination volume.
    pub volume: Option<crate::destination::VolumeInfo>,
}

#[cfg(not(any(test, feature = "test-util")))]
#[derive(Default)]
pub(crate) struct Seams {
    pub(crate) fs: Option<Arc<dyn Fs>>,
    pub(crate) clock: Option<Arc<dyn Clock>>,
    pub(crate) volume: Option<crate::destination::VolumeInfo>,
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
    pub(crate) volume_is_forced: bool,
    pub(crate) fs: Arc<dyn Fs>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) ledger: Ledger,
    pub(crate) in_flight: Mutex<InFlight>,
    /// Per directory (by collision key): collision key of each entry -> its
    /// actual name. Filled on first use; the no-replace rename remains the
    /// authority for whether a name is free.
    pub(crate) dir_names: Mutex<HashMap<String, HashMap<String, String>>>,
    /// Serialises "choose a name and rename into place".
    pub(crate) commit_lock: Mutex<()>,
    temp_counter: AtomicU64,
    temp_salt: u64,
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
        let volume_is_forced = seams.volume.is_some();
        if let Some(volume) = seams.volume {
            dest = force_volume(dest, volume);
        }
        let fs: Arc<dyn Fs> = seams.fs.unwrap_or_else(|| Arc::new(RealFs));
        let clock: Arc<dyn Clock> = seams.clock.unwrap_or_else(|| Arc::new(SystemClock));

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
        let mut ledger = Ledger::open_unstarted(&ledger_dir)?;

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
        ledger.start_session(now)?;
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

        let defer_recovery = cfg.defer_recovery;
        let store = Store {
            inner: Arc::new(Inner {
                cfg,
                dest,
                volume_is_forced,
                fs,
                clock,
                ledger,
                in_flight: Mutex::new(InFlight::default()),
                dir_names: Mutex::new(HashMap::new()),
                commit_lock: Mutex::new(()),
                temp_counter: AtomicU64::new(0),
                temp_salt: random_u64(),
                recovery: Mutex::new(None),
                notes,
                _root_lock: root_lock,
                _ledger_lock: ledger_lock,
            }),
        };
        if !defer_recovery {
            store.run_recovery(&CancelToken::new())?;
        }
        Ok(store)
    }

    /// The destination this store writes to.
    pub fn destination(&self) -> &Destination {
        &self.inner.dest
    }

    /// This open's session number. It grows by one every time the store is
    /// opened and is what "an earlier session" means in
    /// [`Store::verify_for_deletion`].
    pub fn session(&self) -> u64 {
        self.inner.ledger.session()
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

    /// All registered devices.
    pub fn devices(&self) -> Result<Vec<DeviceRecord>, StoreError> {
        Ok(self.inner.ledger.devices()?)
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

    /// A fresh temp-file name.
    pub(crate) fn temp_name(&self) -> String {
        let n = self.temp_counter.fetch_add(1, Ordering::Relaxed);
        let mix = random_u64() ^ self.temp_salt.rotate_left((n % 61) as u32);
        format!(
            "{TEMP_PREFIX}{:x}-{:x}-{:016x}{TEMP_SUFFIX}",
            self.ledger.session(),
            n,
            mix
        )
    }

    /// Walks from the root down `dir`, refusing reparse points and anything
    /// that is not a directory. With `create`, missing directories are made
    /// (reusing an existing directory whose name differs only by case).
    ///
    /// Returns the absolute path and the directory's path as it is actually
    /// spelled on disk, or `None` if a component is missing and `create` is
    /// false.
    pub(crate) fn walk_dirs(
        &self,
        dir: &SafeRelPath,
        create: bool,
    ) -> Result<Option<(PathBuf, SafeRelPath)>, StoreError> {
        let mut path = self.root().to_path_buf();
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
        let below = resolved.strip_prefix(self.root()).map_err(|_| mismatch())?;
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
        Ok(Some((actual.under(self.root()), actual)))
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
fn force_volume(dest: Destination, volume: crate::destination::VolumeInfo) -> Destination {
    dest.with_volume_for_testing(volume)
}

#[cfg(not(any(test, feature = "test-util")))]
fn force_volume(dest: Destination, _volume: crate::destination::VolumeInfo) -> Destination {
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

fn new_destination_id() -> String {
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
