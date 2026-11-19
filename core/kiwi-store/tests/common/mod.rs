//! Shared helpers for the integration tests.
//!
//! Every test gets its own directory under Cargo's target directory (on this
//! project's machines that is a fixed NTFS disk); nothing outside it is touched.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kiwi_store::destination::{BusKind, DriveKind};
use kiwi_store::testing::{FaultFs, ManualClock};
use kiwi_store::{
    CommitReceipt, ContentHash, DeviceId, DeviceLimits, FileRequest, Seams, Store, StoreConfig, StoreError, VolumeInfo,
    STORE_DIR, TEMP_PREFIX,
};

/// 2027-01-15T08:00:00Z, in milliseconds.
pub const T0: i64 = 1_800_000_000_000;
pub const HOUR: i64 = 3_600_000;

/// A test's private world: a destination root, a ledger directory, a
/// steerable file system and a clock.
pub struct World {
    pub base: PathBuf,
    pub root: PathBuf,
    pub ledger_dir: PathBuf,
    pub outside: PathBuf,
    pub fs: FaultFs,
    pub clock: Arc<ManualClock>,
    pub volume: Option<VolumeInfo>,
    pub configure: fn(&mut StoreConfig),
}

fn no_change(_: &mut StoreConfig) {}

impl World {
    /// A fresh, empty world. `name` must be unique within the test binary.
    pub fn new(name: &str) -> World {
        // KIWI_STORE_TEST_TMP moves the test worlds elsewhere (for example to
        // a volume with different properties); the default is Cargo's own
        // per-target temp directory.
        let parent = std::env::var_os("KIWI_STORE_TEST_TMP").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
        let base = parent.join(format!("{}-{name}", module_path!().replace("::", "-")));
        if base.exists() {
            remove_tree(&base);
        }
        let root = base.join("root");
        let ledger_dir = base.join("ledger");
        let outside = base.join("outside");
        for dir in [&root, &ledger_dir, &outside] {
            std::fs::create_dir_all(dir).unwrap();
        }
        World {
            root: std::fs::canonicalize(&root).unwrap(),
            ledger_dir,
            outside: std::fs::canonicalize(&outside).unwrap(),
            base,
            fs: FaultFs::new(),
            clock: ManualClock::new(T0),
            volume: Some(fixed_ntfs()),
            configure: no_change,
        }
    }

    pub fn config(&self) -> StoreConfig {
        let mut cfg = StoreConfig::new(&self.root, &self.ledger_dir);
        cfg.safety_margin_bytes = 1024 * 1024;
        (self.configure)(&mut cfg);
        cfg
    }

    pub fn seams(&self) -> Seams {
        Seams { fs: Some(Arc::new(self.fs.clone())), clock: Some(self.clock.clone()), volume: self.volume.clone() }
    }

    pub fn try_open(&self) -> Result<Store, StoreError> {
        Store::open_with_seams(self.config(), self.seams())
    }

    /// Opens the store (a new session) with the phone registered.
    pub fn open(&self) -> Store {
        let store = self.try_open().expect("the store should open");
        store.register_device(&phone(), "Pixel 8", DeviceLimits::default()).unwrap();
        store
    }

    /// Absolute path of a file relative to the root (`/`-separated).
    pub fn path(&self, rel: &str) -> PathBuf {
        let mut p = self.root.clone();
        for part in rel.split('/') {
            p.push(part);
        }
        p
    }

    /// All files under the root (not the bookkeeping directory), as sorted
    /// `/`-separated relative paths. Links are listed, not followed.
    pub fn files(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect(&self.root, String::new(), &mut out, true);
        out.sort();
        out
    }

    /// Temp files anywhere under the root.
    pub fn temp_files(&self) -> Vec<String> {
        self.files().into_iter().filter(|f| f.rsplit('/').next().unwrap().starts_with(TEMP_PREFIX)).collect()
    }

    pub fn ledger_file(&self) -> PathBuf {
        self.ledger_dir.join("ledger.db")
    }
}

fn collect(dir: &Path, rel: String, out: &mut Vec<String>, top: bool) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if top && name == STORE_DIR {
            continue;
        }
        let child = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        if meta.is_dir() && !is_link(&meta) {
            collect(&entry.path(), child, out, false);
        } else {
            out.push(child);
        }
    }
}

#[cfg(windows)]
pub fn is_link(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
pub fn is_link(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Removes a test tree without following links out of it.
pub fn remove_tree(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return };
    if is_link(&meta) {
        // Remove the link itself, never what it points to. A junction or
        // directory link goes with remove_dir, a file link with remove_file.
        if std::fs::remove_dir(path).is_err() {
            std::fs::remove_file(path).unwrap();
        }
    } else if meta.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            remove_tree(&entry.unwrap().path());
        }
        std::fs::remove_dir(path).unwrap();
    } else {
        std::fs::remove_file(path).unwrap();
    }
}

/// What the platform reports for an internal SATA disk with NTFS.
pub fn fixed_ntfs() -> VolumeInfo {
    VolumeInfo {
        drive: DriveKind::Fixed,
        filesystem: "NTFS".to_owned(),
        serial: Some(0x1234_5678),
        read_only: false,
        removable_media: Some(false),
        hot_plug: Some(false),
        bus: Some(BusKind::Sata),
        volume_root: "test".to_owned(),
    }
}

pub fn phone() -> DeviceId {
    DeviceId::new("phone-1").unwrap()
}

pub fn tablet() -> DeviceId {
    DeviceId::new("tablet-2").unwrap()
}

/// Deterministic pseudo-random bytes.
pub fn data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

pub fn request<'a>(device: &'a DeviceId, name: &'a str, bytes: &[u8]) -> FileRequest<'a> {
    FileRequest {
        device,
        name,
        size: bytes.len() as u64,
        claimed_hash: Some(ContentHash::of_bytes(bytes)),
        capture_time: None,
        mtime_unix_ns: None,
    }
}

/// Sends one whole file the way the transfer layer would.
pub fn try_put(store: &Store, device: &DeviceId, name: &str, bytes: &[u8]) -> Result<CommitReceipt, StoreError> {
    let mut incoming = store.begin_file(request(device, name, bytes))?;
    for chunk in bytes.chunks(64 * 1024) {
        incoming.write(chunk)?;
    }
    incoming.finish(None)
}

pub fn put(store: &Store, name: &str, bytes: &[u8]) -> CommitReceipt {
    try_put(store, &phone(), name, bytes).unwrap_or_else(|e| panic!("storing {name:?} failed: {e}"))
}

/// Flips one bit of a file in place, keeping its size and modification time.
pub fn corrupt_silently(path: &Path) {
    let meta = std::fs::metadata(path).unwrap();
    let mtime = meta.modified().unwrap();
    let mut bytes = std::fs::read(path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(path, &bytes).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(mtime).unwrap();
    drop(file);
    assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), mtime);
    assert_eq!(std::fs::metadata(path).unwrap().len(), meta.len());
}
