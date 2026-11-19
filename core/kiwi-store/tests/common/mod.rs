//! Shared helpers for the integration tests.
//!
//! Every test gets its own directory under Cargo's target directory (on this
//! project's machines that is a fixed NTFS disk); nothing outside it is touched.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kiwi_store::destination::{BusKind, DriveKind};
use kiwi_store::testing::{FaultFs, ManualClock};
use kiwi_store::{
    CommitReceipt, ContentHash, DeletionDenied, DeletionProof, DeviceId, DeviceLimits, FileRequest,
    HazardEnv, Seams, Store, StoreConfig, StoreError, VerifyRequest, VolumeInfo, STORE_DIR,
    TEMP_PREFIX,
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
    /// Where sync folders and system-managed folders are looked for. By
    /// default: nowhere above the test's own directory, so the machine the
    /// tests run on cannot change their outcome.
    pub hazards: HazardEnv,
    /// What the "platform" says about the stand-in disks (see [`World::disk`]).
    pub volumes: Arc<Mutex<HashMap<PathBuf, VolumeInfo>>>,
}

fn no_change(_: &mut StoreConfig) {}

impl World {
    /// A fresh, empty world. `name` must be unique within the test binary.
    pub fn new(name: &str) -> World {
        // KIWI_STORE_TEST_TMP moves the test worlds elsewhere (for example to
        // a volume with different properties); the default is Cargo's own
        // per-target temp directory.
        let parent = std::env::var_os("KIWI_STORE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
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
            fs: FaultFs::new(),
            clock: ManualClock::new(T0),
            volume: Some(fixed_ntfs()),
            configure: no_change,
            hazards: HazardEnv {
                ceiling: Some(std::fs::canonicalize(&base).unwrap()),
                ..HazardEnv::default()
            },
            volumes: Arc::new(Mutex::new(HashMap::new())),
            base,
        }
    }

    /// A directory that stands in for a second disk: `<base>/<name>`, an
    /// external USB disk with its own volume serial number and its own
    /// device number. Created if absent.
    pub fn disk(&self, name: &str) -> PathBuf {
        let dir = self.base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let mut volumes = self.volumes.lock().unwrap();
        let next = usb_ntfs(0xD15C_0000 + volumes.len() as u64);
        volumes.entry(dir.clone()).or_insert(next);
        dir
    }

    /// Pretends the volume behind a stand-in disk was exchanged for another.
    pub fn set_serial(&self, disk: &Path, serial: u64) {
        let mut volumes = self.volumes.lock().unwrap();
        let volume = volumes
            .entry(disk.to_path_buf())
            .or_insert_with(|| usb_ntfs(serial));
        volume.serial = Some(serial);
    }

    /// Replaces everything the "platform" says about a stand-in disk.
    pub fn set_volume(&self, disk: &Path, volume: VolumeInfo) {
        self.volumes
            .lock()
            .unwrap()
            .insert(disk.to_path_buf(), volume);
    }

    pub fn config(&self) -> StoreConfig {
        let mut cfg = StoreConfig::new(&self.root, &self.ledger_dir);
        cfg.safety_margin_bytes = 1024 * 1024;
        (self.configure)(&mut cfg);
        cfg
    }

    pub fn seams(&self) -> Seams {
        Seams {
            fs: Some(Arc::new(self.fs.clone())),
            clock: Some(self.clock.clone()),
            volume: self.volume.clone(),
            volume_probe: Some(self.volume_probe()),
            hazards: Some(self.hazards.clone()),
        }
    }

    /// What the "platform" says about the volume of a mirror: whatever was
    /// registered for the stand-in disk the path lies on.
    pub fn volume_probe(&self) -> kiwi_store::VolumeProbe {
        let volumes = Arc::clone(&self.volumes);
        Arc::new(move |path: &Path| {
            let volumes = volumes.lock().unwrap();
            Ok(volumes
                .iter()
                .find(|(disk, _)| path.starts_with(disk))
                .map(|(_, volume)| volume.clone())
                .unwrap_or_else(|| usb_ntfs(0x0BAD_D15C)))
        })
    }

    pub fn try_open(&self) -> Result<Store, StoreError> {
        Store::open_with_seams(self.config(), self.seams())
    }

    /// Opens the store with the phone registered and connected: a new
    /// session of the phone has begun.
    pub fn open(&self) -> Store {
        let store = self.open_idle();
        store.new_session(&phone(), None).unwrap();
        store
    }

    /// Opens the store with the phone registered, but not connected: the
    /// program was started and no session of the phone has begun.
    pub fn open_idle(&self) -> Store {
        let store = self.try_open().expect("the store should open");
        store
            .register_device(&phone(), "Pixel 8", DeviceLimits::default())
            .unwrap();
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
        tree(&self.root)
    }

    /// Temp files anywhere under the root.
    pub fn temp_files(&self) -> Vec<String> {
        self.files()
            .into_iter()
            .filter(|f| f.rsplit('/').next().unwrap().starts_with(TEMP_PREFIX))
            .collect()
    }

    pub fn ledger_file(&self) -> PathBuf {
        self.ledger_dir.join("ledger.db")
    }
}

/// All files under `dir` (not its bookkeeping directory), as sorted
/// `/`-separated relative paths. Links are listed, not followed.
pub fn tree(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    collect(dir, String::new(), &mut out, true);
    out.sort();
    out
}

/// Copies the ledger database (as it is after a clean close) and the
/// destination's commit note aside, and puts them back: the state an older
/// backup, or a power failure that lost the last writes, leaves behind.
pub struct LedgerSnapshot {
    ledger: Vec<u8>,
    witness: Option<Vec<u8>>,
}

impl LedgerSnapshot {
    pub fn take(w: &World) -> LedgerSnapshot {
        LedgerSnapshot {
            ledger: std::fs::read(w.ledger_file()).unwrap(),
            witness: std::fs::read(w.root.join(STORE_DIR).join("commits")).ok(),
        }
    }

    /// Puts the ledger back. `with_witness` also puts the destination's note
    /// back (a power failure loses both; a restored backup of the program's
    /// data only loses the ledger).
    pub fn restore(&self, w: &World, with_witness: bool) {
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(w.ledger_dir.join(format!("ledger.db{suffix}")));
        }
        std::fs::write(w.ledger_file(), &self.ledger).unwrap();
        if let (true, Some(witness)) = (with_witness, &self.witness) {
            std::fs::write(w.root.join(STORE_DIR).join("commits"), witness).unwrap();
        }
    }
}

fn collect(dir: &Path, rel: String, out: &mut Vec<String>, top: bool) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if top && name == STORE_DIR {
            continue;
        }
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
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
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
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
        device_number: Some(0),
    }
}

/// What the platform reports for an external USB disk with NTFS.
pub fn usb_ntfs(serial: u64) -> VolumeInfo {
    VolumeInfo {
        drive: DriveKind::Fixed,
        filesystem: "NTFS".to_owned(),
        serial: Some(serial),
        read_only: false,
        removable_media: Some(false),
        hot_plug: Some(true),
        bus: Some(BusKind::Usb),
        volume_root: "test-usb".to_owned(),
        // Every stand-in disk is a physical disk of its own.
        device_number: Some((serial & 0xFFFF) as u32 + 1),
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

/// The item key the "phone" of these tests gives a file: its name.
pub fn key_of(name: &str) -> &[u8] {
    match name.as_bytes() {
        [] => b"-",
        bytes => &bytes[..bytes.len().min(64)],
    }
}

/// The key of the proof the "phone" asks for.
pub const PROOF_KEY: [u8; 32] = [0x5A; 32];

/// Asks, as the phone, whether its copy of the content with this hash may be
/// deleted. The phone names the record on its receipt: here, the oldest one
/// the ledger has for that hash (read straight from the ledger file, as the
/// phone's receipt would simply say it).
pub fn verify(
    store: &Store,
    hash: &ContentHash,
    min_age_sessions: u32,
) -> Result<DeletionProof, DeletionDenied> {
    verify_as(store, &phone(), hash, min_age_sessions)
}

pub fn verify_as(
    store: &Store,
    device: &DeviceId,
    hash: &ContentHash,
    min_age_sessions: u32,
) -> Result<DeletionProof, DeletionDenied> {
    let conn = rusqlite::Connection::open(store.ledger_path()).unwrap();
    let named: Option<(Option<Vec<u8>>, i64, i64)> = conn
        .query_row(
            "SELECT item_key, size, commit_no FROM files WHERE device_id = ?1 AND hash = ?2
             ORDER BY commit_no LIMIT 1",
            rusqlite::params![device.as_str(), hash.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (key, size, commit_seq) = match named {
        Some((key, size, commit_no)) => (key.unwrap_or_default(), size as u64, commit_no as u64),
        None => (b"no-such-item".to_vec(), 0, 0),
    };
    store.verify_for_deletion(
        device,
        &VerifyRequest {
            key: &key,
            hash: *hash,
            size,
            commit_seq,
            proof_key: PROOF_KEY,
            min_age_sessions,
        },
    )
}

/// The request a phone would make for one particular ledger record.
pub fn request_of(record: &kiwi_store::StoredRecord) -> VerifyRequest<'_> {
    VerifyRequest {
        key: &record.key,
        hash: record.hash,
        size: record.size,
        commit_seq: record.commit_seq,
        proof_key: PROOF_KEY,
        min_age_sessions: 1,
    }
}

/// The request a phone would make for a file it holds this receipt for.
pub fn request_for(receipt: &CommitReceipt, name: &str) -> VerifyRequest<'static> {
    VerifyRequest {
        key: Box::leak(key_of(name).to_vec().into_boxed_slice()),
        hash: receipt.hash,
        size: receipt.size,
        commit_seq: receipt.seq,
        proof_key: PROOF_KEY,
        min_age_sessions: 1,
    }
}

pub fn request<'a>(device: &'a DeviceId, name: &'a str, bytes: &[u8]) -> FileRequest<'a> {
    FileRequest {
        device,
        key: key_of(name),
        name,
        size: bytes.len() as u64,
        claimed_hash: Some(ContentHash::of_bytes(bytes)),
        capture_time: None,
        mtime_unix_ns: None,
    }
}

/// Sends one whole file the way the transfer layer would.
pub fn try_put(
    store: &Store,
    device: &DeviceId,
    name: &str,
    bytes: &[u8],
) -> Result<CommitReceipt, StoreError> {
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
