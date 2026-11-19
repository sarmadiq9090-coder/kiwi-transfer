//! The commit pipeline when things go wrong: every step failing in turn,
//! short writes, a full disk, bytes changing on disk, crashes, and races.

mod common;

use std::collections::BTreeMap;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use kiwi_store::fsops::Checkpoint;
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{
    CommitOutcome, CommitReceipt, ContentHash, FileRequest, NotVerifiedReason, Store, StoreError,
    StoredStatus,
};

const NAME: &str = "DCIM/Camera/IMG_0001.jpg";
const STORED: &str = "Pixel 8/DCIM/Camera/IMG_0001.jpg";

fn payload() -> Vec<u8> {
    data(42, 150_000)
}

/// Sends the payload in three writes, with a modification time.
fn send(store: &Store, bytes: &[u8]) -> Result<CommitReceipt, StoreError> {
    let mut incoming = store.begin_file(FileRequest {
        mtime_unix_ns: Some(1_650_000_000_000_000_000),
        ..request(&phone(), NAME, bytes)
    })?;
    for chunk in bytes.chunks(60_000) {
        incoming.write(chunk)?;
    }
    incoming.finish(None)
}

type Snapshot = BTreeMap<String, ContentHash>;

/// Every file under the root with the hash of its content.
fn snapshot(w: &World) -> Snapshot {
    w.files()
        .into_iter()
        .map(|f| {
            (
                f.clone(),
                ContentHash::of_bytes(&std::fs::read(w.path(&f)).unwrap()),
            )
        })
        .collect()
}

/// What must hold after a failed or successful attempt, whatever went wrong.
fn check_invariants(
    w: &World,
    store: &Store,
    bytes: &[u8],
    before: &Snapshot,
    result: &Result<CommitReceipt, StoreError>,
    context: &str,
) {
    let hash = ContentHash::of_bytes(bytes);
    // No temp file survives an attempt, successful or not.
    assert!(
        w.temp_files().is_empty(),
        "{context}: temp files left: {:?}",
        w.temp_files()
    );
    let after = snapshot(w);
    // Nothing that existed before was replaced, changed or removed.
    for (file, old) in before {
        assert_eq!(
            after.get(file),
            Some(old),
            "{context}: the existing file {file} was touched"
        );
    }
    // Whatever is new carries the complete content: never a partial file.
    for (file, new) in &after {
        if !before.contains_key(file) {
            assert_eq!(
                *new, hash,
                "{context}: the new file {file} is not the complete payload"
            );
        }
    }
    let recorded = store.stats().unwrap().files_committed;
    match result {
        Ok(receipt) => {
            assert_eq!(
                std::fs::read(&receipt.abs_path).unwrap(),
                bytes,
                "{context}"
            );
            assert_eq!(receipt.hash, hash, "{context}");
            assert!(recorded >= 1, "{context}: success without a ledger record");
            assert!(
                store
                    .is_safely_stored(&phone(), &hash)
                    .unwrap()
                    .is_verified(),
                "{context}"
            );
        }
        Err(_) => {
            // An error means the file was not recorded, so nobody is ever
            // told it is safe.
            assert!(
                matches!(
                    store.is_safely_stored(&phone(), &hash).unwrap(),
                    StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
                ),
                "{context}: a failed commit must leave no record"
            );
        }
    }
}

/// Runs the scenario once cleanly to learn how many file-system operations it
/// takes, then once per operation with that operation failing.
fn fail_every_operation(label: &str, prepare: fn(&World)) {
    let bytes = payload();
    let hash = ContentHash::of_bytes(&bytes);

    let clean = World::new(&format!("{label}-clean"));
    prepare(&clean);
    let store = clean.open();
    clean.fs.reset_counters();
    send(&store, &bytes).expect("the clean run must succeed");
    let operations = clean.fs.log();
    drop(store);
    assert!(
        operations.len() >= 12,
        "suspiciously few operations: {operations:?}"
    );
    for op in [
        Op::FreeSpace,
        Op::CreateTemp,
        Op::Write,
        Op::SetMtime,
        Op::Sync,
        Op::ReadVerify,
        Op::Rename,
        Op::SyncFile,
        Op::SyncDir,
    ] {
        assert!(
            operations.iter().any(|(o, _)| *o == op),
            "{op:?} never happened in the clean run"
        );
    }
    assert!(operations
        .iter()
        .any(|(o, _)| *o == Op::Checkpoint(Checkpoint::BeforeLedgerRecord)));

    let mut failed = 0;
    let mut survived = 0;
    for (index, (op, path)) in operations.iter().enumerate() {
        let context = format!("{label}: failing operation #{index} ({op:?})");
        let w = World::new(&format!("{label}-{index}"));
        prepare(&w);
        let store = w.open();
        let before = snapshot(&w);
        w.fs.reset_counters();
        w.fs.inject(When::Global(index), Action::Fail(ErrorKind::Other));
        let result = send(&store, &bytes);
        w.fs.clear_rules();

        check_invariants(&w, &store, &bytes, &before, &result, &context);
        match &result {
            Ok(_) => survived += 1,
            Err(_) => failed += 1,
        }
        // Only steps that are explicitly "where possible" may fail without
        // failing the commit: the mtime, the two flushes after the rename
        // (the receipt says whether they happened), and reading an *existing*
        // file to see whether it is identical (if that cannot be read, it is
        // simply not adopted). The read under the final name is not one of
        // them: the payload's own name is not an "existing file".
        if let Ok(receipt) = &result {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let reads_existing_file = *op == Op::ReadVerify
                && !name.starts_with(kiwi_store::TEMP_PREFIX)
                && name != "IMG_0001.jpg";
            assert!(
                matches!(op, Op::SetMtime | Op::SyncDir | Op::SyncFile) || reads_existing_file,
                "{context}: the commit succeeded although a required step failed"
            );
            if matches!(op, Op::SyncDir | Op::SyncFile) {
                assert!(
                    !receipt.dir_synced,
                    "{context}: the receipt must not claim a flush that failed"
                );
            }
        }

        // The phone retries. Whatever state the failure left, the retry must
        // end with exactly one copy, recorded and verified.
        let before_retry = snapshot(&w);
        let retry =
            send(&store, &bytes).unwrap_or_else(|e| panic!("{context}: the retry failed: {e}"));
        check_invariants(
            &w,
            &store,
            &bytes,
            &before_retry,
            &Ok(retry.clone()),
            &format!("{context} (retry)"),
        );
        let copies = w
            .files()
            .into_iter()
            .filter(|f| std::fs::read(w.path(f)).unwrap() == bytes)
            .count();
        assert_eq!(
            copies, 1,
            "{context}: the retry must not create a second copy"
        );
        assert!(
            store
                .is_safely_stored(&phone(), &hash)
                .unwrap()
                .is_verified(),
            "{context}"
        );

        // And it survives a restart.
        drop(store);
        let store = w.open();
        assert!(store.recovery_report().unwrap().completed);
        assert!(
            store
                .is_safely_stored(&phone(), &hash)
                .unwrap()
                .is_verified(),
            "{context}: after restart"
        );
        assert!(
            store.final_move_block().unwrap().is_none(),
            "{context}: nothing here justifies a block"
        );
    }
    println!(
        "{label}: {} operations, {failed} failed the commit, {survived} did not",
        operations.len()
    );
    assert!(failed >= 10);
}

#[test]
fn every_operation_failing_in_turn_fresh_directories() {
    fail_every_operation("matrix-fresh", |_| {});
}

#[test]
fn every_operation_failing_in_turn_with_a_name_collision() {
    // The directories exist and the name is taken by a different file of the
    // same size, so the collision and comparison steps are part of the run.
    fail_every_operation("matrix-collision", |w| {
        std::fs::create_dir_all(w.path("Pixel 8/DCIM/Camera")).unwrap();
        std::fs::write(w.path("Pixel 8/DCIM/Camera/img_0001.JPG"), data(7, 150_000)).unwrap();
    });
}

#[test]
fn short_writes_are_completed() {
    let w = World::new("short-writes");
    let store = w.open();
    let bytes = payload();
    // The file system takes at most 4,097 bytes per call.
    w.fs.inject(When::Every(Op::Write), Action::ShortWrite(4_097));
    w.fs.reset_counters();
    let receipt = send(&store, &bytes).unwrap();
    assert!(
        w.fs.count(Op::Write) >= bytes.len() / 4_097,
        "the writes were really short"
    );
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert_eq!(receipt.hash, ContentHash::of_bytes(&bytes));

    // One byte at a time, for a small file.
    w.fs.clear_rules();
    w.fs.inject(When::Every(Op::Write), Action::ShortWrite(1));
    let tiny = data(9, 257);
    let receipt = put(&store, "tiny.bin", &tiny);
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), tiny);
}

#[test]
fn a_write_that_accepts_nothing_fails_instead_of_spinning() {
    let w = World::new("zero-write");
    let store = w.open();
    let bytes = payload();
    w.fs.reset_counters();
    w.fs.inject(When::Nth(Op::Write, 1), Action::ShortWrite(0));
    match send(&store, &bytes) {
        Err(StoreError::Io { op, source, .. }) => {
            assert_eq!(op, "write");
            assert_eq!(source.kind(), ErrorKind::WriteZero);
        }
        other => panic!("expected a write error, got {other:?}"),
    }
    assert!(w.files().is_empty(), "{:?}", w.files());
}

#[test]
fn a_full_disk_mid_transfer_is_reported_and_cleaned_up() {
    let w = World::new("disk-full");
    let store = w.open();
    let bytes = payload();
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::Write, 2),
        Action::Fail(ErrorKind::StorageFull),
    );

    let mut incoming = store.begin_file(request(&phone(), NAME, &bytes)).unwrap();
    incoming.write(&bytes[..60_000]).unwrap();
    incoming.write(&bytes[60_000..120_000]).unwrap();
    match incoming.write(&bytes[120_000..]) {
        Err(StoreError::DiskFull { path, .. }) => {
            assert!(path.to_string_lossy().contains(".kiwi-tmp-"))
        }
        other => panic!("expected DiskFull, got {other:?}"),
    }
    // The partial file is gone at once, and the writer is dead.
    assert!(w.files().is_empty(), "{:?}", w.files());
    assert!(matches!(
        incoming.write(b"x"),
        Err(StoreError::WriterClosed)
    ));
    assert!(matches!(
        incoming.finish(None),
        Err(StoreError::WriterClosed)
    ));
    assert_eq!(store.stats().unwrap().files_committed, 0);

    // Full at the flush instead of at a write.
    w.fs.clear_rules();
    w.fs.inject(When::Every(Op::Sync), Action::Fail(ErrorKind::StorageFull));
    assert!(matches!(
        send(&store, &bytes),
        Err(StoreError::DiskFull { .. })
    ));
    assert!(w.files().is_empty());

    // Space is back: the same file goes through.
    w.fs.clear_rules();
    assert_eq!(send(&store, &bytes).unwrap().rel_path, STORED);
}

#[test]
fn the_low_space_guard_refuses_before_writing() {
    let w = World::new("low-space");
    let store = w.open();
    let bytes = payload();
    let margin = 1024 * 1024u64;

    // One byte short of "file + margin".
    w.fs.inject(
        When::Every(Op::FreeSpace),
        Action::FreeSpace(bytes.len() as u64 + margin - 1),
    );
    w.fs.reset_counters();
    match send(&store, &bytes) {
        Err(StoreError::InsufficientSpace {
            needed,
            margin: m,
            available,
        }) => {
            assert_eq!(
                (needed, m, available),
                (bytes.len() as u64, margin, bytes.len() as u64 + margin - 1)
            );
        }
        other => panic!("expected InsufficientSpace, got {other:?}"),
    }
    assert_eq!(w.fs.count(Op::CreateTemp), 0);
    assert_eq!(
        w.fs.count(Op::CreateDir),
        0,
        "not even a directory is created"
    );
    assert!(w.files().is_empty());

    // Exactly enough.
    w.fs.clear_rules();
    w.fs.inject(
        When::Every(Op::FreeSpace),
        Action::FreeSpace(bytes.len() as u64 + margin),
    );
    send(&store, &bytes).unwrap();

    // If free space cannot be measured, nothing is written either.
    w.fs.clear_rules();
    w.fs.inject(When::Every(Op::FreeSpace), Action::Fail(ErrorKind::Other));
    assert!(matches!(
        try_put(&store, &phone(), "b.jpg", b"x"),
        Err(StoreError::Io { .. })
    ));
}

#[test]
fn files_in_flight_reserve_their_space() {
    let w = World::new("reservations");
    let store = w.open();
    let mib = 1024 * 1024u64;
    // 10 MiB free, 1 MiB margin: two 6 MiB files do not both fit.
    w.fs.inject(When::Every(Op::FreeSpace), Action::FreeSpace(10 * mib));
    let big = FileRequest {
        device: &phone(),
        name: "a.bin",
        size: 6 * mib,
        claimed_hash: None,
        capture_time: None,
        mtime_unix_ns: None,
    };
    let first = store.begin_file(big).unwrap();
    match store.begin_file(FileRequest {
        name: "b.bin",
        ..big
    }) {
        Err(StoreError::InsufficientSpace { needed, .. }) => assert_eq!(needed, 12 * mib),
        other => panic!("expected InsufficientSpace, got {other:?}"),
    }
    // A small one still fits next to the first.
    let small = store
        .begin_file(FileRequest {
            name: "c.bin",
            size: 2 * mib,
            ..big
        })
        .unwrap();
    drop(small);
    // Once the first is gone, the second fits.
    first.abort();
    store
        .begin_file(FileRequest {
            name: "b.bin",
            ..big
        })
        .unwrap()
        .abort();
    assert!(w.files().is_empty());
}

fn flip_a_byte(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let i = bytes.len() / 3;
    bytes[i] ^= 0x80;
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(i as u64)).unwrap();
    f.write_all(&bytes[i..i + 1]).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn a_byte_that_changes_on_disk_before_the_read_back_is_caught() {
    let w = World::new("bit-flip");
    let store = w.open();
    let bytes = payload();
    let good = ContentHash::of_bytes(&bytes);

    // Between the flush and the read-back, something flips one bit on disk.
    w.fs.reset_counters();
    w.fs.inject(When::Nth(Op::ReadVerify, 0), Action::before(flip_a_byte));
    match send(&store, &bytes) {
        Err(StoreError::DiskVerifyMismatch {
            expected,
            on_disk,
            expected_size,
            on_disk_size,
        }) => {
            assert_eq!(expected, good);
            assert_ne!(on_disk, good);
            assert_eq!(expected_size, on_disk_size);
        }
        other => panic!("expected DiskVerifyMismatch, got {other:?}"),
    }
    assert!(
        w.files().is_empty(),
        "the damaged temp file must be deleted: {:?}",
        w.files()
    );
    assert_eq!(store.stats().unwrap().files_committed, 0);
    assert!(!store
        .is_safely_stored(&phone(), &good)
        .unwrap()
        .is_verified());

    // The same for a file that lost its tail, and one that grew.
    w.fs.clear_rules();
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::ReadVerify, 0),
        Action::before(|p| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(p)
                .unwrap()
                .set_len(100_000)
                .unwrap()
        }),
    );
    assert!(matches!(
        send(&store, &bytes),
        Err(StoreError::DiskVerifyMismatch {
            on_disk_size: 100_000,
            ..
        })
    ));
    w.fs.clear_rules();
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::ReadVerify, 0),
        Action::before(|p| {
            std::fs::OpenOptions::new()
                .append(true)
                .open(p)
                .unwrap()
                .write_all(b"extra")
                .unwrap()
        }),
    );
    assert!(matches!(
        send(&store, &bytes),
        Err(StoreError::DiskVerifyMismatch {
            on_disk_size: 150_005,
            ..
        })
    ));
    assert!(w.files().is_empty());

    // Left alone, the same transfer succeeds.
    w.fs.clear_rules();
    assert_eq!(send(&store, &bytes).unwrap().outcome, CommitOutcome::Stored);
}

#[test]
fn required_steps_fail_the_commit_and_optional_ones_do_not() {
    let w = World::new("step-failures");
    let store = w.open();
    let bytes = payload();

    for (op, what) in [
        (Op::Sync, "flush"),
        (Op::ReadVerify, "read back"),
        (Op::Rename, "rename into place"),
    ] {
        w.fs.clear_rules();
        w.fs.inject(When::Every(op), Action::Fail(ErrorKind::PermissionDenied));
        match send(&store, &bytes) {
            Err(StoreError::Io {
                op: failed, source, ..
            }) => {
                assert_eq!(failed, what);
                assert_eq!(source.kind(), ErrorKind::PermissionDenied);
            }
            other => panic!("{op:?}: expected an I/O error, got {other:?}"),
        }
        assert!(w.files().is_empty(), "{op:?}: {:?}", w.files());
    }
    for op in [Op::CreateTemp, Op::Resolve, Op::Stat] {
        w.fs.clear_rules();
        w.fs.inject(When::Every(op), Action::Fail(ErrorKind::PermissionDenied));
        assert!(
            matches!(send(&store, &bytes), Err(StoreError::Io { .. })),
            "{op:?}"
        );
        assert!(w.files().is_empty(), "{op:?}");
    }
    // A directory that cannot be created (the ones above exist by now).
    w.fs.clear_rules();
    w.fs.inject(
        When::Every(Op::CreateDir),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        try_put(&store, &phone(), "Brand New Folder/x.jpg", b"x"),
        Err(StoreError::Io {
            op: "create the directory",
            ..
        })
    ));
    assert!(!w.path("Pixel 8/Brand New Folder").exists());
    assert_eq!(store.stats().unwrap().files_committed, 0);

    // "Where possible" steps: the commit stands and the receipt says what was skipped.
    w.fs.clear_rules();
    w.fs.inject(
        When::Every(Op::SyncDir),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    w.fs.inject(
        When::Every(Op::SetMtime),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    let receipt = send(&store, &bytes).unwrap();
    assert!(!receipt.dir_synced);
    assert!(!receipt.mtime_applied);
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
}

#[test]
fn a_crash_before_the_rename_leaves_only_a_temp_file_and_recovery_removes_it() {
    let w = World::new("crash-before-rename");
    let bytes = payload();
    let hash = ContentHash::of_bytes(&bytes);
    let temp = {
        let store = w.open();
        let mut incoming = store.begin_file(request(&phone(), NAME, &bytes)).unwrap();
        incoming.write(&bytes).unwrap();
        // The process dies here: all bytes written, nothing renamed.
        incoming.simulate_crash().unwrap()
    };
    assert!(temp.exists());
    assert_eq!(w.temp_files().len(), 1);
    assert!(
        !w.path(STORED).exists(),
        "an unverified file never has a final name"
    );

    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert!(report.completed);
    assert_eq!(report.orphan_temps_removed, 1);
    assert_eq!(report.orphan_temp_bytes, bytes.len() as u64);
    assert!(w.files().is_empty());
    assert!(!store
        .is_safely_stored(&phone(), &hash)
        .unwrap()
        .is_verified());
    assert!(store.final_move_block().unwrap().is_none());

    // The phone still has the file and sends it again.
    assert_eq!(send(&store, &bytes).unwrap().rel_path, STORED);
}

#[test]
fn a_crash_between_rename_and_ledger_leaves_a_complete_file_that_a_retry_adopts() {
    let w = World::new("crash-before-ledger");
    let bytes = payload();
    let hash = ContentHash::of_bytes(&bytes);
    {
        let store = w.open();
        w.fs.inject(
            When::Every(Op::Checkpoint(Checkpoint::BeforeLedgerRecord)),
            Action::Fail(ErrorKind::Other),
        );
        assert!(matches!(
            send(&store, &bytes),
            Err(StoreError::Io { op: "record", .. })
        ));
        w.fs.clear_rules();
        // The file is complete under its final name, but nobody was told so.
        assert_eq!(w.files(), vec![STORED]);
        assert_eq!(std::fs::read(w.path(STORED)).unwrap(), bytes);
        assert_eq!(store.stats().unwrap().files_committed, 0);
        assert!(matches!(
            store.is_safely_stored(&phone(), &hash).unwrap(),
            StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
        ));
    }
    let store = w.open();
    assert_eq!(store.recovery_report().unwrap().orphan_temps_removed, 0);
    assert!(matches!(
        store.is_safely_stored(&phone(), &hash).unwrap(),
        StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
    ));

    let receipt = send(&store, &bytes).unwrap();
    assert_eq!(receipt.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(receipt.rel_path, STORED);
    assert_eq!(
        receipt.session,
        store.session(),
        "its age counts from the session that recorded it"
    );
    assert_eq!(w.files(), vec![STORED], "no ' (2)' copy");
    assert!(store
        .is_safely_stored(&phone(), &hash)
        .unwrap()
        .is_verified());
}

#[test]
fn a_target_that_appears_between_the_check_and_the_rename_is_not_overwritten() {
    let w = World::new("race-different");
    let store = w.open();
    let bytes = payload();
    let intruder = data(77, 150_000);
    let intruder_for_hook = intruder.clone();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in_hook = Arc::clone(&hits);
    // Just before our rename, another program creates the target.
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::Rename, 0),
        Action::before(move |target| {
            hits_in_hook.fetch_add(1, Ordering::SeqCst);
            std::fs::write(target, &intruder_for_hook).unwrap();
        }),
    );
    let receipt = send(&store, &bytes).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/DCIM/Camera/IMG_0001 (2).jpg");
    assert_eq!(
        std::fs::read(w.path(STORED)).unwrap(),
        intruder,
        "the other program's file is untouched"
    );
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert!(w.temp_files().is_empty());
}

#[test]
fn a_target_that_appears_with_identical_content_is_adopted() {
    let w = World::new("race-identical");
    let store = w.open();
    let bytes = payload();
    let twin = bytes.clone();
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::Rename, 0),
        Action::before(move |target| std::fs::write(target, &twin).unwrap()),
    );
    let receipt = send(&store, &bytes).unwrap();
    assert_eq!(receipt.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(receipt.rel_path, STORED);
    assert_eq!(w.files(), vec![STORED]);
    assert!(store
        .is_safely_stored(&phone(), &receipt.hash)
        .unwrap()
        .is_verified());
}

#[test]
fn a_temp_name_that_is_already_taken_is_never_reused() {
    let w = World::new("temp-collision");
    let store = w.open();
    let bytes = payload();
    // Someone else's file sits exactly where our temp file was going to be.
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::CreateTemp, 0),
        Action::before(|p| std::fs::write(p, b"not ours").unwrap()),
    );
    let receipt = send(&store, &bytes).unwrap();
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert_eq!(w.fs.count(Op::CreateTemp), 2);
    // The squatter was not overwritten (it is removed by the next recovery
    // pass, because it carries the engine's reserved temp name).
    let temps = w.temp_files();
    assert_eq!(temps.len(), 1);
    assert_eq!(std::fs::read(w.path(&temps[0])).unwrap(), b"not ours");
}

#[test]
fn a_file_system_that_always_says_the_name_exists_ends_in_an_error_not_a_loop() {
    let w = World::new("always-exists");
    let store = w.open();
    w.fs.inject(
        When::Every(Op::Rename),
        Action::Fail(ErrorKind::AlreadyExists),
    );
    match try_put(&store, &phone(), "a.jpg", b"x") {
        Err(StoreError::TooManyCollisions { dir, name }) => {
            assert_eq!((dir.as_str(), name.as_str()), ("Pixel 8", "a.jpg"))
        }
        other => panic!("expected TooManyCollisions, got {other:?}"),
    }
    assert!(w.files().is_empty());
}

#[test]
fn failing_to_delete_a_temp_file_is_survivable() {
    let w = World::new("remove-fails");
    let bytes = payload();
    {
        let store = w.open();
        w.fs.inject(
            When::Every(Op::RemoveFile),
            Action::Fail(ErrorKind::PermissionDenied),
        );
        let wrong = ContentHash::of_bytes(b"not this");
        let mut incoming = store.begin_file(request(&phone(), NAME, &bytes)).unwrap();
        incoming.write(&bytes).unwrap();
        assert!(matches!(
            incoming.finish(Some(wrong)),
            Err(StoreError::ConflictingSenderHashes)
        ));
        // The delete failed, so the temp file is still there...
        assert_eq!(w.temp_files().len(), 1);
        // ...and a recovery pass that cannot delete it either says so.
        let report = store.run_recovery(&kiwi_store::CancelToken::new()).unwrap();
        assert_eq!(report.orphan_temps_removed, 0);
        assert_eq!(report.orphan_temps_left.len(), 1);
        w.fs.clear_rules();
    }
    // The next start cleans it up.
    let store = w.open();
    assert_eq!(store.recovery_report().unwrap().orphan_temps_removed, 1);
    assert!(w.files().is_empty());
}
