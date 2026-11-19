//! The mirror when things go wrong while it works: every file-system
//! operation failing in turn, a disk pulled out mid-copy, device errors, bytes
//! changing on either disk, and crashes between the steps.

mod common;

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use kiwi_store::fsops::Checkpoint;
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{
    BlockKind, CancelToken, ContentHash, DeletionDenied, MirrorOptions, MirrorPresence, Store,
    TEMP_PREFIX,
};

fn run(store: &Store) -> kiwi_store::MirrorRunReport {
    store.run_mirror(&CancelToken::new()).unwrap()
}

fn scan(store: &Store) -> kiwi_store::MirrorScanReport {
    store
        .scan_mirror(&MirrorOptions::default(), &CancelToken::new())
        .unwrap()
}

fn bytes_of(i: u64) -> Vec<u8> {
    data(300 + i, 5_000 + 64 * i as usize)
}

fn library(store: &Store, n: u64) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let bytes = bytes_of(i);
            let receipt = put(store, &format!("DCIM/{i}.jpg"), &bytes);
            (receipt.rel_path, bytes)
        })
        .collect()
}

fn on(disk: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(disk.to_path_buf(), |p, part| p.join(part))
}

fn is_temp(rel: &str) -> bool {
    rel.rsplit('/').next().unwrap().starts_with(TEMP_PREFIX)
}

/// Every file under a root with its content.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    tree(root)
        .into_iter()
        .map(|rel| {
            let bytes = std::fs::read(on(root, &rel)).unwrap();
            (rel, bytes)
        })
        .collect()
}

/// A world with a library on the destination and a registered, empty mirror.
fn prepared(name: &str, files: u64) -> (World, PathBuf, Store, Vec<(String, Vec<u8>)>) {
    let w = World::new(name);
    let disk = w.disk("usb");
    let store = w.open();
    store.add_mirror(&disk, "USB").unwrap();
    let library = library(&store, files);
    (w, disk, store, library)
}

#[test]
fn every_operation_failing_in_turn_during_a_mirror_run() {
    // One clean run, to learn which operations a run consists of.
    let (clean, _disk, store, files) = prepared("matrix-clean", 3);
    clean.fs.reset_counters();
    assert!(run(&store).completed);
    let operations = clean.fs.log();
    drop(store);
    assert!(
        operations.len() >= 40,
        "suspiciously few: {}",
        operations.len()
    );
    for op in [
        Op::ReadSmall,
        Op::FreeSpace,
        Op::CreateDir,
        Op::CreateTemp,
        Op::Write,
        Op::SetMtime,
        Op::Sync,
        Op::ReadVerify,
        Op::Rename,
        Op::SyncFile,
        Op::SyncDir,
        Op::Checkpoint(Checkpoint::BeforeMirrorRecord),
    ] {
        assert!(
            operations.iter().any(|(o, _)| *o == op),
            "{op:?} never happened in the clean run"
        );
    }
    let payloads: Vec<&Vec<u8>> = files.iter().map(|(_, bytes)| bytes).collect();

    let (mut blocked, mut skipped_disk, mut failed_copies) = (0, 0, 0);
    for (index, (op, _)) in operations.iter().enumerate() {
        let context = format!("failing operation #{index} ({op:?})");
        let (w, disk, store, files) = prepared(&format!("matrix-{index}"), 3);
        let primary = snapshot(&w.root);
        w.fs.reset_counters();
        w.fs.inject(When::Global(index), Action::Fail(ErrorKind::Other));
        // A run never fails as a whole because one operation did.
        let report = store
            .run_mirror(&CancelToken::new())
            .unwrap_or_else(|e| panic!("{context}: the run itself failed: {e}"));
        w.fs.clear_rules();
        let m = &report.mirrors[0];

        // The destination is never touched by a mirror run.
        assert_eq!(snapshot(&w.root), primary, "{context}");
        // Whatever has a final name on the mirror is a complete copy.
        for (rel, bytes) in snapshot(&disk) {
            if !is_temp(&rel) {
                assert!(
                    payloads.contains(&&bytes),
                    "{context}: {rel} on the mirror is not a complete copy"
                );
            }
        }
        if m.presence.is_present() && !m.removed_mid_run {
            // Copying goes on after a failure: every file was attempted.
            assert_eq!(m.copied + m.already_there + m.failed, 3, "{context}: {m:?}");
            failed_copies += m.failed;
        } else {
            skipped_disk += 1;
        }
        // A device error blocks final move; nothing else here does.
        if let Some(block) = &report.block {
            assert_eq!(block.kind, BlockKind::DiskFailing, "{context}: {block:?}");
            blocked += 1;
        }
        // The ledger never believes in a copy that is not there: a check of
        // every recorded copy finds each of them intact.
        let check = store
            .scan_mirror(
                &MirrorOptions {
                    repair: false,
                    ..MirrorOptions::default()
                },
                &CancelToken::new(),
            )
            .unwrap();
        let checked = &check.mirrors[0];
        assert_eq!(
            (checked.missing, checked.changed, checked.unreadable),
            (0, 0, 0),
            "{context}"
        );
        assert_eq!(checked.files_checked, checked.ok, "{context}");

        // The next run finishes the job: one copy of everything, no debris.
        let retry = run(&store);
        assert!(retry.completed, "{context}: {:?}", retry.mirrors[0]);
        let mirrored = snapshot(&disk);
        assert_eq!(
            mirrored.keys().collect::<Vec<_>>(),
            primary.keys().collect::<Vec<_>>(),
            "{context}: exactly the destination's files, no temp files, no second copies"
        );
        assert_eq!(mirrored, primary, "{context}");
        assert!(store.mirror_pending().unwrap().is_empty(), "{context}");
        assert_eq!(
            store.copy_counts(&phone()).unwrap().two_or_more,
            files.len() as u64,
            "{context}"
        );
    }
    println!(
        "{} operations: {failed_copies} copies failed, {blocked} runs set the block, {skipped_disk} runs did not use the disk",
        operations.len()
    );
    assert!(failed_copies >= 20);
    assert!(blocked >= 10);
}

#[test]
fn a_disk_pulled_out_mid_copy_is_not_a_failing_disk() {
    let (w, disk, store, files) = prepared("pulled-out", 4);
    let primary = snapshot(&w.root);
    w.fs.reset_counters();
    // While the second file is being written, the disk is gone.
    let fs = w.fs.clone();
    let gone = disk.clone();
    w.fs.inject(
        When::Nth(Op::Write, 1),
        Action::before(move |_| fs.kill_tree(&gone, ErrorKind::NotFound)),
    );
    let report = run(&store);
    w.fs.clear_rules();
    let m = &report.mirrors[0];
    assert!(m.removed_mid_run);
    assert!(matches!(m.presence, MirrorPresence::Absent(_)));
    assert_eq!((m.copied, m.io_errors), (1, 0));
    assert!(!report.completed);
    // An unplugged disk is not a failing disk: nothing is blocked, and
    // nothing is held against it.
    assert!(report.block.is_none());
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.mirrors().unwrap()[0].io_errors, 0);
    assert_eq!(snapshot(&w.root), primary);
    // A later run with the disk still away is just "absent".
    assert!(matches!(
        run(&store).mirrors[0].presence,
        MirrorPresence::Absent(_)
    ));

    // The disk comes back with the half-written temp file on it.
    w.fs.revive_trees();
    assert_eq!(tree(&disk).into_iter().filter(|f| is_temp(f)).count(), 1);
    let report = run(&store);
    let m = &report.mirrors[0];
    assert!(report.completed);
    assert_eq!(
        m.temps_removed, 1,
        "the debris of the interrupted run is swept"
    );
    assert_eq!((m.rechecked, m.copied), (1, 3));
    assert_eq!(snapshot(&disk), primary);
    assert_eq!(
        store.copy_counts(&phone()).unwrap().two_or_more,
        files.len() as u64
    );
}

#[test]
fn device_errors_block_final_move_and_copying_goes_on() {
    // The mirror returns errors.
    let (w, disk, store, files) = prepared("device-errors", 4);
    w.fs.inject(When::Every(Op::Sync), Action::Fail(ErrorKind::Other));
    let report = run(&store);
    w.fs.clear_rules();
    let m = &report.mirrors[0];
    assert!(m.presence.is_present());
    assert_eq!(
        (m.copied, m.failed, m.io_errors),
        (0, 4, 4),
        "every file was tried"
    );
    assert_eq!(m.failures.len(), 4);
    let block = report.block.expect("a failing disk blocks final move");
    assert_eq!(block.kind, BlockKind::DiskFailing);
    assert!(block.reason.contains("second disk"), "{}", block.reason);
    assert_eq!(store.mirrors().unwrap()[0].io_errors, 4);
    assert!(tree(&disk).is_empty(), "nothing half-done is left behind");
    // Receiving goes on while the block is set.
    put(&store, "DCIM/meanwhile.jpg", b"still accepted");
    // The disk behaves again: the copies are made, the block stays.
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(report.mirrors[0].copied, 5);
    assert!(report.block.is_some());
    assert!(matches!(
        verify(&store, &ContentHash::of_bytes(&files[0].1), 1),
        Err(DeletionDenied::Blocked(_))
    ));
    // A clean scan wipes the disk's record; the block is a person's to clear.
    assert!(scan(&store).completed);
    assert_eq!(store.mirrors().unwrap()[0].io_errors, 0);
    assert!(store.final_move_block().unwrap().is_some());
    drop(store);

    // The destination returns errors for one file.
    let (w, disk, store, files) = prepared("device-errors-primary", 4);
    w.fs.kill_tree(&w.path(&files[2].0), ErrorKind::Other);
    let report = run(&store);
    let m = &report.mirrors[0];
    assert_eq!((m.copied, m.skipped_source, m.failed), (3, 1, 1));
    assert_eq!(report.destination_io_errors, 1);
    let block = report.block.expect("blocked");
    assert_eq!(block.kind, BlockKind::DiskFailing);
    assert!(block.reason.contains("destination"), "{}", block.reason);
    assert_eq!(tree(&disk).len(), 3);
    w.fs.revive_trees();
    assert!(run(&store).completed);
}

#[test]
fn what_a_disk_gives_back_is_compared_before_anything_is_recorded() {
    // (a) The mirror gives back other bytes than it was given.
    let (w, disk, store, files) = prepared("flip-mirror-temp", 3);
    let once = Arc::new(AtomicBool::new(false));
    let mirror = disk.clone();
    w.fs.inject(
        When::Every(Op::ReadVerify),
        Action::before(move |path| {
            let temp = path.starts_with(&mirror)
                && path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(TEMP_PREFIX));
            if temp && !once.swap(true, Ordering::SeqCst) {
                corrupt_silently(path);
            }
        }),
    );
    let report = run(&store);
    w.fs.clear_rules();
    let m = &report.mirrors[0];
    assert_eq!((m.copied, m.failed, m.mismatches), (2, 1, 1));
    // The bad copy never got a name, and is gone.
    assert_eq!(tree(&disk), vec![files[1].0.clone(), files[2].0.clone()]);
    let block = report
        .block
        .expect("a disk that returns wrong bytes blocks");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert_eq!(store.mirror_pending().unwrap()[0].files, 1);
    assert!(run(&store).completed);
    assert_eq!(std::fs::read(on(&disk, &files[0].0)).unwrap(), files[0].1);
    drop(store);

    // (b) The destination's file is not what the ledger says: nothing is
    // published on the mirror, and the damage is on record.
    let (w, disk, store, files) = prepared("flip-primary", 3);
    corrupt_silently(&w.path(&files[1].0));
    let report = run(&store);
    let m = &report.mirrors[0];
    assert_eq!((m.copied, m.skipped_source, m.failed), (2, 1, 1));
    assert_eq!(tree(&disk), vec![files[0].0.clone(), files[2].0.clone()]);
    assert_eq!(store.stats().unwrap().files_changed, 1);
    assert_eq!(
        report.block.expect("blocked").kind,
        BlockKind::IntegrityProblems
    );
    // It stays unmirrored: a damaged file is never copied as if it were good.
    let again = run(&store);
    assert_eq!(again.mirrors[0].copied, 0);
    assert_eq!(tree(&disk).len(), 2);
    drop(store);

    // (c) The copy changes on the mirror between the rename and the look.
    let (w, disk, store, files) = prepared("flip-mirror-final", 2);
    let target = on(&disk, &files[0].0);
    let victim = target.clone();
    let once = Arc::new(AtomicBool::new(false));
    w.fs.inject(
        When::Every(Op::SyncFile),
        Action::before(move |path| {
            if path == victim && !once.swap(true, Ordering::SeqCst) {
                corrupt_silently(path);
            }
        }),
    );
    let report = run(&store);
    w.fs.clear_rules();
    assert_eq!(report.mirrors[0].mismatches, 1);
    // The damaged file has a final name on the mirror, but no record: it is
    // not counted as a copy.
    assert_ne!(std::fs::read(&target).unwrap(), files[0].1);
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 1);
    let damaged = std::fs::read(&target).unwrap();
    // The next run does not overwrite it: the good copy goes next to it.
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(std::fs::read(&target).unwrap(), damaged);
    assert_eq!(
        std::fs::read(on(&disk, "Pixel 8/DCIM/0 (2).jpg")).unwrap(),
        files[0].1
    );
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 2);
    // And the ledger points at the good one.
    store.clear_final_move_block("test").unwrap();
    let check = scan(&store);
    assert_eq!((check.mirrors[0].ok, check.mirrors[0].changed), (2, 0));
    assert!(store.final_move_block().unwrap().is_none());
}

#[test]
fn a_crash_between_the_rename_and_the_record_is_healed_by_the_next_run() {
    // A copy on the mirror.
    let (w, disk, store, files) = prepared("crash-mirror-record", 3);
    w.fs.inject(
        When::Every(Op::Checkpoint(Checkpoint::BeforeMirrorRecord)),
        Action::Fail(ErrorKind::Other),
    );
    let report = run(&store);
    w.fs.clear_rules();
    assert_eq!(report.mirrors[0].failed, 3);
    // The files are on the mirror, complete, but the ledger does not know.
    assert_eq!(snapshot(&disk), snapshot(&w.root));
    assert_eq!(store.mirror_pending().unwrap()[0].files, 3);
    assert_eq!(store.copy_counts(&phone()).unwrap().one_copy, 3);
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(
        (report.mirrors[0].already_there, report.mirrors[0].copied),
        (3, 0),
        "found there, read, and recorded: not copied twice"
    );
    assert_eq!(tree(&disk).len(), 3);
    assert!(report.block.is_none());

    // A file restored to the destination.
    std::fs::remove_file(w.path(&files[0].0)).unwrap();
    store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    w.fs.inject(
        When::Every(Op::Checkpoint(Checkpoint::BeforeRepairRecord)),
        Action::Fail(ErrorKind::Other),
    );
    let report = scan(&store);
    w.fs.clear_rules();
    assert_eq!(
        (report.destination_repaired, report.destination_unrepairable),
        (0, 1)
    );
    // The file is back on the disk; the ledger still says "missing".
    assert_eq!(std::fs::read(w.path(&files[0].0)).unwrap(), files[0].1);
    assert_eq!(store.stats().unwrap().files_missing, 1);
    let report = scan(&store);
    assert_eq!(
        (report.destination_repaired, report.destination_found_intact),
        (0, 1),
        "the next scan finds it intact"
    );
    assert_eq!(store.stats().unwrap().files_missing, 0);
    assert_eq!(w.files().len(), 3);
}

#[test]
fn what_the_previous_run_wrote_is_read_back_when_the_disk_returns() {
    let (w, disk, store, files) = prepared("lost-last-writes", 3);
    assert!(run(&store).completed);
    // The disk was pulled out without "eject": of the last writes, one file
    // is gone and one is garbage.
    std::fs::remove_file(on(&disk, &files[0].0)).unwrap();
    corrupt_silently(&on(&disk, &files[1].0));
    let garbage = std::fs::read(on(&disk, &files[1].0)).unwrap();

    let report = run(&store);
    let m = &report.mirrors[0];
    assert_eq!((m.rechecked, m.recheck_failed), (1, 2));
    // Both are written again in the same run, without touching the garbage.
    assert_eq!(m.copied, 2);
    assert!(report.completed);
    assert_eq!(std::fs::read(on(&disk, &files[0].0)).unwrap(), files[0].1);
    assert_eq!(std::fs::read(on(&disk, &files[1].0)).unwrap(), garbage);
    assert_eq!(
        std::fs::read(on(&disk, "Pixel 8/DCIM/1 (2).jpg")).unwrap(),
        files[1].1
    );
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 3);
    // A disk that loses what it was given is a finding.
    assert_eq!(
        report.block.expect("blocked").kind,
        BlockKind::IntegrityProblems
    );
    // The new copies are read back in their turn.
    assert_eq!(run(&store).mirrors[0].rechecked, 2);
    assert_eq!(snapshot(&w.root).len(), 3);
}

#[test]
fn a_lost_rename_on_the_mirror_gets_its_name_back_too() {
    let (w, disk, store, files) = prepared("mirror-lost-rename", 2);
    w.fs.reset_counters();
    assert!(run(&store).completed);
    let temp =
        w.fs.log()
            .into_iter()
            .find(|(op, path)| *op == Op::CreateTemp && path.starts_with(&disk))
            .map(|(_, path)| path)
            .unwrap();
    // The mirror forgot the rename of the first copy.
    let target = on(&disk, &files[0].0);
    std::fs::rename(&target, &temp).unwrap();
    // A look-alike with a foreign tag sits next to it.
    let look_alike = temp.with_file_name(".kiwi-tmp-00000000deadbeef-0-00000000deadbeef.part");
    std::fs::write(&look_alike, b"somebody's").unwrap();

    let report = scan(&store);
    let m = &report.mirrors[0];
    assert_eq!(m.temps_removed, 0, "it is not debris: it is the copy");
    assert_eq!((m.ok, m.missing, m.repaired), (2, 0, 0));
    assert_eq!(std::fs::read(&target).unwrap(), files[0].1);
    assert!(!temp.exists());
    assert!(look_alike.exists(), "not the engine's: left alone");
    assert!(store.final_move_block().unwrap().is_none());
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "mirror_rename_recreated"));
}

#[test]
fn a_cancelled_run_leaves_nothing_half_done() {
    let (w, disk, store, _files) = prepared("cancelled", 4);
    let cancel = CancelToken::new();
    let stop = cancel.clone();
    w.fs.reset_counters();
    // Cancelled while the second copy is being flushed.
    w.fs.inject(
        When::Nth(Op::Sync, 1),
        Action::before(move |_| stop.cancel()),
    );
    let report = store.run_mirror(&cancel).unwrap();
    w.fs.clear_rules();
    assert!(!report.completed);
    assert_eq!(report.mirrors[0].copied, 1);
    assert_eq!(report.mirrors[0].failed, 0, "cancelling is not a failure");
    assert_eq!(tree(&disk).len(), 1, "no temp file, no half copy");
    assert!(report.block.is_none());
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(snapshot(&disk), snapshot(&w.root));
}
