//! The recovery pass at start-up, and how a ledger is bound to its folder.

mod common;

use common::*;
use kiwi_store::{
    BlockKind, CancelToken, ContentHash, DeletionDenied, LedgerError, NotVerifiedReason, OpenNote, ScanPolicy,
    StoreConfig, StoreError, StoredStatus, STORE_DIR,
};

#[test]
fn orphaned_temp_files_are_removed_and_nothing_else_is() {
    let w = World::new("orphans");
    {
        let store = w.open();
        put(&store, "DCIM/Camera/keep.jpg", b"a real photo");
    }
    // Debris of interrupted transfers, at several depths.
    let debris = [
        ".kiwi-tmp-1-0-00000000deadbeef.part",
        "Pixel 8/.kiwi-tmp-2-7-0123456789abcdef.part",
        "Pixel 8/DCIM/Camera/.kiwi-tmp-3-1-aaaaaaaaaaaaaaaa.part",
        "Pixel 8/DCIM/Camera/.kiwi-tmp-3-2-bbbbbbbbbbbbbbbb.part",
        "Some Folder The User Made/deeper/.kiwi-tmp-9-9-cccccccccccccccc.part",
    ];
    for (i, rel) in debris.iter().enumerate() {
        std::fs::create_dir_all(w.path(rel).parent().unwrap()).unwrap();
        std::fs::write(w.path(rel), vec![0u8; 1_000 * (i + 1)]).unwrap();
    }
    // Things that only look a little like temp files, and must survive.
    let bystanders = [
        "Pixel 8/DCIM/Camera/holiday.part",
        "Pixel 8/DCIM/Camera/.kiwi-tmp-notes.txt",
        "Pixel 8/DCIM/Camera/x.kiwi-tmp-1.part",
        "Pixel 8/DCIM/Camera/.kiwi-tmp-.part",
        "Some Folder The User Made/the user's own file.txt",
        "top-level.txt",
    ];
    for rel in bystanders {
        std::fs::write(w.path(rel), b"not a temp file").unwrap();
    }
    // A directory with a temp-file name is not a file to delete.
    std::fs::create_dir_all(w.path("Pixel 8/.kiwi-tmp-5-5-dddddddddddddddd.part/inside")).unwrap();
    std::fs::write(w.path("Pixel 8/.kiwi-tmp-5-5-dddddddddddddddd.part/inside/file.txt"), b"x").unwrap();
    // Nothing inside the bookkeeping directory is ever swept.
    let inside_store_dir = w.root.join(STORE_DIR).join(".kiwi-tmp-0-0-eeeeeeeeeeeeeeee.part");
    std::fs::write(&inside_store_dir, b"x").unwrap();

    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert!(report.completed);
    assert_eq!(report.orphan_temps_removed, 5);
    assert_eq!(report.orphan_temp_bytes, 1_000 + 2_000 + 3_000 + 4_000 + 5_000);
    assert!(report.orphan_temps_left.is_empty());
    assert_eq!((report.records_checked, report.newly_missing, report.newly_changed), (1, 0, 0));

    let mut expected: Vec<String> = bystanders.iter().map(|s| s.to_string()).collect();
    expected.push("Pixel 8/DCIM/Camera/keep.jpg".to_owned());
    expected.push("Pixel 8/.kiwi-tmp-5-5-dddddddddddddddd.part/inside/file.txt".to_owned());
    expected.sort();
    assert_eq!(w.files(), expected);
    assert!(inside_store_dir.exists());
    assert!(store.final_move_block().unwrap().is_none());
    let events: Vec<String> = store.events_after(0, 1_000).unwrap().into_iter().map(|e| e.kind).collect();
    assert!(events.contains(&"recovery_finished".to_owned()));
}

#[test]
fn records_of_vanished_files_are_marked_and_block_final_move() {
    let w = World::new("vanished");
    let hashes: Vec<ContentHash> = {
        let store = w.open();
        (0..4).map(|i| put(&store, &format!("DCIM/{i}.jpg"), &data(i, 10_000)).hash).collect()
    };
    std::fs::remove_file(w.path("Pixel 8/DCIM/1.jpg")).unwrap();
    // Another one grew: obviously not the file that was stored.
    let mut longer = std::fs::read(w.path("Pixel 8/DCIM/2.jpg")).unwrap();
    longer.extend_from_slice(b"appended");
    std::fs::write(w.path("Pixel 8/DCIM/2.jpg"), longer).unwrap();
    // And one became a directory.
    std::fs::remove_file(w.path("Pixel 8/DCIM/3.jpg")).unwrap();
    std::fs::create_dir(w.path("Pixel 8/DCIM/3.jpg")).unwrap();

    w.clock.advance_hours(30);
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!((report.records_checked, report.newly_missing, report.newly_changed), (4, 1, 2));
    assert!(!report.mass_change, "three files are a problem, not a mass change");
    let stats = store.stats().unwrap();
    assert_eq!((stats.files_committed, stats.files_missing, stats.files_changed), (1, 1, 2));

    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    // Even the intact file cannot be confirmed for deletion while blocked.
    assert!(matches!(store.verify_for_deletion(&hashes[0], 1), Err(DeletionDenied::Blocked(_))));
    assert!(store.is_safely_stored(&hashes[0]).unwrap().is_verified());
    assert!(matches!(store.is_safely_stored(&hashes[1]).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Missing)));
    assert!(matches!(store.is_safely_stored(&hashes[2]).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Changed(_))));
    assert!(matches!(store.is_safely_stored(&hashes[3]).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Changed(_))));
    drop(store);

    // The next start does not report the same findings again.
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!((report.records_checked, report.newly_missing, report.newly_changed), (1, 0, 0));
    assert!(store.final_move_block().unwrap().is_some(), "the block stays until it is cleared");
    store.clear_final_move_block("the user deleted these on purpose").unwrap();
    assert!(store.verify_for_deletion(&hashes[0], 1).is_ok());
    drop(store);
    let store = w.open();
    assert!(store.final_move_block().unwrap().is_none(), "known problems do not block again");
}

#[test]
fn deletions_need_not_block_if_the_policy_says_so() {
    let mut w = World::new("policy");
    w.configure = |cfg: &mut StoreConfig| cfg.scan_policy = ScanPolicy { block_on_missing: false, ..ScanPolicy::default() };
    let (gone, changed) = {
        let store = w.open();
        (put(&store, "gone.jpg", &data(1, 5_000)).hash, put(&store, "changed.jpg", &data(2, 5_000)).hash)
    };
    std::fs::remove_file(w.path("Pixel 8/gone.jpg")).unwrap();
    let store = w.open();
    assert_eq!(store.recovery_report().unwrap().newly_missing, 1);
    assert!(store.final_move_block().unwrap().is_none());
    assert!(!store.is_safely_stored(&gone).unwrap().is_verified());
    // Changed content blocks regardless of that switch.
    corrupt_silently(&w.path("Pixel 8/changed.jpg"));
    assert!(!store.is_safely_stored(&changed).unwrap().is_verified());
    assert_eq!(store.final_move_block().unwrap().unwrap().kind, BlockKind::IntegrityProblems);
}

#[test]
fn many_files_vanishing_at_once_is_a_mass_change() {
    let w = World::new("mass-deletion");
    {
        let store = w.open();
        for i in 0..12 {
            put(&store, &format!("DCIM/{i:02}.jpg"), &data(i, 2_000));
        }
    }
    std::fs::remove_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.newly_missing, 12);
    assert!(report.mass_change);
    let block = store.final_move_block().unwrap().unwrap();
    assert_eq!(block.kind, BlockKind::MassChange);
    assert!(block.reason.contains("12 of 12"), "{}", block.reason);
}

#[test]
fn files_renamed_and_rewritten_look_like_ransomware() {
    let mut w = World::new("ransom");
    // Raise the "share of the library missing" threshold so that the
    // deletions alone would not trip it: the renames are what must be caught.
    w.configure =
        |cfg: &mut StoreConfig| cfg.scan_policy = ScanPolicy { mass_missing_min_percent: 50, ..ScanPolicy::default() };
    {
        let store = w.open();
        for i in 0..30 {
            put(&store, &format!("DCIM/{i:03}.jpg"), &data(i, 300));
        }
    }
    for i in 0..10 {
        let from = w.path(&format!("Pixel 8/DCIM/{i:03}.jpg"));
        let to = w.path(&format!("Pixel 8/DCIM/{i:03}.jpg.locked"));
        std::fs::write(&from, b"ENCRYPTED").unwrap();
        std::fs::rename(&from, &to).unwrap();
    }
    std::fs::write(w.path("Pixel 8/DCIM/README_TO_DECRYPT.txt"), b"pay up").unwrap();
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.newly_missing, 10);
    assert_eq!(report.rename_suspects, 10);
    assert!(report.mass_change);
    assert_eq!(store.final_move_block().unwrap().unwrap().kind, BlockKind::MassChange);
    // The renamed files are evidence; they are not touched.
    assert_eq!(std::fs::read(w.path("Pixel 8/DCIM/000.jpg.locked")).unwrap(), b"ENCRYPTED");
}

#[test]
fn a_recovery_pass_leaves_running_transfers_alone() {
    let mut w = World::new("live");
    w.configure = |cfg: &mut StoreConfig| cfg.defer_recovery = true;
    let store = w.open();
    assert!(store.recovery_report().is_none(), "recovery was deferred");
    std::fs::create_dir_all(w.path("Pixel 8")).unwrap();
    std::fs::write(w.path("Pixel 8/.kiwi-tmp-0-0-0000000000000000.part"), b"orphan").unwrap();

    let bytes = data(1, 50_000);
    let mut incoming = store.begin_file(request(&phone(), "live.jpg", &bytes)).unwrap();
    incoming.write(&bytes[..20_000]).unwrap();
    assert_eq!(w.temp_files().len(), 2);

    let report = store.run_recovery(&CancelToken::new()).unwrap();
    assert_eq!(report.orphan_temps_removed, 1, "only the orphan goes");
    assert_eq!(store.recovery_report().unwrap(), report);
    assert_eq!(w.temp_files().len(), 1);

    incoming.write(&bytes[20_000..]).unwrap();
    let receipt = incoming.finish(None).unwrap();
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert!(w.temp_files().is_empty());
}

#[test]
fn a_cancelled_recovery_says_it_did_not_finish() {
    let mut w = World::new("cancelled");
    w.configure = |cfg: &mut StoreConfig| cfg.defer_recovery = true;
    let store = w.open();
    put(&store, "a.jpg", b"x");
    std::fs::write(w.path("Pixel 8/.kiwi-tmp-0-0-0000000000000000.part"), b"orphan").unwrap();
    let cancel = CancelToken::new();
    cancel.cancel();
    let report = store.run_recovery(&cancel).unwrap();
    assert!(!report.completed);
    assert_eq!(report.orphan_temps_removed, 0);
    let report = store.run_recovery(&CancelToken::new()).unwrap();
    assert!(report.completed);
    assert_eq!(report.orphan_temps_removed, 1);
}

#[test]
fn sessions_count_every_open() {
    let w = World::new("sessions");
    for expected in 1..=5 {
        let store = w.open();
        assert_eq!(store.session(), expected);
        assert_eq!(store.open_notes().contains(&OpenNote::NewDestination), expected == 1);
    }
}

#[test]
fn a_ledger_that_lost_its_records_is_noticed() {
    let w = World::new("ledger-lost");
    let hash = {
        let store = w.open();
        put(&store, "a.jpg", &data(1, 3_000)).hash
    };
    // The application's data directory was wiped: the folder remembers that
    // it has been used, the (new, empty) ledger knows nothing.
    remove_tree(&w.ledger_dir);
    w.clock.advance_hours(30);
    let store = w.open();
    assert_eq!(store.open_notes(), [OpenNote::LedgerLost]);
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::LedgerLost);
    assert!(matches!(store.verify_for_deletion(&hash, 1), Err(DeletionDenied::Blocked(_))));
    assert!(matches!(store.is_safely_stored(&hash).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::NoRecord)));
    // The file itself is untouched and is recognised when it is sent again.
    assert_eq!(w.files(), vec!["Pixel 8/a.jpg"]);
    let receipt = put(&store, "a.jpg", &data(1, 3_000));
    assert_eq!(receipt.outcome, kiwi_store::CommitOutcome::AlreadyPresent);
    assert_eq!(w.files(), vec!["Pixel 8/a.jpg"]);
    drop(store);
    // Later opens are ordinary; the block stays until cleared.
    let store = w.open();
    assert!(store.open_notes().is_empty());
    assert_eq!(store.final_move_block().unwrap().unwrap().kind, BlockKind::LedgerLost);
}

#[test]
fn a_folder_that_lost_its_marker_is_noticed() {
    let w = World::new("marker-lost");
    let hash = {
        let store = w.open();
        put(&store, "a.jpg", &data(1, 3_000)).hash
    };
    // The folder was emptied (or another disk now answers to this path).
    remove_tree(&w.root);
    std::fs::create_dir_all(&w.root).unwrap();
    w.clock.advance_hours(30);
    let store = w.open();
    assert!(store.open_notes().contains(&OpenNote::MarkerRecreated));
    let block = store.final_move_block().unwrap().expect("blocked");
    // The missing file is found by the same open; either reason is a block.
    assert!(matches!(block.kind, BlockKind::MarkerMissing | BlockKind::IntegrityProblems), "{block:?}");
    assert!(matches!(store.verify_for_deletion(&hash, 1), Err(DeletionDenied::Blocked(_))));
    assert!(store.events_after(0, 1_000).unwrap().iter().any(|e| e.detail.as_deref().is_some_and(|d| d.contains("identity marker"))));
}

#[test]
fn a_marker_lost_before_anything_was_stored_is_simply_rewritten() {
    let w = World::new("marker-early");
    drop(w.open());
    std::fs::remove_file(w.root.join(STORE_DIR).join("id")).unwrap();
    let store = w.open();
    assert_eq!(store.open_notes(), [OpenNote::MarkerRecreated]);
    assert!(store.final_move_block().unwrap().is_none());
    assert!(w.root.join(STORE_DIR).join("id").exists());
}

#[test]
fn a_ledger_cannot_be_used_with_another_folder() {
    let a = World::new("bind-a");
    let b = World::new("bind-b");
    drop(a.open());
    drop(b.open());
    // b's folder with a's ledger.
    let mut cfg = b.config();
    cfg.ledger_dir = a.ledger_dir.clone();
    match kiwi_store::Store::open_with_seams(cfg, b.seams()) {
        Err(StoreError::Ledger(LedgerError::DestinationMismatch { ledger_id, marker_id })) => {
            assert_ne!(ledger_id, marker_id);
            assert_eq!(ledger_id.len(), 32);
        }
        other => panic!("expected DestinationMismatch, got {:?}", other.map(|_| ())),
    }
    // Both are still usable with their own ledgers.
    assert_eq!(a.open().session(), 2);
    assert_eq!(b.open().session(), 2);
}

#[test]
fn the_ledger_may_live_inside_the_bookkeeping_directory() {
    let mut w = World::new("ledger-inside");
    w.ledger_dir = w.root.join(STORE_DIR);
    let hash = {
        let store = w.open();
        put(&store, "a.jpg", &data(1, 3_000)).hash
    };
    let store = w.open();
    assert!(store.is_safely_stored(&hash).unwrap().is_verified());
    assert_eq!(w.files(), vec!["Pixel 8/a.jpg"]);
    assert!(store.ledger_path().starts_with(w.root.join(STORE_DIR)));
    // The scan does not mistake the engine's own files for unexpected ones.
    let report = store.integrity_scan(&Default::default(), &CancelToken::new()).unwrap();
    assert_eq!(report.unexpected, 0);
}
