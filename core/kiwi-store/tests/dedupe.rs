//! Deduplication and `is_safely_stored`: a ledger hit counts only after the
//! file has been read back from disk.

mod common;

use std::io::ErrorKind;

use common::*;
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{BlockKind, CommitOutcome, ContentHash, DedupeScope, DeviceLimits, NotVerifiedReason, StoredStatus};

const STORED: &str = "Pixel 8/DCIM/a.jpg";

fn bytes() -> Vec<u8> {
    data(11, 120_000)
}

fn hash() -> ContentHash {
    ContentHash::of_bytes(&bytes())
}

#[test]
fn a_hit_is_confirmed_by_reading_the_file() {
    let w = World::new("hit");
    let store = w.open();
    let receipt = put(&store, "DCIM/a.jpg", &bytes());

    w.fs.reset_counters();
    let found = store.find_duplicate(&hash(), DedupeScope::Device(&phone())).unwrap().expect("a duplicate");
    assert_eq!(w.fs.count(Op::ReadVerify), 1, "the file itself must be read, not just the ledger");
    assert_eq!(found.file_id, receipt.file_id);
    assert_eq!(found.rel_path, STORED);
    assert_eq!(found.abs_path, receipt.abs_path);
    assert_eq!(found.size, 120_000);
    assert_eq!(found.device, "phone-1");
    if cfg!(windows) {
        assert!(found.read_unbuffered);
    }
    // Content the store has never seen.
    assert!(store.find_duplicate(&ContentHash::of_bytes(b"new"), DedupeScope::AnyDevice).unwrap().is_none());
    // The hit is on record.
    assert!(store.events_after(0, 1_000).unwrap().iter().any(|e| e.kind == "dedupe_hit" && e.file_id == Some(receipt.file_id)));
}

#[test]
fn a_silently_modified_file_is_not_a_duplicate() {
    let w = World::new("modified");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());
    // Same size, same modification time, one bit different.
    corrupt_silently(&w.path(STORED));

    assert!(store.find_duplicate(&hash(), DedupeScope::Device(&phone())).unwrap().is_none());
    match store.is_safely_stored(&hash()).unwrap() {
        StoredStatus::NotVerified(NotVerifiedReason::Changed(how)) => assert!(how.contains("hashes to"), "{how}"),
        other => panic!("unexpected: {other:?}"),
    }
    // The damage is recorded and final move is blocked.
    let stats = store.stats().unwrap();
    assert_eq!((stats.files_committed, stats.files_changed), (0, 1));
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert!(block.reason.contains(STORED));
    let events = store.events_after(0, 1_000).unwrap();
    assert!(events.iter().any(|e| e.kind == "file_changed"));

    // So the phone sends the file again. The damaged file is not overwritten;
    // the good copy is stored next to it and is the duplicate from now on.
    let damaged = std::fs::read(w.path(STORED)).unwrap();
    let receipt = put(&store, "DCIM/a.jpg", &bytes());
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/DCIM/a (2).jpg");
    assert_eq!(std::fs::read(w.path(STORED)).unwrap(), damaged);
    let found = store.find_duplicate(&hash(), DedupeScope::Device(&phone())).unwrap().unwrap();
    assert_eq!(found.rel_path, "Pixel 8/DCIM/a (2).jpg");
}

#[test]
fn a_deleted_or_truncated_file_is_not_a_duplicate() {
    let w = World::new("deleted");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());

    std::fs::write(w.path(STORED), &bytes()[..119_999]).unwrap();
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().is_none());
    assert!(matches!(store.is_safely_stored(&hash()).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Changed(_))));

    std::fs::remove_file(w.path(STORED)).unwrap();
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().is_none());
    assert!(matches!(store.is_safely_stored(&hash()).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Missing)));
    assert_eq!(store.stats().unwrap().files_missing, 1);

    // The whole folder is gone.
    std::fs::remove_dir_all(w.path("Pixel 8")).unwrap();
    assert!(matches!(store.is_safely_stored(&hash()).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Missing)));

    // The user puts the file back: it is a duplicate again, and the ledger knows.
    std::fs::create_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    std::fs::write(w.path(STORED), bytes()).unwrap();
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().is_some());
    let stats = store.stats().unwrap();
    assert_eq!((stats.files_committed, stats.files_missing), (1, 0));
    assert!(store.events_after(0, 1_000).unwrap().iter().any(|e| e.kind == "file_restored"));
}

#[test]
fn an_unreadable_file_is_not_a_duplicate_but_is_not_condemned() {
    let w = World::new("unreadable");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());
    w.fs.inject(When::Every(Op::ReadVerify), Action::Fail(ErrorKind::PermissionDenied));
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().is_none());
    assert!(matches!(store.is_safely_stored(&hash()).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Unreadable(_))));
    w.fs.clear_rules();
    // "Could not read" is not "damaged".
    assert_eq!(store.stats().unwrap().files_committed, 1);
    assert!(store.final_move_block().unwrap().is_none());
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().is_some());
}

#[test]
fn a_file_held_open_for_writing_by_another_program_is_not_verified() {
    if !cfg!(windows) {
        return; // Share modes are a Windows concept.
    }
    let w = World::new("in-use");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());
    let editor = std::fs::OpenOptions::new().write(true).open(w.path(STORED)).unwrap();
    assert!(matches!(store.is_safely_stored(&hash()).unwrap(), StoredStatus::NotVerified(NotVerifiedReason::Unreadable(_))));
    drop(editor);
    assert!(store.is_safely_stored(&hash()).unwrap().is_verified());
}

#[test]
fn scope_limits_which_devices_files_count() {
    let w = World::new("scope");
    let store = w.open();
    store.register_device(&tablet(), "Tab S9", DeviceLimits::default()).unwrap();
    put(&store, "DCIM/a.jpg", &bytes());

    assert!(store.find_duplicate(&hash(), DedupeScope::Device(&phone())).unwrap().is_some());
    assert!(store.find_duplicate(&hash(), DedupeScope::Device(&tablet())).unwrap().is_none());
    let any = store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().unwrap();
    assert_eq!(any.device, "phone-1");

    // The tablet stores its own copy in its own folder.
    let receipt = try_put(&store, &tablet(), "DCIM/a.jpg", &bytes()).unwrap();
    assert_eq!(receipt.rel_path, "Tab S9/DCIM/a.jpg");
    let own = store.find_duplicate(&hash(), DedupeScope::Device(&tablet())).unwrap().unwrap();
    assert_eq!(own.rel_path, "Tab S9/DCIM/a.jpg");
    // Per-device accounting.
    assert_eq!(store.device(&phone()).unwrap().unwrap().used_files, 1);
    assert_eq!(store.device(&tablet()).unwrap().unwrap().used_files, 1);
}

#[test]
fn when_one_copy_is_damaged_another_intact_copy_is_found() {
    let w = World::new("second-copy");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());
    put(&store, "Backup/b.jpg", &bytes());
    corrupt_silently(&w.path(STORED));
    let found = store.find_duplicate(&hash(), DedupeScope::AnyDevice).unwrap().unwrap();
    assert_eq!(found.rel_path, "Pixel 8/Backup/b.jpg");
    // The damaged copy was still noticed.
    assert_eq!(store.stats().unwrap().files_changed, 1);
    assert!(store.final_move_block().unwrap().is_some());
}

#[test]
fn a_record_whose_path_is_not_clean_is_never_followed() {
    let w = World::new("bad-path");
    let store = w.open();
    put(&store, "DCIM/a.jpg", &bytes());
    // A file outside the root with the same content, and a ledger row edited
    // to point at it. (The edit also breaks the row's checksum; the point here
    // is that even the path alone would be refused.)
    std::fs::write(w.outside.join("a.jpg"), bytes()).unwrap();
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute("UPDATE files SET rel_path = '../outside/a.jpg'", []).unwrap();
    }
    assert!(store.is_safely_stored(&hash()).is_err());
    assert!(store.find_duplicate(&hash(), DedupeScope::AnyDevice).is_err());
}

#[test]
fn ledger_state_is_only_a_belief() {
    // The ledger says "missing", the disk says "here and intact": the disk wins.
    let w = World::new("belief");
    let store = w.open();
    let receipt = put(&store, "DCIM/a.jpg", &bytes());
    let hidden = w.base.join("hidden.jpg");
    std::fs::rename(w.path(STORED), &hidden).unwrap();
    assert!(!store.is_safely_stored(&hash()).unwrap().is_verified());
    assert_eq!(store.stats().unwrap().files_missing, 1);
    std::fs::rename(&hidden, w.path(STORED)).unwrap();
    match store.is_safely_stored(&hash()).unwrap() {
        StoredStatus::Verified(file) => assert_eq!(file.file_id, receipt.file_id),
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(store.stats().unwrap().files_committed, 1);
}
