//! A damaged ledger: the engine refuses to rely on it, says so clearly, and
//! never confirms a deletion on its strength.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};

use common::*;
use kiwi_store::{
    BlockKind, CommitOutcome, ContentHash, DeletionDenied, LedgerError, NotVerifiedReason,
    OpenNote, Store, StoreConfig, StoreError, StoredStatus,
};

/// Stores a few files in session 1 and returns their hashes. Afterwards the
/// store is closed and a day has passed.
fn seeded(w: &World) -> Vec<ContentHash> {
    let hashes = {
        let store = w.open();
        (0..6)
            .map(|i| {
                put(
                    &store,
                    &format!("DCIM/a{i}.jpg"),
                    &data(i, 4_000 + i as usize),
                )
                .hash
            })
            .collect()
    };
    w.clock.advance_hours(25);
    // SQLite folds the write-ahead log into the database when it closes.
    assert!(
        !w.ledger_dir.join("ledger.db-wal").exists()
            || std::fs::metadata(w.ledger_dir.join("ledger.db-wal"))
                .unwrap()
                .len()
                == 0
    );
    hashes
}

fn ledger_len(w: &World) -> u64 {
    std::fs::metadata(w.ledger_file()).unwrap().len()
}

fn overwrite(w: &World, offset: u64, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(w.ledger_file())
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn expect_corrupt(result: Result<Store, StoreError>, w: &World) -> String {
    match result {
        Err(StoreError::Ledger(LedgerError::Corrupt { path, detail })) => {
            assert_eq!(
                std::fs::canonicalize(&path).unwrap(),
                std::fs::canonicalize(w.ledger_file()).unwrap()
            );
            assert!(!detail.is_empty());
            let message = StoreError::Ledger(LedgerError::Corrupt { path, detail }).to_string();
            assert!(message.contains("damaged"), "{message}");
            assert!(message.contains("ledger.db"), "{message}");
            message
        }
        Ok(_) => panic!("a damaged ledger was opened as if nothing had happened"),
        Err(other) => panic!("expected LedgerError::Corrupt, got {other:?}"),
    }
}

fn reset(w: &World) -> Store {
    Store::reset_corrupt_ledger_with_seams(w.config(), || w.seams())
        .expect("the reset should succeed")
}

/// After a reset: blocked, nothing confirmed, files intact, and usable again.
fn check_after_reset(w: &World, store: &Store, hashes: &[ContentHash]) {
    let quarantined = match store.open_notes() {
        [OpenNote::LedgerReset { quarantined }] => quarantined.clone(),
        other => panic!("expected a LedgerReset note, got {other:?}"),
    };
    assert!(!quarantined.is_empty());
    for path in &quarantined {
        assert!(
            path.exists(),
            "the damaged ledger is kept, not deleted: {path:?}"
        );
        assert!(path.to_string_lossy().contains(".corrupt-"));
    }
    let block = store
        .final_move_block()
        .unwrap()
        .expect("a reset blocks final move");
    assert_eq!(block.kind, BlockKind::LedgerReset);
    assert!(
        block.reason.contains("damaged") && block.reason.contains("reset"),
        "{}",
        block.reason
    );

    for hash in hashes {
        assert!(matches!(
            store.verify_for_deletion(&phone(), hash, 1),
            Err(DeletionDenied::Blocked(_))
        ));
        assert!(matches!(
            store.is_safely_stored(&phone(), hash).unwrap(),
            StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
        ));
    }
    // The photos themselves were never touched.
    assert_eq!(w.files().len(), hashes.len());
    for (i, hash) in hashes.iter().enumerate() {
        let on_disk = std::fs::read(w.path(&format!("Pixel 8/DCIM/a{i}.jpg"))).unwrap();
        assert_eq!(ContentHash::of_bytes(&on_disk), *hash);
    }

    // Receiving works again (the device has to be registered again), and a
    // file that is already there is recognised rather than duplicated.
    store
        .register_device(&phone(), "Pixel 8", Default::default())
        .unwrap();
    let again = put(store, "DCIM/a0.jpg", &data(0, 4_000));
    assert_eq!(again.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(
        put(store, "DCIM/new.jpg", b"new").outcome,
        CommitOutcome::Stored
    );
    assert_eq!(w.files().len(), hashes.len() + 1);

    // Even with the block cleared, the re-recorded file is new to this ledger:
    // it has to age like any other before its deletion is confirmed.
    store
        .clear_final_move_block("the user was told about the reset")
        .unwrap();
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hashes[0], 1),
        Err(DeletionDenied::TooRecent { .. })
    ));
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hashes[1], 1),
        Err(DeletionDenied::NoRecord)
    ));
}

#[test]
fn a_truncated_ledger_is_refused() {
    let w = World::new("truncated");
    let hashes = seeded(&w);
    let len = ledger_len(&w);
    assert!(
        len >= 8 * 4096,
        "the ledger should span several pages, has {len} bytes"
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(w.ledger_file())
        .unwrap()
        .set_len(len / 2)
        .unwrap();

    expect_corrupt(w.try_open(), &w);
    // Refusing does not "repair" anything behind the user's back.
    assert_eq!(ledger_len(&w), len / 2);
    expect_corrupt(Store::open(w.config()), &w);

    let store = reset(&w);
    check_after_reset(&w, &store, &hashes);
}

#[test]
fn a_garbled_header_is_refused() {
    let w = World::new("header");
    let hashes = seeded(&w);
    overwrite(&w, 0, &[0xA5; 100]);
    let message = expect_corrupt(w.try_open(), &w);
    println!("reported as: {message}");
    let store = reset(&w);
    check_after_reset(&w, &store, &hashes);
}

#[test]
fn garbled_pages_are_refused() {
    let w = World::new("pages");
    let hashes = seeded(&w);
    let len = ledger_len(&w);
    // Everything after the first page is replaced by noise.
    let noise = data(99, (len - 4096) as usize);
    overwrite(&w, 4096, &noise);
    assert_eq!(ledger_len(&w), len);
    let message = expect_corrupt(w.try_open(), &w);
    println!("reported as: {message}");
    let store = reset(&w);
    check_after_reset(&w, &store, &hashes);
}

#[test]
fn a_single_garbled_page_in_the_middle_is_refused() {
    let w = World::new("one-page");
    seeded(&w);
    let len = ledger_len(&w);
    let pages = len / 4096;
    // Damage each page in turn (on a fresh copy each time); every one of them
    // must be noticed, by SQLite's own check or by ours.
    let pristine = std::fs::read(w.ledger_file()).unwrap();
    let mut noticed = 0;
    let mut harmless = Vec::new();
    for page in 0..pages {
        std::fs::write(w.ledger_file(), &pristine).unwrap();
        overwrite(&w, page * 4096, &data(1_000 + page, 4096));
        match w.try_open() {
            Err(StoreError::Ledger(LedgerError::Corrupt { .. })) => noticed += 1,
            // A page that holds nothing (a free page) can be overwritten
            // without consequence; then the ledger must still be fully intact.
            Ok(store) => {
                assert_eq!(
                    store.stats().unwrap().files_committed,
                    6,
                    "page {page} was damaged silently"
                );
                harmless.push(page);
            }
            Err(other) => panic!("page {page}: unexpected error {other:?}"),
        }
    }
    println!("{noticed} of {pages} damaged pages were refused; unused pages: {harmless:?}");
    assert!(
        noticed >= pages - 2,
        "too many damaged pages went unnoticed: {harmless:?}"
    );
}

#[test]
fn a_ledger_cut_to_nothing_is_noticed_even_though_sqlite_accepts_it() {
    // An empty file is a valid, empty SQLite database. The folder's marker is
    // what reveals that records used to exist.
    let w = World::new("empty-file");
    let hashes = seeded(&w);
    std::fs::OpenOptions::new()
        .write(true)
        .open(w.ledger_file())
        .unwrap()
        .set_len(0)
        .unwrap();
    let store = w.try_open().expect("an empty file opens as a new ledger");
    assert_eq!(store.open_notes(), [OpenNote::LedgerLost]);
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::LedgerLost);
    assert!(
        block.reason.contains("empty or missing"),
        "{}",
        block.reason
    );
    for hash in &hashes {
        assert!(matches!(
            store.verify_for_deletion(&phone(), hash, 1),
            Err(DeletionDenied::Blocked(_))
        ));
    }
    store.clear_final_move_block("acknowledged").unwrap();
    // The new ledger does not even know the phone ...
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hashes[0], 1),
        Err(DeletionDenied::UnknownDevice(_))
    ));
    // ... and once it does, it has no record of anything the phone stored.
    store
        .register_device(&phone(), "Pixel 8", kiwi_store::DeviceLimits::default())
        .unwrap();
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hashes[0], 1),
        Err(DeletionDenied::NoRecord)
    ));
    assert_eq!(w.files().len(), hashes.len());
}

#[test]
fn damage_inside_a_record_that_sqlite_cannot_see_is_caught_by_the_row_checksum() {
    let w = World::new("inside-a-record");
    seeded(&w);
    // Change one letter of a stored path, in place. The database structure
    // stays perfectly valid, so SQLite's integrity check has nothing to say.
    let mut raw = Vec::new();
    std::fs::File::open(w.ledger_file())
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    let needle = b"Pixel 8/DCIM/a3.jpg";
    let positions: Vec<usize> = raw
        .windows(needle.len())
        .enumerate()
        .filter(|(_, win)| win == needle)
        .map(|(i, _)| i)
        .collect();
    assert!(!positions.is_empty(), "the path should appear in the file");
    for at in positions {
        raw[at + needle.len() - 6] = b'b'; // "a3.jpg" -> "b3.jpg"
    }
    std::fs::write(w.ledger_file(), &raw).unwrap();
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        let verdict: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(verdict, "ok", "this damage is invisible to SQLite");
    }
    let message = expect_corrupt(w.try_open(), &w);
    assert!(message.contains("checksum"), "{message}");
}

#[test]
fn nonsense_in_the_bookkeeping_values_is_corruption() {
    let w = World::new("meta");
    seeded(&w);
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute(
            "UPDATE meta SET value = 'not a number' WHERE key = 'session_counter'",
            [],
        )
        .unwrap();
    }
    expect_corrupt(w.try_open(), &w);
    let store = reset(&w);
    assert_eq!(store.session(), 1, "the reset ledger starts over");
    assert_eq!(
        store.final_move_block().unwrap().unwrap().kind,
        BlockKind::LedgerReset
    );
}

#[test]
fn resetting_a_healthy_ledger_changes_nothing() {
    let w = World::new("healthy");
    let hashes = seeded(&w);
    let store = reset(&w);
    assert!(store.open_notes().is_empty());
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.stats().unwrap().files_committed, 6);
    assert!(store.verify_for_deletion(&phone(), &hashes[0], 1).is_ok());
    assert!(!w.ledger_dir.join("ledger.db.corrupt-1").exists());
}

#[test]
fn repeated_resets_keep_every_damaged_copy() {
    let w = World::new("twice");
    seeded(&w);
    overwrite(&w, 0, &[0xFF; 64]);
    drop(reset(&w));
    overwrite(&w, 0, &[0xEE; 64]);
    drop(reset(&w));
    let first = std::fs::read(w.ledger_dir.join("ledger.db.corrupt-1")).unwrap();
    let second = std::fs::read(w.ledger_dir.join("ledger.db.corrupt-2")).unwrap();
    assert_eq!(&first[..64], &[0xFF; 64]);
    assert_eq!(&second[..64], &[0xEE; 64]);
    assert_eq!(w.open().session(), 2);
}

#[test]
fn someone_elses_database_is_not_ours_to_reset() {
    let w = World::new("foreign");
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute_batch(
            "CREATE TABLE recipes(name TEXT); INSERT INTO recipes VALUES ('kiwi jam');",
        )
        .unwrap();
    }
    let not_ours = |r: Result<Store, StoreError>| match r {
        Err(StoreError::Ledger(LedgerError::NotALedger { .. })) => {}
        other => panic!("expected NotALedger, got {:?}", other.map(|_| ())),
    };
    not_ours(w.try_open());
    not_ours(Store::reset_corrupt_ledger_with_seams(w.config(), || {
        w.seams()
    }));
    let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
    let name: String = conn
        .query_row("SELECT name FROM recipes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(name, "kiwi jam");
    assert!(!w.ledger_dir.join("ledger.db.corrupt-1").exists());
}

#[test]
fn a_ledger_from_a_newer_version_is_left_alone() {
    let w = World::new("newer");
    let hashes = seeded(&w);
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute_batch("PRAGMA user_version = 999;").unwrap();
    }
    let too_new = |r: Result<Store, StoreError>| match r {
        Err(StoreError::Ledger(LedgerError::TooNew {
            found: 999,
            supported,
        })) => assert!(supported < 999),
        other => panic!("expected TooNew, got {:?}", other.map(|_| ())),
    };
    too_new(w.try_open());
    too_new(Store::reset_corrupt_ledger_with_seams(w.config(), || {
        w.seams()
    }));
    // Put the version back: nothing was lost and no session was spent.
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA user_version = {};",
            kiwi_store::ledger::SCHEMA_VERSION
        ))
        .unwrap();
    }
    let store = w.open();
    assert_eq!(store.session(), 2);
    assert!(store.verify_for_deletion(&phone(), &hashes[0], 1).is_ok());
}

#[test]
fn a_ledger_directory_that_cannot_be_created_is_an_error() {
    let w = World::new("bad-ledger-dir");
    let file = w.base.join("a-file");
    std::fs::write(&file, b"x").unwrap();
    let mut cfg: StoreConfig = w.config();
    cfg.ledger_dir = file.join("ledger");
    assert!(matches!(
        Store::open(cfg),
        Err(StoreError::Io { .. } | StoreError::DiskFull { .. })
    ));
}
