//! Every answer is given to one phone, from that phone's own records and
//! files. Also here: the keyed proof, ledger rollback, unpairing, final-move
//! states, the audit, and batched ledger commits.

mod common;

use common::*;
use kiwi_store::testing::Op;
use kiwi_store::{
    AuditStatus, BlockKind, CancelToken, CommitOutcome, ContentHash, DeletionDenied, DeviceLimits,
    FileState, FmState, NotVerifiedReason, OpenNote, RollbackCheck, ScanVerdict, Store,
    StoreConfig, StoreError, StoredStatus, Template, VerifyRequest,
};

const NAME: &str = "DCIM/a.jpg";
const STORED: &str = "Pixel 8/DCIM/a.jpg";

fn bytes() -> Vec<u8> {
    data(31, 60_000)
}

fn hash() -> ContentHash {
    ContentHash::of_bytes(&bytes())
}

/// The phone stores the file; a day later it is connected again (session 2).
fn stored_yesterday(w: &World) -> Store {
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(25);
    w.open()
}

fn with_tablet(store: &Store) {
    store
        .register_device(&tablet(), "Tab S9", DeviceLimits::default())
        .unwrap();
    store.new_session(&tablet(), None).unwrap();
}

// ----- one phone never answers for another ---------------------------------

#[test]
fn a_copy_stored_by_one_phone_never_answers_for_another() {
    let w = World::new("cross-device");
    {
        let store = w.open();
        with_tablet(&store);
        put(&store, NAME, &bytes());
        // The tablet stores something of its own (its commit 1).
        try_put(&store, &tablet(), "DCIM/own.jpg", b"the tablet's own").unwrap();
        // The tablet has the very same photo. For the tablet it is not stored.
        assert!(store.find_duplicate(&tablet(), &hash()).unwrap().is_none());
        assert!(matches!(
            store.is_safely_stored(&tablet(), &hash()).unwrap(),
            StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
        ));
        assert!(store.records(&tablet(), &hash()).unwrap().is_empty());
        assert!(store.find_duplicate(&phone(), &hash()).unwrap().is_some());
    }
    w.clock.advance_hours(25);
    let store = w.open();
    store.new_session(&tablet(), None).unwrap();

    // For the phone everything holds.
    let phone_record = store.records(&phone(), &hash()).unwrap().remove(0);
    assert!(verify(&store, &hash(), 1).is_ok());
    // The tablet names the phone's record exactly (key, hash, size, commit
    // number), a day and a session later. It is not the tablet's record.
    assert!(matches!(
        store.verify_for_deletion(&tablet(), &request_of(&phone_record)),
        Err(DeletionDenied::NoRecord)
    ));
    assert_eq!(
        store
            .audit(&tablet(), &phone_record.key, &hash(), phone_record.size)
            .unwrap(),
        AuditStatus::NoRecord
    );
    assert_eq!(
        store
            .mark_sole_copy(&tablet(), &phone_record.key, &hash(), None)
            .unwrap(),
        0
    );

    // The tablet sends it: its own file, in its own folder, with its own
    // commit number. Nothing is shared.
    let receipt = try_put(&store, &tablet(), NAME, &bytes()).unwrap();
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Tab S9/DCIM/a.jpg");
    assert_eq!(receipt.seq, 2);
    assert_eq!(
        w.files(),
        vec![STORED, "Tab S9/DCIM/a.jpg", "Tab S9/DCIM/own.jpg"]
    );
    // The phone's copy is two days old by now. The tablet's is new, and that
    // is what counts for the tablet.
    assert!(matches!(
        verify_as(&store, &tablet(), &hash(), 1),
        Err(DeletionDenied::TooRecent { .. })
    ));
    drop(store);
    w.clock.advance_hours(25);
    let store = w.open();
    store.new_session(&tablet(), None).unwrap();
    let proof = verify_as(&store, &tablet(), &hash(), 1).unwrap();
    assert_eq!(proof.file.rel_path, "Tab S9/DCIM/a.jpg");
    assert_eq!(proof.file.device, "tablet-2");

    // If the tablet's file is damaged, the phone's intact copy of the same
    // bytes does not stand in for it.
    corrupt_silently(&w.path("Tab S9/DCIM/a.jpg"));
    assert!(matches!(
        verify_as(&store, &tablet(), &hash(), 1),
        Err(DeletionDenied::NotVerified(NotVerifiedReason::Changed(_)))
    ));
    assert!(store.find_duplicate(&tablet(), &hash()).unwrap().is_none());
}

#[test]
fn every_layout_keeps_each_phone_in_its_own_folder() {
    // A layout by date, without {device}: two phones with the same photo
    // must still not meet at one path.
    let mut w = World::new("layout-per-device");
    w.configure = |cfg: &mut StoreConfig| cfg.layout = Template::parse("{year}/{month}").unwrap();
    let store = w.open();
    with_tablet(&store);
    let july_2017 = Some(1_500_000_000_000_000_000);
    let send = |device, bytes: &[u8]| {
        let mut incoming = store
            .begin_file(kiwi_store::FileRequest {
                mtime_unix_ns: july_2017,
                ..request(device, "IMG_1.jpg", bytes)
            })
            .unwrap();
        incoming.write(bytes).unwrap();
        incoming.finish(None).unwrap()
    };
    let (first, second) = (phone(), tablet());
    let a = send(&first, &bytes());
    let b = send(&second, &bytes());
    assert_eq!(a.rel_path, "Pixel 8/2017/07/IMG_1.jpg");
    assert_eq!(b.rel_path, "Tab S9/2017/07/IMG_1.jpg");
    assert_eq!(
        (a.outcome, b.outcome),
        (CommitOutcome::Stored, CommitOutcome::Stored)
    );
    assert_ne!(a.file_id, b.file_id);
    // Per-device accounting and numbering.
    assert_eq!(store.device(&phone()).unwrap().unwrap().used_files, 1);
    assert_eq!(store.device(&tablet()).unwrap().unwrap().used_files, 1);
    assert_eq!((a.seq, b.seq), (1, 1));
}

#[test]
fn a_record_outside_its_phones_folder_is_not_used() {
    let w = World::new("outside-folder");
    let store = stored_yesterday(&w);
    // The ledger is edited so that the phone's folder is another one: its
    // record now names a file outside its own folder.
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        conn.execute(
            "UPDATE devices SET folder_name = 'Elsewhere', folder_key = 'elsewhere'",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::NotVerified(
            NotVerifiedReason::InvalidRecord
        ))
    ));
    assert!(store.final_move_block().unwrap().is_some());
}

// ----- the proof -----------------------------------------------------------

#[test]
fn the_proof_is_a_keyed_hash_of_the_bytes_read_in_that_very_pass() {
    let w = World::new("keyed-proof");
    let store = stored_yesterday(&w);
    let record = store.records(&phone(), &hash()).unwrap().remove(0);
    assert_eq!(record.fm, FmState::None);

    w.fs.reset_counters();
    let proof = store
        .verify_for_deletion(&phone(), &request_of(&record))
        .unwrap();
    assert_eq!(
        proof.proof,
        *blake3::keyed_hash(&PROOF_KEY, &bytes()).as_bytes()
    );
    assert_eq!(
        w.fs.count(Op::ReadVerify),
        1,
        "one pass over the file gives both the hash and the proof"
    );
    assert_eq!(proof.copies, 1);
    assert!(proof.file.read_unbuffered);

    // Another nonce, another key, another proof: nothing is replayed.
    let other_key = [0xC3u8; 32];
    let again = store
        .verify_for_deletion(
            &phone(),
            &VerifyRequest {
                proof_key: other_key,
                ..request_of(&record)
            },
        )
        .unwrap();
    assert_ne!(again.proof, proof.proof);
    assert_eq!(
        again.proof,
        *blake3::keyed_hash(&other_key, &bytes()).as_bytes()
    );

    // Each confirmation is a ledger record of its own, and the file is
    // marked "may be the only copy" from the first one on.
    assert!(again.verified_seq > proof.verified_seq);
    let confirmations: Vec<u64> = store
        .events_after(0, 10_000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "deletion_verified")
        .map(|e| e.seq)
        .collect();
    assert_eq!(confirmations, vec![proof.verified_seq, again.verified_seq]);
    let record = store.records(&phone(), &hash()).unwrap().remove(0);
    assert_eq!(record.fm, FmState::Reverified);
    assert_eq!(
        store
            .records_in_state(&phone(), FmState::Reverified)
            .unwrap()
            .len(),
        1
    );

    // A denial computes nothing and marks nothing.
    corrupt_silently(&w.path(STORED));
    assert!(store
        .verify_for_deletion(&phone(), &request_of(&record))
        .is_err());
}

// ----- ledger rollback -----------------------------------------------------

#[test]
fn a_commit_number_the_ledger_never_issued_is_a_rollback() {
    let w = World::new("unknown-commit");
    let store = stored_yesterday(&w);
    let record = store.records(&phone(), &hash()).unwrap().remove(0);
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 1);
    match store.verify_for_deletion(
        &phone(),
        &VerifyRequest {
            commit_seq: 7,
            ..request_of(&record)
        },
    ) {
        Err(DeletionDenied::Blocked(block)) => {
            assert_eq!(block.kind, BlockKind::LedgerRollback);
            assert!(block.reason.contains("commit 7"), "{}", block.reason);
        }
        other => panic!("expected a rollback block, got {other:?}"),
    }
    // The number the phone has seen is never issued again.
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 7);
    assert_eq!(put(&store, "DCIM/next.jpg", b"next").seq, 8);
    // And nothing is confirmed until a person has looked.
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Blocked(_))
    ));
}

/// Three files are stored; the ledger is then put back to the state it had
/// after the first two.
fn rolled_back_world(name: &str, keep_destination_note: bool) -> (World, Vec<u8>, String) {
    let w = World::new(name);
    let third = data(33, 9_000);
    {
        let store = w.open();
        put(&store, NAME, &bytes());
        put(&store, "DCIM/b.jpg", &data(32, 8_000));
    }
    let snapshot = LedgerSnapshot::take(&w);
    let ledger_id = {
        let store = w.open();
        assert_eq!(put(&store, "DCIM/c.jpg", &third).seq, 3);
        store.ledger_id().unwrap()
    };
    // The PC's program data are restored from a backup made after the second
    // file. The photos folder is not touched.
    snapshot.restore(&w, false);
    if !keep_destination_note {
        std::fs::remove_file(w.root.join(kiwi_store::STORE_DIR).join("commits")).unwrap();
    }
    w.clock.advance_hours(25);
    (w, third, ledger_id)
}

#[test]
fn a_restored_ledger_is_caught_by_the_destinations_own_note() {
    let (w, third, old_ledger_id) = rolled_back_world("rollback-note", true);
    let store = w.open();
    match store.open_notes() {
        [OpenNote::LedgerRolledBack { detail }] => {
            assert!(detail.contains("commit 3"), "{detail}")
        }
        other => panic!("expected LedgerRolledBack, got {other:?}"),
    }
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::LedgerRollback);
    // A restored ledger is a different ledger: every receipt is void.
    assert_ne!(store.ledger_id().unwrap(), old_ledger_id);
    // No commit number is ever issued twice.
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 3);
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Blocked(_))
    ));
    // The third file is still on the disk, unknown. Sent again, it is found
    // and recorded under a new number.
    let again = put(&store, "DCIM/c.jpg", &third);
    assert_eq!(again.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(again.seq, 4);
    drop(store);
    // Once is enough: the next start has nothing new to report.
    let store = w.open();
    assert!(store.open_notes().is_empty(), "{:?}", store.open_notes());
    assert!(store.final_move_block().unwrap().is_some());
}

#[test]
fn a_restored_ledger_is_caught_by_the_phones_receipts() {
    let (w, _third, _) = rolled_back_world("rollback-receipts", false);
    let store = w.open();
    assert!(store.open_notes().is_empty());
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 2);

    // The phone holds receipts up to commit 2 on a good day ...
    assert_eq!(
        store.check_peer_commit_seq(&phone(), 2).unwrap(),
        RollbackCheck::Consistent {
            device_commit_hwm: 2
        }
    );
    assert!(store.final_move_block().unwrap().is_none());
    // ... but it holds one for commit 3.
    match store.check_peer_commit_seq(&phone(), 3).unwrap() {
        RollbackCheck::RolledBack {
            peer_commit_seq: 3,
            device_commit_hwm: 2,
            block,
        } => assert_eq!(block.kind, BlockKind::LedgerRollback),
        other => panic!("expected RolledBack, got {other:?}"),
    }
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 3);
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Blocked(_))
    ));
    // The block survives a restart and is cleared only by a person.
    drop(store);
    let store = w.open();
    assert_eq!(
        store.final_move_block().unwrap().unwrap().kind,
        BlockKind::LedgerRollback
    );
    store.clear_final_move_block("the user checked").unwrap();
    assert!(verify(&store, &hash(), 1).is_ok());
    // A rollback the caller found by other means blocks the same way.
    assert_eq!(
        store
            .report_rollback("a receipt names an unknown hash")
            .unwrap()
            .kind,
        BlockKind::LedgerRollback
    );
    assert!(matches!(
        store.check_peer_commit_seq(&tablet(), 1),
        Err(StoreError::UnknownDevice(_))
    ));
}

// ----- unpairing -----------------------------------------------------------

#[test]
fn unpairing_keeps_every_record_and_every_file() {
    let w = World::new("unpair");
    let other = data(34, 5_000);
    let other_hash = ContentHash::of_bytes(&other);
    let store = stored_yesterday(&w);
    put(&store, "DCIM/b.jpg", &other);
    // The phone has already let go of the first photo: this PC has the only copy.
    let expires = T0 + 30 * 24 * HOUR;
    assert_eq!(
        store
            .mark_sole_copy(&phone(), key_of(NAME), &hash(), Some(expires))
            .unwrap(),
        1
    );

    assert!(store
        .detach_device(&phone(), "unpaired by the user")
        .unwrap());
    assert!(!store.detach_device(&phone(), "again").unwrap());
    assert!(!store.detach_device(&tablet(), "never paired").unwrap());

    // Nothing is gone: not a record, not a file, not a mark.
    let device = store.device(&phone()).unwrap().unwrap();
    assert!(device.detached);
    assert_eq!((device.used_files, device.commit_hwm), (2, 2));
    assert_eq!(w.files(), vec![STORED, "Pixel 8/DCIM/b.jpg"]);
    assert_eq!(store.stats().unwrap().files_committed, 2);
    assert!(store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    let sole = store.records_in_state(&phone(), FmState::SoleCopy).unwrap();
    assert_eq!(sole.len(), 1);
    assert_eq!(sole[0].fm_expires_unix_ms, Some(expires));
    // The files of an unpaired phone are still scanned ...
    let scan = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!((scan.verdict, scan.files_checked), (ScanVerdict::Clean, 2));
    // ... and damage to them still counts.
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "device_detached"));

    // The unpaired phone itself gets nothing: no upload, no session, no
    // confirmation.
    assert!(matches!(
        store.begin_file(request(&phone(), "DCIM/c.jpg", b"c")),
        Err(StoreError::DeviceDetached(_))
    ));
    assert!(matches!(
        store.new_session(&phone(), None),
        Err(StoreError::DeviceDetached(_))
    ));
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::DeviceDetached(_))
    ));
    drop(store);

    // It all survives a restart, and pairing again brings the phone back
    // with everything it had.
    w.clock.advance_hours(25);
    let store = w.try_open().unwrap();
    assert!(store.device(&phone()).unwrap().unwrap().detached);
    assert_eq!(store.stats().unwrap().files_committed, 2);
    let device = store
        .register_device(&phone(), "Pixel 8", DeviceLimits::default())
        .unwrap();
    assert!(!device.detached);
    assert_eq!((device.session_seq, device.commit_hwm), (2, 2));
    store.new_session(&phone(), None).unwrap();
    assert!(verify(&store, &hash(), 1).is_ok());
    assert!(verify(&store, &other_hash, 1).is_ok());
    assert_eq!(put(&store, "DCIM/c.jpg", b"c").seq, 3);
}

// ----- final-move states and the audit -------------------------------------

#[test]
fn final_move_states_follow_what_the_phone_reports() {
    let w = World::new("fm-states");
    let store = stored_yesterday(&w);
    let state = |store: &Store| store.records(&phone(), &hash()).unwrap().remove(0).fm;
    assert_eq!(state(&store), FmState::None);
    let _proof = verify(&store, &hash(), 1).unwrap();
    assert_eq!(state(&store), FmState::Reverified);

    let expires = T0 + 30 * 24 * HOUR;
    let key = key_of(NAME);
    assert_eq!(
        store
            .mark_sole_copy(&phone(), key, &hash(), Some(expires))
            .unwrap(),
        1
    );
    assert_eq!(state(&store), FmState::SoleCopy);
    // A later confirmation (the check before the trash lets go) keeps it.
    let _proof = verify(&store, &hash(), 1).unwrap();
    assert_eq!(state(&store), FmState::SoleCopy);
    // Wrong key, wrong content: nothing is marked.
    assert_eq!(
        store
            .mark_sole_copy(&phone(), b"other", &hash(), None)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .mark_in_place(&phone(), key, &ContentHash::of_bytes(b"x"))
            .unwrap(),
        0
    );
    // The phone restored the photo from its trash.
    assert_eq!(store.mark_in_place(&phone(), key, &hash()).unwrap(), 1);
    assert_eq!(state(&store), FmState::None);

    // Only a known problem can be acknowledged.
    let file_id = store.records(&phone(), &hash()).unwrap()[0].file_id;
    assert!(!store
        .acknowledge_removed(file_id, "nothing is wrong")
        .unwrap());
    // The PC user deletes the file in Explorer.
    std::fs::remove_file(w.path(STORED)).unwrap();
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::NotVerified(NotVerifiedReason::Missing))
    ));
    assert!(store.final_move_block().unwrap().is_some());
    assert_eq!(store.copy_counts(&phone()).unwrap().no_copy, 1);
    assert!(store
        .acknowledge_removed(file_id, "deleted on purpose")
        .unwrap());
    store.clear_final_move_block("acknowledged").unwrap();
    // From now on the answer is "removed by the user": an answer, not an alarm.
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::RemovedByUser)
    ));
    assert!(store.final_move_block().unwrap().is_none());
    assert!(matches!(
        store.audit(&phone(), key, &hash(), 60_000).unwrap(),
        AuditStatus::Removed(_)
    ));
    assert_eq!(store.copy_counts(&phone()).unwrap(), Default::default());
    // The phone cannot talk the mark away.
    assert_eq!(store.mark_in_place(&phone(), key, &hash()).unwrap(), 0);
    assert_eq!(state(&store), FmState::UserRemoved);
}

#[test]
fn the_audit_looks_at_the_record_and_the_directory_entry_only() {
    let w = World::new("audit");
    let store = w.open();
    put(&store, NAME, &bytes());
    let key = key_of(NAME);

    w.fs.reset_counters();
    match store.audit(&phone(), key, &hash(), 60_000).unwrap() {
        AuditStatus::Present(record) => {
            assert_eq!(record.rel_path, STORED);
            assert_eq!(record.source_name, NAME);
            assert_eq!((record.commit_seq, record.session_seq), (1, 1));
            assert_eq!(record.state, FileState::Committed);
        }
        other => panic!("expected Present, got {other:?}"),
    }
    assert_eq!(w.fs.count(Op::ReadVerify), 0, "an audit reads no file");
    for (key, size) in [(b"other-key".as_slice(), 60_000), (key, 60_001)] {
        assert_eq!(
            store.audit(&phone(), key, &hash(), size).unwrap(),
            AuditStatus::NoRecord
        );
    }
    assert!(store.final_move_block().unwrap().is_none());

    // The file is cut short behind the engine's back: the audit sees it
    // without reading, tells the ledger, and final move is blocked.
    std::fs::write(w.path(STORED), b"cut short").unwrap();
    assert!(matches!(
        store.audit(&phone(), key, &hash(), 60_000).unwrap(),
        AuditStatus::Damaged(_)
    ));
    assert_eq!(store.stats().unwrap().files_changed, 1);
    assert!(store.final_move_block().unwrap().is_some());
}

// ----- batched ledger commits ----------------------------------------------

fn put_batched(store: &Store, name: &str, bytes: &[u8]) -> kiwi_store::CommitReceipt {
    let mut incoming = store.begin_file(request(&phone(), name, bytes)).unwrap();
    incoming.write(bytes).unwrap();
    incoming.finish_batched(None).unwrap()
}

#[test]
fn batched_records_are_flushed_together() {
    let w = World::new("batch");
    let store = w.open();
    let files: Vec<(String, Vec<u8>)> = (0..5)
        .map(|i| (format!("DCIM/{i}.jpg"), data(40 + i, 3_000)))
        .collect();
    for (i, (name, bytes)) in files.iter().enumerate() {
        let receipt = put_batched(&store, name, bytes);
        assert!(
            !receipt.durable,
            "the receipt says the record is not flushed"
        );
        assert_eq!(receipt.seq, i as u64 + 1);
        assert!(receipt.dir_synced && receipt.verified_unbuffered || !cfg!(windows));
        assert_eq!(store.pending_batch(), i as u64 + 1);
    }
    // The files themselves went through the whole pipeline.
    for (_, bytes) in &files {
        assert!(store
            .is_safely_stored(&phone(), &ContentHash::of_bytes(bytes))
            .unwrap()
            .is_verified());
    }
    store.flush_batch().unwrap();
    assert_eq!(store.pending_batch(), 0);
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "ledger_flushed" && e.detail.as_deref() == Some("5 batched records")));
    // An ordinary commit is flushed by itself.
    assert!(put(&store, "DCIM/plain.jpg", b"plain").durable);
    assert_eq!(store.pending_batch(), 0);
    // A clean shutdown flushes what is pending.
    put_batched(&store, "DCIM/last.jpg", b"last");
    drop(store);
    let store = w.open();
    assert_eq!(store.stats().unwrap().files_committed, 7);
}

#[test]
fn a_power_failure_before_the_flush_costs_a_resend_never_safety() {
    let w = World::new("batch-crash");
    let (b, c) = (data(51, 7_000), data(52, 7_500));
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    let before = LedgerSnapshot::take(&w);
    {
        let store = w.open();
        // Two copies in a batch. The phone has not been told they are stored:
        // the receipts wait for the flush, and the flush never comes.
        assert!(!put_batched(&store, "DCIM/b.jpg", &b).durable);
        assert!(!put_batched(&store, "DCIM/c.jpg", &c).durable);
    }
    // The power fails. What the ledger had not flushed is gone; so is the
    // destination's note of it. The files themselves had been flushed.
    before.restore(&w, true);
    w.clock.advance_hours(25);

    let store = w.open();
    assert!(store.open_notes().is_empty(), "{:?}", store.open_notes());
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.stats().unwrap().files_committed, 1);
    assert_eq!(store.recovery_report().unwrap().orphan_temps_removed, 0);
    assert_eq!(
        w.files(),
        vec![STORED, "Pixel 8/DCIM/b.jpg", "Pixel 8/DCIM/c.jpg"]
    );
    // Nobody is told that the two files are safe ...
    for bytes in [&b, &c] {
        let hash = ContentHash::of_bytes(bytes);
        assert!(matches!(
            store.is_safely_stored(&phone(), &hash).unwrap(),
            StoredStatus::NotVerified(NotVerifiedReason::NoRecord)
        ));
        assert!(matches!(
            verify(&store, &hash, 1),
            Err(DeletionDenied::NoRecord)
        ));
    }
    // ... so the phone sends them again, and that is all it costs: the files
    // are found on the disk, read, and recorded. No second copy.
    let again = put(&store, "DCIM/b.jpg", &b);
    assert_eq!(again.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(again.seq, 2);
    assert_eq!(w.files().len(), 3);
    // What was flushed before the failure is untouched.
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn nothing_that_confirms_a_deletion_rests_on_an_unflushed_record() {
    let w = World::new("batch-verify");
    let store = w.open();
    put_batched(&store, NAME, &bytes());
    assert_eq!(store.pending_batch(), 1);
    w.clock.advance_hours(25);
    // Asking flushes the ledger before anything is looked at, and the answer
    // is still no: the file belongs to the session that is running.
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::TooRecent { .. })
    ));
    assert_eq!(store.pending_batch(), 0);

    // A new session of the phone flushes too.
    put_batched(&store, "DCIM/b.jpg", b"b");
    assert_eq!(store.pending_batch(), 1);
    store.new_session(&phone(), None).unwrap();
    assert_eq!(store.pending_batch(), 0);

    // The confirmation itself is one flushed transaction, never part of a batch.
    put_batched(&store, "DCIM/c.jpg", b"c");
    let proof = verify(&store, &hash(), 1).unwrap();
    assert_eq!(store.pending_batch(), 0);
    let events = store.events_after(0, 10_000).unwrap();
    let flushed = events
        .iter()
        .rev()
        .find(|e| e.kind == "ledger_flushed")
        .expect("a flush");
    assert!(flushed.seq < proof.verified_seq);
}
