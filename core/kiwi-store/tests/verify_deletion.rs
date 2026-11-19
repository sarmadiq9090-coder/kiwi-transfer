//! `verify_for_deletion`: the only answer that lets the phone delete a file.

mod common;

use std::io::ErrorKind;

use common::*;
use kiwi_store::destination::{BusKind, DriveKind};
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{
    BlockKind, ContentHash, CopyOnlyReason, DeletionDenied, NotVerifiedReason, Seams, Store,
    StoreConfig, VerifyRequest, VolumeInfo,
};

const NAME: &str = "DCIM/a.jpg";
const STORED: &str = "Pixel 8/DCIM/a.jpg";

fn bytes() -> Vec<u8> {
    data(5, 80_000)
}

fn hash() -> ContentHash {
    ContentHash::of_bytes(&bytes())
}

/// Session 1 stores the file at T0; the returned store is session 2, 25 hours later.
fn stored_yesterday(w: &World) -> Store {
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(25);
    w.open()
}

fn denied(store: &Store, min_sessions: u32) -> DeletionDenied {
    match verify(store, &hash(), min_sessions) {
        Ok(proof) => panic!("expected a denial, got {proof:?}"),
        Err(e) => e,
    }
}

#[test]
fn confirmed_only_in_a_later_session_and_after_24_hours() {
    let w = World::new("happy");
    let store = w.open();
    let receipt = put(&store, NAME, &bytes());

    // Same session, right away.
    match denied(&store, 1) {
        DeletionDenied::TooRecent {
            committed_session: 1,
            current_session: 1,
            sessions_required: 1,
            age_secs: 0,
            ..
        } => {}
        other => panic!("unexpected: {other:?}"),
    }
    // Same session, two days later: time alone is not enough.
    w.clock.advance_hours(48);
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::TooRecent {
            committed_session: 1,
            current_session: 1,
            ..
        }
    ));
    drop(store);

    // A later session, but only one hour after the commit: a session alone
    // is not enough either.
    w.clock.set(T0 + HOUR);
    let store = w.open();
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::TooRecent {
            committed_session: 1,
            current_session: 2,
            age_secs: 3_600,
            age_secs_required: 86_400,
            ..
        }
    ));
    drop(store);

    // A later session and more than 24 hours: confirmed.
    w.clock.set(T0 + 49 * HOUR);
    let store = w.open();
    let proof = verify(&store, &hash(), 1).expect("all conditions hold");
    assert_eq!(proof.file.rel_path, STORED);
    assert_eq!(proof.file.file_id, receipt.file_id);
    assert_eq!(proof.file.hash, hash());
    assert_eq!(proof.file.committed_session, 1);
    assert!(proof.file.read_unbuffered);
    assert_eq!(proof.sessions_elapsed, store.run_number() - 1);
    assert_eq!(proof.age_secs, 49 * 3600);
    // The confirmation itself is on record.
    let events = store.events_after(0, 10_000).unwrap();
    let event = events
        .iter()
        .find(|e| e.kind == "deletion_verified")
        .expect("logged");
    assert_eq!(event.seq, proof.verified_seq);
    assert_eq!(event.file_id, Some(receipt.file_id));
    // Asking again is fine and re-reads the file again.
    w.fs.reset_counters();
    let again = verify(&store, &hash(), 1).unwrap();
    assert!(again.verified_seq > proof.verified_seq);
    assert_eq!(w.fs.count(Op::ReadVerify), 1);
}

#[test]
fn twenty_four_hours_exactly() {
    let w = World::new("boundary");
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    w.clock.set(T0 + 24 * HOUR - 1);
    {
        let store = w.open();
        match denied(&store, 1) {
            DeletionDenied::TooRecent {
                age_secs,
                age_secs_required,
                committed_session: 1,
                current_session: 2,
                ..
            } => {
                assert_eq!((age_secs, age_secs_required), (86_399, 86_400));
            }
            other => panic!("unexpected: {other:?}"),
        }
        // The clock moves on within the session: now it is enough.
        w.clock.set(T0 + 24 * HOUR);
        assert_eq!(verify(&store, &hash(), 1).unwrap().age_secs, 86_400);
    }
}

#[test]
fn the_requested_number_of_sessions_must_have_passed() {
    let w = World::new("sessions");
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(100);
    for session in 2..=4u64 {
        let store = w.open();
        assert_eq!(store.run_number(), session);
        let elapsed = session - 1;
        match verify(&store, &hash(), 3) {
            Ok(proof) => {
                assert!(elapsed >= 3, "confirmed after only {elapsed} sessions");
                assert_eq!(proof.sessions_elapsed, elapsed);
            }
            Err(DeletionDenied::TooRecent {
                sessions_required: 3,
                committed_session: 1,
                current_session,
                ..
            }) => {
                assert!(elapsed < 3);
                assert_eq!(current_session, session);
            }
            Err(other) => panic!("unexpected: {other:?}"),
        }
        // Zero is not "no waiting": at least one session is always required.
        assert!(verify(&store, &hash(), 0).is_ok());
    }
    // And zero does not help in the session of the commit itself.
    let store = w.open();
    let fresh = data(6, 1_000);
    put(&store, "fresh.jpg", &fresh);
    w.clock.advance_hours(100);
    assert!(matches!(
        verify(&store, &ContentHash::of_bytes(&fresh), 0),
        Err(DeletionDenied::TooRecent {
            sessions_required: 1,
            ..
        })
    ));
}

#[test]
fn the_configured_age_can_be_raised_but_never_lowered() {
    let mut w = World::new("configured-age");
    w.configure = |cfg: &mut StoreConfig| cfg.min_wall_age_secs = 10;
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(23);
    {
        let store = w.open();
        assert!(matches!(
            denied(&store, 1),
            DeletionDenied::TooRecent {
                age_secs_required: 86_400,
                ..
            }
        ));
    }
    w.configure = |cfg: &mut StoreConfig| cfg.min_wall_age_secs = 72 * 3600;
    w.clock.advance_hours(26);
    {
        let store = w.open();
        assert!(matches!(
            denied(&store, 1),
            DeletionDenied::TooRecent {
                age_secs_required: 259_200,
                ..
            }
        ));
        w.clock.advance_hours(24);
        assert!(verify(&store, &hash(), 1).is_ok());
    }
}

#[test]
fn a_clock_that_went_backwards_denies() {
    let w = World::new("clock-back");
    let store = stored_yesterday(&w);
    assert!(verify(&store, &hash(), 1).is_ok());
    // The clock now reads earlier than events already in the ledger.
    w.clock.set(T0 + 20 * HOUR);
    match denied(&store, 1) {
        DeletionDenied::ClockWentBackwards {
            now_unix_ms,
            last_seen_unix_ms,
        } => {
            assert_eq!(now_unix_ms, T0 + 20 * HOUR);
            assert_eq!(last_seen_unix_ms, T0 + 25 * HOUR);
        }
        other => panic!("unexpected: {other:?}"),
    }
    // Far in the past is no better.
    w.clock.set(0);
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::ClockWentBackwards { .. }
    ));
    // Back to a sane time: fine again.
    w.clock.set(T0 + 26 * HOUR);
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn a_clock_that_was_ahead_needs_an_explicit_acknowledgement() {
    let w = World::new("clock-ahead");
    // The clock is ten years ahead while a file is stored...
    w.clock.set(T0 + 10 * 365 * 24 * HOUR);
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    // ...and is then corrected.
    w.clock.set(T0);
    let store = w.open();
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::ClockWentBackwards { .. }
    ));
    // Waiting does not help: the ledger remembers a time years ahead.
    w.clock.advance_hours(24 * 30);
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::ClockWentBackwards { .. }
    ));

    // A person confirms that the clock is right now.
    let restamped = store
        .acknowledge_clock_change("the user confirmed today's date")
        .unwrap();
    assert_eq!(restamped, 1);
    // The file's age starts over: this session, this moment.
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::TooRecent {
            committed_session: 2,
            current_session: 2,
            age_secs: 0,
            ..
        }
    ));
    // The re-stamped record is intact (its checksum was renewed with it).
    assert!(store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    drop(store);

    w.clock.advance_hours(25);
    let store = w.open();
    let proof = verify(&store, &hash(), 1).unwrap();
    assert_eq!(proof.file.committed_session, 2);
    assert_eq!(proof.age_secs, 25 * 3600);
    // With nothing to correct, the call changes nothing.
    assert_eq!(store.acknowledge_clock_change("again").unwrap(), 0);
    assert!(verify(&store, &hash(), 1).is_ok());
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "clock_acknowledged"));
}

#[test]
fn a_file_that_resolves_to_another_place_is_not_confirmed() {
    let w = World::new("resolves-elsewhere");
    let store = stored_yesterday(&w);
    // The content at the recorded path is right, but the operating system
    // says the path really leads somewhere else (a redirect the directory
    // check did not see).
    std::fs::write(w.outside.join("a.jpg"), bytes()).unwrap();
    w.fs.inject(
        When::Every(Op::Resolve),
        Action::ResolveTo(w.outside.join("a.jpg")),
    );
    match denied(&store, 1) {
        DeletionDenied::NotVerified(NotVerifiedReason::ReparsePoint(at)) => {
            assert_eq!(at, w.outside.join("a.jpg"));
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(!store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    assert!(store.final_move_block().unwrap().is_some());
    w.fs.clear_rules();
    store.clear_final_move_block("test").unwrap();
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn copy_only_destinations_never_confirm() {
    let cases: Vec<(&str, VolumeInfo, CopyOnlyReason)> = vec![
        (
            "usb",
            VolumeInfo {
                bus: Some(BusKind::Usb),
                ..fixed_ntfs()
            },
            CopyOnlyReason::Removable,
        ),
        (
            "sd",
            VolumeInfo {
                drive: DriveKind::Removable,
                ..fixed_ntfs()
            },
            CopyOnlyReason::Removable,
        ),
        (
            "share",
            VolumeInfo {
                drive: DriveKind::Remote,
                ..fixed_ntfs()
            },
            CopyOnlyReason::Network,
        ),
        (
            "exfat",
            VolumeInfo {
                filesystem: "exFAT".into(),
                ..fixed_ntfs()
            },
            CopyOnlyReason::Filesystem("exFAT".into()),
        ),
        (
            "hotplug",
            VolumeInfo {
                hot_plug: Some(true),
                ..fixed_ntfs()
            },
            CopyOnlyReason::HotPluggable,
        ),
        (
            "unknown",
            VolumeInfo {
                bus: None,
                ..fixed_ntfs()
            },
            CopyOnlyReason::DeviceUnidentified,
        ),
        (
            "vhd",
            VolumeInfo {
                bus: Some(BusKind::FileBackedVirtual),
                ..fixed_ntfs()
            },
            CopyOnlyReason::VirtualDisk,
        ),
        (
            "readonly",
            VolumeInfo {
                read_only: true,
                ..fixed_ntfs()
            },
            CopyOnlyReason::ReadOnly,
        ),
    ];
    for (label, volume, expected) in cases {
        let mut w = World::new(&format!("copy-only-{label}"));
        w.volume = Some(volume);
        let store = stored_yesterday(&w);
        assert!(!store.destination().supports_final_move(), "{label}");
        // The file is stored and verified like anywhere else...
        assert!(
            store
                .is_safely_stored(&phone(), &hash())
                .unwrap()
                .is_verified(),
            "{label}"
        );
        // ...but deleting the phone's copy is never confirmed.
        match denied(&store, 1) {
            DeletionDenied::Unsupported(reason) => assert_eq!(reason, expected, "{label}"),
            other => panic!("{label}: unexpected {other:?}"),
        }
    }
}

#[test]
fn a_volume_without_identity_denies() {
    let mut w = World::new("no-serial");
    w.volume = Some(VolumeInfo {
        serial: None,
        ..fixed_ntfs()
    });
    let store = stored_yesterday(&w);
    assert!(matches!(denied(&store, 1), DeletionDenied::VolumeChanged));
}

#[test]
fn the_block_denies_until_it_is_cleared_explicitly() {
    let w = World::new("blocked");
    let store = stored_yesterday(&w);
    let block = store.block_final_move("the user paused deletions").unwrap();
    assert_eq!(block.kind, BlockKind::Manual);
    match denied(&store, 1) {
        DeletionDenied::Blocked(info) => {
            assert_eq!(info.kind, BlockKind::Manual);
            assert_eq!(info.reason, "the user paused deletions");
            assert_eq!(info.set_session, 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
    drop(store);
    // A restart does not clear it.
    let store = w.open();
    assert!(matches!(denied(&store, 1), DeletionDenied::Blocked(_)));
    assert!(store.final_move_block().unwrap().is_some());
    // Only this does.
    let cleared = store
        .clear_final_move_block("reviewed by the user")
        .unwrap()
        .unwrap();
    assert_eq!(cleared.reason, "the user paused deletions");
    assert!(store.final_move_block().unwrap().is_none());
    assert!(store.clear_final_move_block("again").unwrap().is_none());
    assert!(verify(&store, &hash(), 1).is_ok());
    let kinds: Vec<String> = store
        .events_after(0, 10_000)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.contains(&"block_set".to_owned()) && kinds.contains(&"block_cleared".to_owned()));
}

#[test]
fn unknown_content_has_no_record() {
    let w = World::new("no-record");
    let store = stored_yesterday(&w);
    let other = ContentHash::of_bytes(b"never sent");
    assert!(matches!(
        verify(&store, &other, 1),
        Err(DeletionDenied::NoRecord)
    ));
}

#[test]
fn a_changed_file_denies_and_blocks() {
    let w = World::new("changed");
    let store = stored_yesterday(&w);
    // One bit differs; size and modification time are as before.
    corrupt_silently(&w.path(STORED));
    match denied(&store, 1) {
        DeletionDenied::NotVerified(NotVerifiedReason::Changed(how)) => {
            assert!(how.contains("hashes to"), "{how}")
        }
        other => panic!("unexpected: {other:?}"),
    }
    let block = store
        .final_move_block()
        .unwrap()
        .expect("a changed file blocks final move");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert!(block.reason.contains(STORED), "{}", block.reason);
    // From now on the block answers first.
    assert!(matches!(denied(&store, 1), DeletionDenied::Blocked(_)));
    // Clearing the block does not make the damaged file acceptable.
    store.clear_final_move_block("test").unwrap();
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Changed(_))
    ));
    assert!(
        store.final_move_block().unwrap().is_none(),
        "a problem already known does not block again"
    );
}

#[test]
fn a_missing_or_resized_file_denies() {
    let w = World::new("missing");
    let store = stored_yesterday(&w);
    let mut longer = bytes();
    longer.push(0);
    std::fs::write(w.path(STORED), &longer).unwrap();
    match denied(&store, 1) {
        DeletionDenied::NotVerified(NotVerifiedReason::Changed(how)) => {
            assert!(how.contains("size"), "{how}")
        }
        other => panic!("unexpected: {other:?}"),
    }
    store.clear_final_move_block("test").unwrap();
    std::fs::remove_file(w.path(STORED)).unwrap();
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Missing)
    ));
    assert_eq!(
        store.final_move_block().unwrap().unwrap().kind,
        BlockKind::IntegrityProblems
    );
    store.clear_final_move_block("test").unwrap();
    // A directory where the file was.
    std::fs::create_dir(w.path(STORED)).unwrap();
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Changed(_))
    ));
    store.clear_final_move_block("test").unwrap();
    // The original content comes back: confirmed again.
    std::fs::remove_dir(w.path(STORED)).unwrap();
    std::fs::write(w.path(STORED), bytes()).unwrap();
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn a_read_that_fails_or_is_only_cached_denies() {
    let w = World::new("read-problems");
    let store = stored_yesterday(&w);

    w.fs.inject(
        When::Every(Op::ReadVerify),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Unreadable(_))
    ));
    w.fs.clear_rules();

    // The content matches, but the read went through the cache.
    w.fs.inject(When::Every(Op::ReadVerify), Action::ReportBuffered);
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::BufferedReadOnly)
    ));
    w.fs.clear_rules();

    w.fs.inject(
        When::Every(Op::Stat),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Unreadable(_))
    ));
    w.fs.clear_rules();

    // None of these is evidence of damage, so none of them blocks.
    assert!(store.final_move_block().unwrap().is_none());
    assert!(verify(&store, &hash(), 1).is_ok());

    // A device error is something else: the disk is failing, and nothing is
    // confirmed for any phone until a person has looked.
    w.fs.inject(When::Every(Op::ReadVerify), Action::Fail(ErrorKind::Other));
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::NotVerified(NotVerifiedReason::Unreadable(_))
    ));
    w.fs.clear_rules();
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::DiskFailing);
    assert!(matches!(denied(&store, 1), DeletionDenied::Blocked(_)));
}

#[test]
fn the_ledger_is_never_taken_at_its_word() {
    let w = World::new("ledger-says-so");
    let store = stored_yesterday(&w);
    let fresh = data(9, 4_000);
    let fresh_hash = ContentHash::of_bytes(&fresh);
    put(&store, "fresh.jpg", &fresh);
    drop(store);
    let store = w.open();
    assert!(matches!(
        verify(&store, &fresh_hash, 1),
        Err(DeletionDenied::TooRecent { .. })
    ));

    // While the store is running, the ledger is edited so that it describes
    // the new file as old: an earlier session, an earlier sequence number, a
    // commit time long ago. Believing it would confirm a deletion too early.
    {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        let changed = conn
            .execute(
                "UPDATE files SET committed_session = 1, committed_seq = 1, committed_unix_ms = 0 WHERE source_name = 'fresh.jpg'",
                [],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }
    match verify(&store, &fresh_hash, 1) {
        Err(DeletionDenied::Ledger(e)) => {
            assert!(e.is_corruption(), "{e}");
            assert!(e.to_string().contains("checksum"), "{e}");
        }
        other => panic!("a tampered record must not be believed: {other:?}"),
    }
    assert!(store.is_safely_stored(&phone(), &fresh_hash).is_err());
    assert!(store.find_duplicate(&phone(), &fresh_hash).is_err());
    // A record that was not touched still works.
    assert!(verify(&store, &hash(), 1).is_ok());
    drop(store);

    // The next start notices on its own and refuses to open the ledger.
    match w.try_open() {
        Err(kiwi_store::StoreError::Ledger(e)) => assert!(e.is_corruption(), "{e}"),
        other => panic!("expected the open to fail, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn a_confirmation_is_for_one_record_not_for_a_hash() {
    let w = World::new("two-copies");
    let store = stored_yesterday(&w);
    // The same content arrives again under another name, in this session.
    let second = put(&store, "DCIM/copy.jpg", &bytes());
    assert_eq!(second.session, 2);
    assert_eq!(second.seq, 2);
    let records = store.records(&phone(), &hash()).unwrap();
    assert_eq!(records.len(), 2);
    let (old, new) = (&records[0], &records[1]);
    assert_eq!((old.rel_path.as_str(), old.commit_seq), (STORED, 1));
    assert_eq!(new.rel_path, "Pixel 8/DCIM/copy.jpg");

    // The phone names the record on its receipt. The old one qualifies ...
    let proof = store
        .verify_for_deletion(&phone(), &request_of(old))
        .unwrap();
    assert_eq!(proof.file.rel_path, STORED);
    // ... and the new one is too recent, although an older file with the very
    // same content exists: that file is another record's business.
    assert!(matches!(
        store.verify_for_deletion(&phone(), &request_of(new)),
        Err(DeletionDenied::TooRecent {
            committed_session: 2,
            ..
        })
    ));
    // A request that mixes the two records up names no record at all.
    for wrong in [
        VerifyRequest {
            commit_seq: new.commit_seq,
            ..request_of(old)
        },
        VerifyRequest {
            key: &new.key,
            ..request_of(old)
        },
        VerifyRequest {
            size: old.size + 1,
            ..request_of(old)
        },
        VerifyRequest {
            hash: ContentHash::of_bytes(b"something else"),
            ..request_of(old)
        },
    ] {
        assert!(matches!(
            store.verify_for_deletion(&phone(), &wrong),
            Err(DeletionDenied::NoRecord)
        ));
    }

    // If the old file is lost, the old record is denied as missing; the new
    // record does not stand in for it.
    std::fs::remove_file(w.path(STORED)).unwrap();
    assert!(matches!(
        store.verify_for_deletion(&phone(), &request_of(old)),
        Err(DeletionDenied::NotVerified(NotVerifiedReason::Missing))
    ));
    drop(store);
    w.clock.advance_hours(30);
    let store = w.open();
    // The missing file was noticed and blocked final move; after a review the
    // surviving record qualifies on its own age.
    assert!(matches!(
        store.verify_for_deletion(&phone(), &request_of(new)),
        Err(DeletionDenied::Blocked(_))
    ));
    store
        .clear_final_move_block("one copy was deleted on purpose")
        .unwrap();
    let proof = store
        .verify_for_deletion(&phone(), &request_of(new))
        .unwrap();
    assert_eq!(proof.file.rel_path, "Pixel 8/DCIM/copy.jpg");
    assert_eq!(proof.file.committed_session, 2);
    assert!(matches!(
        store.verify_for_deletion(&phone(), &request_of(old)),
        Err(DeletionDenied::NotVerified(NotVerifiedReason::Missing))
    ));
}

#[test]
fn a_problem_on_one_file_blocks_confirmation_of_every_other() {
    let w = World::new("copy-damaged");
    {
        let store = w.open();
        put(&store, "DCIM/a.jpg", &bytes());
        put(&store, "Other/b.jpg", &bytes());
    }
    w.clock.advance_hours(25);
    let store = w.open();
    let records = store.records(&phone(), &hash()).unwrap();
    let (a, b) = (&records[0], &records[1]);
    corrupt_silently(&w.path("Pixel 8/DCIM/a.jpg"));
    // The first file is damaged: denied, and the damage is on record.
    assert!(matches!(
        store.verify_for_deletion(&phone(), &request_of(a)),
        Err(DeletionDenied::NotVerified(NotVerifiedReason::Changed(_)))
    ));
    // The second is intact and old enough, but damage was just discovered:
    // no confirmation now, for anything.
    match store.verify_for_deletion(&phone(), &request_of(b)) {
        Err(DeletionDenied::Blocked(info)) => assert!(
            info.reason.contains("Pixel 8/DCIM/a.jpg"),
            "{}",
            info.reason
        ),
        other => panic!("unexpected: {other:?}"),
    }
    store.clear_final_move_block("reviewed").unwrap();
    assert_eq!(
        store
            .verify_for_deletion(&phone(), &request_of(b))
            .unwrap()
            .file
            .rel_path,
        "Pixel 8/Other/b.jpg"
    );
}

#[test]
fn on_the_real_volume_of_this_machine() {
    // No forced volume: the destination is classified by the platform, and
    // verify_for_deletion examines it again on every call.
    let mut w = World::new("real-volume");
    w.volume = None;
    let store = stored_yesterday(&w);
    let dest = store.destination();
    println!(
        "test volume: {:?} -> {:?}",
        dest.volume(),
        dest.final_move_support()
    );
    match verify(&store, &hash(), 1) {
        Ok(proof) => {
            assert!(dest.supports_final_move());
            assert!(proof.file.read_unbuffered);
        }
        Err(DeletionDenied::Unsupported(reason)) => {
            assert!(!dest.supports_final_move());
            println!("this machine's test volume is copy-only: {reason}");
        }
        Err(other) => panic!("unexpected: {other:?}"),
    }
    if cfg!(not(windows)) {
        assert!(
            !dest.supports_final_move(),
            "only Windows volumes are ever classified as safe for final move"
        );
    }
}

#[test]
fn production_open_has_no_seams() {
    // The plain constructors work without the test-only parameters.
    let w = World::new("plain-open");
    let mut cfg = StoreConfig::new(&w.root, &w.ledger_dir);
    cfg.safety_margin_bytes = 0;
    let store = Store::open(cfg.clone()).unwrap();
    store
        .register_device(&phone(), "Pixel 8", Default::default())
        .unwrap();
    put(&store, NAME, &bytes());
    assert!(matches!(
        denied(&store, 1),
        DeletionDenied::TooRecent { .. } | DeletionDenied::Unsupported(_)
    ));
    drop(store);
    let store = Store::open_with_seams(cfg, Seams::default()).unwrap();
    assert_eq!(store.run_number(), 2);
}
