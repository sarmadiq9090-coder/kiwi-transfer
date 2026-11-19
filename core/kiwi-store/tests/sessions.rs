//! Sessions are explicit and belong to one phone: only `new_session` for
//! that phone makes "an earlier session" of what it stored.

mod common;

use common::*;
use kiwi_store::{ContentHash, DeletionDenied, DeviceLimits, StoreError};

const NAME: &str = "DCIM/a.jpg";

fn bytes() -> Vec<u8> {
    data(21, 30_000)
}

fn hash() -> ContentHash {
    ContentHash::of_bytes(&bytes())
}

fn too_recent(denied: DeletionDenied) -> (u64, u64, u64, i64) {
    match denied {
        DeletionDenied::TooRecent {
            committed_session,
            current_session,
            sessions_required,
            age_secs,
            ..
        } => (
            committed_session,
            current_session,
            sessions_required,
            age_secs,
        ),
        other => panic!("expected TooRecent, got {other:?}"),
    }
}

#[test]
fn starting_the_program_is_not_a_session_of_the_phone() {
    let w = World::new("idle-open");
    {
        let store = w.open(); // the phone connects: its session 1
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(25);
    // The tray program is restarted five times. The phone never connects.
    // (Before sessions were explicit, each of these opens counted.)
    let mut runs = Vec::new();
    for _ in 0..5 {
        let store = w.open_idle();
        runs.push(store.run_number());
        assert_eq!(
            too_recent(verify(&store, &hash(), 1).unwrap_err()),
            (1, 1, 1, 25 * 3600)
        );
        assert_eq!(store.device(&phone()).unwrap().unwrap().session_seq, 1);
    }
    assert!(runs.windows(2).all(|p| p[1] == p[0] + 1), "{runs:?}");

    // The phone connects.
    let store = w.open_idle();
    assert_eq!(store.new_session(&phone(), None).unwrap(), 2);
    let proof = verify(&store, &hash(), 1).unwrap();
    assert_eq!(proof.sessions_elapsed, 1);
    assert_eq!(proof.file.committed_session, 1);
}

#[test]
fn another_phone_connecting_is_not_a_session_of_this_phone() {
    let w = World::new("other-phone");
    let store = w.open();
    store
        .register_device(&tablet(), "Tab S9", DeviceLimits::default())
        .unwrap();
    put(&store, NAME, &bytes());
    w.clock.advance_hours(25);
    for expected in 1..=3 {
        assert_eq!(store.new_session(&tablet(), None).unwrap(), expected);
    }
    assert_eq!(
        too_recent(verify(&store, &hash(), 1).unwrap_err()),
        (1, 1, 1, 25 * 3600)
    );
    assert_eq!(store.device(&phone()).unwrap().unwrap().session_seq, 1);
    assert_eq!(store.device(&tablet()).unwrap().unwrap().session_seq, 3);

    assert_eq!(store.new_session(&phone(), None).unwrap(), 2);
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn a_long_running_program_needs_no_restart_and_counts_the_sessions_asked_for() {
    let w = World::new("long-running");
    let store = w.open();
    put(&store, NAME, &bytes());
    w.clock.advance_hours(25);
    // The same session, a day later: time alone is not enough.
    assert_eq!(too_recent(verify(&store, &hash(), 1).unwrap_err()).1, 1);

    assert_eq!(store.new_session(&phone(), None).unwrap(), 2);
    assert_eq!(verify(&store, &hash(), 1).unwrap().sessions_elapsed, 1);
    // Three sessions were asked for; one has begun since the commit.
    assert_eq!(
        too_recent(verify(&store, &hash(), 3).unwrap_err()),
        (1, 2, 3, 25 * 3600)
    );
    store.new_session(&phone(), None).unwrap();
    assert!(verify(&store, &hash(), 3).is_err());
    store.new_session(&phone(), None).unwrap();
    assert_eq!(verify(&store, &hash(), 3).unwrap().sessions_elapsed, 3);
    // Zero means one: never the session that recorded the file.
    assert!(verify(&store, &hash(), 0).is_ok());
}

#[test]
fn the_number_agreed_with_the_phone_is_used_and_survives_restarts() {
    let w = World::new("agreed-number");
    let store = w.open();
    assert_eq!(store.new_session(&phone(), Some(10)).unwrap(), 10);
    for stale in [10, 4, 0] {
        match store.new_session(&phone(), Some(stale)) {
            Err(StoreError::SessionNotNewer { current, requested }) => {
                assert_eq!((current, requested), (10, stale))
            }
            other => panic!("expected SessionNotNewer, got {other:?}"),
        }
    }
    assert!(matches!(
        store.new_session(&phone(), Some(1 << 53)),
        Err(StoreError::SessionNotNewer { .. })
    ));
    assert_eq!(store.new_session(&phone(), None).unwrap(), 11);
    assert_eq!(
        store.new_session(&phone(), Some((1 << 53) - 1)).unwrap(),
        (1 << 53) - 1
    );
    assert!(matches!(
        store.new_session(&phone(), None),
        Err(StoreError::SessionNotNewer { .. })
    ));
    assert!(matches!(
        store.new_session(&tablet(), None),
        Err(StoreError::UnknownDevice(_))
    ));
    // Every session start is in the event log.
    let starts = store
        .events_after(0, 1_000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "device_session_start")
        .count();
    assert_eq!(starts, 4);
    drop(store);

    let store = w.open_idle();
    assert_eq!(
        store.device(&phone()).unwrap().unwrap().session_seq,
        (1 << 53) - 1,
        "the counter is in the ledger"
    );
}

#[test]
fn a_transfer_that_straddles_a_new_session_belongs_to_the_new_one() {
    let w = World::new("straddle");
    let store = w.open();
    let bytes = bytes();
    let mut incoming = store.begin_file(request(&phone(), NAME, &bytes)).unwrap();
    incoming.write(&bytes[..10_000]).unwrap();
    assert_eq!(store.new_session(&phone(), None).unwrap(), 2);
    incoming.write(&bytes[10_000..]).unwrap();
    let receipt = incoming.finish(None).unwrap();
    assert_eq!(receipt.session, 2);

    w.clock.advance_hours(25);
    assert_eq!(
        too_recent(verify(&store, &hash(), 1).unwrap_err()),
        (2, 2, 1, 25 * 3600)
    );
    store.new_session(&phone(), None).unwrap();
    assert!(verify(&store, &hash(), 1).is_ok());
}

#[test]
fn hammering_new_session_does_not_shorten_the_24_hours() {
    let w = World::new("hammer");
    let store = w.open();
    put(&store, NAME, &bytes());
    for _ in 0..50 {
        store.new_session(&phone(), None).unwrap();
    }
    assert_eq!(
        too_recent(verify(&store, &hash(), 1).unwrap_err()),
        (1, 51, 1, 0)
    );
    w.clock.advance_hours(23);
    assert_eq!(
        too_recent(verify(&store, &hash(), 1).unwrap_err()).3,
        23 * 3600
    );
    w.clock.advance_hours(1);
    assert_eq!(verify(&store, &hash(), 1).unwrap().age_secs, 24 * 3600);
}

#[test]
fn a_wall_clock_that_jumps_ahead_does_not_fool_a_running_program() {
    let w = World::new("clock-jump");
    let store = w.open();
    put(&store, NAME, &bytes());
    store.new_session(&phone(), None).unwrap();

    // Somebody sets the PC's clock a day ahead. No time has really passed.
    w.clock.jump_wall_ms(25 * HOUR);
    match verify(&store, &hash(), 1).unwrap_err() {
        DeletionDenied::ClockDisagrees {
            wall_age_secs,
            real_age_at_most_secs,
        } => assert_eq!((wall_age_secs, real_age_at_most_secs), (25 * 3600, 0)),
        other => panic!("expected ClockDisagrees, got {other:?}"),
    }
    // 23 real hours later the wall clock says 48 hours; it is still too early.
    w.clock.advance_hours(23);
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::ClockDisagrees {
            real_age_at_most_secs: 82_800,
            ..
        })
    ));
    w.clock.advance_hours(1);
    assert!(verify(&store, &hash(), 1).is_ok());

    // The limit, stated plainly: a restarted program has no memory of how
    // much time really passed, and has only the wall clock (and the session
    // rule, and the phone's own clock) to go by.
    let second = data(22, 5_000);
    put(&store, "DCIM/b.jpg", &second);
    w.clock.jump_wall_ms(25 * HOUR);
    drop(store);
    let store = w.open();
    assert!(verify(&store, &ContentHash::of_bytes(&second), 1).is_ok());
}
