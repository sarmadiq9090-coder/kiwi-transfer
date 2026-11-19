//! Per-device quotas and limits, enforced before anything is written.

mod common;

use common::*;
use kiwi_store::testing::Op;
use kiwi_store::{DeviceLimits, FileRequest, QuotaKind, Store, StoreError};

fn limit(store: &Store, limits: DeviceLimits) {
    store.register_device(&phone(), "Pixel 8", limits).unwrap();
}

fn usage(store: &Store) -> (u64, u64) {
    let d = store.device(&phone()).unwrap().unwrap();
    (d.used_bytes, d.used_files)
}

fn quota_error(result: Result<kiwi_store::CommitReceipt, StoreError>) -> (QuotaKind, u64, u64) {
    match result {
        Err(StoreError::QuotaExceeded {
            device,
            kind,
            allowed,
            requested,
        }) => {
            assert_eq!(device, "phone-1");
            (kind, allowed, requested)
        }
        other => panic!(
            "expected QuotaExceeded, got {:?}",
            other.map(|r| r.rel_path)
        ),
    }
}

#[test]
fn total_bytes() {
    let w = World::new("bytes");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(1_000),
            ..Default::default()
        },
    );
    put(&store, "a", &data(1, 600));
    w.fs.reset_counters();
    assert_eq!(
        quota_error(try_put(&store, &phone(), "b", &data(2, 401))),
        (QuotaKind::TotalBytes, 1_000, 1_001)
    );
    // Refused before the file system was touched at all.
    assert_eq!(w.fs.log(), vec![]);
    put(&store, "b", &data(2, 400));
    assert_eq!(usage(&store), (1_000, 2));
    assert_eq!(
        quota_error(try_put(&store, &phone(), "c", &data(3, 1))),
        (QuotaKind::TotalBytes, 1_000, 1_001)
    );
    // An empty file still fits.
    put(&store, "empty", b"");
    assert_eq!(w.files().len(), 3);
}

#[test]
fn file_count_and_file_size() {
    let w = World::new("count");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_files: Some(2),
            max_file_bytes: Some(500),
            ..Default::default()
        },
    );
    assert_eq!(
        quota_error(try_put(&store, &phone(), "big", &data(1, 501))),
        (QuotaKind::FileBytes, 500, 501)
    );
    put(&store, "a", &data(1, 500));
    put(&store, "b", &data(2, 10));
    assert_eq!(
        quota_error(try_put(&store, &phone(), "c", &data(3, 10))),
        (QuotaKind::FileCount, 2, 3)
    );
    assert_eq!(usage(&store), (510, 2));
    assert_eq!(w.files().len(), 2);
}

#[test]
fn files_in_flight_count_against_the_quota() {
    let w = World::new("in-flight");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(1_000),
            max_files: Some(3),
            ..Default::default()
        },
    );
    let a_bytes = data(1, 600);
    let b_bytes = data(2, 500);
    let mut a = store.begin_file(request(&phone(), "a", &a_bytes)).unwrap();
    // "a" has not written a byte yet, but its 600 bytes are spoken for.
    match store.begin_file(request(&phone(), "b", &b_bytes)) {
        Err(StoreError::QuotaExceeded {
            kind: QuotaKind::TotalBytes,
            requested: 1_100,
            ..
        }) => {}
        other => panic!("unexpected: {other:?}"),
    }
    a.write(&a_bytes).unwrap();
    assert!(matches!(
        store.begin_file(request(&phone(), "b", &b_bytes)),
        Err(StoreError::QuotaExceeded { .. })
    ));
    a.finish(None).unwrap();
    // Committed now: still counted, exactly once.
    assert_eq!(usage(&store), (600, 1));
    assert!(matches!(
        store.begin_file(request(&phone(), "b", &b_bytes)),
        Err(StoreError::QuotaExceeded { .. })
    ));

    // File count: two more may start, a third may not, until one is abandoned.
    let small = data(3, 10);
    let x = store.begin_file(request(&phone(), "x", &small)).unwrap();
    let y = store.begin_file(request(&phone(), "y", &small)).unwrap();
    match store.begin_file(request(&phone(), "z", &small)) {
        Err(StoreError::QuotaExceeded {
            kind: QuotaKind::FileCount,
            requested: 4,
            allowed: 3,
            ..
        }) => {}
        other => panic!("unexpected: {other:?}"),
    }
    drop(x);
    let z = store.begin_file(request(&phone(), "z", &small)).unwrap();
    drop((y, z));
    assert_eq!(usage(&store), (600, 1));
    assert_eq!(w.files(), vec!["Pixel 8/a"]);
}

#[test]
fn failed_transfers_do_not_use_quota() {
    let w = World::new("failed");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(1_000),
            max_files: Some(1),
            ..Default::default()
        },
    );
    let bytes = data(1, 1_000);
    for _ in 0..5 {
        let mut incoming = store.begin_file(request(&phone(), "a", &bytes)).unwrap();
        incoming.write(&bytes[..999]).unwrap();
        assert!(incoming.finish(None).is_err());
    }
    assert_eq!(usage(&store), (0, 0));
    put(&store, "a", &bytes);
    assert_eq!(usage(&store), (1_000, 1));
}

#[test]
fn devices_have_separate_quotas() {
    let w = World::new("separate");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(100),
            ..Default::default()
        },
    );
    store
        .register_device(
            &tablet(),
            "Tab",
            DeviceLimits {
                max_total_bytes: Some(300),
                ..Default::default()
            },
        )
        .unwrap();
    put(&store, "a", &data(1, 100));
    assert!(matches!(
        try_put(&store, &phone(), "b", b"x"),
        Err(StoreError::QuotaExceeded { .. })
    ));
    try_put(&store, &tablet(), "a", &data(2, 300)).unwrap();
    assert!(matches!(
        try_put(&store, &tablet(), "b", b"x"),
        Err(StoreError::QuotaExceeded { .. })
    ));
    assert_eq!(usage(&store), (100, 1));
    let t = store.device(&tablet()).unwrap().unwrap();
    assert_eq!((t.used_bytes, t.used_files), (300, 1));
    assert_eq!(store.devices().unwrap().len(), 2);
}

#[test]
fn limits_can_be_changed_and_usage_survives_restarts() {
    let w = World::new("changed-limits");
    {
        let store = w.open();
        limit(
            &store,
            DeviceLimits {
                max_total_bytes: Some(100),
                ..Default::default()
            },
        );
        put(&store, "a", &data(1, 100));
        assert!(try_put(&store, &phone(), "b", &data(2, 50)).is_err());
        limit(
            &store,
            DeviceLimits {
                max_total_bytes: Some(150),
                ..Default::default()
            },
        );
        put(&store, "b", &data(2, 50));
        // Lowering a limit below current usage only stops new files.
        limit(
            &store,
            DeviceLimits {
                max_total_bytes: Some(10),
                ..Default::default()
            },
        );
        assert!(try_put(&store, &phone(), "c", b"x").is_err());
        assert_eq!(usage(&store), (150, 2));
    }
    // World::open registers the phone again with default (unlimited) limits.
    let store = w.open();
    assert_eq!(usage(&store), (150, 2));
    assert_eq!(
        store.device(&phone()).unwrap().unwrap().limits,
        DeviceLimits::default()
    );
    put(&store, "c", b"x");
    assert_eq!(usage(&store), (151, 3));
}

#[test]
fn files_that_are_gone_stop_counting() {
    let w = World::new("gone");
    {
        let store = w.open();
        put(&store, "a", &data(1, 400));
        put(&store, "b", &data(2, 600));
        assert_eq!(usage(&store), (1_000, 2));
    }
    std::fs::remove_file(w.path("Pixel 8/a")).unwrap();
    let store = w.open();
    assert_eq!(store.recovery_report().unwrap().newly_missing, 1);
    assert_eq!(usage(&store), (600, 1));
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(1_000),
            ..Default::default()
        },
    );
    put(&store, "a", &data(1, 400));
    assert_eq!(usage(&store), (1_000, 2));
    assert_eq!(
        quota_error(try_put(&store, &phone(), "c", b"x")).0,
        QuotaKind::TotalBytes
    );
}

#[test]
fn a_duplicate_is_counted_once() {
    let w = World::new("dup");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(1_000),
            max_files: Some(1),
            ..Default::default()
        },
    );
    let bytes = data(1, 1_000);
    put(&store, "a", &bytes);
    // Sending the same file again is not a second file: it is found on disk.
    // It must fit within the limits while in flight, so give it room first.
    limit(
        &store,
        DeviceLimits {
            max_total_bytes: Some(2_000),
            max_files: Some(2),
            ..Default::default()
        },
    );
    put(&store, "a", &bytes);
    assert_eq!(usage(&store), (1_000, 1));
}

#[test]
fn declared_size_is_what_is_checked() {
    let w = World::new("declared");
    let store = w.open();
    limit(
        &store,
        DeviceLimits {
            max_file_bytes: Some(100),
            ..Default::default()
        },
    );
    w.fs.reset_counters();
    let too_big = FileRequest {
        device: &phone(),
        name: "a",
        size: 101,
        claimed_hash: None,
        capture_time: None,
        mtime_unix_ns: None,
    };
    assert!(matches!(
        store.begin_file(too_big),
        Err(StoreError::QuotaExceeded {
            kind: QuotaKind::FileBytes,
            ..
        })
    ));
    assert_eq!(w.fs.count(Op::CreateTemp), 0);
    // Declaring less and sending more does not get around it.
    let mut incoming = store
        .begin_file(FileRequest {
            size: 100,
            ..too_big
        })
        .unwrap();
    incoming.write(&[0u8; 100]).unwrap();
    assert!(matches!(
        incoming.write(&[0u8; 1]),
        Err(StoreError::SizeMismatch { .. })
    ));
    assert!(w.files().is_empty());
}
