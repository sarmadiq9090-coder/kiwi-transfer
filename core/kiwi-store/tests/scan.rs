//! The integrity scan: re-hash everything, report, block, resume.

mod common;

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use common::*;
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{
    BlockKind, CancelToken, ContentHash, DeletionDenied, FindingKind, ScanOptions, ScanPolicy,
    ScanReport, ScanVerdict, Store, StoreConfig,
};

fn scan(store: &Store) -> ScanReport {
    store
        .integrity_scan(&ScanOptions::default(), &CancelToken::new())
        .unwrap()
}

/// Stores `count` files named `DCIM/000.jpg`, ... and returns their hashes.
fn fill(store: &Store, count: u64, size: usize) -> Vec<ContentHash> {
    (0..count)
        .map(|i| put(store, &format!("DCIM/{i:03}.jpg"), &data(i, size)).hash)
        .collect()
}

fn file(w: &World, i: u64) -> std::path::PathBuf {
    w.path(&format!("Pixel 8/DCIM/{i:03}.jpg"))
}

fn kinds(report: &ScanReport) -> Vec<(FindingKind, String)> {
    let mut v: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.kind, f.rel_path.clone()))
        .collect();
    v.sort_by(|a, b| a.1.cmp(&b.1));
    v
}

#[test]
fn a_clean_scan_reads_every_file() {
    let w = World::new("clean");
    let store = w.open();
    fill(&store, 8, 20_000);
    w.fs.reset_counters();
    let report = scan(&store);
    assert_eq!(w.fs.count(Op::ReadVerify), 8, "every file is read back");
    assert!(report.completed && !report.resumed);
    assert_eq!(report.verdict, ScanVerdict::Clean);
    assert_eq!(
        (
            report.files_checked,
            report.files_checked_this_call,
            report.ok
        ),
        (8, 8, 8)
    );
    assert_eq!(report.bytes_verified, 8 * 20_000);
    assert_eq!(
        (
            report.missing,
            report.changed,
            report.unreadable,
            report.suspicious,
            report.unexpected
        ),
        (0, 0, 0, 0, 0)
    );
    assert!(report.findings.is_empty());
    assert!(report.block.is_none());
    let events: Vec<String> = store
        .events_after(0, 10_000)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(
        events.contains(&"scan_started".to_owned()) && events.contains(&"scan_finished".to_owned())
    );
    // An empty store scans clean too.
    let empty = World::new("clean-empty");
    assert_eq!(scan(&empty.open()).verdict, ScanVerdict::Clean);
}

#[test]
fn missing_changed_and_unexpected_files_are_reported_and_block() {
    let w = World::new("findings");
    let store = w.open();
    let hashes = fill(&store, 6, 10_000);
    std::fs::remove_file(file(&w, 1)).unwrap();
    corrupt_silently(&file(&w, 3));
    std::fs::write(w.path("Pixel 8/DCIM/added by hand.jpg"), b"the user's").unwrap();
    std::fs::write(w.path("notes.txt"), b"the user's").unwrap();

    let report = scan(&store);
    assert!(report.completed);
    assert_eq!(report.verdict, ScanVerdict::Problems);
    assert_eq!(
        (
            report.files_checked,
            report.ok,
            report.missing,
            report.changed
        ),
        (6, 4, 1, 1)
    );
    assert_eq!(report.unexpected, 2);
    assert_eq!(report.rename_suspects, 0);
    assert_eq!(
        kinds(&report),
        vec![
            (FindingKind::Missing, "Pixel 8/DCIM/001.jpg".to_owned()),
            (FindingKind::Changed, "Pixel 8/DCIM/003.jpg".to_owned()),
            (
                FindingKind::Unexpected,
                "Pixel 8/DCIM/added by hand.jpg".to_owned()
            ),
            (FindingKind::Unexpected, "notes.txt".to_owned()),
        ]
    );
    assert!(report.findings.iter().all(|f| f.new));
    let changed = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Changed)
        .unwrap();
    assert!(changed.detail.contains("hashes to"), "{}", changed.detail);

    let block = report.block.clone().expect("blocked");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert_eq!(store.final_move_block().unwrap(), Some(block));
    // The user's own files are reported, never touched.
    assert_eq!(std::fs::read(w.path("notes.txt")).unwrap(), b"the user's");
    drop(store);

    // The block survives a restart; intact files are still not confirmed.
    w.clock.advance_hours(25);
    let store = w.open();
    assert!(matches!(
        verify(&store, &hashes[0], 1),
        Err(DeletionDenied::Blocked(_))
    ));
    // A second scan does not present old findings as new ones.
    let again = scan(&store);
    assert_eq!(
        (again.ok, again.missing, again.changed, again.known_bad),
        (4, 0, 0, 2)
    );
    assert!(again
        .findings
        .iter()
        .filter(|f| f.kind != FindingKind::Unexpected)
        .all(|f| !f.new));
    assert!(
        again.block.is_some(),
        "a scan never clears the block by itself"
    );

    // Only an explicit call clears it; after that, known problems do not block again.
    store.clear_final_move_block("reviewed").unwrap();
    let third = scan(&store);
    assert_eq!(third.verdict, ScanVerdict::Clean);
    assert!(third.block.is_none());
    assert!(verify(&store, &hashes[0], 1).is_ok());
    assert!(verify(&store, &hashes[1], 1).is_err());
    assert!(verify(&store, &hashes[3], 1).is_err());
}

#[test]
fn a_file_that_comes_back_is_restored() {
    let w = World::new("restored");
    let store = w.open();
    fill(&store, 3, 5_000);
    let original = std::fs::read(file(&w, 2)).unwrap();
    std::fs::remove_file(file(&w, 2)).unwrap();
    assert_eq!(scan(&store).missing, 1);
    assert_eq!(store.stats().unwrap().files_missing, 1);
    std::fs::write(file(&w, 2), &original).unwrap();
    let report = scan(&store);
    assert_eq!(
        (report.ok, report.restored, report.missing, report.known_bad),
        (3, 1, 0, 0)
    );
    assert_eq!(
        kinds(&report),
        vec![(FindingKind::Restored, "Pixel 8/DCIM/002.jpg".to_owned())]
    );
    assert_eq!(store.stats().unwrap().files_committed, 3);
    // Restoring a file does not clear the block either.
    assert!(report.block.is_some());
}

#[test]
fn a_scan_can_be_stopped_and_resumed() {
    let w = World::new("resume");
    let store = w.open();
    fill(&store, 20, 3_000);

    // In slices of seven files.
    let slice = ScanOptions {
        max_files: Some(7),
        ..ScanOptions::default()
    };
    let first = store.integrity_scan(&slice, &CancelToken::new()).unwrap();
    assert!(!first.completed && !first.resumed);
    assert_eq!(first.verdict, ScanVerdict::Incomplete);
    assert_eq!((first.files_checked, first.files_checked_this_call), (7, 7));

    let second = store.integrity_scan(&slice, &CancelToken::new()).unwrap();
    assert!(!second.completed && second.resumed);
    assert_eq!(
        (second.files_checked, second.files_checked_this_call),
        (14, 7)
    );
    drop(store);

    // Progress survives a restart.
    let store = w.open();
    w.fs.reset_counters();
    let third = store.integrity_scan(&slice, &CancelToken::new()).unwrap();
    assert!(third.resumed);
    assert_eq!(
        (third.files_checked, third.files_checked_this_call),
        (20, 6)
    );
    assert_eq!(
        w.fs.count(Op::ReadVerify),
        6,
        "files already checked are not read again"
    );
    // The slice limit was not reached in the records, so this call finished the scan.
    assert!(third.completed);
    assert_eq!(third.verdict, ScanVerdict::Clean);
    assert_eq!(third.ok, 20);

    // The next call starts a new scan from the beginning.
    let fresh = scan(&store);
    assert!(!fresh.resumed);
    assert_eq!(fresh.files_checked, 20);
}

#[test]
fn restart_discards_saved_progress() {
    let w = World::new("restart");
    let store = w.open();
    fill(&store, 10, 1_000);
    let slice = ScanOptions {
        max_files: Some(4),
        ..ScanOptions::default()
    };
    assert_eq!(
        store
            .integrity_scan(&slice, &CancelToken::new())
            .unwrap()
            .files_checked,
        4
    );
    let restarted = ScanOptions {
        restart: true,
        ..ScanOptions::default()
    };
    let report = store
        .integrity_scan(&restarted, &CancelToken::new())
        .unwrap();
    assert!(!report.resumed && report.completed);
    assert_eq!(
        (report.files_checked, report.files_checked_this_call),
        (10, 10)
    );
}

#[test]
fn cancelling_stops_at_once_and_loses_nothing() {
    let w = World::new("cancel");
    let store = w.open();
    fill(&store, 6, 400_000);

    // Cancelled before it starts.
    let cancel = CancelToken::new();
    cancel.cancel();
    let report = store
        .integrity_scan(&ScanOptions::default(), &cancel)
        .unwrap();
    assert_eq!(report.verdict, ScanVerdict::Incomplete);
    assert_eq!(report.files_checked, 0);

    // Cancelled in the middle of a slow scan (100 kB/s: the whole thing would take 24 s).
    let cancel = CancelToken::new();
    let canceller = cancel.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        canceller.cancel();
    });
    let slow = ScanOptions {
        max_bytes_per_sec: Some(100_000),
        ..ScanOptions::default()
    };
    let started = Instant::now();
    let report = store.integrity_scan(&slow, &cancel).unwrap();
    handle.join().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "cancel took {:?}",
        started.elapsed()
    );
    assert!(!report.completed);
    assert!(report.files_checked < 6);
    assert_eq!(
        report.missing + report.changed + report.unreadable,
        0,
        "an interrupted read is not a finding"
    );
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.stats().unwrap().files_committed, 6);

    // Resumed at full speed, it checks the rest, including the interrupted file.
    let rest = scan(&store);
    assert!(rest.resumed && rest.completed);
    assert_eq!((rest.files_checked, rest.ok), (6, 6));
    assert_eq!(rest.verdict, ScanVerdict::Clean);
}

#[test]
fn the_rate_limit_is_respected() {
    let w = World::new("rate");
    let store = w.open();
    fill(&store, 4, 250_000);
    let limited = ScanOptions {
        max_bytes_per_sec: Some(1_000_000),
        skip_unexpected: true,
        ..ScanOptions::default()
    };
    let started = Instant::now();
    let report = store.integrity_scan(&limited, &CancelToken::new()).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(report.ok, 4);
    // 1 MB at 1 MB/s. Allow for timer granularity, not for a broken limiter.
    assert!(
        elapsed >= Duration::from_millis(900),
        "1 MB at 1 MB/s took only {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
}

#[test]
fn many_changed_files_are_a_mass_change() {
    let w = World::new("mass-change");
    let store = w.open();
    let hashes = fill(&store, 30, 2_000);
    for i in 0..10 {
        corrupt_silently(&file(&w, i));
    }
    let report = scan(&store);
    assert_eq!(report.changed, 10);
    assert_eq!(report.verdict, ScanVerdict::MassChange);
    let block = report.block.unwrap();
    assert_eq!(block.kind, BlockKind::MassChange);
    assert!(block.reason.contains("ransomware"), "{}", block.reason);
    drop(store);
    w.clock.advance_hours(25);
    let store = w.open();
    assert!(matches!(
        verify(&store, &hashes[20], 1),
        Err(DeletionDenied::Blocked(info)) if info.kind == BlockKind::MassChange
    ));
}

#[test]
fn a_few_files_changed_within_minutes_are_a_mass_change_too() {
    let w = World::new("burst");
    let store = w.open();
    fill(&store, 30, 2_000);
    // Five files rewritten just now (their on-disk modification times are
    // seconds apart): fewer than the plain threshold, but a burst.
    for i in 0..5 {
        let path = file(&w, i);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
    }
    let report = scan(&store);
    assert_eq!(report.changed, 5);
    assert_eq!(report.verdict, ScanVerdict::MassChange);
    assert!(report.block.unwrap().reason.contains("within 600 seconds"));

    // The same five changes with their old timestamps kept do not look like
    // a burst: a problem, but not a mass change.
    let w = World::new("no-burst");
    let store = w.open();
    fill(&store, 30, 2_000);
    for i in 0..5 {
        let path = file(&w, i);
        let spread =
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000 + i * 100_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(spread)
            .unwrap();
        corrupt_silently(&path);
    }
    let report = scan(&store);
    assert_eq!(report.changed, 5);
    assert_eq!(report.verdict, ScanVerdict::Problems);
    assert_eq!(report.block.unwrap().kind, BlockKind::IntegrityProblems);
}

#[test]
fn renamed_files_are_recognised_as_such() {
    let mut w = World::new("renames");
    // Deletions alone must not trip the "share of the library" rule here.
    w.configure = |cfg: &mut StoreConfig| {
        cfg.scan_policy = ScanPolicy {
            mass_missing_min_percent: 90,
            ..ScanPolicy::default()
        };
    };
    let store = w.open();
    fill(&store, 30, 1_000);
    for i in 0..10 {
        let to = w.path(&format!("Pixel 8/DCIM/{i:03}.jpg.encrypted"));
        std::fs::rename(file(&w, i), to).unwrap();
    }
    std::fs::write(w.path("Pixel 8/DCIM/HOW_TO_RECOVER.txt"), b"...").unwrap();
    let report = scan(&store);
    assert_eq!(
        (report.missing, report.unexpected, report.rename_suspects),
        (10, 11, 10)
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::RenameSuspect)
            .count(),
        10
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Unexpected)
            .count(),
        1
    );
    assert_eq!(report.verdict, ScanVerdict::MassChange);
    assert_eq!(report.block.unwrap().kind, BlockKind::MassChange);
}

#[test]
fn unreadable_files_make_the_scan_inconclusive_but_do_not_block() {
    let w = World::new("unreadable");
    let store = w.open();
    fill(&store, 5, 1_000);
    w.fs.reset_counters();
    w.fs.inject(
        When::Nth(Op::ReadVerify, 2),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    let report = scan(&store);
    assert_eq!((report.ok, report.unreadable), (4, 1));
    assert_eq!(report.verdict, ScanVerdict::Inconclusive);
    assert!(report.block.is_none());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::Unreadable);
    assert_eq!(store.stats().unwrap().files_committed, 5);
    w.fs.clear_rules();
    assert_eq!(scan(&store).verdict, ScanVerdict::Clean);
}

#[test]
fn unexpected_files_can_be_skipped_and_never_block() {
    let w = World::new("unexpected");
    let store = w.open();
    fill(&store, 2, 1_000);
    for i in 0..25 {
        std::fs::write(w.path(&format!("Pixel 8/DCIM/mine {i}.png")), b"user file").unwrap();
    }
    let report = scan(&store);
    assert_eq!(report.unexpected, 25);
    assert_eq!(
        report.verdict,
        ScanVerdict::Clean,
        "files the user adds are not a problem"
    );
    assert!(report.block.is_none());
    let skipped = store
        .integrity_scan(
            &ScanOptions {
                skip_unexpected: true,
                ..Default::default()
            },
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(skipped.unexpected, 0);
    assert!(skipped.findings.is_empty());
    // A transfer in progress is not "unexpected".
    let bytes = data(9, 1_000);
    let incoming = store
        .begin_file(request(&phone(), "DCIM/live.jpg", &bytes))
        .unwrap();
    assert_eq!(scan(&store).unexpected, 25);
    drop(incoming);
}

#[test]
fn files_committed_during_a_scan_are_left_for_the_next_one() {
    let w = World::new("during");
    let store = w.open();
    fill(&store, 4, 1_000);
    let slice = ScanOptions {
        max_files: Some(2),
        skip_unexpected: true,
        ..ScanOptions::default()
    };
    assert_eq!(
        store
            .integrity_scan(&slice, &CancelToken::new())
            .unwrap()
            .files_checked,
        2
    );
    put(&store, "DCIM/late.jpg", b"arrived while scanning");
    let rest = store
        .integrity_scan(
            &ScanOptions {
                skip_unexpected: true,
                ..Default::default()
            },
            &CancelToken::new(),
        )
        .unwrap();
    assert!(rest.completed);
    assert_eq!(
        rest.files_checked, 4,
        "the scan covers the files that existed when it started"
    );
    assert_eq!(scan(&store).files_checked, 5);
}

#[test]
fn findings_are_capped_but_counts_are_complete() {
    let w = World::new("capped");
    let store = w.open();
    fill(&store, 1, 100);
    std::fs::create_dir_all(w.path("bulk")).unwrap();
    for i in 0..1_050 {
        std::fs::write(w.path(&format!("bulk/{i}.bin")), b"").unwrap();
    }
    let report = scan(&store);
    assert_eq!(report.unexpected, 1_050);
    assert_eq!(report.findings.len(), 1_000);
    assert!(report.findings_truncated);
}
