//! The mirror: a second copy on a second disk. What it does when everything
//! works, when a disk is away, when the wrong disk is there, and when files
//! are damaged on one disk or the other. (Faults injected into the copy
//! itself are in `mirror_faults.rs`.)

mod common;

use std::path::Path;

use common::*;
use kiwi_store::destination::DriveKind;
use kiwi_store::testing::Op;
use kiwi_store::{
    BlockKind, CancelToken, ContentHash, CopyCounts, DeletionDenied, DeviceLimits, FmState,
    MirrorError, MirrorOptions, MirrorPending, MirrorPresence, OpenNote, RepairDirection,
    ScanVerdict, Store, StoreError, VolumeInfo, WrongDisk, MAX_MIRRORS, MIRROR_MARKER_FILE,
    STORE_DIR,
};

fn run(store: &Store) -> kiwi_store::MirrorRunReport {
    store.run_mirror(&CancelToken::new()).unwrap()
}

fn scan(store: &Store) -> kiwi_store::MirrorScanReport {
    store
        .scan_mirror(&MirrorOptions::default(), &CancelToken::new())
        .unwrap()
}

fn check_only(store: &Store) -> kiwi_store::MirrorScanReport {
    let opts = MirrorOptions {
        repair: false,
        ..MirrorOptions::default()
    };
    store.scan_mirror(&opts, &CancelToken::new()).unwrap()
}

fn bytes_of(i: u64) -> Vec<u8> {
    data(200 + i, 4_000 + 100 * i as usize)
}

/// Stores `n` files for the phone: `DCIM/0.jpg`, `DCIM/1.jpg`, ...
fn library(store: &Store, n: u64) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let bytes = bytes_of(i);
            let receipt = put(store, &format!("DCIM/{i}.jpg"), &bytes);
            (receipt.rel_path, bytes)
        })
        .collect()
}

fn on(disk: &Path, rel: &str) -> std::path::PathBuf {
    rel.split('/')
        .fold(disk.to_path_buf(), |p, part| p.join(part))
}

fn marker(disk: &Path) -> std::path::PathBuf {
    disk.join(STORE_DIR).join(MIRROR_MARKER_FILE)
}

fn unplug(disk: &Path) -> std::path::PathBuf {
    let away = disk.with_extension("unplugged");
    std::fs::rename(disk, &away).unwrap();
    away
}

fn plug(away: &Path, disk: &Path) {
    std::fs::rename(away, disk).unwrap();
}

fn assert_same_tree(w: &World, disk: &Path, files: &[(String, Vec<u8>)]) {
    let mut expected: Vec<String> = files.iter().map(|(rel, _)| rel.clone()).collect();
    expected.sort();
    assert_eq!(tree(disk), expected);
    assert_eq!(w.files(), expected);
    for (rel, bytes) in files {
        assert_eq!(&std::fs::read(on(disk, rel)).unwrap(), bytes, "{rel}");
    }
}

// ----- when everything works -------------------------------------------------

#[test]
fn a_mirror_gets_a_verified_copy_of_every_file() {
    let w = World::new("happy");
    let store = w.open();
    store
        .register_device(&tablet(), "Tab S9", DeviceLimits::default())
        .unwrap();
    let mut files = library(&store, 3);
    let url = put(&store, "Docs/link.url", b"[InternetShortcut]");
    files.push((url.rel_path, b"[InternetShortcut]".to_vec()));
    for i in 0..2 {
        let bytes = bytes_of(10 + i);
        let receipt = try_put(&store, &tablet(), &format!("Pics/{i}.png"), &bytes).unwrap();
        files.push((receipt.rel_path, bytes));
    }
    let phone_bytes: u64 = files[..4].iter().map(|(_, b)| b.len() as u64).sum();

    // With no mirror, every file is on one disk.
    assert_eq!(
        store.copy_counts(&phone()).unwrap(),
        CopyCounts {
            no_copy: 0,
            one_copy: 4,
            two_or_more: 0
        }
    );
    assert!(store.mirror_pending().unwrap().is_empty());
    let oldest = store.oldest_unmirrored_commit(&phone()).unwrap().unwrap();
    assert_eq!(
        (oldest.rel_path.as_str(), oldest.commit_seq),
        (files[0].0.as_str(), 1)
    );

    let disk = w.disk("usb-a");
    let mirror = store.add_mirror(&disk, "USB A").unwrap();
    assert!(mirror.active);
    assert_eq!(mirror.label, "USB A");
    assert!(marker(&disk).is_file(), "the disk carries a marker");
    assert!(tree(&disk).is_empty(), "adding a mirror copies nothing yet");
    let pending = store.mirror_pending().unwrap();
    assert_eq!(
        pending,
        vec![
            MirrorPending {
                mirror: mirror.id,
                device: "phone-1".into(),
                files: 4,
                bytes: phone_bytes
            },
            MirrorPending {
                mirror: mirror.id,
                device: "tablet-2".into(),
                files: 2,
                bytes: (files[4].1.len() + files[5].1.len()) as u64
            },
        ]
    );

    w.fs.reset_counters();
    let report = run(&store);
    assert!(report.completed);
    assert!(report.block.is_none());
    let m = &report.mirrors[0];
    assert_eq!(m.presence, MirrorPresence::Present);
    assert_eq!((m.copied, m.already_there, m.failed), (6, 0, 0));
    assert_eq!(
        m.bytes_copied,
        files.iter().map(|(_, b)| b.len() as u64).sum::<u64>()
    );
    // Plain files, the same paths, the same (inert) names, the same bytes.
    assert_same_tree(&w, &disk, &files);

    // The order of one copy: the destination's file is read, a temp file on
    // the mirror is written, flushed and read back, renamed, flushed again
    // and read once more under its final name.
    let log = w.fs.log();
    let source = w.path(&files[0].0);
    let target = on(&disk, &files[0].0);
    let at = |op: Op, path: &Path| {
        log.iter()
            .position(|(o, p)| *o == op && p == path)
            .unwrap_or_else(|| panic!("{op:?} on {path:?} never happened"))
    };
    let temp = log
        .iter()
        .find(|(op, path)| *op == Op::CreateTemp && path.starts_with(&disk))
        .map(|(_, path)| path.clone())
        .unwrap();
    assert!(at(Op::ReadVerify, &source) < at(Op::Sync, &temp));
    assert!(at(Op::Sync, &temp) < at(Op::ReadVerify, &temp));
    assert!(at(Op::ReadVerify, &temp) < at(Op::Rename, &target));
    assert!(at(Op::Rename, &target) < at(Op::SyncFile, &target));
    assert!(at(Op::SyncFile, &target) < at(Op::ReadVerify, &target));
    assert_eq!(
        log.iter()
            .filter(|(op, path)| *op == Op::ReadVerify && *path == source)
            .count(),
        1,
        "the destination's file is read once: the bytes that are hashed are the bytes that are copied"
    );

    assert!(store.mirror_pending().unwrap().is_empty());
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 4);
    assert_eq!(store.copy_counts(&tablet()).unwrap().two_or_more, 2);
    assert!(store.oldest_unmirrored_commit(&phone()).unwrap().is_none());
    let copies = store
        .events_after(0, 10_000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "mirror_copy")
        .count();
    assert_eq!(copies, 6);

    // The next run reads back what this one wrote (a disk pulled out without
    // "eject" may have lost it), and copies nothing.
    let again = run(&store);
    assert!(again.completed);
    assert_eq!(
        (again.mirrors[0].rechecked, again.mirrors[0].copied),
        (6, 0)
    );
    // After that there is nothing to do, and nothing is read.
    w.fs.reset_counters();
    let idle = run(&store);
    assert!(idle.completed);
    assert_eq!(w.fs.count(Op::ReadVerify), 0);
    assert_eq!(w.fs.count(Op::CreateTemp), 0);
}

#[test]
fn final_move_does_not_wait_for_the_mirror() {
    let w = World::new("no-wait");
    let disk = w.disk("usb-a");
    let files = {
        let store = w.open();
        store.add_mirror(&disk, "USB A").unwrap();
        library(&store, 2)
        // No mirror run: the disk is "in a drawer".
    };
    let away = unplug(&disk);
    w.clock.advance_hours(25);
    let store = w.open();
    let hash = ContentHash::of_bytes(&files[0].1);
    let proof = verify(&store, &hash, 1).expect("the mirror is not asked");
    assert_eq!(proof.copies, 1, "the phone is told the file is on one disk");
    // What lets the application warn before the phone's trash lets go.
    let oldest = store.oldest_unmirrored_commit(&phone()).unwrap().unwrap();
    assert_eq!(oldest.rel_path, files[0].0);
    assert_eq!(oldest.age_secs, 25 * 3600);
    assert_eq!(store.copy_counts(&phone()).unwrap().one_copy, 2);

    plug(&away, &disk);
    assert!(run(&store).completed);
    assert_eq!(verify(&store, &hash, 1).unwrap().copies, 2);
    assert!(store.oldest_unmirrored_commit(&phone()).unwrap().is_none());
    // The proof never comes from the mirror: with the destination's file
    // gone, an intact second copy confirms nothing.
    std::fs::remove_file(w.path(&files[0].0)).unwrap();
    assert!(verify(&store, &hash, 1).is_err());
}

// ----- which folders may be a mirror ------------------------------------------

#[test]
fn only_a_folder_on_another_disk_can_be_a_mirror() {
    let w = World::new("eligible");
    let store = w.open();
    let refused = |result: Result<kiwi_store::MirrorInfo, StoreError>| match result {
        Err(StoreError::Mirror(e)) => e,
        other => panic!("expected a refusal, got {other:?}"),
    };

    assert!(matches!(
        refused(store.add_mirror(Path::new("relative/dir"), "x")),
        MirrorError::NotADirectory(_)
    ));
    assert!(matches!(
        refused(store.add_mirror(&w.base.join("not-there"), "x")),
        MirrorError::Unavailable { .. }
    ));
    let file = w.outside.join("a-file");
    std::fs::write(&file, b"x").unwrap();
    assert!(matches!(
        refused(store.add_mirror(&file, "x")),
        MirrorError::NotADirectory(_)
    ));
    // Inside the destination, and around it.
    let inside = w.root.join("Mirror");
    std::fs::create_dir(&inside).unwrap();
    assert!(matches!(
        refused(store.add_mirror(&inside, "x")),
        MirrorError::OverlapsDestination(_)
    ));
    std::fs::remove_dir(&inside).unwrap();
    assert!(matches!(
        refused(store.add_mirror(&std::fs::canonicalize(&w.base).unwrap(), "x")),
        MirrorError::OverlapsDestination(_)
    ));

    // The destination's own volume; another partition of its disk; a disk
    // that cannot be identified.
    let same_volume = w.disk("same-volume");
    w.set_serial(&same_volume, fixed_ntfs().serial.unwrap());
    assert!(matches!(
        refused(store.add_mirror(&same_volume, "x")),
        MirrorError::SameDisk(_)
    ));
    let partition = w.disk("other-partition");
    w.set_volume(
        &partition,
        VolumeInfo {
            device_number: fixed_ntfs().device_number,
            ..usb_ntfs(0xAAAA)
        },
    );
    assert!(matches!(
        refused(store.add_mirror(&partition, "x")),
        MirrorError::SameDisk(_)
    ));
    let unknown = w.disk("unknown-disk");
    w.set_volume(
        &unknown,
        VolumeInfo {
            device_number: None,
            ..usb_ntfs(0xBBBB)
        },
    );
    assert!(matches!(
        refused(store.add_mirror(&unknown, "x")),
        MirrorError::DiskUnidentified(_)
    ));
    // A network location; a file system that is not NTFS, ReFS or exFAT.
    let share = w.disk("share");
    w.set_volume(
        &share,
        VolumeInfo {
            drive: DriveKind::Remote,
            ..usb_ntfs(0xCCCC)
        },
    );
    assert!(matches!(
        refused(store.add_mirror(&share, "x")),
        MirrorError::Network(_)
    ));
    let fat = w.disk("fat");
    w.set_volume(
        &fat,
        VolumeInfo {
            filesystem: "FAT32".into(),
            ..usb_ntfs(0xDDDD)
        },
    );
    assert!(matches!(
        refused(store.add_mirror(&fat, "x")),
        MirrorError::Filesystem(name) if name == "FAT32"
    ));
    // A cloud-synced folder.
    let synced = w.disk("synced");
    std::fs::write(synced.join(".dropbox"), b"").unwrap();
    assert!(matches!(
        refused(store.add_mirror(&synced, "x")),
        MirrorError::SyncFolder { .. }
    ));
    // Nothing was written to any of the refused folders.
    for dir in [&same_volume, &partition, &unknown, &share, &fat] {
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0, "{dir:?}");
    }

    // A folder that carries somebody else's marker.
    let foreign = w.disk("foreign");
    std::fs::create_dir(foreign.join(STORE_DIR)).unwrap();
    std::fs::write(
        marker(&foreign),
        "kiwi-mirror 1\nuid=00000000000000000000000000000001\ndestination=00000000000000000000000000000002\n",
    )
    .unwrap();
    assert!(matches!(
        refused(store.add_mirror(&foreign, "x")),
        MirrorError::ForeignMarker { .. }
    ));

    // An exFAT stick is fine, and so are up to four mirrors.
    let stick = w.disk("stick");
    w.set_volume(
        &stick,
        VolumeInfo {
            filesystem: "exFAT".into(),
            ..usb_ntfs(0xEEEE)
        },
    );
    let first = store.add_mirror(&stick, "stick").unwrap();
    for i in 1..MAX_MIRRORS {
        store
            .add_mirror(&w.disk(&format!("more-{i}")), "more")
            .unwrap();
    }
    assert!(matches!(
        refused(store.add_mirror(&w.disk("one-too-many"), "x")),
        MirrorError::TooMany
    ));
    assert!(store.remove_mirror(first.id, "retired").unwrap());
    store.add_mirror(&w.disk("one-too-many"), "x").unwrap();
    assert!(matches!(
        store.remove_mirror(kiwi_store::MirrorId(999), "x"),
        Err(StoreError::Mirror(MirrorError::Unknown(999)))
    ));
}

// ----- a disk that is away, and a disk that is not the mirror -----------------

#[test]
fn an_absent_disk_is_a_normal_state_and_catches_up_when_it_returns() {
    let w = World::new("absent");
    let disk = w.disk("usb-a");
    let store = w.open();
    let mirror = store.add_mirror(&disk, "USB A").unwrap();
    let mut files = library(&store, 2);
    assert!(run(&store).completed);
    drop(store);

    // The disk goes into a drawer. Life goes on for three days.
    let away = unplug(&disk);
    let store = w.open();
    files.push({
        let r = put(&store, "DCIM/later-1.jpg", b"later one");
        (r.rel_path, b"later one".to_vec())
    });
    drop(store);
    w.clock.advance_hours(72);
    let store = w.open();
    files.push({
        let r = put(&store, "DCIM/later-2.jpg", b"later two");
        (r.rel_path, b"later two".to_vec())
    });

    match store.mirror_presence(mirror.id).unwrap() {
        MirrorPresence::Absent(absent) => {
            assert_eq!(absent.secs_since_seen, 72 * 3600);
            assert_eq!(absent.runs_since_seen, 2);
            assert_eq!(absent.last_seen_unix_ms, T0);
        }
        other => panic!("expected Absent, got {other:?}"),
    }
    let report = run(&store);
    assert!(
        !report.completed,
        "there is work the absent disk has not had"
    );
    assert!(matches!(
        report.mirrors[0].presence,
        MirrorPresence::Absent(_)
    ));
    assert_eq!(report.mirrors[0].copied, 0);
    assert!(report.block.is_none(), "an absent disk is not a failure");
    assert!(store.final_move_block().unwrap().is_none());
    assert_eq!(store.mirror_pending().unwrap()[0].files, 2);
    // The ledger still knows what is on the disk in the drawer.
    assert_eq!(
        store.copy_counts(&phone()).unwrap(),
        CopyCounts {
            no_copy: 0,
            one_copy: 2,
            two_or_more: 2
        }
    );

    // It comes back: the marker is checked, what was written last time is
    // read back, the queue is copied.
    plug(&away, &disk);
    assert_eq!(
        store.mirror_presence(mirror.id).unwrap(),
        MirrorPresence::Present
    );
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(
        (report.mirrors[0].rechecked, report.mirrors[0].copied),
        (2, 2)
    );
    assert_same_tree(&w, &disk, &files);
    let seen = store.mirrors().unwrap()[0].last_seen_unix_ms;
    assert_eq!(seen, T0 + 72 * HOUR);
}

#[test]
fn the_wrong_disk_is_never_written_to() {
    let w = World::new("wrong-disk");
    let (a, b) = (w.disk("usb-a"), w.disk("usb-b"));
    let store = w.open();
    let mirror_a = store.add_mirror(&a, "A").unwrap();
    let mirror_b = store.add_mirror(&b, "B").unwrap();
    library(&store, 2);
    assert!(run(&store).completed);
    assert!(store
        .remove_mirror(mirror_b.id, "only A from here on")
        .unwrap());
    put(&store, "DCIM/new.jpg", b"waiting to be mirrored");
    let only_a = MirrorOptions {
        mirror: Some(mirror_a.id),
        ..MirrorOptions::default()
    };
    // Whatever is at A's path in the cases below: it is not written to.
    let attempt = |expected: &dyn Fn(&WrongDisk) -> bool| {
        match store.mirror_presence(mirror_a.id).unwrap() {
            MirrorPresence::WrongDisk(why) => assert!(expected(&why), "{why:?}"),
            other => panic!("expected WrongDisk, got {other:?}"),
        }
        let before = tree(&a);
        w.fs.reset_counters();
        let report = store.run_mirror_with(&only_a, &CancelToken::new()).unwrap();
        assert!(matches!(
            report.mirrors[0].presence,
            MirrorPresence::WrongDisk(_)
        ));
        assert!(!report.completed);
        assert_eq!(report.mirrors[0].copied, 0);
        for (op, path) in w.fs.log() {
            let writes = matches!(
                op,
                Op::CreateTemp | Op::CreateDir | Op::Write | Op::Rename | Op::RemoveFile
            );
            assert!(!(writes && path.starts_with(&a)), "{op:?} on {path:?}");
        }
        assert_eq!(tree(&a), before);
        let scan = check_only(&store);
        assert!(matches!(
            scan.mirrors[0].presence,
            MirrorPresence::WrongDisk(_)
        ));
        assert!(store.final_move_block().unwrap().is_none());
    };

    // (a) Another, empty disk got the drive letter.
    let real_a = unplug(&a);
    std::fs::create_dir(&a).unwrap();
    attempt(&|why| *why == WrongDisk::NoMarker);
    assert_eq!(std::fs::read_dir(&a).unwrap().count(), 0);
    std::fs::remove_dir(&a).unwrap();

    // (b) The other mirror's disk got the drive letter.
    std::fs::rename(&b, &a).unwrap();
    attempt(
        &|why| matches!(why, WrongDisk::OtherMirror { found_uid } if *found_uid == mirror_b.uid),
    );
    std::fs::rename(&a, &b).unwrap();
    plug(&real_a, &a);

    // (c) The right marker on another volume: the folder was copied to a
    // different disk, marker and all.
    let serial = mirror_a.volume_serial.unwrap();
    w.set_serial(&a, 0xBAD);
    attempt(&|why| {
        *why == WrongDisk::VolumeChanged {
            expected: serial,
            found: Some(0xBAD),
        }
    });
    w.set_serial(&a, serial);

    // (d) A marker that belongs to a mirror of another destination.
    let good = std::fs::read_to_string(marker(&a)).unwrap();
    let other_destination = format!(
        "kiwi-mirror 1\nuid={}\ndestination=00000000000000000000000000000002\n",
        mirror_a.uid
    );
    std::fs::write(marker(&a), other_destination).unwrap();
    attempt(&|why| *why == WrongDisk::OtherStore);
    // (e) A marker that cannot be read.
    std::fs::write(marker(&a), "what is this").unwrap();
    attempt(&|why| matches!(why, WrongDisk::MarkerUnreadable(_)));
    std::fs::write(marker(&a), good).unwrap();

    // The right disk again: now it is written to.
    let report = store.run_mirror_with(&only_a, &CancelToken::new()).unwrap();
    assert!(report.completed);
    assert_eq!(report.mirrors[0].copied, 1);
}

#[test]
fn several_mirrors_take_turns() {
    let w = World::new("rotation");
    let (a, b) = (w.disk("usb-a"), w.disk("usb-b"));
    {
        let store = w.open();
        let mirror_a = store.add_mirror(&a, "A").unwrap();
        let mirror_b = store.add_mirror(&b, "B").unwrap();
        let mut files = library(&store, 3);

        // This week A is connected.
        let b_away = unplug(&b);
        let report = run(&store);
        assert!(!report.completed, "B has not had its turn");
        assert!(report.mirrors[0].completed);
        assert!(matches!(
            report.mirrors[1].presence,
            MirrorPresence::Absent(_)
        ));
        assert_same_tree(&w, &a, &files);
        // Two copies on one of the disks are two copies.
        assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 3);
        let pending = store.mirror_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].mirror, pending[0].files), (mirror_b.id, 3));

        // Next week B.
        let a_away = unplug(&a);
        plug(&b_away, &b);
        let r = put(&store, "DCIM/week-2.jpg", b"week two");
        files.push((r.rel_path, b"week two".to_vec()));
        let report = run(&store);
        assert!(matches!(
            report.mirrors[0].presence,
            MirrorPresence::Absent(_)
        ));
        assert_eq!(report.mirrors[1].copied, 4);
        assert_same_tree(&w, &b, &files);
        assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 4);
        let pending = store.mirror_pending().unwrap();
        assert_eq!((pending[0].mirror, pending[0].files), (mirror_a.id, 1));
        plug(&a_away, &a);
    }
    w.clock.advance_hours(25);
    let store = w.open();
    // A file on the destination and on both mirrors: three copies.
    let hash = ContentHash::of_bytes(&bytes_of(0));
    assert_eq!(verify(&store, &hash, 1).unwrap().copies, 3);
}

#[test]
fn removing_a_mirror_touches_nothing_and_it_can_come_back() {
    let w = World::new("remove");
    let disk = w.disk("usb-a");
    let store = w.open();
    let mirror = store.add_mirror(&disk, "USB A").unwrap();
    let files = library(&store, 3);
    assert!(run(&store).completed);

    assert!(store.remove_mirror(mirror.id, "sold the disk?").unwrap());
    assert!(!store.remove_mirror(mirror.id, "again").unwrap());
    // Nothing on the disk is touched, not even the marker.
    assert_same_tree(&w, &disk, &files);
    assert!(marker(&disk).is_file());
    // Its copies no longer count, and nothing waits for it.
    assert_eq!(store.copy_counts(&phone()).unwrap().one_copy, 3);
    assert!(store.mirror_pending().unwrap().is_empty());
    assert!(run(&store).mirrors.is_empty());
    let listed = store.mirrors().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].active, "kept for the record");

    // Added again, it is the same mirror, and nothing has to be copied twice.
    let back = store.add_mirror(&disk, "USB A again").unwrap();
    assert_eq!((back.id, &back.uid), (mirror.id, &mirror.uid));
    assert!(back.active);
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 3);
    let report = run(&store);
    assert_eq!(
        (report.mirrors[0].copied, report.mirrors[0].rechecked),
        (0, 3)
    );

    // The same disk under another drive letter is recognised by its marker.
    let moved = w.base.join("usb-on-another-letter");
    std::fs::rename(&disk, &moved).unwrap();
    let moved = std::fs::canonicalize(&moved).unwrap();
    w.set_serial(&moved, mirror.volume_serial.unwrap());
    assert!(matches!(
        store.mirror_presence(mirror.id).unwrap(),
        MirrorPresence::Absent(_)
    ));
    let relocated = store.add_mirror(&moved, "USB A").unwrap();
    assert_eq!(relocated.id, mirror.id);
    assert_eq!(relocated.root, moved);
    assert_eq!(
        store.mirror_presence(mirror.id).unwrap(),
        MirrorPresence::Present
    );
    assert_eq!(store.mirrors().unwrap().len(), 1);

    // A copy of the folder on some other disk is not that mirror.
    let copy = w.disk("a-copy-of-the-folder");
    std::fs::create_dir(copy.join(STORE_DIR)).unwrap();
    std::fs::copy(marker(&moved), marker(&copy)).unwrap();
    assert!(matches!(
        store.add_mirror(&copy, "copy"),
        Err(StoreError::Mirror(MirrorError::ForeignMarker { .. }))
    ));
}

// ----- damage and repair -------------------------------------------------------

#[test]
fn a_scan_rereads_the_copies_and_writes_damaged_ones_again() {
    let w = World::new("scan-mirror");
    let disk = w.disk("usb-a");
    let files = {
        let store = w.open();
        store.add_mirror(&disk, "USB A").unwrap();
        let files = library(&store, 3);
        assert!(run(&store).completed);
        files
    };
    w.clock.advance_hours(25);
    let store = w.open();
    // One copy rots, one is deleted.
    corrupt_silently(&on(&disk, &files[0].0));
    let rotten = std::fs::read(on(&disk, &files[0].0)).unwrap();
    std::fs::remove_file(on(&disk, &files[1].0)).unwrap();

    // Looking only.
    let report = check_only(&store);
    assert!(report.completed);
    let m = &report.mirrors[0];
    assert_eq!((m.files_checked, m.ok, m.changed, m.missing), (3, 1, 1, 1));
    assert_eq!((m.repaired, m.unrepairable), (0, 0));
    assert!(report.repairs.is_empty());
    assert_eq!(
        store.copy_counts(&phone()).unwrap(),
        CopyCounts {
            no_copy: 0,
            one_copy: 2,
            two_or_more: 1
        }
    );
    // A damaged second copy on a connected disk blocks final move.
    let block = store.final_move_block().unwrap().expect("blocked");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert!(block.reason.contains("second copy"), "{}", block.reason);

    // Repairing.
    let report = scan(&store);
    assert!(report.completed);
    let m = &report.mirrors[0];
    assert_eq!(
        (m.changed, m.missing, m.repaired, m.unrepairable),
        (1, 1, 2, 0)
    );
    assert_eq!(report.repairs.len(), 2);
    for repair in &report.repairs {
        assert!(matches!(
            repair.direction,
            RepairDirection::MirrorFromDestination(_)
        ));
    }
    // The rotten file is exactly where and what it was; the good copy is next to it.
    assert_eq!(std::fs::read(on(&disk, &files[0].0)).unwrap(), rotten);
    assert_eq!(report.repairs[0].rel_path, files[0].0);
    assert_eq!(report.repairs[0].new_rel_path, "Pixel 8/DCIM/0 (2).jpg");
    assert_eq!(
        std::fs::read(on(&disk, "Pixel 8/DCIM/0 (2).jpg")).unwrap(),
        files[0].1
    );
    // The deleted one is back under its own name.
    assert_eq!(report.repairs[1].new_rel_path, files[1].0);
    assert_eq!(std::fs::read(on(&disk, &files[1].0)).unwrap(), files[1].1);
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 3);
    let events = store.events_after(0, 10_000).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.kind == "mirror_repaired")
            .count(),
        2
    );
    assert!(events.iter().any(|e| e.kind == "mirror_file_changed"));
    assert!(events.iter().any(|e| e.kind == "mirror_file_missing"));

    // A repair resolves the file; it does not clear the block.
    assert!(store.final_move_block().unwrap().is_some());
    let hash = ContentHash::of_bytes(&files[0].1);
    assert!(matches!(
        verify(&store, &hash, 1),
        Err(DeletionDenied::Blocked(_))
    ));
    store.clear_final_move_block("looked at the disk").unwrap();
    assert_eq!(verify(&store, &hash, 1).unwrap().copies, 2);

    // A later scan finds everything in order.
    let report = scan(&store);
    let m = &report.mirrors[0];
    assert_eq!((m.ok, m.changed, m.missing), (3, 0, 0));
    assert!(store.final_move_block().unwrap().is_none());
}

#[test]
fn a_damaged_destination_file_is_written_again_from_the_mirror() {
    let w = World::new("repair-primary");
    let disk = w.disk("usb-a");
    let (stored, bytes) = {
        let store = w.open();
        store.add_mirror(&disk, "USB A").unwrap();
        let files = library(&store, 2);
        assert!(run(&store).completed);
        files[0].clone()
    };
    let hash = ContentHash::of_bytes(&bytes);
    w.clock.advance_hours(25);
    let store = w.open();
    let before = store.records(&phone(), &hash).unwrap().remove(0);

    corrupt_silently(&w.path(&stored));
    let damaged = std::fs::read(w.path(&stored)).unwrap();
    let found = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!(found.verdict, ScanVerdict::Problems);
    assert_eq!(store.copy_counts(&phone()).unwrap().one_copy, 1);

    let report = scan(&store);
    assert!(report.completed);
    assert_eq!(
        (report.destination_repaired, report.destination_unrepairable),
        (1, 0)
    );
    let repair = &report.repairs[0];
    assert!(matches!(
        repair.direction,
        RepairDirection::DestinationFromMirror(_)
    ));
    assert_eq!(repair.rel_path, stored);
    assert_eq!(repair.new_rel_path, "Pixel 8/DCIM/0 (2).jpg");
    // The damaged file is not overwritten, moved or deleted.
    assert_eq!(std::fs::read(w.path(&stored)).unwrap(), damaged);
    assert_eq!(
        std::fs::read(w.path("Pixel 8/DCIM/0 (2).jpg")).unwrap(),
        bytes
    );

    // The record points at the good copy and keeps what the phone knows it by.
    let after = store.records(&phone(), &hash).unwrap().remove(0);
    assert_eq!(after.rel_path, "Pixel 8/DCIM/0 (2).jpg");
    assert_eq!(
        (after.file_id, &after.key, after.commit_seq),
        (before.file_id, &before.key, before.commit_seq)
    );
    assert!(store
        .is_safely_stored(&phone(), &hash)
        .unwrap()
        .is_verified());
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 2);
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "primary_repaired" && e.file_id == Some(before.file_id)));

    // The block stays until a person clears it, and the freshly written file
    // has to age again before it confirms anything.
    assert!(matches!(
        verify(&store, &hash, 1),
        Err(DeletionDenied::Blocked(_))
    ));
    store
        .clear_final_move_block("repaired from the second disk")
        .unwrap();
    assert!(matches!(
        verify(&store, &hash, 1),
        Err(DeletionDenied::TooRecent { .. })
    ));
    drop(store);
    w.clock.advance_hours(25);
    let store = w.open();
    let proof = verify(&store, &hash, 1).unwrap();
    assert_eq!(proof.file.rel_path, "Pixel 8/DCIM/0 (2).jpg");
    assert_eq!(proof.copies, 2);
}

#[test]
fn a_destination_that_is_lost_entirely_is_rebuilt_from_the_mirror() {
    let w = World::new("rebuild-primary");
    let disk = w.disk("usb-a");
    let mut files;
    {
        let store = w.open();
        store
            .register_device(&tablet(), "Tab S9", DeviceLimits::default())
            .unwrap();
        store.new_session(&tablet(), None).unwrap();
        store.add_mirror(&disk, "USB A").unwrap();
        files = library(&store, 5);
        let url = put(&store, "Docs/Deep/Deeper/link.url", b"[InternetShortcut]");
        files.push((url.rel_path, b"[InternetShortcut]".to_vec()));
        for i in 0..3 {
            let bytes = bytes_of(20 + i);
            let r = try_put(&store, &tablet(), &format!("Pics/{i}.png"), &bytes).unwrap();
            files.push((r.rel_path, bytes));
        }
        store
            .mark_sole_copy(
                &phone(),
                key_of("DCIM/0.jpg"),
                &ContentHash::of_bytes(&files[0].1),
                None,
            )
            .unwrap();
        assert!(run(&store).completed);
    }
    // The destination's disk dies and is replaced by an empty one. The
    // ledger (kept elsewhere) and the second disk survive.
    for entry in std::fs::read_dir(&w.root).unwrap() {
        remove_tree(&entry.unwrap().path());
    }
    assert!(w.files().is_empty());
    w.clock.advance_hours(25);

    let store = w.open();
    store.new_session(&tablet(), None).unwrap();
    assert_eq!(store.open_notes(), [OpenNote::MarkerRecreated]);
    assert!(store.final_move_block().unwrap().is_some());
    assert_eq!(store.recovery_report().unwrap().newly_missing, 9);
    assert_eq!(store.copy_counts(&phone()).unwrap().one_copy, 6);

    let report = scan(&store);
    assert!(report.completed);
    assert_eq!(
        (report.destination_repaired, report.destination_unrepairable),
        (9, 0)
    );
    // Every file is back, at its own path, byte for byte.
    assert_same_tree(&w, &disk, &files);
    assert_eq!(store.stats().unwrap().files_committed, 9);
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 6);
    assert_eq!(store.copy_counts(&tablet()).unwrap().two_or_more, 3);
    for (i, (_, bytes)) in files.iter().enumerate() {
        let device = if i < 6 { phone() } else { tablet() };
        assert!(
            store
                .is_safely_stored(&device, &ContentHash::of_bytes(bytes))
                .unwrap()
                .is_verified(),
            "file {i}"
        );
    }
    // The records are the same records: same keys, same commit numbers, and
    // what was known about the phone's own copy.
    let first = store
        .records(&phone(), &ContentHash::of_bytes(&files[0].1))
        .unwrap()
        .remove(0);
    assert_eq!((first.commit_seq, first.fm), (1, FmState::SoleCopy));
    assert_eq!(store.commit_hwm(&phone()).unwrap(), 6);
    let clean = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!(clean.ok, 9);
    assert_eq!(clean.missing + clean.changed, 0);

    // Final move stays off until a person says so, and every rebuilt file
    // ages again on the new disk.
    let hash = ContentHash::of_bytes(&files[1].1);
    assert!(matches!(
        verify(&store, &hash, 1),
        Err(DeletionDenied::Blocked(_))
    ));
    store.clear_final_move_block("rebuilt and scanned").unwrap();
    assert!(matches!(
        verify(&store, &hash, 1),
        Err(DeletionDenied::TooRecent { .. })
    ));
    drop(store);
    w.clock.advance_hours(25);
    let store = w.open();
    assert_eq!(verify(&store, &hash, 1).unwrap().copies, 2);
}

#[test]
fn when_both_disks_disagree_nothing_is_repaired() {
    let w = World::new("both-bad");
    let disk = w.disk("usb-a");
    let store = w.open();
    store.add_mirror(&disk, "USB A").unwrap();
    let files = library(&store, 2);
    assert!(run(&store).completed);
    let (stored, bytes) = &files[0];
    // Both copies of one file rot, each in its own way.
    corrupt_silently(&w.path(stored));
    let mut other = bytes.clone();
    other[10] ^= 0x80;
    std::fs::write(on(&disk, stored), &other).unwrap();
    let primary_now = std::fs::read(w.path(stored)).unwrap();

    store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    let report = scan(&store);
    let m = &report.mirrors[0];
    assert_eq!((m.changed, m.repaired, m.unrepairable), (1, 0, 1));
    assert_eq!(report.destination_repaired, 0);
    assert!(report.repairs.is_empty());
    // Neither copy matches the ledger's hash: neither is used, and neither
    // is touched. No new file appears anywhere.
    assert_eq!(std::fs::read(w.path(stored)).unwrap(), primary_now);
    assert_eq!(std::fs::read(on(&disk, stored)).unwrap(), other);
    assert_eq!(w.files().len(), 2);
    assert_eq!(tree(&disk).len(), 2);
    assert_eq!(
        store.copy_counts(&phone()).unwrap(),
        CopyCounts {
            no_copy: 1,
            one_copy: 0,
            two_or_more: 1
        }
    );
    assert!(store.final_move_block().unwrap().is_some());
    // The other file is as safe as before.
    assert!(store
        .is_safely_stored(&phone(), &ContentHash::of_bytes(&files[1].1))
        .unwrap()
        .is_verified());
}

#[test]
fn a_new_disk_replaces_a_dead_mirror() {
    let w = World::new("rebuild-mirror");
    let old = w.disk("usb-old");
    let store = w.open();
    let dead = store.add_mirror(&old, "old").unwrap();
    let files = library(&store, 4);
    assert!(run(&store).completed);
    // The mirror disk dies.
    remove_tree(&old);
    assert!(matches!(
        run(&store).mirrors[0].presence,
        MirrorPresence::Absent(_)
    ));

    let new = w.disk("usb-new");
    let report = store
        .rebuild_mirror(&new, "new", Some(dead.id), &CancelToken::new())
        .unwrap();
    assert!(report.completed);
    assert_eq!(report.mirrors.len(), 1);
    assert_eq!(report.mirrors[0].copied, 4);
    assert_same_tree(&w, &new, &files);
    let listed = store.mirrors().unwrap();
    assert_eq!(
        listed.iter().map(|m| m.active).collect::<Vec<_>>(),
        vec![false, true]
    );
    assert_eq!(store.copy_counts(&phone()).unwrap().two_or_more, 4);
    assert!(store.mirror_pending().unwrap().is_empty());
    assert!(store.final_move_block().unwrap().is_none());
}

// ----- runs in pieces ----------------------------------------------------------

#[test]
fn a_run_can_be_done_in_pieces() {
    let w = World::new("pieces");
    let disk = w.disk("usb-a");
    let store = w.open();
    store.add_mirror(&disk, "USB A").unwrap();
    let files = library(&store, 5);
    let two = MirrorOptions {
        max_files: Some(2),
        ..MirrorOptions::default()
    };
    let report = store.run_mirror_with(&two, &CancelToken::new()).unwrap();
    assert!(!report.completed);
    assert_eq!(report.mirrors[0].copied, 2);
    assert_eq!(tree(&disk).len(), 2);
    let report = run(&store);
    assert!(report.completed);
    assert_eq!(
        (report.mirrors[0].rechecked, report.mirrors[0].copied),
        (2, 3)
    );
    assert_same_tree(&w, &disk, &files);

    // A scan in pieces picks up where it stopped.
    let report = store.scan_mirror(&two, &CancelToken::new()).unwrap();
    assert!(!report.completed);
    assert_eq!(report.mirrors[0].files_checked, 2);
    let report = scan(&store);
    assert!(report.completed);
    assert!(report.mirrors[0].resumed);
    assert_eq!(
        (report.mirrors[0].files_checked, report.mirrors[0].ok),
        (3, 3)
    );
}

#[test]
fn the_files_of_an_unpaired_phone_are_still_mirrored_and_repaired() {
    let w = World::new("unpaired-mirror");
    let disk = w.disk("usb-a");
    let store = w.open();
    let files = library(&store, 2);
    assert!(store.detach_device(&phone(), "unpaired").unwrap());
    store.add_mirror(&disk, "USB A").unwrap();
    assert_eq!(store.mirror_pending().unwrap()[0].device, "phone-1");
    assert!(run(&store).completed);
    assert_same_tree(&w, &disk, &files);
    // Its files are still looked after.
    std::fs::remove_file(w.path(&files[0].0)).unwrap();
    store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!(scan(&store).destination_repaired, 1);
    assert_same_tree(&w, &disk, &files);
}
