//! The commit pipeline with a well-behaved file system.

mod common;

use std::time::{Duration, SystemTime};

use common::*;
use kiwi_store::template::CaptureTime;
use kiwi_store::{
    CommitOutcome, ContentHash, DeviceId, DeviceLimits, FileRequest, QuotaKind, SanitizeError,
    Store, StoreConfig, StoreError, StoredStatus, Template,
};

#[test]
fn stores_a_file_end_to_end() {
    let w = World::new("end-to-end");
    let store = w.open();
    let bytes = data(1, 100_000);
    let hash = ContentHash::of_bytes(&bytes);
    let mtime_ns = 1_600_000_000_123_456_700i64;

    let mut incoming = store
        .begin_file(FileRequest {
            device: &phone(),
            name: "DCIM/Camera/IMG_0001.jpg",
            size: bytes.len() as u64,
            claimed_hash: None,
            capture_time: None,
            mtime_unix_ns: Some(mtime_ns),
        })
        .unwrap();
    // While the transfer runs there is exactly one temp file, next to the target.
    let temps = w.temp_files();
    assert_eq!(temps.len(), 1);
    assert!(
        temps[0].starts_with("Pixel 8/DCIM/Camera/.kiwi-tmp-"),
        "{temps:?}"
    );
    assert!(temps[0].ends_with(".part"));

    incoming.write(&bytes[..40_000]).unwrap();
    incoming.write(&bytes[40_000..]).unwrap();
    assert_eq!(incoming.bytes_written(), 100_000);
    let receipt = incoming.finish(Some(hash)).unwrap();

    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/DCIM/Camera/IMG_0001.jpg");
    assert_eq!(receipt.abs_path, w.path("Pixel 8/DCIM/Camera/IMG_0001.jpg"));
    assert_eq!(receipt.hash, hash);
    assert_eq!(receipt.size, 100_000);
    assert_eq!(receipt.session, store.session());
    assert!(
        receipt.dir_synced,
        "the directory flush works on the platforms we test on"
    );
    assert!(receipt.mtime_applied);
    if cfg!(windows) {
        assert!(
            receipt.verified_unbuffered,
            "NTFS must give an unbuffered read-back"
        );
    }

    // On disk: exactly the file, with exactly the bytes, and the mtime asked for.
    assert_eq!(w.files(), vec!["Pixel 8/DCIM/Camera/IMG_0001.jpg"]);
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    let on_disk = std::fs::metadata(&receipt.abs_path)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        on_disk,
        SystemTime::UNIX_EPOCH + Duration::from_nanos(mtime_ns as u64)
    );

    // In the ledger: one record, counted against the device, logged.
    let stats = store.stats().unwrap();
    assert_eq!((stats.files_committed, stats.bytes_committed), (1, 100_000));
    let device = store.device(&phone()).unwrap().unwrap();
    assert_eq!((device.used_files, device.used_bytes), (1, 100_000));
    let events = store.events_after(0, 1_000).unwrap();
    let commit = events
        .iter()
        .find(|e| e.kind == "commit")
        .expect("a commit event");
    assert_eq!(commit.seq, receipt.seq);
    assert_eq!(commit.file_id, Some(receipt.file_id));
    assert!(events.windows(2).all(|p| p[0].seq < p[1].seq));

    match store.is_safely_stored(&phone(), &hash).unwrap() {
        StoredStatus::Verified(file) => {
            assert_eq!(file.rel_path, receipt.rel_path);
            assert_eq!(file.abs_path, receipt.abs_path);
            assert_eq!(file.committed_seq, receipt.seq);
        }
        other => panic!("expected Verified, got {other:?}"),
    }
}

#[test]
fn large_file_in_awkward_chunks() {
    let w = World::new("awkward-chunks");
    let store = w.open();
    // Not a multiple of the sector size, the chunk size, or the verify buffer.
    let bytes = data(2, 3 * 1024 * 1024 + 12_345);
    let mut incoming = store
        .begin_file(request(&phone(), "video.mp4", &bytes))
        .unwrap();
    for chunk in bytes.chunks(70_001) {
        incoming.write(chunk).unwrap();
    }
    incoming.write(&[]).unwrap();
    let receipt = incoming.finish(None).unwrap();
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert!(store
        .is_safely_stored(&phone(), &receipt.hash)
        .unwrap()
        .is_verified());
}

#[test]
fn empty_files_are_files_too() {
    let w = World::new("empty");
    let store = w.open();
    let receipt = put(&store, "empty.txt", b"");
    assert_eq!(receipt.size, 0);
    assert_eq!(std::fs::metadata(&receipt.abs_path).unwrap().len(), 0);
    assert!(store
        .is_safely_stored(&phone(), &ContentHash::of_bytes(b""))
        .unwrap()
        .is_verified());
}

#[test]
fn never_overwrites_and_names_collisions_deterministically() {
    let w = World::new("collisions");
    let store = w.open();
    let contents: Vec<Vec<u8>> = (0..4).map(|i| data(10 + i, 5_000 + i as usize)).collect();
    let names: Vec<String> = contents
        .iter()
        .map(|c| put(&store, "DCIM/a.jpg", c).rel_path)
        .collect();
    assert_eq!(
        names,
        [
            "Pixel 8/DCIM/a.jpg",
            "Pixel 8/DCIM/a (2).jpg",
            "Pixel 8/DCIM/a (3).jpg",
            "Pixel 8/DCIM/a (4).jpg"
        ]
    );
    for (name, content) in names.iter().zip(&contents) {
        assert_eq!(
            &std::fs::read(w.path(name)).unwrap(),
            content,
            "{name} must still hold its own bytes"
        );
    }
    // Names without an extension, with two, and dot-files.
    assert_eq!(put(&store, "README", b"one").rel_path, "Pixel 8/README");
    assert_eq!(put(&store, "README", b"two").rel_path, "Pixel 8/README (2)");
    assert_eq!(put(&store, "x.tar.gz", b"one").rel_path, "Pixel 8/x.tar.gz");
    assert_eq!(
        put(&store, "x.tar.gz", b"two").rel_path,
        "Pixel 8/x.tar (2).gz"
    );
    assert_eq!(put(&store, ".nomedia", b"one").rel_path, "Pixel 8/.nomedia");
    assert_eq!(
        put(&store, ".nomedia", b"two").rel_path,
        "Pixel 8/.nomedia (2)"
    );
    assert!(w.temp_files().is_empty());
}

#[test]
fn collisions_ignore_case_and_unicode_normalisation() {
    let w = World::new("case-collisions");
    let store = w.open();
    assert_eq!(
        put(&store, "Photo.JPG", b"first").rel_path,
        "Pixel 8/Photo.JPG"
    );
    assert_eq!(
        put(&store, "photo.jpg", b"second").rel_path,
        "Pixel 8/photo (2).jpg"
    );
    assert_eq!(
        put(&store, "PHOTO.jpg", b"third").rel_path,
        "Pixel 8/PHOTO (3).jpg"
    );
    // The same name spelled decomposed (as a Mac would) and precomposed.
    assert_eq!(
        put(&store, "cafe\u{301}.txt", b"nfd").rel_path,
        "Pixel 8/caf\u{e9}.txt"
    );
    assert_eq!(
        put(&store, "caf\u{e9}.txt", b"nfc").rel_path,
        "Pixel 8/caf\u{e9} (2).txt"
    );
    assert_eq!(
        put(&store, "CAF\u{c9}.TXT", b"upper").rel_path,
        "Pixel 8/CAF\u{c9} (3).TXT"
    );
    // A directory that differs only by case is the same directory.
    assert_eq!(
        put(&store, "DCIM/one.jpg", b"1").rel_path,
        "Pixel 8/DCIM/one.jpg"
    );
    assert_eq!(
        put(&store, "dcim/two.jpg", b"2").rel_path,
        "Pixel 8/DCIM/two.jpg"
    );
    assert_eq!(
        put(&store, "Dcim/ONE.JPG", b"3").rel_path,
        "Pixel 8/DCIM/ONE (2).JPG"
    );
    assert_eq!(
        std::fs::read(w.path("Pixel 8/Photo.JPG")).unwrap(),
        b"first"
    );
    assert_eq!(std::fs::read(w.path("Pixel 8/DCIM/one.jpg")).unwrap(), b"1");
    assert_eq!(w.files().len(), 9);
}

#[test]
fn the_same_content_under_the_same_name_is_not_stored_twice() {
    let w = World::new("already-present");
    let store = w.open();
    let bytes = data(3, 50_000);
    let first = put(&store, "DCIM/a.jpg", &bytes);
    let second = put(&store, "DCIM/a.jpg", &bytes);
    assert_eq!(first.outcome, CommitOutcome::Stored);
    assert_eq!(second.outcome, CommitOutcome::AlreadyPresent);
    assert_eq!(second.file_id, first.file_id);
    assert_eq!(second.rel_path, first.rel_path);
    assert_eq!(
        second.seq, first.seq,
        "the original commit is what counts for the file's age"
    );
    assert_eq!(w.files(), vec!["Pixel 8/DCIM/a.jpg"]);
    assert_eq!(store.stats().unwrap().files_committed, 1);
    assert_eq!(store.device(&phone()).unwrap().unwrap().used_files, 1);
    // A case variant of the name finds the same file.
    let third = put(&store, "dcim/A.JPG", &bytes);
    assert_eq!(
        (third.outcome, third.file_id),
        (CommitOutcome::AlreadyPresent, first.file_id)
    );
    assert_eq!(w.files().len(), 1);
}

#[test]
fn an_identical_file_the_user_copied_by_hand_is_adopted() {
    let w = World::new("adopt-manual");
    let store = w.open();
    let bytes = data(4, 20_000);
    std::fs::create_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    std::fs::write(w.path("Pixel 8/DCIM/old.jpg"), &bytes).unwrap();
    let before = std::fs::metadata(w.path("Pixel 8/DCIM/old.jpg"))
        .unwrap()
        .modified()
        .unwrap();
    assert!(
        !store
            .is_safely_stored(&phone(), &ContentHash::of_bytes(&bytes))
            .unwrap()
            .is_verified(),
        "unknown until received"
    );

    let receipt = try_put(&store, &phone(), "DCIM/old.jpg", &bytes).unwrap();
    assert_eq!(receipt.outcome, CommitOutcome::AlreadyPresent);
    assert!(!receipt.mtime_applied);
    assert_eq!(w.files(), vec!["Pixel 8/DCIM/old.jpg"]);
    // The user's file was read, not written.
    assert_eq!(
        std::fs::metadata(w.path("Pixel 8/DCIM/old.jpg"))
            .unwrap()
            .modified()
            .unwrap(),
        before
    );
    assert!(store
        .is_safely_stored(&phone(), &receipt.hash)
        .unwrap()
        .is_verified());
    assert!(store
        .events_after(0, 100)
        .unwrap()
        .iter()
        .any(|e| e.kind == "adopt"));
}

#[test]
fn a_different_file_the_user_put_there_is_left_alone() {
    let w = World::new("keep-manual");
    let store = w.open();
    std::fs::create_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    let theirs: &[u8] = b"the user's own file";
    let ours: &[u8] = b"a new phone file!!!";
    // Same size on purpose: only reading it can tell the two apart.
    assert_eq!(theirs.len(), ours.len());
    std::fs::write(w.path("Pixel 8/DCIM/old.jpg"), theirs).unwrap();
    let receipt = put(&store, "DCIM/old.jpg", ours);
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/DCIM/old (2).jpg");
    assert_eq!(
        std::fs::read(w.path("Pixel 8/DCIM/old.jpg")).unwrap(),
        theirs
    );
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), ours);
    // A directory in the way is not a file to adopt or replace either.
    std::fs::create_dir_all(w.path("Pixel 8/DCIM/thing.jpg")).unwrap();
    assert_eq!(
        put(&store, "DCIM/thing.jpg", b"x").rel_path,
        "Pixel 8/DCIM/thing (2).jpg"
    );
    assert!(w.path("Pixel 8/DCIM/thing.jpg").is_dir());
}

#[test]
fn a_wrong_sender_hash_stores_nothing() {
    let w = World::new("sender-hash");
    let store = w.open();
    let bytes = data(5, 10_000);
    let wrong = ContentHash::of_bytes(b"something else");

    // Claimed up front.
    let mut incoming = store
        .begin_file(FileRequest {
            claimed_hash: Some(wrong),
            ..request(&phone(), "a.jpg", &bytes)
        })
        .unwrap();
    incoming.write(&bytes).unwrap();
    match incoming.finish(None) {
        Err(StoreError::SenderHashMismatch { claimed, received }) => {
            assert_eq!(claimed, wrong);
            assert_eq!(received, ContentHash::of_bytes(&bytes));
        }
        other => panic!("expected SenderHashMismatch, got {other:?}"),
    }
    // Claimed at the end.
    let mut incoming = store
        .begin_file(FileRequest {
            claimed_hash: None,
            ..request(&phone(), "a.jpg", &bytes)
        })
        .unwrap();
    incoming.write(&bytes).unwrap();
    assert!(matches!(
        incoming.finish(Some(wrong)),
        Err(StoreError::SenderHashMismatch { .. })
    ));
    // Two claims that disagree, even if one is right.
    let mut incoming = store
        .begin_file(request(&phone(), "a.jpg", &bytes))
        .unwrap();
    incoming.write(&bytes).unwrap();
    assert!(matches!(
        incoming.finish(Some(wrong)),
        Err(StoreError::ConflictingSenderHashes)
    ));
    // No claim at all.
    let mut incoming = store
        .begin_file(FileRequest {
            claimed_hash: None,
            ..request(&phone(), "a.jpg", &bytes)
        })
        .unwrap();
    incoming.write(&bytes).unwrap();
    assert!(matches!(
        incoming.finish(None),
        Err(StoreError::MissingSenderHash)
    ));

    assert!(
        w.files().is_empty(),
        "nothing may be left behind: {:?}",
        w.files()
    );
    assert_eq!(store.stats().unwrap().files_committed, 0);
    assert_eq!(store.device(&phone()).unwrap().unwrap().used_bytes, 0);
}

#[test]
fn size_must_match_the_declaration_exactly() {
    let w = World::new("size");
    let store = w.open();
    let bytes = data(6, 1_000);

    // Too few bytes.
    let mut incoming = store
        .begin_file(request(&phone(), "a.bin", &bytes))
        .unwrap();
    incoming.write(&bytes[..999]).unwrap();
    assert!(matches!(
        incoming.finish(None),
        Err(StoreError::SizeMismatch {
            declared: 1_000,
            received: 999
        })
    ));

    // Too many bytes: refused at the write that would exceed, and the file is dead.
    let mut incoming = store
        .begin_file(request(&phone(), "a.bin", &bytes))
        .unwrap();
    incoming.write(&bytes).unwrap();
    assert!(matches!(
        incoming.write(b"!"),
        Err(StoreError::SizeMismatch {
            declared: 1_000,
            received: 1_001
        })
    ));
    assert!(matches!(
        incoming.write(b"!"),
        Err(StoreError::WriterClosed)
    ));
    assert_eq!(incoming.bytes_written(), 0);
    assert!(matches!(
        incoming.finish(None),
        Err(StoreError::WriterClosed)
    ));

    assert!(w.files().is_empty(), "{:?}", w.files());
}

#[test]
fn abandoning_a_transfer_removes_what_was_received() {
    let w = World::new("abandon");
    let store = w.open();
    let bytes = data(7, 200_000);

    let mut incoming = store
        .begin_file(request(&phone(), "a/b/c.bin", &bytes))
        .unwrap();
    incoming.write(&bytes[..100_000]).unwrap();
    assert_eq!(w.temp_files().len(), 1);
    incoming.abort();
    assert!(w.files().is_empty());

    let mut incoming = store
        .begin_file(request(&phone(), "a/b/c.bin", &bytes))
        .unwrap();
    incoming.write(&bytes[..100_000]).unwrap();
    drop(incoming);
    assert!(w.files().is_empty());

    // The reservation is gone too: the full file fits again under a tight quota.
    let limits = DeviceLimits {
        max_total_bytes: Some(200_000),
        ..DeviceLimits::default()
    };
    store.register_device(&phone(), "Pixel 8", limits).unwrap();
    put(&store, "a/b/c.bin", &bytes);
}

#[test]
fn devices_must_be_registered_and_well_formed() {
    let w = World::new("devices");
    let store = w.open();
    let stranger = DeviceId::new("stranger").unwrap();
    assert!(
        matches!(try_put(&store, &stranger, "a.jpg", b"x"), Err(StoreError::UnknownDevice(id)) if id == "stranger")
    );
    for bad in [
        "",
        "has space",
        "slash/inside",
        "back\\slash",
        "colon:",
        "..\u{e9}",
        &"x".repeat(129),
    ] {
        assert!(
            matches!(DeviceId::new(bad), Err(StoreError::InvalidDeviceId(_))),
            "{bad:?}"
        );
    }
    for good in ["a", "3f9a6c0e5b7d4a12", "Pixel_8.pro-2", &"x".repeat(128)] {
        assert!(DeviceId::new(good).is_ok(), "{good:?}");
    }
    assert!(w.files().is_empty());
}

#[test]
fn device_folder_names_are_sanitised_and_unique() {
    let w = World::new("device-folders");
    let store = w.try_open().unwrap();
    let limits = DeviceLimits::default();
    let folder = |id: &str, name: &str| {
        store
            .register_device(&DeviceId::new(id).unwrap(), name, limits)
            .unwrap()
            .folder_name
    };
    assert_eq!(folder("d1", "Pixel 8"), "Pixel 8");
    assert_eq!(folder("d2", "pixel 8"), "pixel 8 (2)");
    assert_eq!(folder("d3", "../../Windows"), ".._.._Windows");
    assert_eq!(folder("d4", "CON"), "_CON");
    assert_eq!(folder("d5", "C:\\Users"), "C__Users");
    assert_eq!(folder("d6", "هاتف أحمد"), "هاتف أحمد");
    assert_eq!(folder("d7", "name. . "), "name");
    // Names with nothing usable fall back to the device id.
    assert_eq!(folder("d8", ""), "Device d8");
    assert_eq!(folder("d9", ".."), "Device d9");
    assert_eq!(folder("d10", "   "), "Device d10");
    // Re-registering keeps the folder.
    assert_eq!(folder("d1", "Renamed Phone"), "Pixel 8");
    let receipt = try_put(&store, &DeviceId::new("d3").unwrap(), "a.jpg", b"x").unwrap();
    assert_eq!(receipt.rel_path, ".._.._Windows/a.jpg");
    assert!(receipt.abs_path.starts_with(&w.root));
}

#[test]
fn hostile_names_never_leave_the_root() {
    let w = World::new("hostile");
    let store = w.open();
    let rejected: &[(&str, SanitizeError)] = &[
        ("../escape.txt", SanitizeError::ParentTraversal),
        ("DCIM/../../escape.txt", SanitizeError::ParentTraversal),
        ("DCIM/.. /escape.txt", SanitizeError::ParentTraversal),
        ("/etc/passwd", SanitizeError::AbsolutePath),
        ("\\Windows\\win.ini", SanitizeError::AbsolutePath),
        ("C:\\Windows\\win.ini", SanitizeError::DriveLetter),
        ("C:escape.txt", SanitizeError::DriveLetter),
        ("\\\\server\\share\\x", SanitizeError::UncOrDevicePath),
        ("\\\\?\\C:\\x", SanitizeError::UncOrDevicePath),
        ("\\\\.\\PhysicalDrive0", SanitizeError::UncOrDevicePath),
        ("a\0b", SanitizeError::NulCharacter),
        ("", SanitizeError::Empty),
        ("DCIM/ /x", SanitizeError::BlankComponent),
    ];
    for (name, expected) in rejected {
        match try_put(&store, &phone(), name, b"evil") {
            Err(StoreError::UnsafeName { source, .. }) => assert_eq!(&source, expected, "{name:?}"),
            other => panic!("{name:?} should be refused, got {other:?}"),
        }
    }
    assert!(
        w.files().is_empty(),
        "a refused name must not even create directories: {:?}",
        w.files()
    );

    let neutralised = [
        ("NUL", "Pixel 8/_NUL"),
        ("con.txt", "Pixel 8/_con.txt"),
        ("DCIM/COM1/lpt1.jpg", "Pixel 8/DCIM/_COM1/_lpt1.jpg"),
        ("photo.jpg:hidden", "Pixel 8/photo.jpg_hidden"),
        ("photo.jpg::$DATA", "Pixel 8/photo.jpg__$DATA"),
        ("trailing dot.", "Pixel 8/trailing dot"),
        ("trailing space ", "Pixel 8/trailing space"),
        ("wh?t*.jpg", "Pixel 8/wh_t_.jpg"),
        ("tab\there.txt", "Pixel 8/tab_here.txt"),
        ("evil\u{202e}gpj.exe", "Pixel 8/evil_gpj.exe"),
        (".kiwi-tmp-0.part", "Pixel 8/_.kiwi-tmp-0.part"),
        (".kiwi-store/id", "Pixel 8/_.kiwi-store/id"),
    ];
    for (i, (name, expected)) in neutralised.iter().enumerate() {
        let receipt = put(&store, name, format!("content {i}").as_bytes());
        assert_eq!(&receipt.rel_path, expected, "{name:?}");
        assert!(receipt.abs_path.starts_with(&w.root));
        assert_eq!(
            std::fs::read(&receipt.abs_path).unwrap(),
            format!("content {i}").as_bytes()
        );
    }
    // Everything that exists is exactly what was reported: no alternate data
    // stream on "photo.jpg", no device opened, nothing outside the root.
    let mut expected: Vec<String> = neutralised.iter().map(|(_, e)| e.to_string()).collect();
    expected.sort();
    assert_eq!(w.files(), expected);
    assert!(!w.path("Pixel 8/photo.jpg").exists());
    assert!(std::fs::read_dir(&w.outside).unwrap().next().is_none());
    assert!(!w.base.join("escape.txt").exists());
}

#[test]
fn paths_far_beyond_260_characters_work() {
    let w = World::new("long-paths");
    let store = w.open();
    let segment = "d".repeat(200);
    let name = format!("{0}/{0}/{0}/{0}/{0}/{1}.jpg", segment, "f".repeat(230));
    let bytes = data(8, 30_000);
    let receipt = put(&store, &name, &bytes);
    assert!(receipt.abs_path.as_os_str().len() > 1_200);
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
    assert!(store
        .is_safely_stored(&phone(), &receipt.hash)
        .unwrap()
        .is_verified());
    // A second file with the same long name still gets a suffix that fits.
    let second = put(&store, &name, b"other");
    assert!(second.rel_path.ends_with(" (2).jpg"));
    assert_eq!(std::fs::read(&second.abs_path).unwrap(), b"other");
    assert!(w.temp_files().is_empty());
}

#[test]
fn unicode_names_survive() {
    let w = World::new("unicode");
    let store = w.open();
    for (i, name) in [
        "صور العائلة/رحلة ٢٠٢٤/صورة ١.jpg",
        "写真/東京：夜景.jpg",
        "emoji 😀/👨\u{200d}👩\u{200d}👧.png",
        "Ünïcödé/naïve café.txt",
        "עברית/שלום.txt",
    ]
    .iter()
    .enumerate()
    {
        let bytes = data(100 + i as u64, 1_000);
        let receipt = put(&store, name, &bytes);
        assert_eq!(receipt.rel_path, format!("Pixel 8/{name}"));
        assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
        assert!(store
            .is_safely_stored(&phone(), &receipt.hash)
            .unwrap()
            .is_verified());
    }
}

#[test]
fn layouts_decide_the_folder() {
    let mut w = World::new("layouts");
    w.configure =
        |cfg: &mut StoreConfig| cfg.layout = Template::parse("{year}/{month}/{device}").unwrap();
    let store = w.open();
    let put_with = |name: &str, capture: Option<CaptureTime>, mtime: Option<i64>, bytes: &[u8]| {
        let mut incoming = store
            .begin_file(FileRequest {
                capture_time: capture,
                mtime_unix_ns: mtime,
                ..request(&phone(), name, bytes)
            })
            .unwrap();
        incoming.write(bytes).unwrap();
        incoming.finish(None).unwrap().rel_path
    };
    // 2024-03-09T12:00:00Z
    let march = CaptureTime::utc(1_709_985_600);
    assert_eq!(
        put_with("DCIM/a.jpg", Some(march), None, b"a"),
        "2024/03/Pixel 8/a.jpg"
    );
    // The capture time wins over the modification time.
    assert_eq!(
        put_with("b.jpg", Some(march), Some(1_500_000_000_000_000_000), b"b"),
        "2024/03/Pixel 8/b.jpg"
    );
    // Without a capture time the modification time is used (2017-07-14).
    assert_eq!(
        put_with("c.jpg", None, Some(1_500_000_000_000_000_000), b"c"),
        "2017/07/Pixel 8/c.jpg"
    );
    // Local time decides the month: 2024-12-31T22:30Z is January in UTC+3.
    let new_year = CaptureTime {
        unix_seconds: 1_735_684_200,
        utc_offset_seconds: 3 * 3600,
    };
    assert_eq!(
        put_with("d.jpg", Some(new_year), None, b"d"),
        "2025/01/Pixel 8/d.jpg"
    );
    // No date at all.
    assert_eq!(put_with("e.jpg", None, None, b"e"), "undated/Pixel 8/e.jpg");
    // A nonsense timestamp is "no date", not a folder named after year 292277026596.
    assert_eq!(
        put_with("f.jpg", Some(CaptureTime::utc(i64::MAX)), None, b"f"),
        "undated/Pixel 8/f.jpg"
    );
}

#[test]
fn keep_phone_structure_and_per_device_layouts() {
    let mut w = World::new("layout-presets");
    w.configure = |cfg: &mut StoreConfig| cfg.layout = Template::per_device();
    let store = w.open();
    assert_eq!(
        put(&store, "DCIM/Camera/a.jpg", b"a").rel_path,
        "Pixel 8/a.jpg"
    );
    drop(store);
    w.configure = |cfg: &mut StoreConfig| cfg.layout = Template::by_date();
    let store = w.open();
    assert_eq!(
        put(&store, "DCIM/Camera/b.jpg", b"b").rel_path,
        "undated/b.jpg"
    );
    drop(store);
    w.configure = |cfg: &mut StoreConfig| cfg.layout = Template::keep_phone_structure();
    let store = w.open();
    assert_eq!(
        put(&store, "DCIM/Camera/c.jpg", b"c").rel_path,
        "Pixel 8/DCIM/Camera/c.jpg"
    );
}

#[test]
fn many_writers_at_once_never_clobber_each_other() {
    let w = World::new("concurrent");
    let store = w.open();
    let handles: Vec<_> = (0..12u64)
        .map(|i| {
            let store = store.clone();
            std::thread::spawn(move || {
                let bytes = data(1_000 + i, 40_000 + i as usize);
                let receipt = try_put(&store, &phone(), "DCIM/same-name.jpg", &bytes).unwrap();
                (receipt, bytes)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let mut names: Vec<String> = results.iter().map(|(r, _)| r.rel_path.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 12, "every writer must get its own name");
    for (receipt, bytes) in &results {
        assert_eq!(
            &std::fs::read(&receipt.abs_path).unwrap(),
            bytes,
            "{}",
            receipt.rel_path
        );
    }
    assert_eq!(w.files().len(), 12);
    assert_eq!(store.stats().unwrap().files_committed, 12);
    let mut seqs: Vec<u64> = results.iter().map(|(r, _)| r.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), 12, "sequence numbers are unique");
}

#[test]
fn a_destination_can_only_be_open_once() {
    let w = World::new("exclusive");
    let store = w.open();
    assert!(matches!(w.try_open(), Err(StoreError::AlreadyOpen { .. })));
    // A clone is the same store, not a second one.
    let clone = store.clone();
    drop(store);
    assert!(matches!(w.try_open(), Err(StoreError::AlreadyOpen { .. })));
    drop(clone);
    let reopened = w.open();
    assert_eq!(reopened.session(), 2);
}

#[test]
fn the_low_space_guard_uses_the_real_volume() {
    let w = World::new("low-space-real");
    let store = w.open();
    let free = store.destination().free_space().unwrap();
    assert!(free > 0);
    // Far more than is free, so other activity on the disk cannot change the outcome.
    let size = free.saturating_add(1 << 40);
    let request = FileRequest {
        device: &phone(),
        name: "huge.bin",
        size,
        claimed_hash: None,
        capture_time: None,
        mtime_unix_ns: None,
    };
    match store.begin_file(request) {
        Err(StoreError::InsufficientSpace {
            needed,
            margin,
            available,
        }) => {
            assert_eq!(needed, size);
            assert_eq!(margin, 1024 * 1024);
            assert!(available < needed + margin);
        }
        other => panic!("expected InsufficientSpace, got {other:?}"),
    }
    assert!(
        w.files().is_empty(),
        "the guard must act before anything is created"
    );
}

#[test]
fn quota_kinds_are_reported() {
    let w = World::new("quota-kinds");
    let store = w.open();
    let limits = DeviceLimits {
        max_total_bytes: Some(100),
        max_files: Some(2),
        max_file_bytes: Some(60),
    };
    store.register_device(&phone(), "Pixel 8", limits).unwrap();
    let kind = |r: Result<_, StoreError>| match r {
        Err(StoreError::QuotaExceeded { kind, .. }) => kind,
        other => panic!(
            "expected QuotaExceeded, got {:?}",
            other.map(|_: kiwi_store::CommitReceipt| ())
        ),
    };
    assert_eq!(
        kind(try_put(&store, &phone(), "big", &[0; 61])),
        QuotaKind::FileBytes
    );
    put(&store, "a", &[1; 60]);
    assert_eq!(
        kind(try_put(&store, &phone(), "b", &[2; 41])),
        QuotaKind::TotalBytes
    );
    put(&store, "b", &[2; 40]);
    assert_eq!(
        kind(try_put(&store, &phone(), "c", &[])),
        QuotaKind::FileCount
    );
    assert_eq!(w.files().len(), 2);
}

#[test]
fn opening_needs_a_real_directory() {
    let w = World::new("bad-root");
    let file = w.base.join("a-file");
    std::fs::write(&file, b"x").unwrap();
    for bad in [
        w.base.join("missing"),
        file,
        std::path::PathBuf::from("relative"),
    ] {
        let cfg = StoreConfig::new(&bad, &w.ledger_dir);
        assert!(
            matches!(Store::open(cfg), Err(StoreError::Destination(_))),
            "{bad:?}"
        );
    }
}
