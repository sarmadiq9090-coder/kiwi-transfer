//! One regression test (at least) per finding of the protocol review that
//! touches the store: temp files and their clean-up (KT-13), the durability
//! of the rename (KT-13), shell-active names (KT-17), and destinations that
//! must not hold an only copy (KT-14). Rollback (KT-02) and unpairing (KT-07)
//! are in `per_device.rs`.

mod common;

use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::PathBuf;

use common::*;
use kiwi_store::fsops::Checkpoint;
use kiwi_store::testing::{Action, Op, When};
use kiwi_store::{
    is_shell_active, BlockKind, CancelToken, CommitOutcome, ContentHash, CopyOnlyReason,
    DeletionDenied, Destination, DestinationWarning, FileState, FinalMoveSupport, HazardEnv,
    ManagedFolder, NotVerifiedReason, StoreError, SyncProvider,
};

const NAME: &str = "DCIM/a.jpg";
const STORED: &str = "Pixel 8/DCIM/a.jpg";

fn bytes() -> Vec<u8> {
    data(61, 40_000)
}

fn hash() -> ContentHash {
    ContentHash::of_bytes(&bytes())
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// The temp files the engine created since the counters were last reset.
fn temps_created(w: &World) -> Vec<PathBuf> {
    w.fs.log()
        .into_iter()
        .filter(|(op, _)| *op == Op::CreateTemp)
        .map(|(_, path)| path)
        .collect()
}

// ----- KT-13: the engine's own names ----------------------------------------

#[test]
fn a_phone_cannot_name_anything_in_the_engines_namespace() {
    let w = World::new("namespace");
    let names = [
        ".kiwi-tmp/IMG.jpg",
        ".KIWI-TMP-00112233aabbccdd-0-0123456789abcdef.part",
        "Album/.kiwi-tmp-00112233aabbccdd-0-0123456789abcdef.part",
        ".kiwi-store/id",
        ".Kiwi-Store/second-id",
        ".kiwi-anything-at-all",
    ];
    let mut hashes = Vec::new();
    {
        let store = w.open();
        for (i, name) in names.iter().enumerate() {
            let bytes = data(70 + i as u64, 2_000);
            let receipt = put(&store, name, &bytes);
            // Every component that came from the phone and began with
            // ".kiwi-" got a "_" in front, at whatever depth.
            for part in receipt.rel_path.split('/') {
                assert!(
                    !part.to_lowercase().starts_with(".kiwi-"),
                    "{name:?} was stored as {:?}",
                    receipt.rel_path
                );
            }
            hashes.push(ContentHash::of_bytes(&bytes));
        }
    }
    // The clean-up at the next start does not take any of them for debris.
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.orphan_temps_removed, 0);
    assert_eq!(report.unowned_temp_count, 0);
    assert_eq!(w.files().len(), names.len());
    for hash in &hashes {
        assert!(store
            .is_safely_stored(&phone(), hash)
            .unwrap()
            .is_verified());
    }
}

// ----- KT-13: the clean-up ---------------------------------------------------

#[test]
fn a_temp_file_of_another_ledger_is_never_deleted() {
    // A real temp file, with a real tag: but the tag of another ledger.
    let other = World::new("foreign-tag-source");
    let foreign = {
        let store = other.open();
        let mut incoming = store.begin_file(request(&phone(), NAME, &bytes())).unwrap();
        incoming.write(&bytes()[..5_000]).unwrap();
        incoming.simulate_crash().unwrap()
    };
    let w = World::new("foreign-tag");
    {
        let store = w.open();
        put(&store, NAME, &bytes());
    }
    let planted = w.path("Pixel 8/DCIM").join(file_name(&foreign));
    std::fs::copy(&foreign, &planted).unwrap();

    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.orphan_temps_removed, 0);
    assert_eq!(
        report.unowned_temps,
        vec![format!("Pixel 8/DCIM/{}", file_name(&foreign))]
    );
    assert_eq!(std::fs::read(&planted).unwrap(), &bytes()[..5_000]);
    // In its own store it is debris, and goes.
    drop(other.open());
    assert!(!foreign.exists());
}

#[test]
fn a_committed_file_whose_rename_was_lost_gets_its_name_back() {
    // A drive acknowledges a flush it has not done; the power fails; the
    // ledger has the commit, the directory does not have the rename. The
    // verified bytes are on the disk under the temp name. (The old clean-up
    // deleted every file with a temp name: the only copy on the PC.)
    let w = World::new("lost-rename");
    let (receipt, temp) = {
        let store = w.open();
        w.fs.reset_counters();
        let receipt = put(&store, NAME, &bytes());
        (receipt, temps_created(&w).remove(0))
    };
    assert!(!temp.exists());
    std::fs::rename(&receipt.abs_path, &temp).unwrap();
    assert_eq!(
        w.files(),
        vec![format!("Pixel 8/DCIM/{}", file_name(&temp))]
    );

    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.renames_recreated, vec![STORED]);
    assert_eq!(report.orphan_temps_removed, 0);
    assert_eq!((report.newly_missing, report.newly_changed), (0, 0));
    assert_eq!(w.files(), vec![STORED]);
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes());
    assert!(store.final_move_block().unwrap().is_none());
    assert!(store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    assert!(store
        .events_after(0, 10_000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "rename_recreated" && e.file_id == Some(receipt.file_id)));
}

#[test]
fn a_temp_file_is_hashed_before_it_is_deleted_while_a_file_of_its_size_is_missing() {
    let w = World::new("hash-first");
    let other = data(62, 40_000); // same size, other content
    let (receipt, temp) = {
        let store = w.open();
        let receipt = put(&store, NAME, &bytes());
        let mut incoming = store
            .begin_file(request(&phone(), "DCIM/b.jpg", &other))
            .unwrap();
        incoming.write(&other).unwrap();
        (receipt, incoming.simulate_crash().unwrap())
    };
    // The committed file is really gone (somebody deleted it).
    std::fs::remove_file(&receipt.abs_path).unwrap();

    w.fs.reset_counters();
    let store = w.open();
    let log = w.fs.log();
    let read = log
        .iter()
        .position(|(op, path)| *op == Op::ReadVerify && *path == temp)
        .expect("the temp file must be read before anything is decided");
    let removed = log
        .iter()
        .position(|(op, path)| *op == Op::RemoveFile && *path == temp)
        .expect("it is not the missing file, so it goes");
    assert!(read < removed);
    let report = store.recovery_report().unwrap();
    assert_eq!(report.orphan_temps_removed, 1);
    assert!(report.renames_recreated.is_empty());
    assert_eq!(report.newly_missing, 1);
    assert!(w.files().is_empty());
    assert!(store.final_move_block().unwrap().is_some());

    // With no file missing, a temp file is not read at all: it is simply debris.
    let w = World::new("hash-first-control");
    let temp = {
        let store = w.open();
        put(&store, NAME, &bytes());
        let mut incoming = store
            .begin_file(request(&phone(), "DCIM/b.jpg", &other))
            .unwrap();
        incoming.write(&other).unwrap();
        incoming.simulate_crash().unwrap()
    };
    w.fs.reset_counters();
    let store = w.open();
    assert_eq!(store.recovery_report().unwrap().orphan_temps_removed, 1);
    assert!(!w
        .fs
        .log()
        .iter()
        .any(|(op, path)| *op == Op::ReadVerify && *path == temp));
    assert_eq!(w.files(), vec![STORED]);
}

#[test]
fn every_file_the_engine_ever_deletes_is_one_of_its_own_temp_files() {
    let w = World::new("only-temps");
    let disk = w.disk("usb");
    let mut committed: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    {
        let store = w.open();
        store.add_mirror(&disk, "USB").unwrap();
        for i in 0..4u64 {
            let bytes = data(80 + i, 6_000 + i as usize);
            let receipt = put(&store, &format!("DCIM/{i}.jpg"), &bytes);
            committed.push((receipt.abs_path, bytes));
        }
        // An aborted transfer, one with a wrong hash, one that dies.
        let junk = data(90, 3_000);
        let mut aborted = store.begin_file(request(&phone(), "x.bin", &junk)).unwrap();
        aborted.write(&junk[..1_000]).unwrap();
        aborted.abort();
        let mut wrong = store.begin_file(request(&phone(), "y.bin", &junk)).unwrap();
        wrong.write(&junk).unwrap();
        assert!(wrong
            .finish(Some(ContentHash::of_bytes(b"not this")))
            .is_err());
        let mut dying = store.begin_file(request(&phone(), "z.bin", &junk)).unwrap();
        dying.write(&junk[..2_000]).unwrap();
        dying.simulate_crash().unwrap();
        // A mirror run in which every copy fails and is cleaned up.
        w.fs.inject(When::Every(Op::Sync), Action::Fail(ErrorKind::Other));
        let run = store.run_mirror(&CancelToken::new()).unwrap();
        assert_eq!(run.mirrors[0].failed, 4);
        w.fs.clear_rules();
    }
    // Look-alikes that are not the engine's, on both disks.
    let look_alike = ".kiwi-tmp-00000000deadbeef-0-00000000deadbeef.part";
    std::fs::write(w.path("Pixel 8/DCIM").join(look_alike), b"somebody's").unwrap();
    std::fs::write(disk.join(look_alike), b"somebody's").unwrap();
    {
        let store = w.open(); // recovery
        store.clear_final_move_block("test").unwrap();
        store.run_mirror(&CancelToken::new()).unwrap();
        // Damage on both disks, found and repaired.
        corrupt_silently(&committed[0].0);
        corrupt_silently(&disk.join("Pixel 8/DCIM/1.jpg"));
        store
            .integrity_scan(&Default::default(), &CancelToken::new())
            .unwrap();
        let scan = store
            .scan_mirror(&Default::default(), &CancelToken::new())
            .unwrap();
        assert_eq!(scan.destination_repaired, 1);
        assert_eq!(scan.mirrors[0].repaired, 1);
    }

    let tags: HashSet<String> = {
        let conn = rusqlite::Connection::open(w.ledger_file()).unwrap();
        let mut stmt = conn.prepare("SELECT tag FROM temp_tags").unwrap();
        let tags = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        tags
    };
    let stored: HashSet<PathBuf> = committed.iter().map(|(path, _)| path.clone()).collect();
    let mut deletions = 0;
    for (op, path) in w.fs.log() {
        if op != Op::RemoveFile {
            continue;
        }
        deletions += 1;
        let name = file_name(&path);
        let tag = name
            .strip_prefix(".kiwi-tmp-")
            .and_then(|rest| rest.strip_suffix(".part"))
            .and_then(|middle| middle.split('-').next())
            .unwrap_or_else(|| panic!("the engine deleted {path:?}, which is not a temp file"));
        assert!(
            tags.contains(tag),
            "the engine deleted {path:?}, whose tag is not its own"
        );
        assert!(!stored.contains(&path));
    }
    assert!(
        deletions >= 7,
        "the scenario must really delete: {deletions}"
    );
    // Nothing that was ever given a final name is gone, on either disk,
    // damaged files included; and the look-alikes are where they were.
    for (path, _) in &committed {
        assert!(path.exists(), "{path:?}");
    }
    for (path, bytes) in &committed[1..] {
        assert_eq!(&std::fs::read(path).unwrap(), bytes);
    }
    assert!(w.path("Pixel 8/DCIM").join(look_alike).exists());
    assert!(disk.join(look_alike).exists());
}

// ----- KT-13: the rename is made durable and confirmed -----------------------

#[test]
fn the_new_name_is_flushed_and_confirmed_before_it_is_recorded() {
    let w = World::new("durable-order");
    let store = w.open();
    w.fs.reset_counters();
    let receipt = put(&store, NAME, &bytes());
    assert!(receipt.dir_synced);
    let log = w.fs.log();
    let at = |op: Op, path: &std::path::Path| {
        log.iter()
            .rposition(|(o, p)| *o == op && p == path)
            .unwrap_or_else(|| panic!("{op:?} on {path:?} never happened: {log:?}"))
    };
    let final_path = receipt.abs_path.as_path();
    let rename = at(Op::Rename, final_path);
    let flush_file = at(Op::SyncFile, final_path);
    let flush_dir = at(Op::SyncDir, final_path.parent().unwrap());
    let resolved = at(Op::Resolve, final_path);
    let reread = at(Op::ReadVerify, final_path);
    let record = log
        .iter()
        .position(|(op, _)| *op == Op::Checkpoint(Checkpoint::BeforeLedgerRecord))
        .unwrap();
    assert!(rename < flush_file, "{log:?}");
    assert!(flush_file < flush_dir);
    assert!(flush_dir < resolved && resolved < reread);
    assert!(reread < record, "the ledger is told last");
}

#[test]
fn a_file_that_is_not_there_or_not_right_after_the_rename_is_not_recorded() {
    // Gone after the rename.
    let w = World::new("gone-after-rename");
    let store = w.open();
    let final_path = w.path(STORED);
    let target = final_path.clone();
    w.fs.inject(
        When::Nth(Op::SyncDir, 0),
        Action::before(move |_| std::fs::remove_file(&target).unwrap()),
    );
    match try_put(&store, &phone(), NAME, &bytes()) {
        Err(StoreError::RenameNotConfirmed { path }) => assert_eq!(path, final_path),
        other => panic!("expected RenameNotConfirmed, got {other:?}"),
    }
    assert_eq!(store.stats().unwrap().files_committed, 0);
    assert!(w.files().is_empty());

    // A bit flips between the rename and the look.
    let w = World::new("flip-after-rename");
    let store = w.open();
    let final_path = w.path(STORED);
    let target = final_path.clone();
    w.fs.inject(
        When::Nth(Op::SyncDir, 0),
        Action::before(move |_| corrupt_silently(&target)),
    );
    assert!(matches!(
        try_put(&store, &phone(), NAME, &bytes()),
        Err(StoreError::DiskVerifyMismatch { .. })
    ));
    // Nothing was recorded, so nobody is told the file is safe. The damaged
    // file is not the engine's to delete.
    assert_eq!(store.stats().unwrap().files_committed, 0);
    assert!(!store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    assert_eq!(w.files(), vec![STORED]);
    // The phone sends it again: a good copy is stored next to it.
    let retry = put(&store, NAME, &bytes());
    assert_eq!(retry.outcome, CommitOutcome::Stored);
    assert_eq!(retry.rel_path, "Pixel 8/DCIM/a (2).jpg");
    assert!(store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
}

#[test]
fn where_nothing_can_be_deleted_a_missing_flush_does_not_fail_the_copy() {
    // A copy-only destination whose file system cannot flush a directory.
    let mut w = World::new("copy-only-flush");
    w.volume = Some(usb_ntfs(9));
    let store = w.open();
    w.fs.inject(
        When::Every(Op::SyncDir),
        Action::Fail(ErrorKind::Unsupported),
    );
    let receipt = put(&store, NAME, &bytes());
    assert!(!receipt.dir_synced, "the receipt says so");
    assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes());
}

#[test]
fn a_name_that_was_not_flushed_is_flushed_before_a_deletion_is_confirmed() {
    let mut w = World::new("flush-at-verify");
    // Stored while the disk counted as external, and its directory could not
    // be flushed.
    w.volume = Some(usb_ntfs(9));
    {
        let store = w.open();
        w.fs.inject(
            When::Every(Op::SyncDir),
            Action::Fail(ErrorKind::Unsupported),
        );
        assert!(!put(&store, NAME, &bytes()).dir_synced);
        w.fs.clear_rules();
    }
    // Later the same folder is on a disk that may confirm deletions.
    w.volume = Some(fixed_ntfs());
    w.clock.advance_hours(25);
    let store = w.open();
    w.fs.inject(
        When::Every(Op::SyncFile),
        Action::Fail(ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::NotVerified(
            NotVerifiedReason::NameNotFlushed(_)
        ))
    ));
    w.fs.clear_rules();
    w.fs.reset_counters();
    assert!(verify(&store, &hash(), 1).is_ok());
    assert_eq!((w.fs.count(Op::SyncFile), w.fs.count(Op::SyncDir)), (1, 1));
    // Once flushed, it is on record and is not done again.
    w.fs.reset_counters();
    assert!(verify(&store, &hash(), 1).is_ok());
    assert_eq!((w.fs.count(Op::SyncFile), w.fs.count(Op::SyncDir)), (0, 0));
}

// ----- KT-13: what is never taken for a stored copy ---------------------------

#[test]
fn a_hidden_file_is_never_taken_for_a_stored_copy() {
    if !cfg!(windows) {
        return; // The hidden attribute is a Windows concept.
    }
    let w = World::new("hidden");
    let store = w.open();
    std::fs::create_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    // Identical content already at the target path, but hidden: something
    // else put it there and may take it away again.
    std::fs::write(w.path(STORED), bytes()).unwrap();
    let hide = |flag: &str| {
        let status = std::process::Command::new("attrib")
            .arg(flag)
            .arg(w.path(STORED))
            .status()
            .unwrap();
        assert!(status.success());
    };
    hide("+h");
    let receipt = put(&store, NAME, &bytes());
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/DCIM/a (2).jpg");
    // The same file, visible, would have been recorded as it is.
    hide("-h");
    let w2 = World::new("hidden-control");
    let store = w2.open();
    std::fs::create_dir_all(w2.path("Pixel 8/DCIM")).unwrap();
    std::fs::write(w2.path(STORED), bytes()).unwrap();
    assert_eq!(
        put(&store, NAME, &bytes()).outcome,
        CommitOutcome::AlreadyPresent
    );
}

#[test]
fn the_scan_never_adopts_a_file_it_finds_elsewhere() {
    let w = World::new("no-adoption");
    let store = w.open();
    let receipt = put(&store, NAME, &bytes());
    // The file is renamed behind the engine's back (as ransomware would).
    std::fs::rename(&receipt.abs_path, w.path("Pixel 8/DCIM/a.jpg.locked")).unwrap();
    let scan = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!((scan.missing, scan.rename_suspects), (1, 1));
    // The record still names the path it was committed under, and says the
    // file is missing: nothing was "followed".
    let record = store.records(&phone(), &hash()).unwrap().remove(0);
    assert_eq!(record.rel_path, STORED);
    assert_eq!(record.state, FileState::Missing);
    assert!(!store
        .is_safely_stored(&phone(), &hash())
        .unwrap()
        .is_verified());
    assert_eq!(
        store.final_move_block().unwrap().unwrap().kind,
        BlockKind::IntegrityProblems
    );
}

// ----- KT-17: shell-active names ---------------------------------------------

#[test]
fn shell_active_files_are_stored_under_an_inert_name() {
    let w = World::new("shell-active");
    let store = w.open();
    let cases = [
        ("Docs/evil.url", "Pixel 8/Docs/evil.url.kiwi-blocked"),
        ("desktop.ini", "Pixel 8/desktop.ini.kiwi-blocked"),
        ("Shortcut.LNK", "Pixel 8/Shortcut.LNK.kiwi-blocked"),
        ("a.library-ms", "Pixel 8/a.library-ms.kiwi-blocked"),
        (
            "Bin.{645FF040-5081-101B-9F08-00AA002F954E}",
            "Pixel 8/Bin.{645FF040-5081-101B-9F08-00AA002F954E}.kiwi-blocked",
        ),
    ];
    for (i, (name, stored)) in cases.iter().enumerate() {
        let bytes = data(100 + i as u64, 1_500);
        let receipt = put(&store, name, &bytes);
        assert_eq!(receipt.rel_path, *stored);
        assert!(receipt.neutralised);
        // The content is untouched, and the ledger keeps the phone's name.
        assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes);
        let record = store.records(&phone(), &receipt.hash).unwrap().remove(0);
        assert_eq!(record.source_name, *name);
        // Sending it again is still idempotent.
        assert_eq!(
            put(&store, name, &bytes).outcome,
            CommitOutcome::AlreadyPresent
        );
    }
    // Directories are neutralised too.
    let inside = put(&store, "Trip.lnk/IMG.jpg", b"jpeg");
    assert_eq!(inside.rel_path, "Pixel 8/Trip.lnk.kiwi-blocked/IMG.jpg");
    assert!(!inside.neutralised, "the file's own name was not changed");
    // Another file of the same name: the number goes before the suffix.
    assert_eq!(
        put(&store, "Docs/evil.url", b"other content").rel_path,
        "Pixel 8/Docs/evil.url (2).kiwi-blocked"
    );
    // Ordinary files are not touched, and a name that already carries the
    // suffix is nothing special.
    assert!(!put(&store, "DCIM/photo.jpg", b"photo").neutralised);
    let already = put(&store, "x.kiwi-blocked", b"x");
    assert_eq!(already.rel_path, "Pixel 8/x.kiwi-blocked");
    assert!(!already.neutralised);

    // Nothing on the disk has a name Explorer would act on.
    for file in w.files() {
        for part in file.split('/') {
            assert!(!is_shell_active(part), "{file}");
        }
    }
    assert!(w
        .files()
        .iter()
        .all(|f| !f.to_lowercase().ends_with(".url")));
}

// ----- KT-14: destinations that must not hold an only copy --------------------

fn copy_only_reason(store: &kiwi_store::Store) -> CopyOnlyReason {
    match store.destination().final_move_support() {
        FinalMoveSupport::CopyOnly(reason) => reason.clone(),
        FinalMoveSupport::Supported => panic!("the destination must be copy-only"),
    }
}

#[test]
fn a_destination_inside_a_synced_folder_is_copy_only() {
    let cases = [
        (".dropbox", false, SyncProvider::Dropbox),
        (".dropbox.cache", true, SyncProvider::Dropbox),
        (".tmp.driveupload", true, SyncProvider::GoogleDrive),
        (".owncloudsync.log", false, SyncProvider::Nextcloud),
        (".stfolder", true, SyncProvider::Syncthing),
        (".sync/ID", false, SyncProvider::Resilio),
    ];
    for (i, (marker, is_dir, provider)) in cases.into_iter().enumerate() {
        let w = World::new(&format!("sync-{i}"));
        // The marker sits in a folder above the destination, where the sync
        // program keeps it; for every other case in the destination itself.
        let holder = if i % 2 == 0 {
            std::fs::canonicalize(&w.base).unwrap()
        } else {
            w.root.clone()
        };
        let path = marker.split('/').fold(holder, |p, part| p.join(part));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        if is_dir {
            std::fs::create_dir(&path).unwrap();
        } else {
            std::fs::write(&path, b"").unwrap();
        }

        let store = w.open();
        assert_eq!(
            copy_only_reason(&store),
            CopyOnlyReason::SyncFolder(provider),
            "{marker}"
        );
        assert!(
            store.destination().warnings().iter().any(
                |w| matches!(w, DestinationWarning::SyncFolder { provider: p, .. } if *p == provider)
            ),
            "{marker}: {:?}",
            store.destination().warnings()
        );
        // Copying works as usual.
        let receipt = put(&store, NAME, &bytes());
        assert_eq!(std::fs::read(&receipt.abs_path).unwrap(), bytes());
        drop(store);
        // A deletion is never confirmed.
        w.clock.advance_hours(25);
        let store = w.open();
        assert!(
            matches!(
                verify(&store, &hash(), 1),
                Err(DeletionDenied::Unsupported(CopyOnlyReason::SyncFolder(p))) if p == provider
            ),
            "{marker}"
        );
    }
}

#[test]
fn a_sync_program_pointed_at_the_folder_later_is_noticed_at_the_next_question() {
    let w = World::new("sync-later");
    {
        let store = w.open();
        assert!(store.destination().supports_final_move());
        assert!(store.destination().warnings().is_empty());
        put(&store, NAME, &bytes());
    }
    w.clock.advance_hours(25);
    let store = w.open();
    assert!(verify(&store, &hash(), 1).is_ok());
    // The user adds the folder to Dropbox while the program is running.
    std::fs::write(w.root.join(".dropbox"), b"").unwrap();
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Unsupported(CopyOnlyReason::SyncFolder(
            SyncProvider::Dropbox
        )))
    ));
}

#[test]
fn known_sync_roots_and_folders_the_system_empties_are_copy_only() {
    // A sync root known from the environment (OneDrive has no marker file).
    let mut w = World::new("env-roots");
    let base = std::fs::canonicalize(&w.base).unwrap();
    w.hazards = HazardEnv {
        sync_roots: vec![(SyncProvider::OneDrive, base.clone())],
        ceiling: Some(base.clone()),
        ..HazardEnv::default()
    };
    assert_eq!(
        copy_only_reason(&w.open()),
        CopyOnlyReason::SyncFolder(SyncProvider::OneDrive)
    );
    // A temp folder.
    w.hazards = HazardEnv {
        managed: vec![(ManagedFolder::Temp, base.clone())],
        ceiling: Some(base.clone()),
        ..HazardEnv::default()
    };
    assert_eq!(
        copy_only_reason(&w.open()),
        CopyOnlyReason::ManagedFolder(ManagedFolder::Temp)
    );

    // Any user's Downloads folder, and the recycle bin, by their place.
    for (i, (sub, kind)) in [
        ("Users/someone/Downloads/Kiwi", ManagedFolder::Downloads),
        ("$RECYCLE.BIN/S-1-5-21", ManagedFolder::RecycleBin),
    ]
    .into_iter()
    .enumerate()
    {
        let mut w = World::new(&format!("managed-{i}"));
        let root = sub.split('/').fold(w.base.clone(), |p, part| p.join(part));
        std::fs::create_dir_all(&root).unwrap();
        w.root = std::fs::canonicalize(&root).unwrap();
        let store = w.open();
        assert_eq!(
            copy_only_reason(&store),
            CopyOnlyReason::ManagedFolder(kind),
            "{sub}"
        );
        put(&store, NAME, &bytes());
        drop(store);
        w.clock.advance_hours(25);
        assert!(matches!(
            verify(&w.open(), &hash(), 1),
            Err(DeletionDenied::Unsupported(CopyOnlyReason::ManagedFolder(
                _
            )))
        ));
    }
}

#[cfg(windows)]
fn let_everyone_write(dir: &std::path::Path) {
    let plain = dir.to_string_lossy().trim_start_matches(r"\\?\").to_owned();
    let status = std::process::Command::new("icacls")
        .arg(&plain)
        .args(["/grant", "*S-1-1-0:(OI)(CI)M"])
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn let_everyone_write(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777)).unwrap();
}

#[test]
fn a_folder_others_may_write_to_is_copy_only_until_it_is_made_private() {
    let mut w = World::new("access-list");
    w.hazards.check_access = true;
    let_everyone_write(&w.root);

    let store = w.open();
    assert_eq!(copy_only_reason(&store), CopyOnlyReason::WritableByOthers);
    let principals = store
        .destination()
        .warnings()
        .iter()
        .find_map(|w| match w {
            DestinationWarning::WritableByOthers { principals } => Some(principals.clone()),
            _ => None,
        })
        .expect("the warning names who else may write");
    assert!(
        principals
            .iter()
            .any(|p| p.to_lowercase().contains("everyone")),
        "{principals:?}"
    );
    put(&store, NAME, &bytes());
    drop(store);
    w.clock.advance_hours(25);
    let store = w.open();
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Unsupported(
            CopyOnlyReason::WritableByOthers
        ))
    ));
    drop(store);

    // "Make this folder private to my account."
    Destination::make_private(&w.root).unwrap();
    let store = w.open();
    assert!(
        !store
            .destination()
            .warnings()
            .iter()
            .any(|w| matches!(w, DestinationWarning::WritableByOthers { .. })),
        "{:?}",
        store.destination().warnings()
    );
    assert!(store.destination().supports_final_move());
    assert!(verify(&store, &hash(), 1).is_ok());
    // The check is repeated at every question: the folder is opened up again
    // while the program runs.
    let_everyone_write(&w.root);
    assert!(matches!(
        verify(&store, &hash(), 1),
        Err(DeletionDenied::Unsupported(
            CopyOnlyReason::WritableByOthers
        ))
    ));
}
