//! Reparse points: junctions and symbolic links are never followed anywhere
//! between the root and a file. On Windows the tests create real NTFS
//! junctions (which need no privilege); on Unix they use symbolic links.

mod common;

use std::path::Path;

use common::*;
use kiwi_store::{
    BlockKind, CancelToken, CommitOutcome, ContentHash, DeletionDenied, NotVerifiedReason,
    StoreError, StoredStatus,
};

/// A path without the verbatim prefix, for handing to `cmd`.
fn plain(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
}

/// Makes `link` a directory link (junction / symlink) to `target`.
#[cfg(windows)]
fn link_dir(link: &Path, target: &Path) {
    let out = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J", &plain(link), &plain(target)])
        .output()
        .expect("cmd is available");
    assert!(
        out.status.success(),
        "mklink /J failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(is_link(&std::fs::symlink_metadata(link).unwrap()));
}

#[cfg(unix)]
fn link_dir(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// Makes `link` a file symlink to `target`. Returns false where the platform
/// refuses (Windows without Developer Mode or elevation).
#[cfg(windows)]
fn link_file(link: &Path, target: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(unix)]
fn link_file(link: &Path, target: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

fn outside_listing(w: &World) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&w.outside)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn expect_reparse(result: Result<kiwi_store::CommitReceipt, StoreError>, ends_with: &str) {
    match result {
        Err(StoreError::ReparsePoint { path }) => {
            // Compared without regard to case: the error names the path as it was asked for.
            let got = plain(&path).replace('\\', "/").to_lowercase();
            assert!(
                got.ends_with(&ends_with.to_lowercase()),
                "{path:?} should end with {ends_with}"
            );
        }
        other => panic!("expected ReparsePoint, got {:?}", other.map(|r| r.rel_path)),
    }
}

#[test]
fn a_junction_in_place_of_the_device_folder_is_refused() {
    let w = World::new("device-folder");
    let store = w.open();
    link_dir(&w.path("Pixel 8"), &w.outside);
    expect_reparse(
        try_put(&store, &phone(), "DCIM/a.jpg", b"photo"),
        "/root/Pixel 8",
    );
    expect_reparse(
        try_put(&store, &phone(), "a.jpg", b"photo"),
        "/root/Pixel 8",
    );
    // Nothing was written through the link: no directory, no temp file, no photo.
    assert!(outside_listing(&w).is_empty(), "{:?}", outside_listing(&w));
    assert_eq!(store.stats().unwrap().files_committed, 0);
}

#[test]
fn a_junction_deeper_in_the_path_is_refused() {
    let w = World::new("deeper");
    let store = w.open();
    std::fs::create_dir_all(w.path("Pixel 8/DCIM")).unwrap();
    link_dir(&w.path("Pixel 8/DCIM/Camera"), &w.outside);
    expect_reparse(
        try_put(&store, &phone(), "DCIM/Camera/a.jpg", b"photo"),
        "/Pixel 8/DCIM/Camera",
    );
    expect_reparse(
        try_put(&store, &phone(), "DCIM/Camera/Sub/Dir/a.jpg", b"photo"),
        "/Pixel 8/DCIM/Camera",
    );
    // The name differs in case only: still the junction.
    expect_reparse(
        try_put(&store, &phone(), "dcim/CAMERA/a.jpg", b"photo"),
        "/Camera",
    );
    assert!(outside_listing(&w).is_empty());
    // Paths that do not go through it are unaffected.
    assert_eq!(
        put(&store, "DCIM/Other/a.jpg", b"photo").rel_path,
        "Pixel 8/DCIM/Other/a.jpg"
    );
    assert_eq!(
        put(&store, "DCIM/b.jpg", b"photo2").rel_path,
        "Pixel 8/DCIM/b.jpg"
    );
}

#[test]
fn a_junction_that_stays_inside_the_root_is_refused_too() {
    // It would not escape the root, but it would let one path alias another.
    let w = World::new("inside");
    let store = w.open();
    std::fs::create_dir_all(w.path("Pixel 8/Real")).unwrap();
    link_dir(&w.path("Pixel 8/Alias"), &w.path("Pixel 8/Real"));
    expect_reparse(
        try_put(&store, &phone(), "Alias/a.jpg", b"photo"),
        "/Pixel 8/Alias",
    );
    assert!(std::fs::read_dir(w.path("Pixel 8/Real"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn a_directory_swapped_for_a_junction_after_the_commit_fails_every_check() {
    let w = World::new("swapped");
    let bytes = data(1, 30_000);
    let hash = ContentHash::of_bytes(&bytes);
    {
        let store = w.open();
        put(&store, "DCIM/a.jpg", &bytes);
    }
    // The folder is moved elsewhere and a junction is left in its place. The
    // file is still reachable under the same path, with the same content.
    std::fs::rename(w.path("Pixel 8/DCIM"), w.outside.join("DCIM")).unwrap();
    link_dir(&w.path("Pixel 8/DCIM"), &w.outside.join("DCIM"));
    assert_eq!(std::fs::read(w.path("Pixel 8/DCIM/a.jpg")).unwrap(), bytes);

    w.clock.advance_hours(25);
    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.reparse_points_skipped, vec!["Pixel 8/DCIM"]);

    match store.is_safely_stored(&phone(), &hash).unwrap() {
        StoredStatus::NotVerified(NotVerifiedReason::ReparsePoint(at)) => {
            assert!(
                plain(&at).replace('\\', "/").ends_with("/Pixel 8/DCIM"),
                "{at:?}"
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(store.find_duplicate(&phone(), &hash).unwrap().is_none());
    let block = store
        .final_move_block()
        .unwrap()
        .expect("a junction on the way to a stored file blocks final move");
    assert_eq!(block.kind, BlockKind::IntegrityProblems);
    assert!(block.reason.contains("junction"), "{}", block.reason);
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hash, 1),
        Err(DeletionDenied::Blocked(_))
    ));
    // Clearing the block does not make the junction acceptable; it blocks again.
    store.clear_final_move_block("test").unwrap();
    assert!(matches!(
        store.verify_for_deletion(&phone(), &hash, 1),
        Err(DeletionDenied::NotVerified(
            NotVerifiedReason::ReparsePoint(_)
        ))
    ));
    assert!(store.final_move_block().unwrap().is_some());
    // New files cannot go through it either.
    expect_reparse(
        try_put(&store, &phone(), "DCIM/b.jpg", b"x"),
        "/Pixel 8/DCIM",
    );

    // The scan reports it and does not follow it.
    let scan = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!(scan.suspicious, 1);
    assert_eq!(scan.reparse_points, 1);
    assert_eq!(
        scan.unexpected, 0,
        "files behind the junction are not walked"
    );

    // Remove the junction and put the folder back: all is well again.
    remove_tree(&w.path("Pixel 8/DCIM"));
    std::fs::rename(w.outside.join("DCIM"), w.path("Pixel 8/DCIM")).unwrap();
    store
        .clear_final_move_block("the junction was removed")
        .unwrap();
    assert!(store.verify_for_deletion(&phone(), &hash, 1).is_ok());
}

#[test]
fn a_directory_swapped_for_a_junction_between_the_check_and_the_create_is_caught() {
    use kiwi_store::testing::{Action, Op, When};
    let w = World::new("swap-race");
    let store = w.open();
    put(&store, "DCIM/first.jpg", b"first");
    let dcim = w.path("Pixel 8/DCIM");
    let moved = w.outside.join("DCIM");
    // The directory has passed every check. In the instant before the temp
    // file is created, it is moved away and a junction takes its place.
    w.fs.reset_counters();
    let (from, to) = (dcim.clone(), moved.clone());
    w.fs.inject(
        When::Nth(Op::CreateTemp, 0),
        Action::before(move |_| {
            std::fs::rename(&from, &to).unwrap();
            link_dir(&from, &to);
        }),
    );
    match try_put(&store, &phone(), "DCIM/second.jpg", b"second") {
        Err(StoreError::PathMismatch { expected, resolved }) => {
            assert!(expected.starts_with(&w.root), "{expected:?}");
            assert!(resolved.starts_with(&w.outside), "{resolved:?}");
        }
        other => panic!("expected PathMismatch, got {:?}", other.map(|r| r.rel_path)),
    }
    // The temp file that was created through the junction is gone again, and
    // nothing else was written there.
    let behind: Vec<String> = std::fs::read_dir(&moved)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(behind, vec!["first.jpg"]);
    assert_eq!(store.stats().unwrap().files_committed, 1);
    remove_tree(&dcim);
}

#[test]
fn recovery_and_scan_never_enter_a_junction() {
    let w = World::new("not-entered");
    // Outside the root: something that looks exactly like our debris, and a file.
    let bait = w.outside.join(".kiwi-tmp-1-1-0123456789abcdef.part");
    std::fs::write(&bait, b"not ours to delete").unwrap();
    std::fs::write(w.outside.join("precious.txt"), b"precious").unwrap();
    link_dir(&w.path("Linked"), &w.outside);
    std::fs::create_dir_all(w.path("Pixel 8")).unwrap();
    link_dir(&w.path("Pixel 8/Linked Too"), &w.outside);
    // A look-alike inside the root: named like debris, but not the engine's.
    std::fs::write(
        w.path("Pixel 8/.kiwi-tmp-1-2-0123456789abcdef.part"),
        b"not ours either",
    )
    .unwrap();

    let store = w.open();
    let report = store.recovery_report().unwrap();
    assert_eq!(report.orphan_temps_removed, 0);
    assert_eq!(
        report.unowned_temps,
        vec!["Pixel 8/.kiwi-tmp-1-2-0123456789abcdef.part"]
    );
    let mut skipped = report.reparse_points_skipped.clone();
    skipped.sort();
    assert_eq!(skipped, vec!["Linked", "Pixel 8/Linked Too"]);
    assert_eq!(std::fs::read(&bait).unwrap(), b"not ours to delete");
    assert_eq!(
        outside_listing(&w),
        vec![".kiwi-tmp-1-1-0123456789abcdef.part", "precious.txt"]
    );

    put(&store, "a.jpg", b"photo");
    let scan = store
        .integrity_scan(&Default::default(), &CancelToken::new())
        .unwrap();
    assert_eq!(scan.reparse_points, 2);
    assert_eq!(
        scan.unexpected, 0,
        "nothing behind a junction is listed: {:?}",
        scan.findings
    );
    assert!(
        store.final_move_block().unwrap().is_none(),
        "a stray junction that no stored file depends on does not block"
    );
    assert_eq!(std::fs::read(&bait).unwrap(), b"not ours to delete");
}

#[test]
fn the_root_itself_may_be_reached_through_a_junction() {
    // What lies above the root is the user's choice; it is resolved once.
    let w = World::new("root-via-link");
    let via = w.base.join("via");
    link_dir(&via, &w.root);
    let mut cfg = w.config();
    cfg.root = via.clone();
    let store = kiwi_store::Store::open_with_seams(cfg, w.seams()).unwrap();
    assert_eq!(store.destination().root(), w.root.as_path());
    store
        .register_device(&phone(), "Pixel 8", Default::default())
        .unwrap();
    let receipt = put(&store, "a.jpg", b"photo");
    assert!(receipt.abs_path.starts_with(&w.root));
    assert_eq!(std::fs::read(w.path("Pixel 8/a.jpg")).unwrap(), b"photo");
    drop(store);
    remove_tree(&via);
}

#[test]
fn file_links_are_never_read_adopted_or_deleted() {
    let w = World::new("file-links");
    let bytes = data(2, 10_000);
    let hash = ContentHash::of_bytes(&bytes);
    let elsewhere = w.outside.join("elsewhere.jpg");
    std::fs::write(&elsewhere, &bytes).unwrap();
    std::fs::create_dir_all(w.path("Pixel 8")).unwrap();
    if !link_file(&w.path("Pixel 8/a.jpg"), &elsewhere) {
        println!("skipped: this account may not create file symlinks (needs Developer Mode or elevation)");
        return;
    }
    // A temp-named link to a file outside the root.
    let bait = w.outside.join("bait.bin");
    std::fs::write(&bait, b"bait").unwrap();
    assert!(link_file(
        &w.path("Pixel 8/.kiwi-tmp-1-1-0123456789abcdef.part"),
        &bait
    ));

    let store = w.open();
    // Recovery does not delete through (or even delete) the link.
    assert_eq!(store.recovery_report().unwrap().orphan_temps_removed, 0);
    assert_eq!(std::fs::read(&bait).unwrap(), b"bait");

    // The name "a.jpg" is taken by a link to identical content. It is not
    // adopted (that would record a file that is not really here); the photo
    // is stored under the next name.
    let receipt = put(&store, "a.jpg", &bytes);
    assert_eq!(receipt.outcome, CommitOutcome::Stored);
    assert_eq!(receipt.rel_path, "Pixel 8/a (2).jpg");
    assert!(
        is_link(&std::fs::symlink_metadata(w.path("Pixel 8/a.jpg")).unwrap()),
        "the link is untouched"
    );

    // A stored file replaced by a link to an identical copy does not verify.
    std::fs::remove_file(w.path("Pixel 8/a (2).jpg")).unwrap();
    assert!(link_file(&w.path("Pixel 8/a (2).jpg"), &elsewhere));
    assert_eq!(
        std::fs::read(w.path("Pixel 8/a (2).jpg")).unwrap(),
        bytes,
        "through the link the content looks right"
    );
    match store.is_safely_stored(&phone(), &hash).unwrap() {
        StoredStatus::NotVerified(NotVerifiedReason::ReparsePoint(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn a_short_name_alias_of_another_folder_is_refused() {
    // With 8.3 names enabled, "LONGFO~1" is another way to say
    // "Long Folder Name For Alias". A peer must not be able to use it to write
    // into a folder under a name the engine did not choose.
    let w = World::new("short-names");
    let store = w.open();
    let long = w.path("Pixel 8/Long Folder Name For Alias");
    std::fs::create_dir_all(&long).unwrap();
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .raw_arg(format!("for %I in (\"{}\") do @echo %~sI", plain(&long)))
        .output()
        .unwrap();
    let short_path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let short_name = short_path.rsplit('\\').next().unwrap_or("").to_owned();
    if short_name.is_empty() || !short_name.contains('~') {
        println!("skipped: 8.3 short names are not generated on this volume ({short_path:?})");
        return;
    }
    println!("short name of the folder: {short_name}");
    match try_put(&store, &phone(), &format!("{short_name}/a.jpg"), b"photo") {
        Err(StoreError::PathMismatch { expected, resolved }) => {
            assert!(plain(&expected).ends_with(&short_name));
            assert!(plain(&resolved).ends_with("Long Folder Name For Alias"));
        }
        other => panic!("expected PathMismatch, got {:?}", other.map(|r| r.rel_path)),
    }
    assert!(
        std::fs::read_dir(&long).unwrap().next().is_none(),
        "nothing was written through the alias"
    );
    // The real name works.
    assert_eq!(
        put(&store, "Long Folder Name For Alias/a.jpg", b"photo").rel_path,
        "Pixel 8/Long Folder Name For Alias/a.jpg"
    );
}
