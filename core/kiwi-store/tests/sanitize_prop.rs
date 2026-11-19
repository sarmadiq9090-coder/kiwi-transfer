//! Property tests: whatever a peer sends as a name, the sanitised path stays
//! inside the root and consists only of plain, portable file names.
//!
//! The checker in this file is written independently of the sanitiser (it
//! states what "safe" means; it does not call the code under test to decide).

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kiwi_store::sanitize::{collision_key, MAX_COMPONENT_UTF16, MAX_DEPTH};
use kiwi_store::template::{CivilDate, Template, TemplateContext};
use kiwi_store::{sanitize_component, sanitize_rel_path, SafeName, SafeRelPath, SanitizeError};
use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

/// Pieces that file-name attacks are made of, plus ordinary text.
const VOCABULARY: &[&str] = &[
    "..",
    ".",
    "...",
    "/",
    "\\",
    "//",
    "\\\\",
    "\\\\?\\",
    "\\\\.\\",
    "?\\",
    "C:",
    "c:",
    "Z:\\",
    ":",
    "::$DATA",
    ":$I30",
    "CON",
    "con",
    "PRN",
    "AUX",
    "nul",
    "NUL.txt",
    "COM1",
    "com9",
    "LPT1",
    "LPT0",
    "COM\u{b9}",
    "CONIN$",
    "CLOCK$",
    "aux.",
    " ",
    "  ",
    "\t",
    "\n",
    "\r",
    "\0",
    "\u{1b}",
    "\u{7f}",
    "\u{85}",
    "\u{a0}",
    "\u{3000}",
    "\u{202e}",
    "\u{202d}",
    "\u{2066}",
    "\u{200b}",
    "\u{200d}",
    "\u{feff}",
    "\u{fffe}",
    "\u{2028}",
    "e\u{301}",
    "\u{e9}",
    "\u{fb01}",
    "\u{df}",
    "\u{130}",
    "\u{3a9}",
    "\u{212b}",
    "\u{212a}",
    "\u{1112}\u{1161}\u{11ab}",
    "\u{1f600}",
    "\u{1f468}\u{200d}\u{1f469}",
    ".kiwi-tmp-",
    ".KIWI-",
    ".kiwi-store",
    ".part",
    "a",
    "B",
    "photo",
    "IMG_0001",
    ".jpg",
    ".JPG",
    ".tar.gz",
    "~1",
    " (2)",
    "*",
    "?",
    "\"",
    "<",
    ">",
    "|",
    "%",
    "$",
    "&",
    "'",
    ";",
    "\u{635}\u{648}\u{631}\u{629}",
    "\u{5e9}\u{5dc}\u{5d5}\u{5dd}",
    "\u{5199}\u{771f}",
    "\u{ff1a}",
    "\u{ff0f}",
    "\u{2215}",
    "\u{ff0e}\u{ff0e}",
];

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => prop::sample::select(VOCABULARY).prop_map(str::to_owned),
        2 => prop::collection::vec(any::<char>(), 0..6).prop_map(|v| v.into_iter().collect::<String>()),
        1 => (prop::sample::select(vec!['a', '.', ' ', '\u{e9}', '\u{1f600}', '\u{301}', '_', '/']), 1usize..300)
            .prop_map(|(c, n)| std::iter::repeat_n(c, n).collect::<String>()),
    ]
}

/// A hostile or merely unusual name.
fn nasty_name() -> impl Strategy<Value = String> {
    prop::collection::vec(fragment(), 0..12).prop_map(|v| v.concat())
}

/// What "a safe file name" means, stated from scratch.
fn check_component(c: &str) -> Result<(), String> {
    let fail = |why: &str| Err(format!("{why}: {c:?}"));
    if c.is_empty() {
        return fail("empty");
    }
    if c == "." || c == ".." {
        return fail("dot component");
    }
    for ch in c.chars() {
        if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            return fail("character that is illegal or special on Windows");
        }
        let u = ch as u32;
        if u < 0x20 || (0x7f..=0x9f).contains(&u) {
            return fail("control character");
        }
        if (0x202a..=0x202e).contains(&u) || (0x2066..=0x2069).contains(&u) {
            return fail("bidirectional override");
        }
    }
    if c.ends_with('.') || c.ends_with(' ') {
        return fail("trailing dot or space");
    }
    if c.encode_utf16().count() > 255 {
        return fail("longer than NTFS allows");
    }
    if c.encode_utf16().count() > MAX_COMPONENT_UTF16 {
        return fail("longer than the engine's own limit");
    }
    let base = c
        .split('.')
        .next()
        .unwrap()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let numbered = |prefix: &str| {
        base.strip_prefix(prefix).is_some_and(|rest| {
            let mut it = rest.chars();
            matches!(
                (it.next(), it.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    };
    if matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || numbered("COM")
        || numbered("LPT")
    {
        return fail("reserved device name");
    }
    if c.to_lowercase().starts_with(".kiwi-") {
        return fail("the engine's reserved prefix");
    }
    if c.nfc().collect::<String>() != c {
        return fail("not NFC");
    }
    Ok(())
}

fn check_path(p: &SafeRelPath) -> Result<(), String> {
    if p.is_empty() || p.depth() > MAX_DEPTH {
        return Err(format!("bad depth {}", p.depth()));
    }
    for c in p.components() {
        check_component(c.as_str())?;
    }
    Ok(())
}

/// Joins the path under a root and checks, with the standard library's own
/// path parser, that it is the root plus exactly the expected names.
fn check_under_root(p: &SafeRelPath, root: &Path) -> Result<(), String> {
    let full = p.under(root);
    if !full.starts_with(root) {
        return Err(format!("{full:?} does not start with {root:?}"));
    }
    let tail: Vec<Component<'_>> = full.components().skip(root.components().count()).collect();
    if tail.len() != p.depth() {
        return Err(format!(
            "{full:?} has {} components below the root, expected {}",
            tail.len(),
            p.depth()
        ));
    }
    for (component, expected) in tail.iter().zip(p.components()) {
        match component {
            Component::Normal(name) if name.to_str() == Some(expected.as_str()) => {}
            other => {
                return Err(format!(
                    "component {other:?} is not the plain name {expected:?}"
                ))
            }
        }
    }
    Ok(())
}

fn roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![
            PathBuf::from(r"C:\dest root"),
            PathBuf::from(r"\\?\C:\dest root"),
            PathBuf::from(r"\\server\share\dest"),
        ]
    } else {
        vec![PathBuf::from("/dest root"), PathBuf::from("relative/root")]
    }
}

/// Characters that give a component no visible content: dots, blanks,
/// control characters and invisible formatting characters.
fn carries_nothing(c: char) -> bool {
    c == '.'
        || c.is_whitespace()
        || c.is_control()
        || matches!(
            c,
            '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200b}'
                | '\u{2060}'
                | '\u{feff}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

/// Number of cases per property; `PROPTEST_CASES` overrides the default
/// (the on-disk property runs a thirtieth of it).
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn components_of(input: &str) -> Vec<&str> {
    input.split(['/', '\\']).collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(3_000), ..ProptestConfig::default() })]

    #[test]
    fn a_sanitised_path_never_escapes_the_root(name in nasty_name()) {
        if let Ok(path) = sanitize_rel_path(&name) {
            prop_assert_eq!(check_path(&path), Ok(()), "input {:?}", name);
            for root in roots() {
                prop_assert_eq!(check_under_root(&path, &root), Ok(()), "input {:?}", name);
            }
            // The result is a fixed point: what is stored in the ledger reads back unchanged.
            let stored = path.to_slash_string();
            prop_assert_eq!(SafeRelPath::from_stored(&stored), Some(path.clone()), "input {:?}", name);
            prop_assert_eq!(sanitize_rel_path(&stored).ok(), Some(path), "input {:?}", name);
        }
    }

    #[test]
    fn structural_attacks_are_always_rejected(name in nasty_name()) {
        let result = sanitize_rel_path(&name);
        let parts = components_of(&name);
        if parts.contains(&"..") {
            prop_assert!(result.is_err(), "a '..' component was accepted: {:?} -> {:?}", name, result);
        }
        if name.contains('\0') {
            prop_assert_eq!(result.clone().err(), Some(SanitizeError::NulCharacter), "{:?}", name);
        } else {
            if name.starts_with(['/', '\\']) {
                prop_assert!(
                    matches!(result, Err(SanitizeError::AbsolutePath | SanitizeError::UncOrDevicePath)),
                    "{:?} -> {:?}",
                    name,
                    result
                );
            }
            let bytes = name.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                prop_assert_eq!(result.clone().err(), Some(SanitizeError::DriveLetter), "{:?}", name);
            }
        }
        // Components that Win32 would trim into "." or "..".
        if parts.iter().any(|p| p.len() >= 2 && p.contains("..") && p.chars().all(|c| c == '.' || c == ' ')) {
            prop_assert!(result.is_err(), "a disguised '..' was accepted: {:?} -> {:?}", name, result);
        }
    }

    #[test]
    fn rejections_are_honest(name in nasty_name()) {
        // An error must describe something that is really in the input.
        if let Err(e) = sanitize_rel_path(&name) {
            let parts = components_of(&name);
            let blank = |p: &&str| !p.is_empty() && **p != *"." && p.chars().all(carries_nothing);
            let justified = match &e {
                SanitizeError::Empty => parts.iter().all(|p| p.is_empty() || *p == "."),
                SanitizeError::InputTooLong { bytes } => *bytes == name.len() && name.len() > 16 * 1024,
                SanitizeError::NulCharacter => name.contains('\0'),
                SanitizeError::AbsolutePath => name.starts_with(['/', '\\']),
                SanitizeError::DriveLetter => name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[1] == b':',
                SanitizeError::UncOrDevicePath => name.len() >= 2 && name[..2].chars().all(|c| c == '/' || c == '\\'),
                SanitizeError::ParentTraversal => parts.iter().any(|p| blank(p) && p.matches('.').count() >= 2),
                SanitizeError::BlankComponent => parts.iter().any(blank),
                SanitizeError::TooDeep { depth } => *depth > MAX_DEPTH,
                other => panic!("unexpected error kind {other:?}"),
            };
            prop_assert!(justified, "{:?} was rejected with {:?} without cause", name, e);
        }
    }

    #[test]
    fn ordinary_names_are_not_mangled(
        stem in "[A-Za-z0-9_][A-Za-z0-9_ ()\\-]{0,40}[A-Za-z0-9_)]",
        ext in "[a-z0-9]{1,5}",
        dirs in prop::collection::vec("[A-Za-z0-9_][A-Za-z0-9_ \\-]{0,20}[A-Za-z0-9_]", 0..5),
    ) {
        // Names made of letters, digits and a few harmless marks must pass
        // through untouched, unless they happen to be reserved device names.
        let reserved = |s: &str| check_component(s).is_err();
        prop_assume!(!reserved(&stem) && !dirs.iter().any(|d| reserved(d)));
        let mut name = dirs.join("/");
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(&format!("{stem}.{ext}"));
        let path = sanitize_rel_path(&name);
        prop_assert_eq!(path.map(|p| p.to_slash_string()), Ok(name));
    }

    #[test]
    fn a_single_component_never_contains_a_separator(name in nasty_name()) {
        if let Ok(component) = sanitize_component(&name) {
            prop_assert_eq!(check_component(component.as_str()), Ok(()), "input {:?}", name);
            prop_assert_eq!(SafeName::from_stored(component.as_str()), Some(component.clone()), "input {:?}", name);
            let as_path = SafeRelPath::from_components(vec![component]);
            for root in roots() {
                prop_assert_eq!(check_under_root(&as_path, &root), Ok(()), "input {:?}", name);
            }
        } else {
            // Only empty or blank names, names carrying a NUL, and absurdly
            // long ones are refused outright; everything else is neutralised.
            prop_assert!(
                name.is_empty() || name.contains('\0') || name.len() > 16 * 1024 || name.chars().all(carries_nothing),
                "{:?} was refused",
                name
            );
        }
    }

    #[test]
    fn collision_suffixes_stay_safe(name in nasty_name(), n in 2u32..) {
        if let Ok(component) = sanitize_component(&name) {
            let renamed = component.with_collision_suffix(n);
            prop_assert_eq!(check_component(renamed.as_str()), Ok(()), "input {:?} n {}", name, n);
            prop_assert_eq!(SafeName::from_stored(renamed.as_str()), Some(renamed.clone()));
            prop_assert!(renamed.as_str().contains(&format!(" ({n})")), "{:?}", renamed);
            // Different numbers give different names.
            let other = component.with_collision_suffix(n.wrapping_add(1).max(2));
            if n != u32::MAX {
                prop_assert_ne!(other.collision_key(), renamed.collision_key());
            }
        }
    }

    #[test]
    fn collision_keys_ignore_ascii_case(name in nasty_name()) {
        if let Ok(path) = sanitize_rel_path(&name) {
            let stored = path.to_slash_string();
            let swapped: String = stored
                .chars()
                .map(|c| if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
                .collect();
            let key_of = |s: &str| s.split('/').map(collision_key).collect::<Vec<_>>().join("/");
            prop_assert_eq!(key_of(&swapped), path.collision_key());
        }
    }

    #[test]
    fn templates_never_escape_either(
        device in nasty_name(),
        phone in nasty_name(),
        template in prop::sample::select(vec![
            "{device}/{phone_dir}", "{year}/{month}/{device}", "{phone_dir}", "{device}", "{year}-{month}-{day} {device}",
            "Photos/{device}./{phone_dir}", "NUL{device}/{year}", "{device} /x", "CON{year}",
        ]),
        dated in any::<bool>(),
    ) {
        let (Ok(device), Ok(phone)) = (sanitize_component(&device), sanitize_rel_path(&phone)) else { return Ok(()) };
        let date = dated.then_some(CivilDate { year: 2024, month: 2, day: 29 });
        let phone_dir = phone.parent();
        let context = TemplateContext { device_folder: &device, date, phone_dir: &phone_dir };
        match Template::parse(template).unwrap().render(&context) {
            Ok(dir) => {
                for c in dir.components() {
                    prop_assert_eq!(check_component(c.as_str()), Ok(()), "template {:?} device {:?}", template, device);
                }
                prop_assert!(dir.is_empty() || SafeRelPath::from_stored(&dir.to_slash_string()).is_some());
            }
            Err(e) => prop_assert!(matches!(e, SanitizeError::TooDeep { .. }), "template {:?}: {:?}", template, e),
        }
    }
}

// ---------------------------------------------------------------------------
// The same property against a real file system: create the file through the
// ordinary (normalising) Windows path API and look at what actually appeared.

static CASE: AtomicU64 = AtomicU64::new(0);

fn disk_root() -> PathBuf {
    let parent = std::env::var_os("KIWI_STORE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    let root = parent.join("sanitize-prop-disk");
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn remove_all(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(3_000) / 30, ..ProptestConfig::default() })]

    #[test]
    fn on_a_real_disk_the_file_appears_exactly_where_expected(name in nasty_name()) {
        let Ok(path) = sanitize_rel_path(&name) else { return Ok(()) };
        // Keep the tree small enough to create quickly; on file systems that
        // count bytes (Linux: 255 per name) skip names they cannot hold.
        prop_assume!(path.depth() <= 12 && path.utf16_len() <= 2_000);
        if !cfg!(windows) {
            prop_assume!(path.components().iter().all(|c| c.as_str().len() <= 255));
        }
        let case_root = disk_root().join(format!("case-{}-{}", std::process::id(), CASE.fetch_add(1, Ordering::SeqCst)));
        remove_all(&case_root);
        std::fs::create_dir_all(&case_root).unwrap();
        let canonical_root = std::fs::canonicalize(&case_root).unwrap();

        // Deliberately the plain, non-verbatim root: Win32 applies all of its
        // name normalisation here (trailing dots and spaces, device names,
        // stream syntax). If the sanitiser left anything for Win32 to
        // reinterpret, the file would appear under another name or not at all.
        let target = path.under(&case_root);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, name.as_bytes()).unwrap();

        // 1. It resolves to a place inside the root.
        let resolved = std::fs::canonicalize(&target).unwrap();
        prop_assert!(resolved.starts_with(&canonical_root), "{:?} resolved to {:?}", name, resolved);

        // 2. Walking down from the root, every directory holds exactly one
        //    entry, and its name is exactly the expected component.
        let mut dir = canonical_root.clone();
        for component in path.components() {
            let entries: Vec<String> =
                std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            prop_assert_eq!(&entries, &vec![component.as_str().to_owned()], "input {:?} in {:?}", name, dir);
            dir.push(component.as_str());
        }
        // 3. The file holds what was written (it is a file, not a stream or a device).
        prop_assert_eq!(std::fs::read(&dir).unwrap(), name.as_bytes());
        prop_assert_eq!(resolved, dir);
        remove_all(&canonical_root);
    }
}
