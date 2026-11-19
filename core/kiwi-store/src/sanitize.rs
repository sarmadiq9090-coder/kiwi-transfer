//! Name and path safety.
//!
//! A peer (the phone) supplies relative names. Nothing it supplies is trusted.
//! [`sanitize_rel_path`] turns such a name into a [`SafeRelPath`]: a list of
//! components each of which is a plain, portable Windows file name. The rules
//! fall into two groups.
//!
//! **Rejected** (no honest sender produces these, so the transfer layer should
//! treat them as a misbehaving peer):
//! empty names, NUL bytes, absolute paths, drive letters, UNC and device
//! paths, any `..` component, and components made only of dots, blanks or
//! invisible characters (Win32 would normalise those into `.` or `..`).
//!
//! **Neutralised** (legal on a phone, illegal or dangerous on Windows; the
//! photo must still be storable):
//! `< > : " | ? *` and control characters become `_` (this also removes the
//! `:` that selects an NTFS alternate data stream), bidirectional override and
//! zero-width formatting characters become `_`, trailing dots and spaces are
//! removed, reserved device names (`CON`, `NUL`, `COM1`, ... with or without an
//! extension) and the engine's own `.kiwi-` prefix get a leading `_`, names
//! are normalised to Unicode NFC, and over-long components are shortened while
//! keeping the extension.
//!
//! The output never needs Win32 path normalisation, so it can be appended to a
//! `\\?\` (verbatim) root as is.
//!
//! Sanitising is *necessary but not sufficient*: it is a pure function of the
//! name and knows nothing about the disk. Reparse points, 8.3 aliases and
//! existing files are handled by the store when the path is actually used.

use std::fmt;
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

/// Longest component, in UTF-16 code units, the engine will create.
///
/// NTFS allows 255. Staying below it leaves slack for other tools that append
/// their own suffixes to a name. Collision suffixes do not need the slack:
/// [`SafeName::with_collision_suffix`] shortens the stem to stay within this
/// limit.
pub const MAX_COMPONENT_UTF16: usize = 240;

/// Deepest relative path accepted, in components.
pub const MAX_DEPTH: usize = 64;

/// Longest peer-supplied name accepted, in bytes.
pub const MAX_INPUT_BYTES: usize = 16 * 1024;

/// Longest extension (including the dot, in UTF-16 units) that is preserved
/// when a component has to be shortened.
const MAX_KEPT_EXTENSION_UTF16: usize = 32;

/// Prefix reserved for the engine's own files (temp files, lock, marker).
/// Peer names starting with it are neutralised.
pub const RESERVED_PREFIX: &str = ".kiwi-";

/// Suffix appended to the name of a shell-active file. See
/// [`SafeName::neutralised`].
pub const NEUTRAL_SUFFIX: &str = ".kiwi-safe";

/// Extensions (lower case, without the dot) of the file types Windows
/// Explorer parses when a folder is merely *displayed*: shortcuts and their
/// relatives, whose icon or target may point at a remote server and make
/// Explorer authenticate to it without anybody opening anything.
pub const SHELL_ACTIVE_EXTENSIONS: &[&str] = &[
    "url",
    "lnk",
    "pif",
    "scf",
    "website",
    "library-ms",
    "search-ms",
    "searchconnector-ms",
];

/// Whole file names (lower case) Explorer treats as instructions for the
/// folder they are in.
pub const SHELL_ACTIVE_NAMES: &[&str] = &["desktop.ini", "autorun.inf"];

/// Whether a file with this name must not be stored under this name: its
/// type is shell-active (see [`SHELL_ACTIVE_EXTENSIONS`] and
/// [`SHELL_ACTIVE_NAMES`]), or it already ends in [`NEUTRAL_SUFFIX`] (which
/// is escaped by the same rule so that the scheme stays reversible).
pub fn is_shell_active(name: &str) -> bool {
    let key = collision_key(name);
    if key.ends_with(NEUTRAL_SUFFIX) || SHELL_ACTIVE_NAMES.contains(&key.as_str()) {
        return true;
    }
    match key.rfind('.') {
        Some(dot) => SHELL_ACTIVE_EXTENSIONS.contains(&&key[dot + 1..]),
        None => false,
    }
}

/// Undoes [`SafeName::neutralised`]: the name a stored file had on the phone,
/// if the stored name carries the suffix.
///
/// The scheme is: a name that [`is_shell_active`] is stored with
/// [`NEUTRAL_SUFFIX`] appended, every other name is stored unchanged. A name
/// that already ends in the suffix counts as shell-active, so no other name
/// ever ends in it, and stripping the suffix once is the exact inverse.
pub fn restore_neutralised_name(stored: &str) -> Option<&str> {
    let start = stored.len().checked_sub(NEUTRAL_SUFFIX.len())?;
    let (name, suffix) = (stored.get(..start)?, stored.get(start..)?);
    (suffix.eq_ignore_ascii_case(NEUTRAL_SUFFIX) && !name.is_empty()).then_some(name)
}

/// Why a peer-supplied name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SanitizeError {
    /// The name was empty or contained no usable component.
    #[error("the name is empty")]
    Empty,
    /// The name was longer than [`MAX_INPUT_BYTES`].
    #[error("the name is too long ({bytes} bytes)")]
    InputTooLong {
        /// Length of the rejected input.
        bytes: usize,
    },
    /// The name contained a NUL character.
    #[error("the name contains a NUL character")]
    NulCharacter,
    /// The name started with a path separator.
    #[error("absolute paths are not accepted")]
    AbsolutePath,
    /// The name started with a drive letter such as `C:`.
    #[error("drive letters are not accepted")]
    DriveLetter,
    /// The name was a UNC path (`\\server\share`) or a device path (`\\?\`, `\\.\`).
    #[error("UNC and device paths are not accepted")]
    UncOrDevicePath,
    /// The name contained a `..` component.
    #[error("parent-directory components (..) are not accepted")]
    ParentTraversal,
    /// A component consisted only of dots, blanks or invisible characters.
    #[error("a component made only of dots or blanks is not accepted")]
    BlankComponent,
    /// The name had more than [`MAX_DEPTH`] components.
    #[error("the path is nested too deeply ({depth} levels)")]
    TooDeep {
        /// Number of components in the rejected input.
        depth: usize,
    },
}

/// One sanitised path component.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeName(String);

impl SafeName {
    /// The component text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in UTF-16 code units (what NTFS counts).
    pub fn utf16_len(&self) -> usize {
        utf16_len(&self.0)
    }

    /// The key under which this name collides with others on a
    /// case-insensitive, normalisation-insensitive file system.
    pub fn collision_key(&self) -> String {
        collision_key(&self.0)
    }

    /// The deterministic alternative name used when the plain name is taken:
    /// `photo.jpg` becomes `photo (2).jpg`, `photo (3).jpg`, ...
    ///
    /// `n` values below 2 return the name unchanged. The result never exceeds
    /// [`MAX_COMPONENT_UTF16`]: the stem is shortened to make room, so the
    /// result is itself a name the sanitiser would leave untouched.
    pub fn with_collision_suffix(&self, n: u32) -> SafeName {
        if n < 2 {
            return self.clone();
        }
        let suffix = format!(" ({n})");
        let (stem, ext) = split_extension(&self.0);
        let (stem, ext) = if utf16_len(ext) + utf16_len(&suffix) < MAX_COMPONENT_UTF16 {
            (stem, ext)
        } else {
            (self.0.as_str(), "")
        };
        let budget = MAX_COMPONENT_UTF16 - utf16_len(ext) - utf16_len(&suffix);
        let kept = take_utf16(stem, budget);
        SafeName(format!("{kept}{suffix}{ext}"))
    }

    /// The name a file from a phone is stored under: unchanged, unless it is
    /// shell-active ([`is_shell_active`]), in which case [`NEUTRAL_SUFFIX`]
    /// is appended (`x.url` is stored as `x.url.kiwi-safe`) and `true` is
    /// returned with it. Windows then treats the file as an unknown type and
    /// Explorer leaves it alone. [`restore_neutralised_name`] is the inverse.
    ///
    /// An over-long name is shortened first, keeping its own extension, so
    /// that the result still fits in [`MAX_COMPONENT_UTF16`].
    pub fn neutralised(&self) -> (SafeName, bool) {
        if !is_shell_active(&self.0) {
            return (self.clone(), false);
        }
        let room = MAX_COMPONENT_UTF16 - utf16_len(NEUTRAL_SUFFIX);
        let mut name = shorten(&self.0, room);
        name.push_str(NEUTRAL_SUFFIX);
        (SafeName(name), true)
    }

    /// The n-th alternative for a name that is already in its stored form
    /// (see [`SafeName::neutralised`]): like
    /// [`SafeName::with_collision_suffix`], except that the number goes
    /// before the original extension of a neutralised name, so
    /// `x.url.kiwi-safe` becomes `x (2).url.kiwi-safe` and still restores to
    /// a shortcut name.
    pub fn stored_variant(&self, n: u32) -> SafeName {
        match restore_neutralised_name(&self.0) {
            Some(original) if n >= 2 => {
                SafeName(original.to_owned())
                    .with_collision_suffix(n)
                    .neutralised()
                    .0
            }
            _ => self.with_collision_suffix(n),
        }
    }

    /// Re-validates a name read back from the ledger or from a directory
    /// listing: it is accepted only if sanitising it changes nothing.
    pub fn from_stored(name: &str) -> Option<SafeName> {
        match sanitize_component(name) {
            Ok(safe) if safe.0 == name => Some(safe),
            _ => None,
        }
    }
}

impl fmt::Display for SafeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SafeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafeName({:?})", self.0)
    }
}

/// A sanitised relative path: zero or more [`SafeName`] components.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct SafeRelPath {
    parts: Vec<SafeName>,
}

impl SafeRelPath {
    /// The empty path (the root itself).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a path from already sanitised components.
    pub fn from_components(parts: Vec<SafeName>) -> Self {
        Self { parts }
    }

    /// The components, outermost first.
    pub fn components(&self) -> &[SafeName] {
        &self.parts
    }

    /// True for the empty path.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Number of components.
    pub fn depth(&self) -> usize {
        self.parts.len()
    }

    /// The last component, if any.
    pub fn file_name(&self) -> Option<&SafeName> {
        self.parts.last()
    }

    /// Everything except the last component.
    pub fn parent(&self) -> SafeRelPath {
        let mut parts = self.parts.clone();
        parts.pop();
        Self { parts }
    }

    /// This path with one more component.
    pub fn join(&self, name: SafeName) -> SafeRelPath {
        let mut parts = self.parts.clone();
        parts.push(name);
        Self { parts }
    }

    /// This path followed by all components of `other`.
    pub fn join_path(&self, other: &SafeRelPath) -> SafeRelPath {
        let mut parts = self.parts.clone();
        parts.extend(other.parts.iter().cloned());
        Self { parts }
    }

    /// The path with `/` separators. This is the form stored in the ledger.
    pub fn to_slash_string(&self) -> String {
        let mut s = String::new();
        for (i, p) in self.parts.iter().enumerate() {
            if i > 0 {
                s.push('/');
            }
            s.push_str(&p.0);
        }
        s
    }

    /// Collision key of the whole path (see [`SafeName::collision_key`]).
    pub fn collision_key(&self) -> String {
        let mut s = String::new();
        for (i, p) in self.parts.iter().enumerate() {
            if i > 0 {
                s.push('/');
            }
            s.push_str(&p.collision_key());
        }
        s
    }

    /// Length in UTF-16 code units including one separator between components.
    pub fn utf16_len(&self) -> usize {
        let names: usize = self.parts.iter().map(SafeName::utf16_len).sum();
        names + self.parts.len().saturating_sub(1)
    }

    /// The absolute path of this relative path under `root`.
    ///
    /// Components are appended one at a time, so the result is valid under a
    /// verbatim (`\\?\`) root, where Win32 performs no normalisation.
    pub fn under(&self, root: &Path) -> PathBuf {
        let mut p = root.to_path_buf();
        for part in &self.parts {
            p.push(&part.0);
        }
        p
    }

    /// Re-validates a path read back from the ledger: it is accepted only if
    /// it is non-empty and sanitising it changes nothing. A damaged or
    /// tampered ledger therefore cannot point the engine outside the root.
    pub fn from_stored(stored: &str) -> Option<SafeRelPath> {
        if stored.contains('\\') {
            return None;
        }
        match sanitize_rel_path(stored) {
            Ok(safe) if safe.to_slash_string() == stored => Some(safe),
            _ => None,
        }
    }
}

impl fmt::Display for SafeRelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_slash_string())
    }
}

impl fmt::Debug for SafeRelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafeRelPath({:?})", self.to_slash_string())
    }
}

/// Sanitises a peer-supplied relative path (components separated by `/` or `\`).
///
/// See the [module documentation](self) for the rules.
pub fn sanitize_rel_path(input: &str) -> Result<SafeRelPath, SanitizeError> {
    precheck(input)?;

    let bytes = input.as_bytes();
    let is_sep = |b: u8| b == b'/' || b == b'\\';
    if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) {
        return Err(SanitizeError::UncOrDevicePath);
    }
    if is_sep(bytes[0]) {
        return Err(SanitizeError::AbsolutePath);
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(SanitizeError::DriveLetter);
    }

    let mut parts = Vec::new();
    for raw in input.split(['/', '\\']) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        parts.push(clean_component(raw)?);
    }
    if parts.is_empty() {
        return Err(SanitizeError::Empty);
    }
    if parts.len() > MAX_DEPTH {
        return Err(SanitizeError::TooDeep { depth: parts.len() });
    }
    Ok(SafeRelPath { parts })
}

/// Sanitises a single name. Path separators inside it are neutralised to `_`
/// rather than splitting it, so the result is always exactly one component.
///
/// Used for device folder names and for rendered template segments.
pub fn sanitize_component(input: &str) -> Result<SafeName, SanitizeError> {
    precheck(input)?;
    clean_component(input)
}

fn precheck(input: &str) -> Result<(), SanitizeError> {
    if input.is_empty() {
        return Err(SanitizeError::Empty);
    }
    if input.len() > MAX_INPUT_BYTES {
        return Err(SanitizeError::InputTooLong { bytes: input.len() });
    }
    if input.contains('\0') {
        return Err(SanitizeError::NulCharacter);
    }
    Ok(())
}

/// Characters that are replaced by `_`.
fn is_neutralised(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\')
        || c.is_control()
        || is_invisible_format(c)
        || is_noncharacter(c)
}

/// Formatting characters that are invisible and either reorder text (used to
/// disguise extensions, e.g. `photo<RLO>gpj.exe`) or make two names look the
/// same. Joiners needed by real scripts and emoji (ZWJ, ZWNJ) and the plain
/// direction marks (LRM, RLM, ALM) are deliberately not in this list.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'      // embeddings and overrides
            | '\u{2066}'..='\u{2069}' // isolates
            | '\u{200B}'              // zero width space
            | '\u{2060}'              // word joiner
            | '\u{FEFF}'              // byte order mark / zero width no-break space
            | '\u{2028}'              // line separator
            | '\u{2029}'              // paragraph separator
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
    )
}

fn is_noncharacter(c: char) -> bool {
    let u = c as u32;
    (0xFDD0..=0xFDEF).contains(&u) || (u & 0xFFFE) == 0xFFFE
}

/// True if Win32 normalisation could turn the component into `.`/`..`/nothing,
/// or if it carries no visible content at all.
fn is_blank_component(raw: &str) -> bool {
    raw.chars()
        .all(|c| c == '.' || c.is_whitespace() || c.is_control() || is_invisible_format(c))
}

fn clean_component(raw: &str) -> Result<SafeName, SanitizeError> {
    if raw == ".." {
        return Err(SanitizeError::ParentTraversal);
    }
    if is_blank_component(raw) {
        // Covers "..", ". .", ".. ", "...", " " and friends. A lone "." never
        // reaches this function from `sanitize_rel_path`; as a single name it
        // is refused as well.
        let dots = raw.chars().filter(|c| *c == '.').count();
        return Err(if dots >= 2 {
            SanitizeError::ParentTraversal
        } else {
            SanitizeError::BlankComponent
        });
    }

    let mapped: String = raw
        .nfc()
        .map(|c| if is_neutralised(c) { '_' } else { c })
        .collect();
    let trimmed = mapped.trim_end_matches(['.', ' ']);
    let mut name = if trimmed.is_empty() {
        "_".to_owned()
    } else {
        trimmed.to_owned()
    };

    // Prefixing can lengthen the name and shortening can expose a reserved
    // name, so repeat until neither applies. Two rounds always suffice; the
    // bound is a guard, not a tuning knob.
    for _ in 0..4 {
        let before = name.clone();
        if is_reserved_device_name(&name) || has_reserved_prefix(&name) {
            name.insert(0, '_');
        }
        name = shorten(&name, MAX_COMPONENT_UTF16);
        if name == before {
            break;
        }
    }

    let name: String = name.nfc().collect();
    debug_assert!(utf16_len(&name) <= MAX_COMPONENT_UTF16);
    Ok(SafeName(name))
}

/// Reserved DOS device names. Windows matches them case-insensitively, with
/// or without an extension, and ignoring spaces before the extension.
fn is_reserved_device_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = base.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$" => true,
        _ => {
            let mut chars = upper.chars();
            let prefix: String = chars.by_ref().take(3).collect();
            let digit = chars.next();
            let rest = chars.next();
            (prefix == "COM" || prefix == "LPT")
                && rest.is_none()
                && matches!(
                    digit,
                    Some('0'..='9' | '\u{00B9}' | '\u{00B2}' | '\u{00B3}')
                )
        }
    }
}

fn has_reserved_prefix(name: &str) -> bool {
    collision_key(name).starts_with(RESERVED_PREFIX)
}

/// Splits `photo.jpg` into (`photo`, `.jpg`). A leading dot is not an
/// extension separator (`.profile` has no extension).
fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    }
}

fn shorten(name: &str, max_utf16: usize) -> String {
    if utf16_len(name) <= max_utf16 {
        return name.to_owned();
    }
    let (stem, ext) = split_extension(name);
    let (stem, ext) = if utf16_len(ext) <= MAX_KEPT_EXTENSION_UTF16 {
        (stem, ext)
    } else {
        (name, "")
    };
    let kept = take_utf16(stem, max_utf16 - utf16_len(ext));
    let kept = kept.trim_end_matches(['.', ' ']);
    let mut out = if kept.is_empty() {
        "_".to_owned()
    } else {
        kept.to_owned()
    };
    out.push_str(ext);
    // Cutting can remove the only visible character of a name that began
    // with, say, a no-break space followed by hundreds of blanks. What is left
    // would be a blank name, which this module itself refuses.
    if is_blank_component(&out) {
        out = "_".to_owned();
    }
    out
}

/// The longest prefix of `s` that fits in `budget` UTF-16 code units without
/// splitting a character.
fn take_utf16(s: &str, budget: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += c.len_utf16();
        if used > budget {
            return &s[..i];
        }
    }
    s
}

pub(crate) fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// The key under which two names are treated as the same file.
///
/// It is NFC plus full Unicode case folding (upper then lower). NTFS compares
/// with a simpler per-code-unit upper-case table, so this key treats at least
/// as many names as equal as NTFS does; erring that way only ever produces an
/// extra ` (2)` suffix, never an overwrite.
pub fn collision_key(name: &str) -> String {
    name.nfc()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .nfc()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> String {
        sanitize_rel_path(input)
            .unwrap_or_else(|e| panic!("{input:?} was rejected: {e}"))
            .to_slash_string()
    }

    fn err(input: &str) -> SanitizeError {
        match sanitize_rel_path(input) {
            Ok(p) => panic!("{input:?} was accepted as {p:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn plain_names_pass_unchanged() {
        for name in [
            "IMG_0001.jpg",
            "DCIM/Camera/IMG_0001.jpg",
            "Pictures/WhatsApp Images/IMG-20240101-WA0001.jpeg",
            ".nomedia",
            ".hidden/.profile",
            "archive.tar.gz",
            "no extension",
            " leading space.txt",
            "name with (2).jpg",
            "a~1.jpg",
            "100%.png",
            "semi;colon,comma'quote&amp.txt",
            "[brackets]{braces}.txt",
            "صورة العائلة.jpg",
            "مجلد/صورة ١٢٣.png",
            "写真/東京：夜景.jpg",
            "😀/👨\u{200D}👩\u{200D}👧.png",
            "می\u{200C}خواهم.txt",
            "עברית\u{200F}.txt",
        ] {
            assert_eq!(ok(name), name, "{name:?} should pass unchanged");
        }
    }

    #[test]
    fn structural_attacks_are_rejected() {
        use SanitizeError::*;
        let cases: &[(&str, SanitizeError)] = &[
            ("", Empty),
            (".", Empty),
            ("./", Empty),
            ("./.", Empty),
            ("a\0b", NulCharacter),
            ("photo.jpg\0.exe", NulCharacter),
            // absolute
            ("/etc/passwd", AbsolutePath),
            ("\\Windows\\System32\\x.dll", AbsolutePath),
            ("/", AbsolutePath),
            ("\\", AbsolutePath),
            // drive letters, with and without a separator (drive-relative)
            ("C:", DriveLetter),
            ("C:\\Windows\\x", DriveLetter),
            ("c:/Windows/x", DriveLetter),
            ("C:evil.txt", DriveLetter),
            ("z:..\\x", DriveLetter),
            // UNC and device namespaces
            ("\\\\server\\share\\x", UncOrDevicePath),
            ("//server/share/x", UncOrDevicePath),
            ("\\/server/share/x", UncOrDevicePath),
            ("/\\server/share/x", UncOrDevicePath),
            ("\\\\?\\C:\\x", UncOrDevicePath),
            ("\\\\.\\PhysicalDrive0", UncOrDevicePath),
            ("\\\\?\\UNC\\server\\share\\x", UncOrDevicePath),
            (
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\x",
                UncOrDevicePath,
            ),
            ("//./pipe/x", UncOrDevicePath),
            // traversal
            ("..", ParentTraversal),
            ("../x", ParentTraversal),
            ("..\\x", ParentTraversal),
            ("a/../b", ParentTraversal),
            ("a\\..\\b", ParentTraversal),
            ("a/b/..", ParentTraversal),
            ("a/./../b", ParentTraversal),
            ("DCIM/../../x", ParentTraversal),
            // things Win32 would normalise into a parent reference
            ("a/.. /b", ParentTraversal),
            ("a/..  /b", ParentTraversal),
            ("a/. ./b", ParentTraversal),
            ("a/.../b", ParentTraversal),
            ("a/..../b", ParentTraversal),
            ("a/..\t/b", ParentTraversal),
            ("a/..\u{200B}/b", ParentTraversal),
            ("a/.\u{202E}./b", ParentTraversal),
            // blank components
            (" ", BlankComponent),
            ("a/ /b", BlankComponent),
            ("a/   /b", BlankComponent),
            ("a/. /b", BlankComponent),
            ("a/\t/b", BlankComponent),
            ("a/\u{3000}/b", BlankComponent),
            ("a/\u{200B}/b", BlankComponent),
        ];
        for (input, expected) in cases {
            assert_eq!(&err(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn length_and_depth_limits() {
        let long = "a".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(err(&long), SanitizeError::InputTooLong { .. }));

        let deep = vec!["d"; MAX_DEPTH].join("/");
        assert_eq!(sanitize_rel_path(&deep).unwrap().depth(), MAX_DEPTH);
        let too_deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert!(
            matches!(err(&too_deep), SanitizeError::TooDeep { depth } if depth == MAX_DEPTH + 1)
        );
    }

    #[test]
    fn separators_and_dot_components_are_folded() {
        let cases = [
            ("a/b", "a/b"),
            ("a\\b", "a/b"),
            ("a//b", "a/b"),
            ("a\\\\b", "a/b"),
            ("a/./b", "a/b"),
            ("./a/b", "a/b"),
            ("a/b/", "a/b"),
            ("a/b\\", "a/b"),
            ("a\\b/c\\d", "a/b/c/d"),
        ];
        for (input, expected) in cases {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn illegal_characters_are_neutralised() {
        let cases = [
            ("a<b.txt", "a_b.txt"),
            ("a>b.txt", "a_b.txt"),
            ("a\"b.txt", "a_b.txt"),
            ("a|b.txt", "a_b.txt"),
            ("a?b.txt", "a_b.txt"),
            ("a*b.txt", "a_b.txt"),
            ("<>\"|?*", "______"),
            // alternate data streams
            ("photo.jpg:hidden", "photo.jpg_hidden"),
            ("photo.jpg:hidden:$DATA", "photo.jpg_hidden_$DATA"),
            ("photo.jpg::$DATA", "photo.jpg__$DATA"),
            ("dir:stream/file", "dir_stream/file"),
            ("dir/:", "dir/_"),
            (
                "Screenshot 2024-01-01 12:30:00.png",
                "Screenshot 2024-01-01 12_30_00.png",
            ),
            // a drive-like component that is not at the start is just a name
            ("dir/C:/x", "dir/C_/x"),
            (" C:/x", " C_/x"),
            // control characters: C0, DEL, C1
            ("a\tb", "a_b"),
            ("a\nb", "a_b"),
            ("a\rb", "a_b"),
            ("a\u{1}b", "a_b"),
            ("a\u{1F}b", "a_b"),
            ("a\u{7F}b", "a_b"),
            ("a\u{85}b", "a_b"),
            ("a\u{9F}b", "a_b"),
            // bidirectional overrides used to disguise an extension
            ("photo\u{202E}gpj.exe", "photo_gpj.exe"),
            ("a\u{202A}b\u{202B}c\u{202C}d\u{202D}e", "a_b_c_d_e"),
            ("a\u{2066}b\u{2067}c\u{2068}d\u{2069}e", "a_b_c_d_e"),
            // invisible characters that make two names look alike
            ("a\u{200B}b", "a_b"),
            ("a\u{2060}b", "a_b"),
            ("a\u{FEFF}b", "a_b"),
            ("\u{FEFF}name.txt", "_name.txt"),
            ("a\u{2028}b", "a_b"),
            ("a\u{2029}b", "a_b"),
            ("a\u{FFF9}b", "a_b"),
            // noncharacters
            ("a\u{FFFE}b", "a_b"),
            ("a\u{FFFF}b", "a_b"),
            ("a\u{FDD0}b", "a_b"),
            ("a\u{1FFFE}b", "a_b"),
            ("a\u{10FFFF}b", "a_b"),
        ];
        for (input, expected) in cases {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn trailing_dots_and_spaces_are_removed() {
        let cases = [
            ("name.", "name"),
            ("name..", "name"),
            ("name ", "name"),
            ("name. ", "name"),
            ("name .", "name"),
            ("name . . ", "name"),
            ("name.txt.", "name.txt"),
            ("name.txt ", "name.txt"),
            ("dir./file.", "dir/file"),
            ("dir /file ", "dir/file"),
            // a trailing dot is what makes "x." and "x" the same file on Win32
            ("a/b. /c", "a/b/c"),
            // characters that become '_' are not trailing dots or spaces
            ("name.\t", "name._"),
            ("?.", "_"),
            ("?. .", "_"),
            // other whitespace is legal and distinct on NTFS; it is kept
            ("name\u{A0}", "name\u{A0}"),
            ("name\u{3000}", "name\u{3000}"),
        ];
        for (input, expected) in cases {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn reserved_device_names_are_neutralised() {
        let reserved = [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "CONIN$",
            "CONOUT$",
            "CLOCK$",
            "COM0",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT0",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
            "COM\u{B9}",
            "COM\u{B2}",
            "COM\u{B3}",
            "LPT\u{B9}",
            "LPT\u{B2}",
            "LPT\u{B3}",
        ];
        for name in reserved {
            assert_eq!(ok(name), format!("_{name}"), "bare {name}");
            let lower = name.to_lowercase();
            assert_eq!(ok(&lower), format!("_{lower}"), "lower-case {name}");
            assert_eq!(
                ok(&format!("{name}.txt")),
                format!("_{name}.txt"),
                "{name} with extension"
            );
            assert_eq!(
                ok(&format!("{name}.tar.gz")),
                format!("_{name}.tar.gz"),
                "{name} with two extensions"
            );
            assert_eq!(
                ok(&format!("{name} .txt")),
                format!("_{name} .txt"),
                "{name} with space before extension"
            );
            assert_eq!(
                ok(&format!("dir/{name}/file")),
                format!("dir/_{name}/file"),
                "{name} as a directory"
            );
            // Trailing dots, spaces and stream syntax must not hide the name.
            assert_eq!(
                ok(&format!("{name}.")),
                format!("_{name}"),
                "{name} with trailing dot"
            );
            assert_eq!(
                ok(&format!("{name} ")),
                format!("_{name}"),
                "{name} with trailing space"
            );
            assert_eq!(
                ok(&format!("{name}. . ")),
                format!("_{name}"),
                "{name} with trailing dots and spaces"
            );
        }
        let mixed = [
            ("CoN", "_CoN"),
            ("nUl.TXT", "_nUl.TXT"),
            ("Com1.log", "_Com1.log"),
            // U+212A KELVIN SIGN is canonically 'K': NFC must run before the check.
            ("CLOC\u{212A}$", "_CLOCK$"),
        ];
        for (input, expected) in mixed {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
        // Stream syntax is neutralised first, which leaves an ordinary name.
        assert_eq!(ok("NUL:"), "NUL_");
        assert_eq!(ok("CON:stream"), "CON_stream");
    }

    #[test]
    fn names_that_only_resemble_reserved_ones_pass() {
        for name in [
            "CONSOLE",
            "CON1",
            "COM",
            "COM10",
            "COM1A",
            "LPT",
            "LPT10",
            "NULL",
            "AUXILIARY",
            "PRNT",
            "_CON",
            "CON_",
            "xCON",
            " CON",
            "CONIN",
            "CONOUT",
            "CLOCK",
            "my.CON",
            "a.NUL.txt",
            "COM\u{2074}",
            "icon",
            "nul-file",
        ] {
            assert_eq!(ok(name), name, "{name:?} should pass unchanged");
        }
    }

    #[test]
    fn engine_prefix_is_reserved() {
        let cases = [
            (".kiwi-tmp-0123.part", "_.kiwi-tmp-0123.part"),
            (".KIWI-TMP-0123.part", "_.KIWI-TMP-0123.part"),
            (".Kiwi-store", "_.Kiwi-store"),
            ("dir/.kiwi-store/id", "dir/_.kiwi-store/id"),
            (".kiwi-", "_.kiwi-"),
            // Not the reserved prefix.
            (".kiwi", ".kiwi"),
            (".kiwis-are-birds", ".kiwis-are-birds"),
            ("kiwi-tmp", "kiwi-tmp"),
            ("x.kiwi-tmp", "x.kiwi-tmp"),
        ];
        for (input, expected) in cases {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn unicode_is_normalised_to_nfc() {
        let cases = [
            // e + combining acute -> precomposed
            ("cafe\u{301}.txt", "caf\u{E9}.txt"),
            // Hangul jamo -> syllable
            ("\u{1112}\u{1161}\u{11AB}.txt", "\u{D55C}.txt"),
            // A + ring above, and the ANGSTROM SIGN singleton
            ("A\u{30A}", "\u{C5}"),
            ("\u{212B}", "\u{C5}"),
            // Arabic alef + madda above -> alef with madda
            ("\u{627}\u{653}.jpg", "\u{622}.jpg"),
            // combining marks in non-canonical order are reordered
            ("a\u{301}\u{323}", "\u{1EA1}\u{301}"),
            // compatibility forms are NOT folded (that would change names)
            ("\u{FB01}le", "\u{FB01}le"),
            ("\u{FF21}", "\u{FF21}"),
        ];
        for (input, expected) in cases {
            assert_eq!(ok(input), expected, "input {input:?}");
        }
        // NFD and NFC spellings of the same name collide.
        assert_eq!(ok("re\u{301}sume\u{301}.pdf"), ok("r\u{E9}sum\u{E9}.pdf"));
    }

    #[test]
    fn collision_keys_fold_case_and_normalisation() {
        let same = [
            ("IMG_0001.JPG", "img_0001.jpg"),
            ("Straße", "STRASSE"),
            ("ΟΔΟΣ", "οδος"),
            ("οδός", "ΟΔΌΣ"),
            ("caf\u{E9}", "CAFE\u{301}"),
            ("İstanbul", "i\u{307}stanbul"),
            ("Ǆ", "ǆ"),
            ("ﬁle", "FILE"),
        ];
        for (a, b) in same {
            assert_eq!(collision_key(a), collision_key(b), "{a:?} vs {b:?}");
        }
        let different = [
            ("a", "b"),
            ("img (2).jpg", "img.jpg"),
            ("résumé", "resume"),
            ("صورة", "صوره"),
        ];
        for (a, b) in different {
            assert_ne!(collision_key(a), collision_key(b), "{a:?} vs {b:?}");
        }
        let p = sanitize_rel_path("DCIM/Camera/IMG.JPG").unwrap();
        let q = sanitize_rel_path("dcim/camera/img.jpg").unwrap();
        assert_eq!(p.collision_key(), q.collision_key());
        assert_ne!(p, q);
    }

    #[test]
    fn overlong_components_are_shortened_keeping_the_extension() {
        let long = format!("{}.jpg", "a".repeat(400));
        let out = ok(&long);
        assert_eq!(utf16_len(&out), MAX_COMPONENT_UTF16);
        assert!(out.ends_with(".jpg"));

        // No extension.
        let out = ok(&"b".repeat(400));
        assert_eq!(utf16_len(&out), MAX_COMPONENT_UTF16);

        // An absurdly long "extension" is not preserved.
        let out = ok(&format!("x.{}", "e".repeat(400)));
        assert_eq!(utf16_len(&out), MAX_COMPONENT_UTF16);
        assert!(out.starts_with("x.eee"));

        // Astral characters count as two UTF-16 units and are never split.
        let emoji = format!("{}.png", "😀".repeat(200));
        let out = ok(&emoji);
        assert!(utf16_len(&out) <= MAX_COMPONENT_UTF16);
        assert!(out.ends_with(".png"));
        assert!(out.trim_end_matches(".png").chars().all(|c| c == '😀'));

        // Shortening must not leave a trailing dot or space behind.
        let tricky = format!("{}{}tail.jpg", "c".repeat(MAX_COMPONENT_UTF16 - 6), "  ");
        let out = ok(&tricky);
        assert!(!out.trim_end_matches(".jpg").ends_with(' '), "{out:?}");

        // Shortening must not expose a reserved device name.
        let hidden = format!("COM1{}x", " ".repeat(400));
        let out = ok(&hidden);
        assert_eq!(out, "_COM1");

        // Shortening must not leave a blank name behind (found by the property
        // tests: a no-break space, a long run of spaces, then the only letter).
        let blank = format!("\u{a0}{}a", " ".repeat(MAX_COMPONENT_UTF16));
        let out = ok(&blank);
        assert_eq!(out, "_");
        assert_eq!(ok(&out), out);
        let blank_stem = format!("\u{3000}{}a.jpg", " ".repeat(MAX_COMPONENT_UTF16));
        let out = ok(&blank_stem);
        assert_eq!(out, "\u{3000}.jpg");
        assert_eq!(ok(&out), out);

        // Exactly at the limit: untouched.
        let exact = "d".repeat(MAX_COMPONENT_UTF16);
        assert_eq!(ok(&exact), exact);
    }

    #[test]
    fn sanitising_is_idempotent_on_its_own_output() {
        let inputs = [
            "DCIM/Camera/IMG_0001.jpg",
            "CON.txt",
            "ab:c/d?e/f*g",
            "name. . ",
            ".kiwi-tmp-x.part",
            "cafe\u{301}",
            "COM1                                                                                                  x",
        ];
        let long = format!("NUL.{}", "z".repeat(500));
        for input in inputs.iter().copied().chain(std::iter::once(long.as_str())) {
            let once = ok(input);
            assert_eq!(ok(&once), once, "input {input:?}");
            assert!(SafeRelPath::from_stored(&once).is_some(), "input {input:?}");
        }
    }

    #[test]
    fn single_component_mode_never_splits() {
        let cases = [
            ("Pixel 8", "Pixel 8"),
            ("a/b", "a_b"),
            ("a\\b", "a_b"),
            ("../../x", ".._.._x"),
            ("/abs", "_abs"),
            ("C:\\x", "C__x"),
            ("\\\\server\\share", "__server_share"),
            ("هاتف أحمد", "هاتف أحمد"),
            ("NUL", "_NUL"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_component(input).unwrap().as_str(),
                expected,
                "input {input:?}"
            );
        }
        for input in ["", ".", "..", "...", " ", ". .", "a\0b"] {
            assert!(sanitize_component(input).is_err(), "input {input:?}");
        }
    }

    #[test]
    fn collision_suffixes() {
        let n = |s: &str, k: u32| {
            sanitize_component(s)
                .unwrap()
                .with_collision_suffix(k)
                .as_str()
                .to_owned()
        };
        assert_eq!(n("photo.jpg", 1), "photo.jpg");
        assert_eq!(n("photo.jpg", 2), "photo (2).jpg");
        assert_eq!(n("photo.jpg", 137), "photo (137).jpg");
        assert_eq!(n("archive.tar.gz", 2), "archive.tar (2).gz");
        assert_eq!(n("README", 3), "README (3)");
        assert_eq!(n(".profile", 2), ".profile (2)");
        assert_eq!(n("photo (2).jpg", 2), "photo (2) (2).jpg");
        // The longest sanitised name makes room for the largest suffix.
        let longest = sanitize_component(&format!("{}.jpg", "a".repeat(400))).unwrap();
        let renamed = longest.with_collision_suffix(u32::MAX);
        assert_eq!(renamed.utf16_len(), MAX_COMPONENT_UTF16);
        assert!(renamed.as_str().ends_with(" (4294967295).jpg"));
        // ... also when the name has no extension, or an absurd one.
        let bare = sanitize_component(&"b".repeat(400))
            .unwrap()
            .with_collision_suffix(7);
        assert_eq!(bare.utf16_len(), MAX_COMPONENT_UTF16);
        assert!(bare.as_str().ends_with(" (7)"));
        let odd = sanitize_component(&format!("x.{}", "e".repeat(238)))
            .unwrap()
            .with_collision_suffix(7);
        assert_eq!(odd.utf16_len(), MAX_COMPONENT_UTF16);
        assert!(odd.as_str().ends_with(" (7)"));
        // ... and never splits a character while doing so.
        let emoji = sanitize_component(&format!("{}.png", "😀".repeat(118)))
            .unwrap()
            .with_collision_suffix(2);
        assert!(emoji.utf16_len() <= MAX_COMPONENT_UTF16);
        assert!(emoji.as_str().ends_with(" (2).png"));
        // A suffixed name is itself a clean name (it must survive the ledger round trip).
        for name in [&renamed, &bare, &odd, &emoji] {
            assert!(SafeName::from_stored(name.as_str()).is_some(), "{name:?}");
        }
        assert!(SafeName::from_stored(&n("photo.jpg", 2)).is_some());
        assert!(SafeName::from_stored(&n("trailing space .jpg", 2)).is_some());
    }

    #[test]
    fn stored_paths_are_revalidated() {
        assert!(SafeRelPath::from_stored("a/b/c.jpg").is_some());
        for bad in [
            "",
            "/a",
            "a//b",
            "a/../b",
            "a\\b",
            "a/b/",
            "C:/x",
            "a/CON",
            "a/b.",
            "a/b ",
            "./a",
            "cafe\u{301}",
        ] {
            assert!(
                SafeRelPath::from_stored(bad).is_none(),
                "{bad:?} must not be accepted from the ledger"
            );
        }
        assert!(SafeName::from_stored("ok.txt").is_some());
        for bad in ["", "a/b", "NUL", "x.", ".kiwi-tmp-1.part"] {
            assert!(SafeName::from_stored(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn path_helpers() {
        let p = sanitize_rel_path("a/b/c.jpg").unwrap();
        assert_eq!(p.depth(), 3);
        assert_eq!(p.file_name().unwrap().as_str(), "c.jpg");
        assert_eq!(p.parent().to_slash_string(), "a/b");
        assert_eq!(p.parent().parent().parent(), SafeRelPath::empty());
        assert_eq!(p.utf16_len(), 9);
        assert_eq!(SafeRelPath::empty().utf16_len(), 0);
        let joined = p.parent().join(sanitize_component("d.png").unwrap());
        assert_eq!(joined.to_slash_string(), "a/b/d.png");
        assert_eq!(
            p.parent()
                .join_path(&sanitize_rel_path("x/y").unwrap())
                .to_slash_string(),
            "a/b/x/y"
        );
        let root = Path::new("root");
        let abs = p.under(root);
        assert!(abs.starts_with(root));
        assert_eq!(abs.components().count(), 4);
    }

    #[test]
    fn shell_active_names_are_neutralised_reversibly() {
        let stored = |name: &str| {
            let (out, changed) = sanitize_component(name).unwrap().neutralised();
            (out.as_str().to_owned(), changed)
        };
        for (name, expected) in [
            ("x.url", "x.url.kiwi-safe"),
            ("X.URL", "X.URL.kiwi-safe"),
            ("Holiday.LNK", "Holiday.LNK.kiwi-safe"),
            ("a.pif", "a.pif.kiwi-safe"),
            ("a.scf", "a.scf.kiwi-safe"),
            ("a.website", "a.website.kiwi-safe"),
            ("Docs.library-ms", "Docs.library-ms.kiwi-safe"),
            ("q.search-ms", "q.search-ms.kiwi-safe"),
            ("q.searchConnector-ms", "q.searchConnector-ms.kiwi-safe"),
            ("desktop.ini", "desktop.ini.kiwi-safe"),
            ("Desktop.INI", "Desktop.INI.kiwi-safe"),
            ("AUTORUN.inf", "AUTORUN.inf.kiwi-safe"),
            (".url", ".url.kiwi-safe"),
            // Trailing dots and blanks are gone before the type is judged.
            ("x.url. .", "x.url.kiwi-safe"),
            // A name that already carries the suffix is escaped, not trusted.
            ("x.url.kiwi-safe", "x.url.kiwi-safe.kiwi-safe"),
            ("photo.jpg.KIWI-SAFE", "photo.jpg.KIWI-SAFE.kiwi-safe"),
        ] {
            let (out, changed) = stored(name);
            assert_eq!(out, expected, "{name:?}");
            assert!(changed, "{name:?}");
            // What is stored is inert, is a name the sanitiser accepts as it
            // is, and gives the original back.
            assert!(!is_shell_active(&out) || out.ends_with(NEUTRAL_SUFFIX));
            assert!(SafeName::from_stored(&out).is_some(), "{out:?}");
            let original = sanitize_component(name).unwrap();
            assert_eq!(restore_neutralised_name(&out), Some(original.as_str()));
        }
        for name in [
            "photo.jpg",
            "url",
            "x.urls",
            "x.url.jpg",
            "desktop.ini.txt",
            "my desktop.ini.bak",
            "lnk.txt",
            "kiwi-safe",
            "x.kiwi-safely",
        ] {
            let (out, changed) = stored(name);
            assert_eq!(out, name);
            assert!(!changed, "{name:?}");
            assert_eq!(restore_neutralised_name(&out), None, "{name:?}");
        }
        // The suffix alone is not a neutralised name.
        assert_eq!(restore_neutralised_name(".kiwi-safe"), None);
    }

    #[test]
    fn neutralising_keeps_the_type_of_an_over_long_name() {
        let long = format!("{}.url", "n".repeat(300));
        let (out, changed) = sanitize_component(&long).unwrap().neutralised();
        assert!(changed);
        assert!(out.utf16_len() <= MAX_COMPONENT_UTF16);
        assert!(out.as_str().ends_with(".url.kiwi-safe"));
        assert!(SafeName::from_stored(out.as_str()).is_some());
        // Collision suffixes go before the type, so the original name stays a shortcut name.
        let second = sanitize_component("a.url")
            .unwrap()
            .with_collision_suffix(2)
            .neutralised()
            .0;
        assert_eq!(second.as_str(), "a (2).url.kiwi-safe");
    }
}
