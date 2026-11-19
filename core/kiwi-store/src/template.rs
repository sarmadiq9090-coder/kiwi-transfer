//! Organisation templates: where under the destination root a file goes.
//!
//! A template is a `/`-separated list of segments. A segment is literal text
//! mixed with tokens:
//!
//! | token         | value                                                        |
//! |---------------|--------------------------------------------------------------|
//! | `{year}`      | four-digit year of the capture time                          |
//! | `{month}`     | two-digit month                                              |
//! | `{day}`       | two-digit day                                                |
//! | `{device}`    | the paired device's folder name                              |
//! | `{phone_dir}` | the folders the file was in on the phone (a whole segment)   |
//!
//! There are no conditionals, no escapes and no way to name a parent
//! directory. Every rendered segment still passes through the sanitiser, so a
//! template can never produce a path the sanitiser would not have produced.

use crate::sanitize::{sanitize_component, SafeName, SafeRelPath, SanitizeError, MAX_DEPTH};

/// Longest template source accepted, in bytes.
pub const MAX_TEMPLATE_BYTES: usize = 512;

/// Folder name used when a file has no usable date.
pub const UNDATED: &str = "undated";

/// A calendar date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilDate {
    /// Year, 1601..=9999.
    pub year: i32,
    /// Month, 1..=12.
    pub month: u8,
    /// Day of month, 1..=31.
    pub day: u8,
}

/// A point in time supplied by the caller, with the offset that was in effect
/// where the photo was taken (so that a photo taken at 00:30 local time is
/// filed under the local day, not the UTC day).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureTime {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub unix_seconds: i64,
    /// Local offset from UTC in seconds. Use 0 if unknown.
    pub utc_offset_seconds: i32,
}

impl CaptureTime {
    /// A UTC time.
    pub fn utc(unix_seconds: i64) -> Self {
        Self {
            unix_seconds,
            utc_offset_seconds: 0,
        }
    }
}

impl CivilDate {
    /// Converts a timestamp to a calendar date. Returns `None` for dates
    /// outside 1601..=9999 (garbage timestamps must not create folders such as
    /// `-29719/04`).
    pub fn from_capture_time(t: CaptureTime) -> Option<CivilDate> {
        // Real-world offsets are within +-14 h; anything else is ignored.
        let offset = if t.utc_offset_seconds.unsigned_abs() <= 18 * 3600 {
            t.utc_offset_seconds as i64
        } else {
            0
        };
        let local = t.unix_seconds.checked_add(offset)?;
        let days = local.div_euclid(86_400);
        // Howard Hinnant's civil_from_days.
        let z = days.checked_add(719_468)?;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        if !(1601..=9999).contains(&year) {
            return None;
        }
        Some(CivilDate {
            year: year as i32,
            month: month as u8,
            day: day as u8,
        })
    }
}

/// Why a template was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateError {
    /// The template was empty.
    #[error("the template is empty")]
    Empty,
    /// The template was longer than [`MAX_TEMPLATE_BYTES`].
    #[error("the template is too long")]
    TooLong,
    /// The template started with a separator or a drive letter.
    #[error("a template must be a relative path")]
    NotRelative,
    /// Two separators in a row, or a trailing separator.
    #[error("the template has an empty segment")]
    EmptySegment,
    /// A segment was `.` or `..` or only dots and blanks.
    #[error("the template has a segment made only of dots or blanks")]
    DotSegment,
    /// A `{` without `}` or a stray `}`.
    #[error("unbalanced brace in the template")]
    UnbalancedBrace,
    /// A token that is not part of the language.
    #[error("unknown template token {{{0}}}")]
    UnknownToken(String),
    /// `{phone_dir}` shared a segment with other text.
    #[error("{{phone_dir}} must be a segment on its own")]
    PhoneDirNotAlone,
    /// Literal text contained a character that is not allowed in file names.
    #[error("the template contains a character that is not allowed in a file name: {0:?}")]
    ForbiddenCharacter(char),
    /// More segments than the engine's depth limit.
    #[error("the template has too many segments")]
    TooDeep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Literal(String),
    Year,
    Month,
    Day,
    Device,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    PhoneDir,
    Pieces(Vec<Piece>),
}

/// A parsed organisation template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    source: String,
    segments: Vec<Segment>,
}

/// Values a template is rendered with.
#[derive(Debug, Clone, Copy)]
pub struct TemplateContext<'a> {
    /// Folder name of the paired device (already sanitised).
    pub device_folder: &'a SafeName,
    /// Date to file under: the capture date, else the modification date, else `None`.
    pub date: Option<CivilDate>,
    /// Folders the file was in on the phone (already sanitised, may be empty).
    pub phone_dir: &'a SafeRelPath,
}

impl Template {
    /// `{year}/{month}`: one folder per month of capture.
    pub fn by_date() -> Template {
        Template::parse("{year}/{month}").expect("built-in template is valid")
    }

    /// `{device}`: one folder per paired device.
    pub fn per_device() -> Template {
        Template::parse("{device}").expect("built-in template is valid")
    }

    /// `{device}/{phone_dir}`: mirror the phone's folder structure per device.
    pub fn keep_phone_structure() -> Template {
        Template::parse("{device}/{phone_dir}").expect("built-in template is valid")
    }

    /// Parses a template such as `{year}/{month}/{device}`.
    pub fn parse(source: &str) -> Result<Template, TemplateError> {
        if source.is_empty() {
            return Err(TemplateError::Empty);
        }
        if source.len() > MAX_TEMPLATE_BYTES {
            return Err(TemplateError::TooLong);
        }
        let bytes = source.as_bytes();
        if bytes[0] == b'/'
            || bytes[0] == b'\\'
            || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        {
            return Err(TemplateError::NotRelative);
        }

        let mut segments = Vec::new();
        for raw in source.split(['/', '\\']) {
            if raw.is_empty() {
                return Err(TemplateError::EmptySegment);
            }
            segments.push(parse_segment(raw)?);
        }
        if segments.len() > MAX_DEPTH {
            return Err(TemplateError::TooDeep);
        }
        Ok(Template {
            source: source.to_owned(),
            segments,
        })
    }

    /// The text the template was parsed from.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Renders the directory (relative to the destination root) for one file.
    ///
    /// When no date is known, every segment that mentions a date token becomes
    /// the single folder [`UNDATED`] (adjacent ones are merged), so
    /// `{year}/{month}/{device}` renders as `undated/<device>`.
    pub fn render(&self, ctx: &TemplateContext<'_>) -> Result<SafeRelPath, SanitizeError> {
        let mut parts: Vec<SafeName> = Vec::new();
        let mut last_was_undated = false;
        for segment in &self.segments {
            match segment {
                Segment::PhoneDir => {
                    parts.extend(ctx.phone_dir.components().iter().cloned());
                    last_was_undated = false;
                }
                Segment::Pieces(pieces) => {
                    let dated = pieces
                        .iter()
                        .any(|p| matches!(p, Piece::Year | Piece::Month | Piece::Day));
                    if dated && ctx.date.is_none() {
                        if !last_was_undated {
                            parts.push(sanitize_component(UNDATED)?);
                        }
                        last_was_undated = true;
                        continue;
                    }
                    let mut text = String::new();
                    for piece in pieces {
                        match (piece, ctx.date) {
                            (Piece::Literal(s), _) => text.push_str(s),
                            (Piece::Device, _) => text.push_str(ctx.device_folder.as_str()),
                            (Piece::Year, Some(d)) => text.push_str(&format!("{:04}", d.year)),
                            (Piece::Month, Some(d)) => text.push_str(&format!("{:02}", d.month)),
                            (Piece::Day, Some(d)) => text.push_str(&format!("{:02}", d.day)),
                            (Piece::Year | Piece::Month | Piece::Day, None) => {
                                unreachable!("handled above")
                            }
                        }
                    }
                    parts.push(sanitize_component(&text)?);
                    last_was_undated = false;
                }
            }
        }
        if parts.len() > MAX_DEPTH {
            return Err(SanitizeError::TooDeep { depth: parts.len() });
        }
        Ok(SafeRelPath::from_components(parts))
    }
}

fn parse_segment(raw: &str) -> Result<Segment, TemplateError> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut has_phone_dir = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                let mut token = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some('{') | None => return Err(TemplateError::UnbalancedBrace),
                        Some(t) => token.push(t),
                    }
                }
                if !literal.is_empty() {
                    pieces.push(Piece::Literal(std::mem::take(&mut literal)));
                }
                match token.as_str() {
                    "year" => pieces.push(Piece::Year),
                    "month" => pieces.push(Piece::Month),
                    "day" => pieces.push(Piece::Day),
                    "device" => pieces.push(Piece::Device),
                    "phone_dir" => has_phone_dir = true,
                    _ => return Err(TemplateError::UnknownToken(token)),
                }
            }
            '}' => return Err(TemplateError::UnbalancedBrace),
            c if c == '\0'
                || c.is_control()
                || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') =>
            {
                return Err(TemplateError::ForbiddenCharacter(c));
            }
            c => literal.push(c),
        }
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    if has_phone_dir {
        return if pieces.is_empty() {
            Ok(Segment::PhoneDir)
        } else {
            Err(TemplateError::PhoneDirNotAlone)
        };
    }
    // A segment of pure literal text must already be a clean name; otherwise
    // the user would get a folder that differs from what they typed.
    if pieces.iter().all(|p| matches!(p, Piece::Literal(_))) {
        let text: String = pieces
            .iter()
            .map(|p| {
                if let Piece::Literal(s) = p {
                    s.as_str()
                } else {
                    ""
                }
            })
            .collect();
        match sanitize_component(&text) {
            Ok(_) => {}
            Err(_) => return Err(TemplateError::DotSegment),
        }
    }
    Ok(Segment::Pieces(pieces))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize::sanitize_rel_path;

    fn date(y: i32, m: u8, d: u8) -> Option<CivilDate> {
        Some(CivilDate {
            year: y,
            month: m,
            day: d,
        })
    }

    fn render(template: &str, device: &str, date: Option<CivilDate>, phone_dir: &str) -> String {
        let device = sanitize_component(device).unwrap();
        let phone_dir = if phone_dir.is_empty() {
            SafeRelPath::empty()
        } else {
            sanitize_rel_path(phone_dir).unwrap()
        };
        let ctx = TemplateContext {
            device_folder: &device,
            date,
            phone_dir: &phone_dir,
        };
        Template::parse(template)
            .unwrap()
            .render(&ctx)
            .unwrap()
            .to_slash_string()
    }

    #[test]
    fn civil_dates() {
        let d = |s| CivilDate::from_capture_time(CaptureTime::utc(s));
        assert_eq!(d(0), date(1970, 1, 1));
        assert_eq!(d(86_399), date(1970, 1, 1));
        assert_eq!(d(86_400), date(1970, 1, 2));
        assert_eq!(d(-1), date(1969, 12, 31));
        assert_eq!(d(951_782_400), date(2000, 2, 29));
        assert_eq!(d(951_868_800), date(2000, 3, 1));
        assert_eq!(d(1_709_164_800), date(2024, 2, 29));
        assert_eq!(d(1_735_689_599), date(2024, 12, 31));
        assert_eq!(d(1_735_689_600), date(2025, 1, 1));
        assert_eq!(d(4_102_444_800), date(2100, 1, 1));
        assert_eq!(d(-11_644_473_600), date(1601, 1, 1));
        assert_eq!(d(-11_644_473_601), None);
        assert_eq!(d(253_402_300_799), date(9999, 12, 31));
        assert_eq!(d(253_402_300_800), None);
        assert_eq!(d(i64::MAX), None);
        assert_eq!(d(i64::MIN), None);
    }

    #[test]
    fn local_offset_decides_the_day() {
        // 2024-12-31T22:30:00Z is already New Year's Day in UTC+3.
        let utc = 1_735_684_200;
        let at = |off| {
            CivilDate::from_capture_time(CaptureTime {
                unix_seconds: utc,
                utc_offset_seconds: off,
            })
        };
        assert_eq!(at(0), date(2024, 12, 31));
        assert_eq!(at(3 * 3600), date(2025, 1, 1));
        assert_eq!(at(-8 * 3600), date(2024, 12, 31));
        // A nonsensical offset is ignored rather than trusted.
        assert_eq!(at(400 * 3600), date(2024, 12, 31));
        assert_eq!(at(i32::MIN), date(2024, 12, 31));
    }

    #[test]
    fn presets() {
        assert_eq!(
            render(
                Template::by_date().source(),
                "Pixel",
                date(2024, 3, 9),
                "DCIM/Camera"
            ),
            "2024/03"
        );
        assert_eq!(
            render(
                Template::per_device().source(),
                "Pixel",
                date(2024, 3, 9),
                "DCIM/Camera"
            ),
            "Pixel"
        );
        assert_eq!(
            render(
                Template::keep_phone_structure().source(),
                "Pixel",
                date(2024, 3, 9),
                "DCIM/Camera"
            ),
            "Pixel/DCIM/Camera"
        );
        assert_eq!(
            render(Template::keep_phone_structure().source(), "Pixel", None, ""),
            "Pixel"
        );
    }

    #[test]
    fn custom_templates() {
        let d = date(2023, 11, 5);
        assert_eq!(
            render("{year}/{month}/{device}", "Pixel 8", d, ""),
            "2023/11/Pixel 8"
        );
        assert_eq!(render("{year}-{month}-{day}", "P", d, ""), "2023-11-05");
        assert_eq!(
            render("Photos/{year}/{month} ({device})", "P", d, ""),
            "Photos/2023/11 (P)"
        );
        assert_eq!(render("{device}\\{year}", "P", d, ""), "P/2023");
        assert_eq!(render("صور/{year}", "P", d, ""), "صور/2023");
        assert_eq!(render("{phone_dir}", "P", d, "a/b"), "a/b");
        assert_eq!(render("{phone_dir}", "P", d, ""), "");
        assert_eq!(
            render("{device}/{phone_dir}/{year}", "P", d, "a/b"),
            "P/a/b/2023"
        );
    }

    #[test]
    fn missing_dates_use_one_undated_folder() {
        assert_eq!(
            render("{year}/{month}/{device}", "P", None, ""),
            "undated/P"
        );
        assert_eq!(render("{year}/{month}/{day}", "P", None, ""), "undated");
        assert_eq!(
            render("{year}-{month}/{device}/{day}", "P", None, ""),
            "undated/P/undated"
        );
        assert_eq!(render("Photos {year}", "P", None, ""), "undated");
        assert_eq!(render("{device}", "P", None, ""), "P");
    }

    #[test]
    fn rendered_segments_are_sanitised() {
        // The device folder is sanitised before it reaches the template, and
        // the rendered segment is sanitised again.
        assert_eq!(render("{device}", "CON", None, ""), "_CON");
        assert_eq!(render("{device}.", "Pixel", None, ""), "Pixel");
        assert_eq!(render("{device} ", "Pixel", None, ""), "Pixel");
        assert_eq!(render("NUL{device}", "x", None, ""), "NULx");
        assert_eq!(
            render("{device}/{year}", "../../evil", date(2024, 1, 1), ""),
            ".._.._evil/2024"
        );
        // A device named like a reserved name in a compound segment.
        assert_eq!(render("{device}.txt", "aux", None, ""), "_aux.txt");
        // Over-long results are shortened like any other name.
        let long = "d".repeat(300);
        assert!(render("{device}", &long, None, "").len() <= crate::sanitize::MAX_COMPONENT_UTF16);
    }

    #[test]
    fn bad_templates_are_rejected() {
        use TemplateError::*;
        let cases: &[(&str, TemplateError)] = &[
            ("", Empty),
            ("/abs", NotRelative),
            ("\\abs", NotRelative),
            ("C:/x", NotRelative),
            ("c:{year}", NotRelative),
            ("a//b", EmptySegment),
            ("a/", EmptySegment),
            ("a/../b", DotSegment),
            ("..", DotSegment),
            ("./a", DotSegment),
            ("a/ /b", DotSegment),
            ("a/.../b", DotSegment),
            ("{year", UnbalancedBrace),
            ("year}", UnbalancedBrace),
            ("{{year}}", UnbalancedBrace),
            ("{year}/{", UnbalancedBrace),
            ("{}", UnknownToken(String::new())),
            ("{Year}", UnknownToken("Year".into())),
            ("{hour}", UnknownToken("hour".into())),
            ("{..}", UnknownToken("..".into())),
            ("{env:USERPROFILE}", UnknownToken("env:USERPROFILE".into())),
            ("x{phone_dir}", PhoneDirNotAlone),
            ("{phone_dir}{year}", PhoneDirNotAlone),
            ("ab:c", ForbiddenCharacter(':')),
            ("a/b?", ForbiddenCharacter('?')),
            ("a/b*c", ForbiddenCharacter('*')),
            ("a\tb", ForbiddenCharacter('\t')),
            ("a\0b", ForbiddenCharacter('\0')),
        ];
        for (input, expected) in cases {
            assert_eq!(
                &Template::parse(input).unwrap_err(),
                expected,
                "template {input:?}"
            );
        }
        assert_eq!(
            Template::parse(&"a".repeat(MAX_TEMPLATE_BYTES + 1)).unwrap_err(),
            TooLong
        );
        let deep = vec!["a"; MAX_DEPTH + 1].join("/");
        assert_eq!(Template::parse(&deep).unwrap_err(), TooDeep);
    }

    #[test]
    fn deep_phone_dirs_cannot_exceed_the_depth_limit() {
        let device = sanitize_component("P").unwrap();
        let phone_dir = sanitize_rel_path(&vec!["d"; MAX_DEPTH].join("/")).unwrap();
        let ctx = TemplateContext {
            device_folder: &device,
            date: None,
            phone_dir: &phone_dir,
        };
        let err = Template::keep_phone_structure().render(&ctx).unwrap_err();
        assert!(matches!(err, SanitizeError::TooDeep { .. }));
    }
}
