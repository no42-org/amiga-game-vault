/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! TOSEC filename parsing, title sanitization, and the canonical filename schema.
//!
//! Canonical schema: `<Title-Kebab>[_v<Ver>][_<lang>][_d<NN>of<MM>]_<uid>.adf`
//! where `_` separates fields and `-` separates words inside the title. Optional
//! fields are omitted when unknown and recovered on read by their shape.

use crate::identity::UID_LEN;

/// A parsed TOSEC-style filename. Free-form and best-effort: absent fields are
/// left `None`, and unrecognized parenthesized groups fall through to publisher.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TosecName {
    pub title: String,
    pub version: Option<String>,
    pub language: Option<String>,
    pub publisher: Option<String>,
    pub year: Option<i32>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
    /// Raw bracket contents, e.g. `"cr QTX"`, `"t +9 TLPI"`, `"a2 highscore"`, `"b corrupt file"`.
    pub flags: Vec<String>,
}

/// ISO-639-1 / common region codes we accept as a language slot.
const LANG_CODES: &[&str] = &[
    "en", "de", "fr", "es", "it", "nl", "se", "da", "pl", "cs", "pt", "fi", "no", "gr", "hu", "ru",
    "us", "uk", "au", "jp", "mul",
];

fn is_lang_token(t: &str) -> bool {
    let lower = t.to_ascii_lowercase();
    LANG_CODES.contains(&lower.as_str())
}

/// Parse a TOSEC-style filename (with or without extension) into its fields.
///
/// Returns `None` only for input with no recognizable title at all.
pub fn parse_tosec(filename: &str) -> Option<TosecName> {
    // Drop a trailing extension (.adf/.adz/.dms/.zip) if present.
    let stem = match filename.rsplit_once('.') {
        Some((s, ext)) if ext.len() <= 4 && ext.chars().all(|c| c.is_ascii_alphanumeric()) => s,
        _ => filename,
    };

    // Title = everything before the first '(' or '['. A name with no metadata
    // groups at all is not TOSEC-shaped and cannot be identified from its name.
    let first_marker = stem.find(['(', '['])?;
    let mut title = stem[..first_marker].trim().to_string();
    if title.is_empty() {
        return None;
    }

    let mut out = TosecName::default();

    // Pull a trailing version token ("... v1.0") out of the title text.
    if let Some((head, last)) = title.rsplit_once(' ') {
        if is_version_token(last) {
            out.version = Some(last.to_string());
            title = head.trim_end().to_string();
        }
    }
    out.title = title;

    // Walk the remaining ()/[] groups.
    let rest = &stem[first_marker..];
    for (open, close, content) in group_iter(rest) {
        let content = content.trim();
        if open == '[' && close == ']' {
            out.flags.push(content.to_string());
            continue;
        }
        // Parenthesized group: classify.
        if let Some((n, m)) = parse_disk(content) {
            out.disk_no = Some(n);
            out.disk_count = Some(m);
        } else if let Some(y) = parse_year(content) {
            out.year = Some(y);
        } else if is_lang_token(content) {
            out.language = Some(content.to_ascii_lowercase());
        } else if out.publisher.is_none() {
            out.publisher = Some(content.to_string());
        }
    }

    Some(out)
}

fn is_version_token(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() >= 2 && (b[0] == b'v' || b[0] == b'V') && b[1].is_ascii_digit()
}

/// Extract a 4-digit leading year (handles `1992` and `1992-04-27`).
fn parse_year(s: &str) -> Option<i32> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() == 4 {
        digits.parse().ok()
    } else {
        None
    }
}

/// Parse `Disk N of M` (case-insensitive) into `(N, M)`.
fn parse_disk(s: &str) -> Option<(u32, u32)> {
    let lower = s.to_ascii_lowercase();
    let rest = lower.strip_prefix("disk ")?;
    let (n, m) = rest.split_once(" of ")?;
    Some((n.trim().parse().ok()?, m.trim().parse().ok()?))
}

/// Iterate `(...)` and `[...]` groups in order, yielding `(open, close, inner)`.
fn group_iter(s: &str) -> Vec<(char, char, String)> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let (open, close) = match chars[i] {
            '(' => ('(', ')'),
            '[' => ('[', ']'),
            _ => {
                i += 1;
                continue;
            }
        };
        let mut depth = 1;
        let mut j = i + 1;
        let mut inner = String::new();
        while j < chars.len() && depth > 0 {
            if chars[j] == open {
                depth += 1;
            } else if chars[j] == close {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            inner.push(chars[j]);
            j += 1;
        }
        out.push((open, close, inner));
        i = j + 1;
    }
    out
}

// --- Sanitization & canonical filenames -----------------------------------

/// Sanitize a display title into the kebab title segment.
///
/// Spaces/`_` become `-`; `&` becomes `and`; reserved and punctuation chars are
/// dropped; obvious non-ASCII is transliterated; runs of `-` collapse; case is
/// preserved.
pub fn sanitize_title(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    for ch in title.chars() {
        match ch {
            '&' => out.push_str("-and-"),
            c if c.is_ascii_alphanumeric() => out.push(c),
            ' ' | '_' | '-' => out.push('-'),
            // Transliterate the common German/Latin-1 letters, preserving case.
            'ä' => out.push_str("ae"),
            'Ä' => out.push_str("Ae"),
            'ö' => out.push_str("oe"),
            'Ö' => out.push_str("Oe"),
            'ü' => out.push_str("ue"),
            'Ü' => out.push_str("Ue"),
            'ß' => out.push_str("ss"),
            'é' | 'è' | 'ê' => out.push('e'),
            'É' | 'È' | 'Ê' => out.push('E'),
            'á' | 'à' | 'â' => out.push('a'),
            'Á' | 'À' | 'Â' => out.push('A'),
            'ó' | 'ò' | 'ô' => out.push('o'),
            'Ó' | 'Ò' | 'Ô' => out.push('O'),
            'í' | 'ì' | 'î' => out.push('i'),
            'ú' | 'ù' | 'û' => out.push('u'),
            'ñ' => out.push('n'),
            'Ñ' => out.push('N'),
            // Everything else (: / \ * ? " < > | ' , . ! ( ) [ ] etc.) is dropped.
            _ => {}
        }
    }
    // Collapse runs of '-' and trim.
    let mut collapsed = String::with_capacity(out.len());
    let mut prev_dash = false;
    for c in out.chars() {
        if c == '-' {
            if !prev_dash {
                collapsed.push('-');
            }
            prev_dash = true;
        } else {
            collapsed.push(c);
            prev_dash = false;
        }
    }
    collapsed.trim_matches('-').to_string()
}

/// Normalize a version token to always start with a lowercase `v`.
fn normalize_version(v: &str) -> String {
    let trimmed = v.trim();
    if trimmed.starts_with('v') || trimmed.starts_with('V') {
        format!("v{}", &trimmed[1..])
    } else {
        format!("v{trimmed}")
    }
}

/// The fields that make up a canonical filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    pub title: String,
    pub version: Option<String>,
    pub language: Option<String>,
    pub disk: Option<(u32, u32)>,
    pub uid: String,
}

/// Build a canonical filename from an already-sanitized (or raw) display title.
pub fn build_canonical(
    display_title: &str,
    version: Option<&str>,
    language: Option<&str>,
    disk: Option<(u32, u32)>,
    uid: &str,
) -> String {
    let mut s = sanitize_title(display_title);
    if let Some(v) = version {
        s.push('_');
        s.push_str(&normalize_version(v));
    }
    if let Some(l) = language {
        s.push('_');
        s.push_str(&l.to_ascii_lowercase());
    }
    if let Some((n, m)) = disk {
        s.push_str(&format!("_d{n:02}of{m:02}"));
    }
    s.push('_');
    s.push_str(uid);
    s.push_str(".adf");
    s
}

fn is_disk_field(t: &str) -> Option<(u32, u32)> {
    let rest = t.strip_prefix('d')?;
    let (n, m) = rest.split_once("of")?;
    Some((n.parse().ok()?, m.parse().ok()?))
}

fn is_uid_field(t: &str) -> bool {
    t.len() >= UID_LEN && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse a canonical filename back into fields by field shape, tolerating omitted
/// optional fields. Returns `None` if no UID field is present.
pub fn parse_canonical(filename: &str) -> Option<Canonical> {
    let stem = filename.strip_suffix(".adf").unwrap_or(filename);
    let mut parts = stem.split('_');
    let title = parts.next()?.to_string();

    let mut version = None;
    let mut language = None;
    let mut disk = None;
    let mut uid = None;

    for p in parts {
        if is_version_token(p) {
            version = Some(normalize_version(p));
        } else if let Some(d) = is_disk_field(p) {
            disk = Some(d);
        } else if p.len() == 2 && p.chars().all(|c| c.is_ascii_lowercase()) || p == "mul" {
            language = Some(p.to_string());
        } else if is_uid_field(p) {
            uid = Some(p.to_string());
        }
    }

    Some(Canonical {
        title,
        version,
        language,
        disk,
        uid: uid?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_a10_variant() {
        let n = parse_tosec(
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX][a2 highscore].adf",
        )
        .unwrap();
        assert_eq!(n.title, "A-10 Tank Killer");
        assert_eq!(n.version.as_deref(), Some("v1.0"));
        assert_eq!(n.year, Some(1990));
        assert_eq!(n.publisher.as_deref(), Some("Dynamix"));
        assert_eq!(n.disk_no, Some(1));
        assert_eq!(n.disk_count, Some(2));
        assert_eq!(
            n.flags,
            vec!["h QTX".to_string(), "a2 highscore".to_string()]
        );
    }

    #[test]
    fn parse_mi2_language_editions() {
        let it = parse_tosec(
            "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(C.T.O.)(IT)(Disk 1 of 11)[cr IBB].adf",
        )
        .unwrap();
        assert_eq!(it.language.as_deref(), Some("it"));
        assert_eq!(it.disk_count, Some(11));
        assert_eq!(it.publisher.as_deref(), Some("C.T.O."));

        let us = parse_tosec("Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts - U.S. Gold)(Disk 1 of 11)[cr DTC].adf").unwrap();
        assert_eq!(us.language, None); // implicit English -> no lang token
        assert_eq!(us.publisher.as_deref(), Some("LucasArts - U.S. Gold"));
    }

    #[test]
    fn sanitize_handles_reserved_and_punctuation() {
        assert_eq!(
            sanitize_title("Monkey Island 2 - LeChuck's Revenge"),
            "Monkey-Island-2-LeChucks-Revenge"
        );
        assert_eq!(
            sanitize_title("Turrican II: The Final Fight"),
            "Turrican-II-The-Final-Fight"
        );
        assert_eq!(sanitize_title("A-10 Tank Killer"), "A-10-Tank-Killer");
        assert_eq!(
            sanitize_title("Rick Dangerous & Friends"),
            "Rick-Dangerous-and-Friends"
        );
    }

    #[test]
    fn sanitize_transliterates() {
        assert_eq!(sanitize_title("Über Wing"), "Ueber-Wing");
    }

    #[test]
    fn build_full_and_minimal() {
        assert_eq!(
            build_canonical(
                "A-10 Tank Killer",
                Some("v1.0"),
                Some("en"),
                Some((1, 2)),
                "a1b2c3d4e5"
            ),
            "A-10-Tank-Killer_v1.0_en_d01of02_a1b2c3d4e5.adf"
        );
        assert_eq!(
            build_canonical("State of the Art", None, None, None, "9f8e7d6c5b"),
            "State-of-the-Art_9f8e7d6c5b.adf"
        );
    }

    #[test]
    fn round_trip_canonical() {
        let built = build_canonical(
            "A-10 Tank Killer",
            Some("v1.0"),
            Some("en"),
            Some((1, 2)),
            "a1b2c3d4e5",
        );
        let parsed = parse_canonical(&built).unwrap();
        assert_eq!(parsed.title, "A-10-Tank-Killer");
        assert_eq!(parsed.version.as_deref(), Some("v1.0"));
        assert_eq!(parsed.language.as_deref(), Some("en"));
        assert_eq!(parsed.disk, Some((1, 2)));
        assert_eq!(parsed.uid, "a1b2c3d4e5");
    }

    #[test]
    fn parse_canonical_with_omitted_fields() {
        let c = parse_canonical("State-of-the-Art_9f8e7d6c5b.adf").unwrap();
        assert_eq!(c.title, "State-of-the-Art");
        assert_eq!(c.version, None);
        assert_eq!(c.language, None);
        assert_eq!(c.disk, None);
        assert_eq!(c.uid, "9f8e7d6c5b");
    }
}
