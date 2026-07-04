/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Reference DAT import and hash lookup.
//!
//! DATs (TOSEC, WHDLoad) are the authoritative source of canonical identity. We
//! parse the Logiqx XML form (`<game name="..."><rom crc sha1 md5 .../></game>`)
//! into [`DatEntry`] records, deriving structured metadata from each canonical
//! name, and match ingested artifacts against them by content hash.

use crate::edition::interpret_flags;
use crate::identity::Hashes;
use crate::naming::parse_tosec;

/// One reference entry: a canonical name plus its content hashes and derived
/// metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatEntry {
    pub source: String,
    pub name: String,
    pub sha1: Option<String>,
    pub crc32: Option<String>,
    pub md5: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    pub language: Option<String>,
    pub publisher: Option<String>,
    pub year: Option<i32>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
    pub dump_type: Option<String>,
    pub crack_group: Option<String>,
}

/// Extract the value of `key="..."` from a tag fragment.
fn attr(fragment: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = fragment.find(&needle)? + needle.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn norm_hash(h: Option<String>) -> Option<String> {
    h.map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Parse a Logiqx-format DAT into entries, tagging them with `source`.
pub fn parse_dat(xml: &str, source: &str) -> Vec<DatEntry> {
    let mut entries = Vec::new();
    // Each "<game ...>...</game>" (or "<machine ...>") holds a name and one rom.
    for chunk in xml.split("<game").skip(1) {
        let head = &chunk[..chunk.find('>').unwrap_or(chunk.len())];
        let Some(name) = attr(head, "name") else {
            continue;
        };
        // Find the first <rom ...> in this game block.
        let Some(rom_start) = chunk.find("<rom") else {
            continue;
        };
        let rom = &chunk[rom_start..];
        let rom = &rom[..rom.find('>').unwrap_or(rom.len())];

        let mut e = DatEntry {
            source: source.to_string(),
            name: name.clone(),
            sha1: norm_hash(attr(rom, "sha1")),
            crc32: norm_hash(attr(rom, "crc")),
            md5: norm_hash(attr(rom, "md5")),
            ..Default::default()
        };

        if let Some(parsed) = parse_tosec(&name) {
            e.title = Some(parsed.title.clone());
            e.version = parsed.version.clone();
            e.language = parsed.language.clone();
            e.publisher = parsed.publisher.clone();
            e.year = parsed.year;
            e.disk_no = parsed.disk_no;
            e.disk_count = parsed.disk_count;
            let info = interpret_flags(&parsed.flags);
            e.dump_type = Some(info.dump_type.as_str().to_string());
            e.crack_group = info.crack_group;
        }
        entries.push(e);
    }
    entries
}

/// Find the reference entry whose hash matches `hashes`, preferring SHA1, then
/// MD5, then CRC32.
pub fn match_entry<'a>(entries: &'a [DatEntry], hashes: &Hashes) -> Option<&'a DatEntry> {
    entries
        .iter()
        .find(|e| e.sha1.as_deref() == Some(hashes.sha1.as_str()))
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.md5.as_deref() == Some(hashes.md5.as_str()))
        })
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.crc32.as_deref() == Some(hashes.crc32.as_str()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    <datafile>
      <game name="A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX]">
        <rom name="A-10 Tank Killer.adf" size="901120" crc="A1B2C3D4" md5="00112233445566778899aabbccddeeff" sha1="abcdef0123456789abcdef0123456789abcdef01"/>
      </game>
      <game name="Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts)(ES)(Disk 1 of 11)[cr Crucial]">
        <rom name="mi2.adf" size="901120" crc="deadbeef" sha1="1111111111111111111111111111111111111111"/>
      </game>
    </datafile>"#;

    #[test]
    fn parse_and_derive_metadata() {
        let entries = parse_dat(SAMPLE, "TOSEC");
        assert_eq!(entries.len(), 2);

        let a10 = &entries[0];
        assert_eq!(a10.title.as_deref(), Some("A-10 Tank Killer"));
        assert_eq!(a10.version.as_deref(), Some("v1.0"));
        assert_eq!(a10.year, Some(1990));
        assert_eq!(a10.disk_count, Some(2));
        assert_eq!(a10.crc32.as_deref(), Some("a1b2c3d4")); // lowercased
        assert_eq!(a10.dump_type.as_deref(), Some("cracked"));
        assert_eq!(a10.crack_group.as_deref(), Some("QTX"));

        let mi2 = &entries[1];
        assert_eq!(mi2.language.as_deref(), Some("es"));
        assert_eq!(mi2.disk_count, Some(11));
    }

    #[test]
    fn match_by_sha1_then_crc() {
        let entries = parse_dat(SAMPLE, "TOSEC");
        let hit = Hashes {
            sha1: "abcdef0123456789abcdef0123456789abcdef01".into(),
            crc32: "ffffffff".into(),
            md5: "zz".into(),
        };
        assert_eq!(
            match_entry(&entries, &hit).unwrap().title.as_deref(),
            Some("A-10 Tank Killer")
        );

        // No sha1/md5 match, but crc32 matches the second entry.
        let by_crc = Hashes {
            sha1: "no".into(),
            crc32: "deadbeef".into(),
            md5: "no".into(),
        };
        assert_eq!(match_entry(&entries, &by_crc).unwrap().disk_count, Some(11));

        let miss = Hashes {
            sha1: "x".into(),
            crc32: "y".into(),
            md5: "z".into(),
        };
        assert!(match_entry(&entries, &miss).is_none());
    }
}
