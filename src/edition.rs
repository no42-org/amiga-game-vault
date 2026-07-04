/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The Title -> Edition -> Artifact identity model.
//!
//! Scene "dump flags" (`[cr GROUP]`, `[t +N]`, `[h]`, `[f]`, `[b]`, `[a2]`, ...)
//! are interpreted into a [`DumpInfo`]. The [`EditionKey`] is the dedup grouping
//! key: it keeps version, language, publisher and disk number but strips all
//! scene flags, so crack/trainer/hack variants of one logical disk collapse into
//! a single Edition.

use std::collections::BTreeMap;

use crate::naming::TosecName;

/// The base nature of a dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpType {
    Original,
    Cracked,
    Hacked,
    Modified,
    Trainer,
}

impl DumpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DumpType::Original => "original",
            DumpType::Cracked => "cracked",
            DumpType::Hacked => "hacked",
            DumpType::Modified => "modified",
            DumpType::Trainer => "trainer",
        }
    }

    /// Parse the stored string form; unknown values fall back to `Original`.
    pub fn from_str(s: &str) -> DumpType {
        match s {
            "cracked" => DumpType::Cracked,
            "hacked" => DumpType::Hacked,
            "modified" => DumpType::Modified,
            "trainer" => DumpType::Trainer,
            _ => DumpType::Original,
        }
    }
}

/// Interpreted scene attributes for a single artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpInfo {
    pub dump_type: DumpType,
    pub crack_group: Option<String>,
    pub trainer: Option<String>,
    pub bad: bool,
    pub virus: bool,
    pub over: bool,
    pub under: bool,
    /// 0 = base dump, 1 = `[a]`, 2 = `[a2]`, ...
    pub alt_index: u32,
    /// `[!]` verified-good marker.
    pub verified_good: bool,
    /// Number of modifying flags (cr/h/f/m/t) — used by primary ranking.
    pub modifications: u32,
    /// Crack lineage tag (the crack/hack group), for multi-disk set coherence.
    pub lineage: Option<String>,
}

impl DumpInfo {
    /// True for markers that permanently disqualify an artifact from being primary.
    pub fn disqualified(&self) -> bool {
        self.bad || self.virus || self.over || self.under
    }
}

/// Interpret raw bracket flag tokens into a [`DumpInfo`].
pub fn interpret_flags(flags: &[String]) -> DumpInfo {
    let mut info = DumpInfo {
        dump_type: DumpType::Original,
        crack_group: None,
        trainer: None,
        bad: false,
        virus: false,
        over: false,
        under: false,
        alt_index: 0,
        verified_good: false,
        modifications: 0,
        lineage: None,
    };

    let mut saw_crack = false;
    let mut saw_hack = false;
    let mut saw_modified = false;
    let mut saw_trainer = false;

    for raw in flags {
        let raw = raw.trim();
        let (tag, arg) = match raw.split_once(' ') {
            Some((t, a)) => (t, a.trim()),
            None => (raw, ""),
        };
        let arg_opt = (!arg.is_empty()).then(|| arg.to_string());

        match tag {
            "cr" => {
                saw_crack = true;
                info.modifications += 1;
                if info.crack_group.is_none() {
                    info.crack_group = arg_opt.clone();
                }
                if info.lineage.is_none() {
                    info.lineage = arg_opt;
                }
            }
            "h" => {
                saw_hack = true;
                info.modifications += 1;
                if info.lineage.is_none() {
                    info.lineage = arg_opt;
                }
            }
            "f" => {
                saw_modified = true;
                info.modifications += 1;
                if info.lineage.is_none() {
                    info.lineage = arg_opt;
                }
            }
            "m" => {
                saw_modified = true;
                info.modifications += 1;
            }
            "t" => {
                saw_trainer = true;
                info.modifications += 1;
                info.trainer = Some(arg.to_string());
            }
            "b" => info.bad = true,
            "v" => info.virus = true,
            "o" => info.over = true,
            "u" => info.under = true,
            "!" => info.verified_good = true,
            other if other.starts_with('a') => {
                // Alternate dump: `a`, `a2`, `a3`, ... (the tag may carry a number).
                let num: String = other[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
                info.alt_index = if num.is_empty() { 1 } else { num.parse().unwrap_or(1) };
            }
            _ => {}
        }
    }

    info.dump_type = if saw_crack {
        DumpType::Cracked
    } else if saw_hack {
        DumpType::Hacked
    } else if saw_modified {
        DumpType::Modified
    } else if saw_trainer {
        DumpType::Trainer
    } else {
        DumpType::Original
    };

    info
}

/// The Edition grouping key. Scene flags are deliberately absent; version,
/// language, publisher and disk number are retained.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EditionKey {
    pub title: String,
    pub version: Option<String>,
    pub language: Option<String>,
    pub publisher: Option<String>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
}

/// Derive the Edition key for a parsed name (flags dropped).
pub fn edition_key(name: &TosecName) -> EditionKey {
    EditionKey {
        title: name.title.trim().to_string(),
        version: name.version.clone(),
        language: name.language.clone(),
        publisher: name.publisher.clone(),
        disk_no: name.disk_no,
        disk_count: name.disk_count,
    }
}

/// The Edition key used for grouping *whole multi-disk sets* — like [`edition_key`]
/// but ignoring the individual disk number, so all disks of one release share it.
pub fn set_key(name: &TosecName) -> EditionKey {
    EditionKey {
        title: name.title.trim().to_string(),
        version: name.version.clone(),
        language: name.language.clone(),
        publisher: name.publisher.clone(),
        disk_no: None,
        disk_count: name.disk_count,
    }
}

/// Group parsed names by Edition, returning a deterministic map from key to the
/// indices of the members within `items`.
pub fn group_by_edition(items: &[TosecName]) -> BTreeMap<EditionKey, Vec<usize>> {
    let mut map: BTreeMap<EditionKey, Vec<usize>> = BTreeMap::new();
    for (i, n) in items.iter().enumerate() {
        map.entry(edition_key(n)).or_default().push(i);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::parse_tosec;

    fn p(s: &str) -> TosecName {
        parse_tosec(s).unwrap()
    }

    #[test]
    fn interpret_crack_and_trainer() {
        let n = p("Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL][t +9 TLPI].adf");
        let info = interpret_flags(&n.flags);
        assert_eq!(info.dump_type, DumpType::Cracked);
        assert_eq!(info.crack_group.as_deref(), Some("CSL"));
        assert_eq!(info.trainer.as_deref(), Some("+9 TLPI"));
        assert_eq!(info.lineage.as_deref(), Some("CSL"));
        assert_eq!(info.modifications, 2);
        assert!(!info.disqualified());
    }

    #[test]
    fn interpret_bad_and_virus_disqualify() {
        let bad = interpret_flags(&p("Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL][b corrupt file].adf").flags);
        assert!(bad.bad && bad.disqualified());
        let vir = interpret_flags(&p("Monkey Island 2 (1992)(x)(Disk 1 of 11)[h GF][v Saddam 1].adf").flags);
        assert!(vir.virus && vir.disqualified());
    }

    #[test]
    fn interpret_alt_index() {
        let a2 = interpret_flags(&p("A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX][a2 highscore].adf").flags);
        assert_eq!(a2.alt_index, 2);
        let base = interpret_flags(&p("A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX].adf").flags);
        assert_eq!(base.alt_index, 0);
    }

    #[test]
    fn a10_variants_collapse_to_one_edition() {
        let names: Vec<TosecName> = [
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h PDX].adf",
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h PDX][a2].adf",
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX].adf",
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX][a2 highscore].adf",
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h SR].adf",
            "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h TAH].adf",
        ]
        .iter()
        .map(|s| p(s))
        .collect();
        let groups = group_by_edition(&names);
        assert_eq!(groups.len(), 1, "all A-10 disk-1 variants are one Edition");
        assert_eq!(groups.values().next().unwrap().len(), names.len());
    }

    #[test]
    fn mi2_languages_are_separate_editions() {
        let names: Vec<TosecName> = [
            "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(C.T.O.)(IT)(Disk 1 of 11)[cr IBB].adf",
            "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts - U.S. Gold)(Disk 1 of 11)[cr DTC].adf",
            "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts)(ES)(Disk 1 of 11)[cr Crucial].adf",
        ]
        .iter()
        .map(|s| p(s))
        .collect();
        let groups = group_by_edition(&names);
        assert_eq!(groups.len(), 3, "IT / US / ES are three Editions");
    }
}
