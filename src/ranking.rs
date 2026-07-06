/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Primary selection within an Edition — a non-destructive, deterministic policy.
//!
//! Selection is *disqualify-then-rank*: bad/virus/over/under dumps can never be
//! primary; among the survivors the least-modified, verified/original,
//! trainer-free, base (non-alternate) variant wins, with a stable tie-break.
//! Nothing here mutates or removes artifacts — it only chooses a flag.

use std::collections::{BTreeMap, BTreeSet};

use crate::edition::DumpInfo;

/// The comparable ranking key (ascending = better).
pub fn rank_key(info: &DumpInfo) -> (bool, u32, bool, u32) {
    let is_clean = info.verified_good || info.modifications == 0;
    (
        !is_clean,              // clean (verified/original) first
        info.modifications,     // fewest modifications
        info.trainer.is_some(), // trainer-free preferred
        info.alt_index,         // base dump before [a], [a2], ...
    )
}

/// Select the primary among an Edition's variants.
///
/// `variants` pairs each variant's [`DumpInfo`] with a stable tie-break key
/// (e.g. the artifact UID). Returns the index of the chosen primary, or `None`
/// if every variant is disqualified.
pub fn select_primary(variants: &[(DumpInfo, String)]) -> Option<usize> {
    variants
        .iter()
        .enumerate()
        .filter(|(_, (info, _))| !info.disqualified())
        .min_by(|(_, (a, ta)), (_, (b, tb))| rank_key(a).cmp(&rank_key(b)).then_with(|| ta.cmp(tb)))
        .map(|(i, _)| i)
}

/// One disk of a multi-disk release.
#[derive(Debug, Clone)]
pub struct DiskMember {
    pub disk_no: u32,
    pub lineage: Option<String>,
    pub info: DumpInfo,
    pub tiebreak: String,
}

/// Select the primary *lineage* for a multi-disk Edition set.
///
/// Prefers a coherent single crack-lineage that covers all `disk_count` disks;
/// among complete lineages, the one with the fewest total modifications wins,
/// with a stable tie-break by lineage tag. Disqualified members do not count
/// toward a lineage's coverage. Returns the chosen lineage tag (empty string
/// denotes the no-group/original lineage), or `None` if nothing qualifies.
pub fn select_primary_lineage(members: &[DiskMember], disk_count: u32) -> Option<String> {
    let mut by: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, m) in members.iter().enumerate() {
        if m.info.disqualified() {
            continue;
        }
        by.entry(m.lineage.clone().unwrap_or_default())
            .or_default()
            .push(i);
    }
    if by.is_empty() {
        return None;
    }

    // Score each lineage; smaller key = better.
    // key = (not_complete, usize::MAX - coverage, sum_modifications, tag)
    let mut best: Option<(bool, usize, u32, String)> = None;
    for (tag, idxs) in &by {
        let disks: BTreeSet<u32> = idxs.iter().map(|&i| members[i].disk_no).collect();
        let coverage = disks.len();
        let complete = disk_count == 0 || (1..=disk_count).all(|d| disks.contains(&d));
        let sum_mods: u32 = idxs.iter().map(|&i| members[i].info.modifications).sum();
        let key = (!complete, usize::MAX - coverage, sum_mods, tag.clone());
        match &best {
            Some(b) if *b <= key => {}
            _ => best = Some(key),
        }
    }
    best.map(|(_, _, _, tag)| tag)
}

/// A candidate lineage of a Set: which disks it covers and whether it is complete.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LineageCoverage {
    /// The crack/hack group; `None` for the no-group/orphan lineage.
    pub lineage: Option<String>,
    /// Disk numbers this lineage covers, ascending.
    pub disks_covered: Vec<u32>,
    /// Covers every disk `1..=disk_count`.
    pub complete: bool,
    /// The lineage the vault auto-selects as the coherent primary set.
    pub is_primary: bool,
}

/// Enumerate every candidate lineage of a set with its coverage, sorted best-first
/// (complete before partial, then by the primary-selection ranking). Disqualified
/// members do not count toward coverage — a bad-dump disk does not complete a set.
pub fn lineage_coverage(members: &[DiskMember], disk_count: u32) -> Vec<LineageCoverage> {
    let mut by: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, m) in members.iter().enumerate() {
        if m.info.disqualified() {
            continue;
        }
        by.entry(m.lineage.clone().unwrap_or_default())
            .or_default()
            .push(i);
    }
    // (not_complete, MAX-coverage, sum_mods, tag) — same key as select_primary_lineage,
    // so the first row after sorting is the auto-primary lineage.
    let mut scored: Vec<(bool, usize, u32, String, LineageCoverage)> = Vec::new();
    for (tag, idxs) in &by {
        let disks: BTreeSet<u32> = idxs.iter().map(|&i| members[i].disk_no).collect();
        let coverage = disks.len();
        let complete = disk_count == 0 || (1..=disk_count).all(|d| disks.contains(&d));
        let sum_mods: u32 = idxs.iter().map(|&i| members[i].info.modifications).sum();
        let cov = LineageCoverage {
            lineage: (!tag.is_empty()).then(|| tag.clone()),
            disks_covered: disks.into_iter().collect(),
            complete,
            is_primary: false,
        };
        scored.push((!complete, usize::MAX - coverage, sum_mods, tag.clone(), cov));
    }
    scored.sort_by(|a, b| (a.0, a.1, a.2, &a.3).cmp(&(b.0, b.1, b.2, &b.3)));
    let mut out: Vec<LineageCoverage> = scored.into_iter().map(|t| t.4).collect();
    if let Some(first) = out.first_mut() {
        first.is_primary = true;
    }
    out
}

/// Pick the best non-disqualified member of a given lineage for each disk.
pub fn primary_set_for_lineage(members: &[DiskMember], lineage: &str) -> Vec<usize> {
    let mut by_disk: BTreeMap<u32, usize> = BTreeMap::new();
    for (i, m) in members.iter().enumerate() {
        if m.info.disqualified() {
            continue;
        }
        if m.lineage.clone().unwrap_or_default() != lineage {
            continue;
        }
        match by_disk.get(&m.disk_no) {
            Some(&cur) => {
                let better = rank_key(&m.info)
                    .cmp(&rank_key(&members[cur].info))
                    .then_with(|| m.tiebreak.cmp(&members[cur].tiebreak));
                if better == std::cmp::Ordering::Less {
                    by_disk.insert(m.disk_no, i);
                }
            }
            None => {
                by_disk.insert(m.disk_no, i);
            }
        }
    }
    by_disk.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edition::interpret_flags;
    use crate::naming::parse_tosec;

    fn info(name: &str) -> DumpInfo {
        interpret_flags(&parse_tosec(name).unwrap().flags)
    }

    #[test]
    fn disqualified_never_primary() {
        let variants = vec![
            (
                info("Agony (1992)(P)(Disk 1 of 3)[cr CSL][b corrupt file].adf"),
                "uid_bad".into(),
            ),
            (
                info("Agony (1992)(P)(Disk 1 of 3)[cr CSL].adf"),
                "uid_ok".into(),
            ),
        ];
        let idx = select_primary(&variants).unwrap();
        assert_eq!(variants[idx].1, "uid_ok");
    }

    #[test]
    fn prefers_least_modified() {
        let variants = vec![
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr QTX][t +5][h SR].adf"),
                "uid_heavy".into(),
            ),
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr QTX].adf"),
                "uid_light".into(),
            ),
        ];
        let idx = select_primary(&variants).unwrap();
        assert_eq!(variants[idx].1, "uid_light");
    }

    #[test]
    fn prefers_verified_original() {
        let variants = vec![
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr QTX].adf"),
                "uid_crack".into(),
            ),
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[!].adf"),
                "uid_verified".into(),
            ),
        ];
        let idx = select_primary(&variants).unwrap();
        assert_eq!(variants[idx].1, "uid_verified");
    }

    #[test]
    fn base_before_alternate_and_deterministic() {
        let variants = vec![
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr QTX][a2].adf"),
                "uid_a2".into(),
            ),
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr QTX].adf"),
                "uid_base".into(),
            ),
        ];
        assert_eq!(variants[select_primary(&variants).unwrap()].1, "uid_base");
        // Deterministic: reversing input order yields the same winner.
        let mut rev = variants.clone();
        rev.reverse();
        assert_eq!(rev[select_primary(&rev).unwrap()].1, "uid_base");
    }

    #[test]
    fn all_disqualified_returns_none() {
        let variants = vec![
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[cr X][b].adf"),
                "uid1".into(),
            ),
            (
                info("A-10 (1990)(D)(Disk 1 of 2)[h Y][v virus].adf"),
                "uid2".into(),
            ),
        ];
        assert!(select_primary(&variants).is_none());
    }

    #[test]
    fn complete_lineage_preferred_over_partial() {
        let mut members = Vec::new();
        // DTC: complete 1..3
        for d in 1..=3 {
            members.push(DiskMember {
                disk_no: d,
                lineage: Some("DTC".into()),
                info: info("X (1992)(L)(Disk 1 of 3)[cr DTC].adf"),
                tiebreak: format!("dtc{d}"),
            });
        }
        // Conet: only disk 1
        members.push(DiskMember {
            disk_no: 1,
            lineage: Some("Conet".into()),
            info: info("X (1992)(L)(Disk 1 of 3)[cr Conet].adf"),
            tiebreak: "conet1".into(),
        });

        let lineage = select_primary_lineage(&members, 3).unwrap();
        assert_eq!(lineage, "DTC");
        let set = primary_set_for_lineage(&members, &lineage);
        assert_eq!(
            set.len(),
            3,
            "primary set spans all three disks of one lineage"
        );
    }

    #[test]
    fn lineage_coverage_enumerates_complete_and_partial() {
        let mut members = Vec::new();
        let mut push = |disk: u32, lin: &str, tag: &str| {
            members.push(DiskMember {
                disk_no: disk,
                lineage: Some(lin.into()),
                info: info(&format!("Agony (1992)(P)(Disk {disk} of 3)[cr {lin}].adf")),
                tiebreak: tag.into(),
            });
        };
        // Bobic: complete (a plain crack, fewest mods → the auto-primary)
        for d in 1..=3 {
            push(d, "Bobic", &format!("bobic{d}"));
        }
        // CSL: complete, with several variants on disk 1
        for d in 1..=3 {
            push(d, "CSL", &format!("csl{d}"));
        }
        push(1, "CSL", "csl1b");
        push(1, "CSL", "csl1c");
        // A-Team: partial — missing disk 3
        push(1, "A-Team", "at1");
        push(2, "A-Team", "at2");

        let cov = lineage_coverage(&members, 3);
        let by: std::collections::HashMap<_, _> = cov
            .iter()
            .map(|c| (c.lineage.clone().unwrap(), c))
            .collect();

        assert!(by["Bobic"].complete && by["CSL"].complete);
        assert!(!by["A-Team"].complete);
        assert_eq!(by["A-Team"].disks_covered, vec![1, 2]);
        // Complete lineages sort before the partial one.
        assert!(cov.last().unwrap().lineage.as_deref() == Some("A-Team"));
        // Exactly one lineage is marked the auto-primary, and it is complete.
        let primaries: Vec<_> = cov.iter().filter(|c| c.is_primary).collect();
        assert_eq!(primaries.len(), 1);
        assert!(primaries[0].complete);
    }
}
