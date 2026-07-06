/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! End-to-end tests over the real screenshot cases: A-10 Tank Killer's crack /
//! trainer variants collapsing into one Edition, and Monkey Island 2 splitting
//! into three language Editions.

use amiga_game_vault::service::{IngestOutcome, Vault};

/// Distinct ADF bytes per variant, so each is a separate artifact.
fn adf_for(name: &str) -> Vec<u8> {
    let mut v = vec![0u8; 1024];
    v.extend_from_slice(name.as_bytes());
    v
}

fn ingest(v: &Vault, name: &str) -> Vec<IngestOutcome> {
    v.ingest(name, &adf_for(name)).unwrap()
}

#[test]
fn a10_variants_collapse_and_pick_clean_primary() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    let names = [
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h PDX].adf",
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h QTX][a2 highscore].adf",
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[h SR].adf",
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX].adf",
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX][b corrupt file].adf",
        "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[!].adf", // verified/original
    ];
    for n in names {
        assert!(matches!(ingest(&vault, n)[0], IngestOutcome::Stored { .. }));
    }

    // All six variants land in a single Edition.
    let editions = vault.browse(Some("A-10"), None, None, None).unwrap();
    assert_eq!(
        editions.len(),
        1,
        "all A-10 disk-1 variants form one Edition"
    );
    let ed = &editions[0];
    assert_eq!(ed.title, "A-10 Tank Killer");
    assert_eq!(ed.disk_no, Some(1));
    assert_eq!(ed.disk_count, Some(2));
    assert_eq!(ed.variant_count, 6);

    let variants = vault.variants(ed.edition_id).unwrap();
    let primaries: Vec<_> = variants.iter().filter(|v| v.is_primary).collect();
    assert_eq!(primaries.len(), 1, "exactly one primary");

    let primary = primaries[0];
    // The verified/original [!] dump must win over crack/hack variants...
    assert_eq!(primary.dump_type.as_deref(), Some("original"));
    // ...and it must never be the corrupt/bad dump.
    let bad = variants
        .iter()
        .find(|v| {
            v.tosec_name
                .as_deref()
                .map(|n| n.contains("corrupt"))
                .unwrap_or(false)
        })
        .unwrap();
    assert!(!bad.is_primary, "a bad dump is never primary");

    // Normalization: the primary's canonical filename is clean and self-identifying.
    assert!(
        primary.canonical_name.starts_with("A-10-Tank-Killer_v1.0"),
        "unexpected canonical name: {}",
        primary.canonical_name
    );
    assert!(primary
        .canonical_name
        .ends_with(&format!("_{}.adf", primary.uid)));

    // Download serves the stored bytes under the canonical name (bytes unchanged).
    let (name, bytes) = vault.blob_for(&primary.uid).unwrap().unwrap();
    assert_eq!(name, primary.canonical_name);
    assert_eq!(bytes, adf_for(names[5]));
}

#[test]
fn mi2_splits_into_three_language_editions() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    let names = [
        "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(C.T.O.)(IT)(Disk 1 of 11)[cr IBB].adf",
        "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts - U.S. Gold)(Disk 1 of 11)[cr DTC].adf",
        "Monkey Island 2 - LeChuck's Revenge v1.0 (1992)(LucasArts)(ES)(Disk 1 of 11)[cr Crucial].adf",
    ];
    for n in names {
        ingest(&vault, n);
    }

    let editions = vault
        .browse(Some("Monkey Island 2"), None, None, None)
        .unwrap();
    assert_eq!(
        editions.len(),
        3,
        "IT / US / ES are three distinct Editions"
    );

    // Filtering by language narrows to the Spanish edition only.
    let es = vault
        .browse(Some("Monkey Island 2"), None, Some("es"), None)
        .unwrap();
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].language.as_deref(), Some("es"));
}

#[test]
fn exact_duplicate_is_collapsed() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    let name = "Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL].adf";
    let bytes = adf_for(name);

    let first = vault.ingest(name, &bytes).unwrap();
    let second = vault.ingest(name, &bytes).unwrap();
    assert!(matches!(first[0], IngestOutcome::Stored { .. }));
    assert!(matches!(second[0], IngestOutcome::Duplicate { .. }));

    // Only one artifact exists for those bytes.
    let editions = vault.browse(Some("Agony"), None, None, None).unwrap();
    assert_eq!(editions[0].variant_count, 1);
}

#[test]
fn unidentifiable_upload_is_quarantined_then_resolvable() {
    use amiga_game_vault::service::ResolveMeta;

    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    let out = vault
        .ingest("mystery-disk-047.adf", &adf_for("mystery"))
        .unwrap();
    let uid = match &out[0] {
        IngestOutcome::Stored {
            uid,
            quarantined: true,
            ..
        } => uid.clone(),
        other => panic!("expected quarantine, got {other:?}"),
    };
    assert_eq!(vault.quarantine_list().unwrap().len(), 1);

    // Resolving it assigns identity and removes it from quarantine.
    vault
        .resolve_quarantine(
            &uid,
            &ResolveMeta {
                title: "Lost Patrol".into(),
                category: "game".into(),
                version: Some("v1.0".into()),
                language: Some("en".into()),
                disk_no: Some(1),
                disk_count: Some(1),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(vault.quarantine_list().unwrap().len(), 0);
    let editions = vault.browse(Some("Lost Patrol"), None, None, None).unwrap();
    assert_eq!(editions.len(), 1);
    // Regression (#1): the resolved artifact becomes the Edition's primary,
    // rather than being dropped and leaving the Edition with a NULL primary.
    assert_eq!(editions[0].primary_uid.as_deref(), Some(uid.as_str()));
    // After resolution the artifact has a clean canonical name.
    let art = vault.get_artifact(&uid).unwrap().unwrap();
    assert!(art
        .canonical_name
        .starts_with("Lost-Patrol_v1.0_en_d01of01_"));
}

#[test]
fn multidisk_set_picks_one_coherent_lineage() {
    // Regression (#3): a 3-disk game where only lineage "DTC" spans all disks;
    // "Conet" exists only for disk 1. Every disk's primary must be DTC so the
    // set is coherent (never disk 1 = Conet while disk 2 = DTC).
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    for n in [
        "Triple Quest (1992)(Acme)(Disk 1 of 3)[cr DTC].adf",
        "Triple Quest (1992)(Acme)(Disk 1 of 3)[cr Conet].adf",
        "Triple Quest (1992)(Acme)(Disk 2 of 3)[cr DTC].adf",
        "Triple Quest (1992)(Acme)(Disk 3 of 3)[cr DTC].adf",
    ] {
        ingest(&vault, n);
    }

    let editions = vault
        .browse(Some("Triple Quest"), None, None, None)
        .unwrap();
    assert_eq!(editions.len(), 3, "one Edition per disk");

    for ed in &editions {
        let variants = vault.variants(ed.edition_id).unwrap();
        let primary = variants
            .iter()
            .find(|v| v.is_primary)
            .expect("each disk has a primary");
        assert_eq!(
            primary.crack_group.as_deref(),
            Some("DTC"),
            "disk {:?} primary must be the coherent DTC lineage, not a mixed one",
            ed.disk_no
        );
    }
}

#[test]
fn agony_demos_and_game_are_categorized_and_distinct() {
    // The real screenshot case: the 3-disk full game plus 1991 playable/rolling
    // demos. Demos become category `demo` with publisher `Psygnosis` preserved,
    // and the two demo types stay distinct via their qualifier.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    for n in [
        "Agony (demo-playable) (1991)(Psygnosis)[h PRD].adf",
        "Agony (demo-rolling) (1991)(Psygnosis).adf",
        "Agony (demo-rolling) (1991)(Psygnosis)[h TRSI].adf",
        "Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL].adf",
    ] {
        ingest(&vault, n);
    }

    let eds = vault.browse(Some("Agony"), None, None, None).unwrap();
    assert_eq!(
        eds.len(),
        3,
        "playable demo, rolling demo, and the game disk"
    );

    let demos: Vec<_> = eds.iter().filter(|e| e.category == "demo").collect();
    assert_eq!(demos.len(), 2, "two demo editions");
    assert!(
        demos
            .iter()
            .all(|e| e.publisher.as_deref() == Some("Psygnosis")),
        "publisher restored, not eaten by the demo token"
    );
    let mut quals: Vec<_> = demos.iter().filter_map(|e| e.qualifier.clone()).collect();
    quals.sort();
    assert_eq!(quals, vec!["demo-playable", "demo-rolling"]);

    let game: Vec<_> = eds.iter().filter(|e| e.category == "game").collect();
    assert_eq!(game.len(), 1);
    assert_eq!(game[0].disk_no, Some(1));
    assert_eq!(game[0].disk_count, Some(3));
    assert_eq!(game[0].publisher.as_deref(), Some("Psygnosis"));

    // The category filter is now meaningful.
    assert_eq!(
        vault
            .browse(Some("Agony"), Some("demo"), None, None)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        vault
            .browse(Some("Agony"), Some("game"), None, None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn agony_multi_disk_set_candidate_lineages_and_export() {
    // A 3-disk release with two complete lineages (Bobic all-3, CSL all-3) and a
    // partial one (A-Team missing disk 3). Verify set enumeration, coherence, and
    // coherent export.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();

    let mut names = vec![];
    for d in 1..=3 {
        names.push(format!(
            "Agony (1992)(Psygnosis)(Disk {d} of 3)[h Bobic][HD].adf"
        ));
        names.push(format!(
            "Agony (1992)(Psygnosis)(Disk {d} of 3)[cr CSL][t +9 TLPI].adf"
        ));
    }
    // extra CSL variant on disk 1, and a partial A-Team (disks 1 & 2 only)
    names.push("Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL].adf".into());
    names.push("Agony (1992)(Psygnosis)(Disk 1 of 3)[cr A-Team][t +5 Access].adf".into());
    names.push("Agony (1992)(Psygnosis)(Disk 2 of 3)[cr A-Team].adf".into());
    for n in &names {
        ingest(&vault, n);
    }

    // One Set card, multi-disk, all 3 disks present.
    let sets = vault
        .list_sets(Some("Agony"), Some("game"), None, false)
        .unwrap();
    assert_eq!(sets.len(), 1);
    let s = &sets[0];
    assert!(s.multi);
    assert_eq!(s.disk_count, Some(3));
    assert_eq!(s.disks_present, vec![1, 2, 3]);
    assert_eq!(s.complete_lineages, 2, "Bobic and CSL are complete");

    // Candidate lineages: Bobic & CSL complete, A-Team partial (missing disk 3).
    let cov = vault.set_lineages(s.rep_edition_id).unwrap();
    let by = |lin: &str| {
        cov.iter()
            .find(|c| c.lineage.as_deref() == Some(lin))
            .unwrap()
    };
    assert!(by("Bobic").complete && by("CSL").complete);
    assert!(!by("A-Team").complete);
    assert_eq!(by("A-Team").disks_covered, vec![1, 2]);
    assert_eq!(cov.iter().filter(|c| c.is_primary).count(), 1);

    // Resolve CSL to a coherent set: one file per disk, all CSL, never mixed.
    let resolved = vault.resolve_set(s.rep_edition_id, "CSL").unwrap();
    assert_eq!(
        resolved.iter().map(|(d, _)| *d).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    for (_disk, uid) in &resolved {
        let a = vault.get_artifact(uid).unwrap().unwrap();
        assert!(a.tosec_name.unwrap().contains("[cr CSL]"));
    }

    // Coherent export = 3 files.
    let files = vault.export_set(s.rep_edition_id, "CSL").unwrap();
    assert_eq!(files.len(), 3);
}

#[test]
fn incomplete_set_is_flagged_and_single_disk_is_trivial() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    // A 2-disk release with only disk 1 present.
    ingest(
        &vault,
        "Lemmings (1991)(Psygnosis)(Disk 1 of 2)[cr QTX].adf",
    );
    // A single-disk title.
    ingest(&vault, "Zool (1992)(Gremlin)[cr PDX].adf");

    let all = vault.list_sets(None, None, None, false).unwrap();
    let lem = all.iter().find(|s| s.title == "Lemmings").unwrap();
    assert!(
        lem.multi && lem.complete_lineages == 0,
        "missing disk 2 => no complete set"
    );
    let zool = all.iter().find(|s| s.title == "Zool").unwrap();
    assert!(!zool.multi, "single-disk title is a trivial set");

    // Incomplete filter surfaces Lemmings, not the complete single-disk Zool.
    let incomplete = vault.list_sets(None, None, None, true).unwrap();
    assert!(incomplete.iter().any(|s| s.title == "Lemmings"));
    assert!(!incomplete.iter().any(|s| s.title == "Zool"));
}

#[test]
fn export_set_refuses_incomplete_lineage() {
    // A-Team covers only disks 1 & 2 of a 3-disk set; exporting it must error
    // rather than silently produce a partial (unbootable) zip.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    for d in 1..=3 {
        ingest(
            &vault,
            &format!("Agony (1992)(Psygnosis)(Disk {d} of 3)[cr CSL].adf"),
        );
    }
    ingest(
        &vault,
        "Agony (1992)(Psygnosis)(Disk 1 of 3)[cr A-Team].adf",
    );
    ingest(
        &vault,
        "Agony (1992)(Psygnosis)(Disk 2 of 3)[cr A-Team].adf",
    );

    let sets = vault.list_sets(Some("Agony"), None, None, false).unwrap();
    let rep = sets[0].rep_edition_id;

    // Complete lineage exports fine.
    assert_eq!(vault.export_set(rep, "CSL").unwrap().len(), 3);
    // Partial and unknown lineages are refused.
    assert!(vault.export_set(rep, "A-Team").is_err());
    assert!(vault.export_set(rep, "Nonexistent").is_err());
}

#[test]
fn work_groups_releases_and_playable_sets_with_trainer_override() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    // Two demos + a 3-disk CSL game whose boot disk has a plain and a trained variant.
    ingest(&vault, "Agony (demo-playable) (1991)(Psygnosis)[h PRD].adf");
    ingest(&vault, "Agony (demo-rolling) (1991)(Psygnosis).adf");
    ingest(&vault, "Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL].adf");
    ingest(
        &vault,
        "Agony (1992)(Psygnosis)(Disk 1 of 3)[cr CSL][t +9 TLPI].adf",
    );
    ingest(&vault, "Agony (1992)(Psygnosis)(Disk 2 of 3)[cr CSL].adf");
    ingest(&vault, "Agony (1992)(Psygnosis)(Disk 3 of 3)[cr CSL].adf");

    // The Work gathers the game and both demos.
    let works = vault.list_works(Some("Agony"), None, None).unwrap();
    assert_eq!(works.len(), 1);
    let w = &works[0];
    assert_eq!(w.name, "Agony");
    assert_eq!((w.game_count, w.demo_count), (1, 2));

    let game = w.releases.iter().find(|r| r.category == "game").unwrap();
    let rep = game.rep_edition_id;

    // Playable sets: CSL is a complete, recommended variation with a trainer choice.
    let sets = vault.playable_sets(rep).unwrap();
    let csl = sets
        .iter()
        .find(|s| s.lineage.as_deref() == Some("CSL"))
        .unwrap();
    assert!(csl.complete && csl.is_recommended && csl.disks.len() == 3);
    assert_eq!(csl.trainer_options.len(), 2);
    let trained = csl
        .trainer_options
        .iter()
        .find(|t| t.trainer.as_deref() == Some("+9 TLPI"))
        .unwrap();
    let plain = csl
        .trainer_options
        .iter()
        .find(|t| t.trainer.is_none())
        .unwrap();
    assert!(
        plain.is_default,
        "ranking prefers the trainer-free boot disk"
    );

    // Default download uses the plain boot; the override swaps in the trained boot.
    let default_files = vault.export_set(rep, "CSL").unwrap();
    assert!(default_files.len() == 3 && default_files.iter().any(|(n, _)| n.contains(&plain.uid)));
    let trained_files = vault
        .export_set_with(rep, "CSL", Some(&trained.uid))
        .unwrap();
    assert!(trained_files.iter().any(|(n, _)| n.contains(&trained.uid)));
    // An invalid boot override falls back to the default (still a complete set).
    assert_eq!(
        vault
            .export_set_with(rep, "CSL", Some("deadbeef00"))
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn single_release_title_is_a_trivial_work() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    ingest(&vault, "Zool (1992)(Gremlin)[cr PDX].adf");
    let works = vault.list_works(Some("Zool"), None, None).unwrap();
    assert_eq!(works.len(), 1);
    assert_eq!(works[0].release_count, 1);
    assert_eq!(works[0].game_count, 1);
}

#[test]
fn original_uncracked_set_is_downloadable() {
    // A clean uncracked multi-disk game (no [cr]/[h]) is the "original" lineage;
    // its coherent set must be exportable (regression: empty lineage tag).
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_memory(dir.path()).unwrap();
    ingest(&vault, "Lemmings (1991)(Psygnosis)(Disk 1 of 2).adf");
    ingest(&vault, "Lemmings (1991)(Psygnosis)(Disk 2 of 2).adf");

    let works = vault.list_works(Some("Lemmings"), None, None).unwrap();
    let game = works[0]
        .releases
        .iter()
        .find(|r| r.category == "game")
        .unwrap();
    let sets = vault.playable_sets(game.rep_edition_id).unwrap();
    let orig = sets.iter().find(|s| s.lineage.is_none()).unwrap();
    assert!(orig.complete, "the uncracked original set is complete");
    // The original (empty lineage tag) exports as a coherent 2-disk set.
    assert_eq!(
        vault
            .export_set_with(game.rep_edition_id, "", None)
            .unwrap()
            .len(),
        2
    );
}
