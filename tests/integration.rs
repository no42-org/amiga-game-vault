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
    assert_eq!(editions.len(), 1, "all A-10 disk-1 variants form one Edition");
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
        .find(|v| v.tosec_name.as_deref().map(|n| n.contains("corrupt")).unwrap_or(false))
        .unwrap();
    assert!(!bad.is_primary, "a bad dump is never primary");

    // Normalization: the primary's canonical filename is clean and self-identifying.
    assert!(
        primary.canonical_name.starts_with("A-10-Tank-Killer_v1.0"),
        "unexpected canonical name: {}",
        primary.canonical_name
    );
    assert!(primary.canonical_name.ends_with(&format!("_{}.adf", primary.uid)));

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

    let editions = vault.browse(Some("Monkey Island 2"), None, None, None).unwrap();
    assert_eq!(editions.len(), 3, "IT / US / ES are three distinct Editions");

    // Filtering by language narrows to the Spanish edition only.
    let es = vault.browse(Some("Monkey Island 2"), None, Some("es"), None).unwrap();
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

    let out = vault.ingest("mystery-disk-047.adf", &adf_for("mystery")).unwrap();
    let uid = match &out[0] {
        IngestOutcome::Stored { uid, quarantined: true, .. } => uid.clone(),
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
    assert!(art.canonical_name.starts_with("Lost-Patrol_v1.0_en_d01of01_"));
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

    let editions = vault.browse(Some("Triple Quest"), None, None, None).unwrap();
    assert_eq!(editions.len(), 3, "one Edition per disk");

    for ed in &editions {
        let variants = vault.variants(ed.edition_id).unwrap();
        let primary = variants.iter().find(|v| v.is_primary).expect("each disk has a primary");
        assert_eq!(
            primary.crack_group.as_deref(),
            Some("DTC"),
            "disk {:?} primary must be the coherent DTC lineage, not a mixed one",
            ed.disk_no
        );
    }
}
