/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The Vault: orchestration tying together the blob store, database, ingest
//! pipeline, identification engines, deduplication and normalization.
//!
//! Ingest flow per decoded ADF: store bytes (exact-dedup for free) -> identify
//! (hash->DAT, else filename parse, else quarantine) -> group into an Edition ->
//! recompute the non-destructive primary.

use std::path::Path;

use crate::dat::{parse_dat, DatEntry};
use crate::db::{ArtifactView, Db, EditionView, NewArtifact};
use crate::edition::{
    edition_key, infer_category, interpret_flags, Category, DumpInfo, EditionKey,
};
use crate::identity::Hashes;
use crate::ingest::{detect_container, DiskImage, Tools};
use crate::naming::{parse_tosec, TosecName};
use crate::ranking::{
    lineage_coverage, primary_set_for_lineage, rank_key, select_primary, select_primary_lineage,
    DiskMember, LineageCoverage,
};
use crate::{Error, Result};

/// A resolved identity: parsed name, interpreted dump info, the authoritative
/// canonical name to retain, and the inferred category.
type Identity = (TosecName, DumpInfo, String, Category);

/// The outcome of ingesting one decoded ADF.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IngestOutcome {
    /// A newly stored artifact.
    Stored {
        uid: String,
        verified: bool,
        quarantined: bool,
    },
    /// Byte-identical to an existing artifact; nothing new stored.
    Duplicate { uid: String },
}

/// A release (Set): the disks that form one game, rolled up from the Editions
/// sharing a set key. `multi` is false for a trivial single-disk title.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SetView {
    pub rep_edition_id: i64,
    /// The logical work this release belongs to; the key for enrichment.
    pub title_id: i64,
    pub multi: bool,
    pub title: String,
    pub category: String,
    pub publisher: Option<String>,
    pub year: Option<i32>,
    pub version: Option<String>,
    /// Sortable natural-version key (see [`crate::naming::version_key`]); `None`
    /// when the release has no version. Drives the browse version timeline.
    pub version_key: Option<String>,
    pub language: Option<String>,
    pub qualifier: Option<String>,
    pub disk_count: Option<u32>,
    pub disks_present: Vec<u32>,
    pub complete_lineages: usize,
    pub primary_lineage: Option<String>,
    pub variant_count: i64,
    /// Count of this release's lineages that fold to each browse type class (by
    /// lineage: the no-group lineage is `original`, each crack lineage is
    /// `cracked` or `hacked`). Drives the colour-coded summary chips.
    pub original_count: usize,
    pub cracked_count: usize,
    pub hacked_count: usize,
    /// Merged online metadata for the work (description/genre/screenshots), or
    /// `None` when the title has not been enriched. Same object is served by the
    /// per-title meta endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<crate::db::TitleMeta>,
}

/// A Work: everything sharing a title name (the game release(s) and demos),
/// grouped at read time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkView {
    pub name: String,
    pub release_count: usize,
    pub game_count: usize,
    pub demo_count: usize,
    pub tool_count: usize,
    /// Work-level totals of each browse type class, summed across releases, so the
    /// card header can show summary chips without re-summing on the client.
    pub original_count: usize,
    pub cracked_count: usize,
    pub hacked_count: usize,
    pub releases: Vec<SetView>,
}

/// A boot-disk (trainer) option for a playable set.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrainerOption {
    pub uid: String,
    /// Trainer text (e.g. "+9 TLPI"), or `None` for the plain boot disk.
    pub trainer: Option<String>,
    /// Whether this is the ranking-default boot disk.
    pub is_default: bool,
}

/// A playable variation of a game: a complete coherent set the user can download.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlayableSet {
    pub rep_edition_id: i64,
    /// The crack/hack group, or `None` for the original.
    pub lineage: Option<String>,
    /// Browse type class of this lineage: `original` (no group), else `cracked`
    /// or `hacked` (if any member is a hack/modification/trainer).
    pub kind: String,
    /// Trainer text (e.g. "+3 DC") if any member of this lineage carries one, so
    /// the UI can show a trainer chip even when there is no plain/trained *choice*
    /// (which is all `trainer_options` captures). `None` if the lineage is untrained.
    pub trainer: Option<String>,
    pub complete: bool,
    pub missing_disks: Vec<u32>,
    pub is_recommended: bool,
    /// Coherent `(disk_no, uid)` (best per disk); empty for an incomplete variation.
    /// Internal only (drives trainer options) — not shipped to the client.
    #[serde(skip)]
    pub disks: Vec<(u32, String)>,
    /// Boot-disk trainer choices for this lineage.
    pub trainer_options: Vec<TrainerOption>,
}

/// The result of a re-identification pass.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReidentifyReport {
    pub scanned: usize,
    pub moved: usize,
    pub editions_removed: usize,
    pub titles_removed: usize,
}

/// Metadata supplied when a user resolves a quarantined artifact.
#[derive(Debug, Clone, Default)]
pub struct ResolveMeta {
    pub title: String,
    pub category: String,
    pub version: Option<String>,
    pub language: Option<String>,
    pub publisher: Option<String>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
}

/// The browse display class of one lineage of a set: the 5→3 fold
/// ([`crate::edition::DumpType::class3`]) of the lineage's best-ranked member —
/// i.e. the dump the set actually downloads (`rank_key` prefers the cleanest,
/// verified/original, trainer-free variant). So a bucket that holds only a
/// hack/trainer reads as `hacked`, while one that also holds a clean dump reads
/// as `original`; the no-group (`""`) lineage is not special-cased. Empty (all
/// members disqualified) falls back to `original`.
fn lineage_class(tag: &str, members: &[DiskMember]) -> &'static str {
    members
        .iter()
        .filter(|m| m.lineage.as_deref().unwrap_or("") == tag && !m.info.disqualified())
        .min_by(|a, b| rank_key(&a.info).cmp(&rank_key(&b.info)))
        .map(|m| m.info.dump_type.class3())
        .unwrap_or("original")
}

pub struct Vault {
    store: crate::store::BlobStore,
    db: Db,
    tools: Tools,
}

impl Vault {
    /// Open a vault under `data_dir` (blobs + SQLite).
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        std::fs::create_dir_all(data_dir)?;
        let store = crate::store::BlobStore::open(data_dir.join("blobs"))?;
        let db_path = data_dir.join("vault.sqlite");
        let db = Db::open(
            db_path
                .to_str()
                .ok_or_else(|| Error::Invalid("bad data dir".into()))?,
        )?;
        Ok(Self {
            store,
            db,
            tools: Tools,
        })
    }

    /// A vault backed entirely in memory (for tests).
    pub fn open_memory(blob_dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: crate::store::BlobStore::open(blob_dir)?,
            db: Db::open_memory()?,
            tools: Tools,
        })
    }

    /// Import a Logiqx-format DAT into the reference database.
    pub fn import_dat_xml(&self, xml: &str, source: &str) -> Result<usize> {
        let entries = parse_dat(xml, source);
        self.db.import_dat(&entries)
    }

    /// Ingest an upload, returning one outcome per contained ADF.
    pub fn ingest(&self, filename: &str, bytes: &[u8]) -> Result<Vec<IngestOutcome>> {
        let container = detect_container(filename, bytes)?;
        let decoded = self.tools.decode(container, bytes, filename)?;

        let mut outcomes = Vec::new();
        for d in decoded {
            outcomes.push(self.ingest_one(&d.name, &d.adf, d.container.as_str())?);
        }
        Ok(outcomes)
    }

    fn ingest_one(&self, name: &str, adf: &[u8], container: &str) -> Result<IngestOutcome> {
        let (hashes, _is_new) = self.store.put(adf)?;

        // Exact duplicate: identical bytes already stored.
        if let Some(uid) = self.db.artifact_uid_by_sha1(&hashes.sha1)? {
            return Ok(IngestOutcome::Duplicate { uid });
        }

        let uid = self.db.unique_uid_for(&hashes.sha1)?;

        // Identify: hash->DAT (verified) wins over filename parse (unverified).
        let (identity, verified) = self.identify(name, &hashes)?;

        let mut rec = NewArtifact {
            uid: uid.clone(),
            hashes: hashes.clone(),
            container: container.to_string(),
            blob_sha1: hashes.sha1.clone(),
            orig_filename: Some(name.to_string()),
            verified,
            ..Default::default()
        };

        match identity {
            Some((parsed, info, canonical_name, category)) => {
                rec.display_title = Some(parsed.title.clone());
                rec.year = parsed.year;
                // Retain the authoritative canonical name: the DAT entry name when
                // hash-verified, else the (parseable) upload filename.
                rec.tosec_name = Some(canonical_name);
                apply_dump_info(&mut rec, &info);

                let key = edition_key(&parsed);
                let edition_id = self.ensure_edition(category.as_str(), &key)?;
                rec.edition_id = Some(edition_id);
                self.db.insert_artifact(&rec)?;
                self.recompute_set_primaries(edition_id)?;
                Ok(IngestOutcome::Stored {
                    uid,
                    verified,
                    quarantined: false,
                })
            }
            None => {
                // Unidentifiable: store bare and quarantine.
                self.db.insert_artifact(&rec)?;
                self.db
                    .quarantine(&uid, "no DAT match and unparseable filename")?;
                Ok(IngestOutcome::Stored {
                    uid,
                    verified: false,
                    quarantined: true,
                })
            }
        }
    }

    /// Resolve identity: prefer a verified hash match, else a filename parse.
    /// Returns the parsed name, interpreted dump info, and the authoritative
    /// canonical name to retain.
    fn identify(&self, name: &str, hashes: &Hashes) -> Result<(Option<Identity>, bool)> {
        if let Some(entry) = self.db.match_dat(hashes)? {
            // Authoritative: build identity from the DAT's canonical name.
            let parsed = parse_tosec(&entry.name).unwrap_or_else(|| dat_to_name(&entry));
            let info = interpret_flags(&parsed.flags);
            let category = infer_category(parsed.qualifier.as_deref(), Some(&entry.source));
            return Ok((Some((parsed, info, entry.name, category)), true));
        }
        if let Some(parsed) = parse_tosec(name) {
            let info = interpret_flags(&parsed.flags);
            let category = infer_category(parsed.qualifier.as_deref(), None);
            return Ok((Some((parsed, info, name.to_string(), category)), false));
        }
        Ok((None, false))
    }

    fn ensure_edition(&self, category: &str, key: &EditionKey) -> Result<i64> {
        let title_id = self.db.upsert_title(&key.title, category)?;
        self.db.upsert_edition(title_id, key)
    }

    /// Recompute primaries for the whole set that `edition_id` belongs to, using
    /// the persisted [`DumpInfo`] columns (never re-parsing filenames, so no
    /// variant is ever dropped). Non-destructive: only `primary_artifact_uid`
    /// flags change.
    ///
    /// Baseline: each Edition (one disk) gets its own best primary. For multi-disk
    /// sets, a single coherent crack-lineage is then chosen across all disks and
    /// overrides the baseline for the disks it covers.
    fn recompute_set_primaries(&self, edition_id: i64) -> Result<()> {
        let (disk_count, siblings) = self.db.set_siblings(edition_id)?;

        let mut members: Vec<DiskMember> = Vec::new();
        let mut owner: Vec<(i64, String)> = Vec::new(); // parallel to `members`

        for (ed_id, disk_no) in &siblings {
            let infos = self.db.edition_variant_infos(*ed_id)?;
            let variants: Vec<(DumpInfo, String)> = infos
                .iter()
                .map(|(uid, info)| (info.clone(), uid.clone()))
                .collect();

            // Baseline per-Edition primary.
            let primary = select_primary(&variants).map(|i| variants[i].1.clone());
            self.db.set_primary(*ed_id, primary.as_deref())?;

            for (uid, info) in infos {
                members.push(DiskMember {
                    disk_no: disk_no.unwrap_or(0),
                    lineage: info.lineage.clone(),
                    info,
                    tiebreak: uid.clone(),
                });
                owner.push((*ed_id, uid));
            }
        }

        // Multi-disk coherence: pick one lineage spanning all disks and override.
        if let Some(dc) = disk_count {
            if dc > 1 {
                if let Some(lineage) = select_primary_lineage(&members, dc) {
                    for idx in primary_set_for_lineage(&members, &lineage) {
                        let (ed_id, uid) = &owner[idx];
                        self.db.set_primary(*ed_id, Some(uid))?;
                    }
                }
            }
        }
        Ok(())
    }

    // --- Reads / actions for the web layer --------------------------------

    pub fn browse(
        &self,
        q: Option<&str>,
        category: Option<&str>,
        language: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<EditionView>> {
        self.db.browse(q, category, language, status)
    }

    pub fn variants(&self, edition_id: i64) -> Result<Vec<ArtifactView>> {
        let mut views = self.db.edition_variants(edition_id)?;
        for v in &mut views {
            // Size via a filesystem stat; a failed lookup degrades to no size
            // rather than failing the whole list.
            v.byte_len = self.store.byte_len(&v.blob_sha1).ok();
        }
        Ok(views)
    }

    pub fn get_artifact(&self, uid: &str) -> Result<Option<ArtifactView>> {
        self.db.get_artifact(uid)
    }

    /// The canonical filename for an artifact (normalization output).
    pub fn canonical_name(&self, uid: &str) -> Result<Option<String>> {
        Ok(self.get_artifact(uid)?.map(|v| v.canonical_name))
    }

    /// Read an artifact's stored bytes (never mutated).
    pub fn blob_for(&self, uid: &str) -> Result<Option<(String, Vec<u8>)>> {
        let Some(v) = self.db.get_artifact(uid)? else {
            return Ok(None);
        };
        let bytes = self.store.get(&v.blob_sha1)?;
        Ok(Some((v.canonical_name, bytes)))
    }

    pub fn quarantine_list(&self) -> Result<Vec<ArtifactView>> {
        self.db.quarantine_list()
    }

    /// Resolve a quarantined artifact by assigning identity metadata.
    pub fn resolve_quarantine(&self, uid: &str, meta: &ResolveMeta) -> Result<()> {
        let key = EditionKey {
            title: meta.title.trim().to_string(),
            version: meta.version.clone(),
            language: meta.language.clone(),
            publisher: meta.publisher.clone(),
            qualifier: None,
            disk_no: meta.disk_no,
            disk_count: meta.disk_count,
        };
        let category = if meta.category.is_empty() {
            "game"
        } else {
            &meta.category
        };
        let edition_id = self.ensure_edition(category, &key)?;
        self.db.set_artifact_edition(uid, edition_id)?;
        self.db.set_display_title(uid, &meta.title)?;
        self.db.dequarantine(uid)?;
        self.recompute_set_primaries(edition_id)?;
        Ok(())
    }

    // --- Sets (releases) --------------------------------------------------

    /// Gather every disk member of the Set that `edition_id` belongs to (with the
    /// set's disk count). Reuses the stored `lineage`.
    fn gather_set(&self, edition_id: i64) -> Result<(u32, Vec<DiskMember>)> {
        let (disk_count, siblings) = self.db.set_siblings(edition_id)?;
        let mut members = Vec::new();
        for (ed_id, disk_no) in &siblings {
            for (uid, info) in self.db.edition_variant_infos(*ed_id)? {
                members.push(DiskMember {
                    // A single-disk release with no "Disk N" is its own disk 1.
                    disk_no: disk_no.unwrap_or(1),
                    lineage: info.lineage.clone(),
                    info,
                    tiebreak: uid,
                });
            }
        }
        // When the release doesn't declare "of N", require covering every disk we
        // actually hold, so a lineage that misses a present disk isn't "complete".
        let max_present = siblings.iter().filter_map(|(_, d)| *d).max().unwrap_or(1);
        let dc = disk_count.unwrap_or(max_present).max(1);
        Ok((dc, members))
    }

    /// Browse releases: roll up multi-disk Editions into Sets (representative =
    /// the lowest disk). `incomplete_only` keeps only Sets with no complete lineage.
    pub fn list_sets(
        &self,
        q: Option<&str>,
        category: Option<&str>,
        language: Option<&str>,
        incomplete_only: bool,
    ) -> Result<Vec<SetView>> {
        use std::collections::BTreeMap;
        type Key = (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<u32>,
        );
        let mut groups: BTreeMap<Key, Vec<EditionView>> = BTreeMap::new();
        for e in self.db.browse(q, category, language, None)? {
            let key = (
                e.title.clone(),
                e.category.clone(),
                e.version.clone(),
                e.language.clone(),
                e.publisher.clone(),
                e.qualifier.clone(),
                e.disk_count,
            );
            groups.entry(key).or_default().push(e);
        }

        // Batch-load enrichment once, then attach to each release by title_id.
        let meta_by_title = self.db.all_title_meta()?;
        let mut sets = Vec::new();
        for (_key, mut editions) in groups {
            editions.sort_by_key(|e| e.disk_no.unwrap_or(0));
            let rep = &editions[0];
            let disk_count = rep.disk_count;
            let multi = disk_count.is_some_and(|d| d > 1) || editions.len() > 1;
            let mut disks_present: Vec<u32> = editions.iter().filter_map(|e| e.disk_no).collect();
            disks_present.sort_unstable();
            disks_present.dedup();
            let variant_count: i64 = editions.iter().map(|e| e.variant_count).sum();

            // Completeness is computed the same way for every set (so a single-disk
            // title whose only variants are disqualified reports 0, like the
            // multi-disk case). NOTE: this issues per-set reads on browse — cheap at
            // the current scale; a batched aggregate is a documented follow-up.
            // Gather once, then derive both coverage and the type-class counts from
            // the same members (no extra read for the summary chips).
            let (dc, members) = self.gather_set(rep.edition_id)?;
            let covs = lineage_coverage(&members, dc);
            let complete_lineages = covs.iter().filter(|c| c.complete).count();
            let primary_lineage = covs
                .iter()
                .find(|c| c.is_primary)
                .and_then(|c| c.lineage.clone());
            if incomplete_only && complete_lineages > 0 {
                continue;
            }
            let mut tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for m in &members {
                if !m.info.disqualified() {
                    tags.insert(m.lineage.clone().unwrap_or_default());
                }
            }
            let (mut original_count, mut cracked_count, mut hacked_count) =
                (0usize, 0usize, 0usize);
            for tag in &tags {
                match lineage_class(tag, &members) {
                    "original" => original_count += 1,
                    "cracked" => cracked_count += 1,
                    _ => hacked_count += 1,
                }
            }
            sets.push(SetView {
                rep_edition_id: rep.edition_id,
                title_id: rep.title_id,
                meta: meta_by_title.get(&rep.title_id).cloned(),
                multi,
                title: rep.title.clone(),
                category: rep.category.clone(),
                publisher: rep.publisher.clone(),
                year: rep.year,
                version_key: rep.version.as_deref().map(crate::naming::version_key),
                version: rep.version.clone(),
                language: rep.language.clone(),
                qualifier: rep.qualifier.clone(),
                disk_count,
                disks_present,
                complete_lineages,
                primary_lineage,
                variant_count,
                original_count,
                cracked_count,
                hacked_count,
            });
        }
        sets.sort_by(|a, b| {
            a.title
                .cmp(&b.title)
                .then(a.category.cmp(&b.category))
                .then(a.qualifier.cmp(&b.qualifier))
                .then(a.disk_count.cmp(&b.disk_count))
        });
        Ok(sets)
    }

    /// Candidate lineages of a Set (complete/partial coverage), best-first.
    pub fn set_lineages(&self, edition_id: i64) -> Result<Vec<LineageCoverage>> {
        let (dc, members) = self.gather_set(edition_id)?;
        Ok(lineage_coverage(&members, dc))
    }

    /// The Set's disks as `(disk_no, edition_id)`, so the UI can always reach the
    /// disks held even when no lineage is complete.
    pub fn set_disks(&self, edition_id: i64) -> Result<Vec<(u32, i64)>> {
        let (_, siblings) = self.db.set_siblings(edition_id)?;
        let mut disks: Vec<(u32, i64)> = siblings
            .into_iter()
            .map(|(ed, dn)| (dn.unwrap_or(0), ed))
            .collect();
        disks.sort_by_key(|(dn, _)| *dn);
        Ok(disks)
    }

    /// Resolve a lineage to one coherent set: the best variant of each disk in it,
    /// as `(disk_no, uid)` sorted by disk.
    pub fn resolve_set(&self, edition_id: i64, lineage: &str) -> Result<Vec<(u32, String)>> {
        let (_, members) = self.gather_set(edition_id)?;
        let mut files: Vec<(u32, String)> = primary_set_for_lineage(&members, lineage)
            .into_iter()
            .map(|i| (members[i].disk_no, members[i].tiebreak.clone()))
            .collect();
        files.sort_by_key(|(d, _)| *d);
        Ok(files)
    }

    /// Export a coherent set (best-per-disk of `lineage`) under canonical names.
    pub fn export_set(&self, edition_id: i64, lineage: &str) -> Result<Vec<(String, Vec<u8>)>> {
        self.export_set_with(edition_id, lineage, None)
    }

    /// Export a coherent set, optionally overriding the boot disk with `boot_uid`
    /// (a chosen trainer variant). Refuses an incomplete or unknown lineage, and
    /// ignores a boot override that isn't a valid boot-disk variant of the lineage.
    pub fn export_set_with(
        &self,
        edition_id: i64,
        lineage: &str,
        boot_uid: Option<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        use std::collections::BTreeMap;
        let (dc, members) = self.gather_set(edition_id)?;
        // `lineage` is the empty string for the original (no-group) set, which is
        // stored as `None` — compare via unwrap_or("") so it matches.
        let complete = lineage_coverage(&members, dc)
            .iter()
            .any(|c| c.lineage.as_deref().unwrap_or("") == lineage && c.complete);
        if !complete {
            return Err(Error::Invalid(format!(
                "lineage '{lineage}' is not a complete set"
            )));
        }
        let mut chosen: BTreeMap<u32, String> = primary_set_for_lineage(&members, lineage)
            .into_iter()
            .map(|i| (members[i].disk_no, members[i].tiebreak.clone()))
            .collect();
        let boot_disk = *chosen.keys().min().expect("a complete set has disks");
        if let Some(b) = boot_uid {
            let valid = members.iter().any(|m| {
                m.tiebreak == b
                    && m.disk_no == boot_disk
                    && !m.info.disqualified()
                    && m.lineage.as_deref().unwrap_or("") == lineage
            });
            if valid {
                chosen.insert(boot_disk, b.to_string());
            }
        }
        let mut out = Vec::new();
        for (_disk, uid) in chosen {
            if let Some(v) = self.db.get_artifact(&uid)? {
                out.push((v.canonical_name.clone(), self.store.get(&v.blob_sha1)?));
            }
        }
        Ok(out)
    }

    // --- Works & playable sets --------------------------------------------

    /// Group releases into Works by title name (across category).
    pub fn list_works(
        &self,
        q: Option<&str>,
        category: Option<&str>,
        language: Option<&str>,
    ) -> Result<Vec<WorkView>> {
        use std::collections::BTreeMap;
        let mut by_name: BTreeMap<String, Vec<SetView>> = BTreeMap::new();
        for s in self.list_sets(q, category, language, false)? {
            by_name
                .entry(s.title.trim().to_string())
                .or_default()
                .push(s);
        }
        let mut works: Vec<WorkView> = by_name
            .into_iter()
            .map(|(name, releases)| {
                let count = |c: &str| releases.iter().filter(|r| r.category == c).count();
                let sum = |f: fn(&SetView) -> usize| releases.iter().map(f).sum();
                WorkView {
                    release_count: releases.len(),
                    game_count: count("game"),
                    demo_count: count("demo"),
                    tool_count: count("tool"),
                    original_count: sum(|r| r.original_count),
                    cracked_count: sum(|r| r.cracked_count),
                    hacked_count: sum(|r| r.hacked_count),
                    name,
                    releases,
                }
            })
            .collect();
        works.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(works)
    }

    /// Playable variations of a game release: complete coherent sets to download,
    /// plus incomplete ones (marked), each with its boot-disk trainer options.
    pub fn playable_sets(&self, edition_id: i64) -> Result<Vec<PlayableSet>> {
        let (dc, members) = self.gather_set(edition_id)?;
        let mut out = Vec::new();
        for c in lineage_coverage(&members, dc) {
            let tag = c.lineage.clone().unwrap_or_default();
            let missing_disks: Vec<u32> =
                (1..=dc).filter(|d| !c.disks_covered.contains(d)).collect();
            let disks: Vec<(u32, String)> = if c.complete {
                let mut files: Vec<(u32, String)> = primary_set_for_lineage(&members, &tag)
                    .into_iter()
                    .map(|i| (members[i].disk_no, members[i].tiebreak.clone()))
                    .collect();
                files.sort_by_key(|(d, _)| *d);
                files
            } else {
                Vec::new()
            };
            let trainer_options = self.trainer_options(&members, &tag, &disks);
            let kind = lineage_class(&tag, &members).to_string();
            // Any trainer present in this lineage (not just when there's a choice).
            let trainer = members
                .iter()
                .filter(|m| m.lineage.as_deref().unwrap_or("") == tag && !m.info.disqualified())
                .find_map(|m| m.info.trainer.clone());
            out.push(PlayableSet {
                rep_edition_id: edition_id,
                lineage: c.lineage,
                kind,
                trainer,
                complete: c.complete,
                missing_disks,
                is_recommended: c.is_primary,
                disks,
                trainer_options,
            });
        }
        Ok(out)
    }

    /// The boot-disk trainer choices for a lineage: the best variant per distinct
    /// trainer on the set's boot (lowest) disk. Empty unless there's a real choice.
    fn trainer_options(
        &self,
        members: &[DiskMember],
        lineage: &str,
        disks: &[(u32, String)],
    ) -> Vec<TrainerOption> {
        use std::collections::BTreeMap;
        let Some(boot_disk) = disks.iter().map(|(d, _)| *d).min() else {
            return Vec::new();
        };
        let default_uid = disks
            .iter()
            .find(|(d, _)| *d == boot_disk)
            .map(|(_, u)| u.clone());
        let mut best: BTreeMap<Option<String>, usize> = BTreeMap::new();
        for (i, m) in members.iter().enumerate() {
            if m.info.disqualified()
                || m.disk_no != boot_disk
                || m.lineage.as_deref().unwrap_or("") != lineage
            {
                continue;
            }
            let key = m.info.trainer.clone();
            match best.get(&key) {
                Some(&cur) => {
                    let better = rank_key(&m.info)
                        .cmp(&rank_key(&members[cur].info))
                        .then_with(|| m.tiebreak.cmp(&members[cur].tiebreak));
                    if better == std::cmp::Ordering::Less {
                        best.insert(key, i);
                    }
                }
                None => {
                    best.insert(key, i);
                }
            }
        }
        if best.len() < 2 {
            return Vec::new(); // no real choice
        }
        best.into_iter()
            .map(|(trainer, i)| {
                let uid = members[i].tiebreak.clone();
                TrainerOption {
                    is_default: default_uid.as_deref() == Some(uid.as_str()),
                    trainer,
                    uid,
                }
            })
            .collect()
    }

    /// Re-identify all named artifacts from their retained TOSEC name: recompute
    /// category/qualifier/publisher, re-group into the correct Title/Edition, fix
    /// primaries, and drop Editions/Titles left empty. Non-destructive and
    /// idempotent; artifacts without a TOSEC name are skipped.
    pub fn reidentify(&self) -> Result<ReidentifyReport> {
        use std::collections::BTreeSet;
        let named = self.db.all_artifacts_named()?;
        let scanned = named.len();
        let mut moved = 0;
        let mut affected: BTreeSet<i64> = BTreeSet::new();

        for (uid, tosec) in named {
            let Some(parsed) = parse_tosec(&tosec) else {
                continue;
            };
            // The name only gives a definitive demo signal; the DAT-source signal
            // used at ingest isn't stored per artifact. So only *upgrade* to demo
            // from the name, and otherwise preserve the artifact's current
            // category rather than downgrading a DAT-classified tool/demo to game.
            let category = match infer_category(parsed.qualifier.as_deref(), None) {
                Category::Demo => Category::Demo,
                _ => match self.db.artifact_category(&uid)?.as_deref() {
                    Some("tool") => Category::Tool,
                    Some("demo") => Category::Demo,
                    _ => Category::Game,
                },
            };
            let new_ed = self.ensure_edition(category.as_str(), &edition_key(&parsed))?;
            let old = self.db.artifact_edition(&uid)?;
            if old != Some(new_ed) {
                self.db.set_artifact_edition(&uid, new_ed)?;
                if let Some(o) = old {
                    affected.insert(o);
                }
                affected.insert(new_ed);
                moved += 1;
            }
        }

        // Fix primaries on every touched Edition (rows still exist here)...
        for ed in &affected {
            self.recompute_set_primaries(*ed)?;
        }
        // ...then drop the now-empty Editions and Titles.
        let editions_removed = self.db.delete_empty_editions()?;
        let titles_removed = self.db.delete_empty_titles()?;

        Ok(ReidentifyReport {
            scanned,
            moved,
            editions_removed,
            titles_removed,
        })
    }

    /// Re-flag which artifact is an Edition's primary (non-destructive).
    pub fn set_primary(&self, edition_id: i64, uid: &str) -> Result<()> {
        self.db.set_primary(edition_id, Some(uid))
    }

    /// Export an Edition's artifacts under their canonical names (bytes unchanged).
    pub fn export_edition(&self, edition_id: i64) -> Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        for v in self.db.edition_variants(edition_id)? {
            let bytes = self.store.get(&v.blob_sha1)?;
            out.push((v.canonical_name, bytes));
        }
        Ok(out)
    }

    // --- Enrichment --------------------------------------------------------

    /// Titles to enrich, as provider queries (see [`crate::db::Db::titles_for_enrich`]).
    pub fn titles_for_enrich(
        &self,
        only: Option<i64>,
        skip_fetched: bool,
    ) -> Result<Vec<crate::enrich::TitleQuery>> {
        Ok(self
            .db
            .titles_for_enrich(only, skip_fetched)?
            .into_iter()
            .map(
                |(title_id, name, category, year)| crate::enrich::TitleQuery {
                    title_id,
                    name,
                    year,
                    category,
                },
            )
            .collect())
    }

    /// Persist a merged enrichment record: store each screenshot's bytes in the
    /// content-addressed blob store, then write metadata and screenshots in one
    /// transaction. `images` are `(bytes, mime, caption, source, ord)`.
    ///
    /// If the merge expected screenshots but every download failed (a transient
    /// image-CDN error), the existing screenshots are kept rather than wiped —
    /// only a run that actually produced images (or one that legitimately found
    /// none) replaces them.
    pub fn save_enrichment(
        &self,
        title_id: i64,
        merged: &crate::enrich::Merged,
        images: &[crate::enrich::ScreenshotBytes],
    ) -> Result<()> {
        let mut shots = Vec::with_capacity(images.len());
        for (bytes, mime, caption, source, ord) in images {
            let (hashes, _is_new) = self.store.put(bytes)?;
            shots.push((
                hashes.sha1,
                mime.clone(),
                caption.clone(),
                source.clone(),
                *ord,
            ));
        }
        // Replace screenshots when we downloaded some, or when the merge found no
        // screenshots at all; otherwise (expected some, got none) leave them be.
        let shots_arg = if !shots.is_empty() || merged.shots.is_empty() {
            Some(shots.as_slice())
        } else {
            None
        };
        self.db.save_enrichment(
            title_id,
            merged.genre.as_deref(),
            merged.description.as_deref(),
            merged.year,
            Some(merged.sources.as_str()),
            merged.external_url.as_deref(),
            Some(f64::from(merged.score)),
            crate::enrich::now_secs(),
            shots_arg,
        )?;
        Ok(())
    }

    /// Merged online metadata (with screenshots) for a title, if enriched.
    pub fn title_meta(&self, title_id: i64) -> Result<Option<crate::db::TitleMeta>> {
        self.db.title_meta(title_id)
    }

    /// A stored screenshot as `(mime, bytes)`, for the `/media/{sha1}` route.
    pub fn screenshot_media(&self, sha1: &str) -> Result<Option<(String, Vec<u8>)>> {
        match self.db.screenshot_mime(sha1)? {
            Some(mime) => Ok(Some((mime, self.store.get(sha1)?))),
            None => Ok(None),
        }
    }
}

/// Copy interpreted dump info onto a new artifact record.
fn apply_dump_info(rec: &mut NewArtifact, info: &DumpInfo) {
    rec.dump_type = Some(info.dump_type.as_str().to_string());
    rec.crack_group = info.crack_group.clone();
    rec.trainer = info.trainer.clone();
    rec.bad = info.bad;
    rec.virus = info.virus;
    rec.over = info.over;
    rec.under = info.under;
    rec.alt_index = info.alt_index;
    rec.modifications = info.modifications;
    rec.verified_good = info.verified_good;
    rec.lineage = info.lineage.clone();
}

/// Build a minimal [`TosecName`] from a DAT entry when its name failed to parse.
fn dat_to_name(entry: &DatEntry) -> TosecName {
    TosecName {
        title: entry.title.clone().unwrap_or_else(|| entry.name.clone()),
        version: entry.version.clone(),
        language: entry.language.clone(),
        publisher: entry.publisher.clone(),
        year: entry.year,
        disk_no: entry.disk_no,
        disk_count: entry.disk_count,
        qualifier: None,
        flags: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adf(marker: &str) -> Vec<u8> {
        // Distinct bytes per marker so each is a different artifact.
        let mut v = vec![0u8; 512];
        v.extend_from_slice(marker.as_bytes());
        v
    }

    #[test]
    fn exact_duplicate_collapses() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_memory(dir.path()).unwrap();
        let bytes = adf("same");
        let a = v
            .ingest(
                "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX].adf",
                &bytes,
            )
            .unwrap();
        let b = v
            .ingest(
                "A-10 Tank Killer v1.0 (1990)(Dynamix)(Disk 1 of 2)[cr QTX].adf",
                &bytes,
            )
            .unwrap();
        assert!(matches!(a[0], IngestOutcome::Stored { .. }));
        assert!(matches!(b[0], IngestOutcome::Duplicate { .. }));
    }

    #[test]
    fn quarantine_on_unidentifiable() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_memory(dir.path()).unwrap();
        let out = v.ingest("disk047.adf", &adf("junk")).unwrap();
        assert!(matches!(
            out[0],
            IngestOutcome::Stored {
                quarantined: true,
                ..
            }
        ));
        assert_eq!(v.quarantine_list().unwrap().len(), 1);
    }

    #[test]
    fn reidentify_heals_mislabeled_demo_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_memory(dir.path()).unwrap();

        // Simulate OLD-style ingest: filed as `game` with the demo token as the
        // publisher (the exact defect this change fixes).
        let title_id = v.db.upsert_title("Agony", "game").unwrap();
        let key = EditionKey {
            title: "Agony".into(),
            version: None,
            language: None,
            publisher: Some("demo-playable".into()),
            qualifier: None,
            disk_no: None,
            disk_count: None,
        };
        let old_ed = v.db.upsert_edition(title_id, &key).unwrap();
        let rec = NewArtifact {
            uid: "deadbeef01".into(),
            hashes: Hashes {
                sha1: "sha_agony_demo".into(),
                crc32: "c".into(),
                md5: "m".into(),
            },
            edition_id: Some(old_ed),
            display_title: Some("Agony".into()),
            tosec_name: Some("Agony (demo-playable) (1991)(Psygnosis)[h PRD].adf".into()),
            container: "adf".into(),
            blob_sha1: "sha_agony_demo".into(),
            ..Default::default()
        };
        v.db.insert_artifact(&rec).unwrap();
        v.db.set_primary(old_ed, Some("deadbeef01")).unwrap();

        let rep = v.reidentify().unwrap();
        assert_eq!(rep.moved, 1);
        assert!(rep.editions_removed >= 1 && rep.titles_removed >= 1);

        // Now a demo Title with the real publisher and qualifier; the game Title is gone.
        let demo = v.browse(Some("Agony"), Some("demo"), None, None).unwrap();
        assert_eq!(demo.len(), 1);
        assert_eq!(demo[0].publisher.as_deref(), Some("Psygnosis"));
        assert_eq!(demo[0].qualifier.as_deref(), Some("demo-playable"));
        assert!(v
            .browse(Some("Agony"), Some("game"), None, None)
            .unwrap()
            .is_empty());

        // Idempotent: a second pass moves nothing.
        assert_eq!(v.reidentify().unwrap().moved, 0);
    }

    #[test]
    fn reidentify_preserves_dat_categorized_tool() {
        // A tool categorized via a DAT source at ingest (no qualifier in the
        // name) must not be downgraded to `game` by re-identify.
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_memory(dir.path()).unwrap();
        let title_id = v.db.upsert_title("DiskMaster", "tool").unwrap();
        let key = EditionKey {
            title: "DiskMaster".into(),
            version: None,
            language: None,
            publisher: Some("SomeCorp".into()),
            qualifier: None,
            disk_no: None,
            disk_count: None,
        };
        let ed = v.db.upsert_edition(title_id, &key).unwrap();
        let rec = NewArtifact {
            uid: "toolaaaa01".into(),
            hashes: Hashes {
                sha1: "sha_tool".into(),
                crc32: "c".into(),
                md5: "m".into(),
            },
            edition_id: Some(ed),
            display_title: Some("DiskMaster".into()),
            tosec_name: Some("DiskMaster (1990)(SomeCorp).adf".into()),
            container: "adf".into(),
            blob_sha1: "sha_tool".into(),
            ..Default::default()
        };
        v.db.insert_artifact(&rec).unwrap();
        v.db.set_primary(ed, Some("toolaaaa01")).unwrap();

        let rep = v.reidentify().unwrap();
        assert_eq!(rep.moved, 0, "category preserved, nothing to move");
        assert_eq!(
            v.browse(Some("DiskMaster"), Some("tool"), None, None)
                .unwrap()
                .len(),
            1
        );
        assert!(v
            .browse(Some("DiskMaster"), Some("game"), None, None)
            .unwrap()
            .is_empty());
    }
}
