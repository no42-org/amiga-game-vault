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
use crate::ranking::{primary_set_for_lineage, select_primary, select_primary_lineage, DiskMember};
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
        self.db.edition_variants(edition_id)
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
            let category = infer_category(parsed.qualifier.as_deref(), None);
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
}
