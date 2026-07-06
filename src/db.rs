/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! SQLite persistence: schema, artifact/edition writes, and browse/search reads.
//!
//! The database is the authoritative source of full metadata, keyed by UID; the
//! filename is only a projection of it.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::dat::DatEntry;
use crate::edition::{DumpInfo, DumpType, EditionKey};
use crate::identity::{Hashes, UID_LEN};
use crate::naming::build_canonical;
use crate::Result;

const MIGRATION: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_enrichment.sql");

/// The disk count of a set and its sibling Editions as `(edition_id, disk_no)`.
type SetSiblings = (Option<u32>, Vec<(i64, Option<u32>)>);

/// An enrichment target: `(title_id, name, category, earliest_artifact_year)`.
pub type EnrichTarget = (i64, String, String, Option<i32>);

/// A screenshot row to store: `(blob_sha1, mime, caption, source, ord)`.
pub type StoredShot = (String, String, Option<String>, String, i64);

/// A new artifact row to insert.
#[derive(Debug, Clone, Default)]
pub struct NewArtifact {
    pub uid: String,
    pub hashes: Hashes,
    pub edition_id: Option<i64>,
    pub display_title: Option<String>,
    pub year: Option<i32>,
    pub dump_type: Option<String>,
    pub crack_group: Option<String>,
    pub trainer: Option<String>,
    pub bad: bool,
    pub virus: bool,
    pub over: bool,
    pub under: bool,
    pub alt_index: u32,
    pub modifications: u32,
    pub verified_good: bool,
    pub lineage: Option<String>,
    pub verified: bool,
    pub tosec_name: Option<String>,
    pub orig_filename: Option<String>,
    pub container: String,
    pub decoded_sha1: Option<String>,
    pub blob_sha1: String,
}

/// A view of an Edition for browsing.
#[derive(Debug, Clone, Serialize)]
pub struct EditionView {
    pub edition_id: i64,
    pub title_id: i64,
    pub title: String,
    pub category: String,
    pub version: Option<String>,
    pub language: Option<String>,
    pub publisher: Option<String>,
    pub qualifier: Option<String>,
    pub year: Option<i32>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
    pub primary_uid: Option<String>,
    pub variant_count: i64,
}

/// Merged editorial metadata for a title (a logical work), with its screenshots.
#[derive(Debug, Clone, Serialize)]
pub struct TitleMeta {
    pub title_id: i64,
    pub genre: Option<String>,
    pub description: Option<String>,
    pub year: Option<i32>,
    /// Comma-joined providers that contributed to this merged record.
    pub sources: Option<String>,
    /// Canonical page on the winning provider.
    pub external_url: Option<String>,
    pub screenshots: Vec<Screenshot>,
}

/// A stored screenshot: bytes live in the [`crate::store::BlobStore`] under `sha1`.
#[derive(Debug, Clone, Serialize)]
pub struct Screenshot {
    pub sha1: String,
    pub mime: String,
    pub caption: Option<String>,
    pub source: String,
}

/// A view of a single artifact (variant).
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactView {
    pub uid: String,
    pub display_title: Option<String>,
    pub canonical_name: String,
    pub dump_type: Option<String>,
    pub crack_group: Option<String>,
    pub trainer: Option<String>,
    pub year: Option<i32>,
    pub verified: bool,
    pub is_primary: bool,
    pub tosec_name: Option<String>,
    pub blob_sha1: String,
    pub crc32: String,
    pub md5: String,
    pub alt_index: u32,
    /// Blob size in bytes; a computed (non-column) field filled by the service
    /// layer from the blob store, like `is_primary`. `None` when unavailable.
    pub byte_len: Option<u64>,
    pub version: Option<String>,
    pub language: Option<String>,
    pub disk_no: Option<u32>,
    pub disk_count: Option<u32>,
}

impl ArtifactView {
    /// The canonical filename projected from this artifact's metadata.
    fn canonical(&self) -> String {
        let title = self
            .display_title
            .clone()
            .unwrap_or_else(|| "Unknown".into());
        let disk = match (self.disk_no, self.disk_count) {
            (Some(n), Some(m)) => Some((n, m)),
            _ => None,
        };
        build_canonical(
            &title,
            self.version.as_deref(),
            self.language.as_deref(),
            disk,
            &self.uid,
        )
    }
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(MIGRATION)?;
        // Additive enrichment tables (0002). Idempotent CREATE ... IF NOT EXISTS,
        // so this is safe to run on both fresh and existing databases.
        self.conn.execute_batch(MIGRATION_0002)?;
        // Bring an `edition` table created before `qualifier` up to the current
        // schema. A plain ALTER ADD COLUMN can't rebuild the UNIQUE constraint
        // (which must now include `qualifier`), so rebuild the table when the
        // column is absent. Idempotent: fresh DBs already have the column.
        let has_qualifier = self
            .conn
            .prepare("PRAGMA table_info(edition)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .filter_map(std::result::Result::ok)
            .any(|c| c == "qualifier");
        if !has_qualifier {
            // Standard SQLite table-rebuild: disable FK enforcement across the
            // swap (artifact.edition_id references edition; ids are preserved).
            self.conn.execute_batch("PRAGMA foreign_keys=OFF")?;
            self.conn.execute_batch(
                "BEGIN;
                 CREATE TABLE edition_new (
                    id                   INTEGER PRIMARY KEY,
                    title_id             INTEGER NOT NULL REFERENCES title(id),
                    version              TEXT,
                    language             TEXT,
                    publisher            TEXT,
                    qualifier            TEXT,
                    disk_no              INTEGER,
                    disk_count           INTEGER,
                    primary_artifact_uid TEXT,
                    UNIQUE (title_id, version, language, publisher, qualifier, disk_no, disk_count)
                 );
                 INSERT INTO edition_new
                     (id, title_id, version, language, publisher, disk_no, disk_count, primary_artifact_uid)
                     SELECT id, title_id, version, language, publisher, disk_no, disk_count, primary_artifact_uid
                     FROM edition;
                 DROP TABLE edition;
                 ALTER TABLE edition_new RENAME TO edition;
                 COMMIT;",
            )?;
        }
        Ok(())
    }

    // --- DAT ---------------------------------------------------------------

    pub fn import_dat(&self, entries: &[DatEntry]) -> Result<usize> {
        let tx = self.conn.unchecked_transaction()?;
        for e in entries {
            tx.execute(
                "INSERT INTO dat_entry (source, name, sha1, crc32, md5, title, version, language, publisher, year, disk_no, disk_count, dump_type, crack_group)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    e.source, e.name, e.sha1, e.crc32, e.md5, e.title, e.version, e.language,
                    e.publisher, e.year, e.disk_no, e.disk_count, e.dump_type, e.crack_group
                ],
            )?;
        }
        tx.commit()?;
        Ok(entries.len())
    }

    /// Look up a reference entry by hash (SHA1, then MD5, then CRC32).
    pub fn match_dat(&self, h: &Hashes) -> Result<Option<DatEntry>> {
        let row = self
            .conn
            .query_row(
                // Honor the SHA1 > MD5 > CRC32 priority: a true SHA1 match outranks
                // an MD5 match, which outranks a (collision-prone) CRC32 match.
                "SELECT source,name,sha1,crc32,md5,title,version,language,publisher,year,disk_no,disk_count,dump_type,crack_group
                 FROM dat_entry WHERE sha1 = ?1 OR md5 = ?2 OR crc32 = ?3
                 ORDER BY (sha1 = ?1) DESC, (md5 = ?2) DESC LIMIT 1",
                params![h.sha1, h.md5, h.crc32],
                |r| {
                    Ok(DatEntry {
                        source: r.get(0)?,
                        name: r.get(1)?,
                        sha1: r.get(2)?,
                        crc32: r.get(3)?,
                        md5: r.get(4)?,
                        title: r.get(5)?,
                        version: r.get(6)?,
                        language: r.get(7)?,
                        publisher: r.get(8)?,
                        year: r.get(9)?,
                        disk_no: r.get(10)?,
                        disk_count: r.get(11)?,
                        dump_type: r.get(12)?,
                        crack_group: r.get(13)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // --- Identity ----------------------------------------------------------

    pub fn artifact_uid_by_sha1(&self, sha1: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT uid FROM artifact WHERE sha1 = ?1", [sha1], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Resolve a unique UID for `sha1`, extending the prefix past any collision
    /// with a *different* artifact.
    pub fn unique_uid_for(&self, sha1: &str) -> Result<String> {
        let mut len = UID_LEN;
        loop {
            let cand = &sha1[..len.min(sha1.len())];
            let conflict: Option<String> = self
                .conn
                .query_row("SELECT sha1 FROM artifact WHERE uid = ?1", [cand], |r| {
                    r.get(0)
                })
                .optional()?;
            match conflict {
                Some(other) if other != sha1 => {
                    if len >= sha1.len() {
                        return Ok(cand.to_string());
                    }
                    len += 1;
                }
                _ => return Ok(cand.to_string()),
            }
        }
    }

    // --- Titles / Editions -------------------------------------------------

    pub fn upsert_title(&self, name: &str, category: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO title (name, category) VALUES (?1, ?2)",
            params![name, category],
        )?;
        Ok(self.conn.query_row(
            "SELECT id FROM title WHERE name = ?1 AND category = ?2",
            params![name, category],
            |r| r.get(0),
        )?)
    }

    pub fn upsert_edition(&self, title_id: i64, key: &EditionKey) -> Result<i64> {
        // NULL columns are not deduped by a UNIQUE constraint, so match first
        // with `IS` (null-safe equality) and insert only when absent.
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM edition WHERE title_id = ?1 AND version IS ?2 AND language IS ?3
                     AND publisher IS ?4 AND qualifier IS ?5 AND disk_no IS ?6 AND disk_count IS ?7",
                params![
                    title_id,
                    key.version,
                    key.language,
                    key.publisher,
                    key.qualifier,
                    key.disk_no,
                    key.disk_count
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(id);
        }
        self.conn.execute(
            "INSERT INTO edition (title_id, version, language, publisher, qualifier, disk_no, disk_count)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                title_id,
                key.version,
                key.language,
                key.publisher,
                key.qualifier,
                key.disk_no,
                key.disk_count
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn edition_variant_uids(&self, edition_id: i64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uid FROM artifact WHERE edition_id = ?1 ORDER BY uid")?;
        let uids = stmt
            .query_map([edition_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(uids)
    }

    /// Variant UIDs of an Edition paired with their [`DumpInfo`], reconstructed
    /// from the persisted columns (no filename re-parsing). Every artifact row
    /// contributes — nothing is dropped for an unparseable name.
    pub fn edition_variant_infos(&self, edition_id: i64) -> Result<Vec<(String, DumpInfo)>> {
        let mut stmt = self.conn.prepare(
            "SELECT uid, dump_type, crack_group, trainer, bad, virus, over, under, alt_index,
                    modifications, verified_good, lineage
             FROM artifact WHERE edition_id = ?1 ORDER BY uid",
        )?;
        let rows = stmt
            .query_map([edition_id], |r| {
                let uid: String = r.get(0)?;
                let info = DumpInfo {
                    dump_type: DumpType::from_label(
                        &r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    ),
                    crack_group: r.get(2)?,
                    trainer: r.get(3)?,
                    bad: r.get::<_, i32>(4)? != 0,
                    virus: r.get::<_, i32>(5)? != 0,
                    over: r.get::<_, i32>(6)? != 0,
                    under: r.get::<_, i32>(7)? != 0,
                    alt_index: r.get(8)?,
                    modifications: r.get(9)?,
                    verified_good: r.get::<_, i32>(10)? != 0,
                    lineage: r.get(11)?,
                };
                Ok((uid, info))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The disk count of an Edition and every sibling Edition in the same set
    /// (same title/version/language/publisher, any disk number).
    pub fn set_siblings(&self, edition_id: i64) -> Result<SetSiblings> {
        // (title_id, version, language, publisher, qualifier, disk_count)
        type SetMeta = (
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<u32>,
        );
        let (title_id, version, language, publisher, qualifier, disk_count): SetMeta =
            self.conn.query_row(
                "SELECT title_id, version, language, publisher, qualifier, disk_count
                 FROM edition WHERE id = ?1",
                [edition_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?;

        let mut stmt = self.conn.prepare(
            "SELECT id, disk_no FROM edition
             WHERE title_id = ?1 AND version IS ?2 AND language IS ?3 AND publisher IS ?4
                   AND qualifier IS ?5 AND disk_count IS ?6 ORDER BY disk_no",
        )?;
        let siblings = stmt
            .query_map(
                params![title_id, version, language, publisher, qualifier, disk_count],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<u32>>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((disk_count, siblings))
    }

    pub fn set_display_title(&self, uid: &str, title: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE artifact SET display_title = ?1 WHERE uid = ?2",
            params![title, uid],
        )?;
        Ok(())
    }

    pub fn set_primary(&self, edition_id: i64, uid: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE edition SET primary_artifact_uid = ?1 WHERE id = ?2",
            params![uid, edition_id],
        )?;
        Ok(())
    }

    // --- Artifacts ---------------------------------------------------------

    pub fn insert_artifact(&self, a: &NewArtifact) -> Result<()> {
        self.conn.execute(
            "INSERT INTO artifact
             (uid, sha1, crc32, md5, edition_id, display_title, year, dump_type, crack_group,
              trainer, bad, virus, over, under, alt_index, modifications, verified_good, lineage,
              verified, tosec_name, orig_filename, container, decoded_sha1, blob_sha1)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
            params![
                a.uid, a.hashes.sha1, a.hashes.crc32, a.hashes.md5, a.edition_id, a.display_title,
                a.year, a.dump_type, a.crack_group, a.trainer, a.bad as i32, a.virus as i32,
                a.over as i32, a.under as i32, a.alt_index, a.modifications, a.verified_good as i32,
                a.lineage, a.verified as i32, a.tosec_name, a.orig_filename, a.container,
                a.decoded_sha1, a.blob_sha1
            ],
        )?;
        Ok(())
    }

    pub fn quarantine(&self, uid: &str, reason: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO quarantine (artifact_uid, reason) VALUES (?1, ?2)",
            params![uid, reason],
        )?;
        Ok(())
    }

    pub fn dequarantine(&self, uid: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM quarantine WHERE artifact_uid = ?1", [uid])?;
        Ok(())
    }

    // --- Reads for the web layer ------------------------------------------

    fn map_artifact(r: &rusqlite::Row) -> rusqlite::Result<ArtifactView> {
        let mut v = ArtifactView {
            uid: r.get(0)?,
            display_title: r.get(1)?,
            canonical_name: String::new(),
            dump_type: r.get(2)?,
            crack_group: r.get(3)?,
            trainer: r.get(4)?,
            year: r.get(5)?,
            verified: r.get::<_, i32>(6)? != 0,
            is_primary: false,
            tosec_name: r.get(7)?,
            blob_sha1: r.get(8)?,
            version: r.get(9)?,
            language: r.get(10)?,
            disk_no: r.get(11)?,
            disk_count: r.get(12)?,
            crc32: r.get(13)?,
            md5: r.get(14)?,
            alt_index: r.get(15)?,
            byte_len: None,
        };
        v.canonical_name = v.canonical();
        Ok(v)
    }

    const ARTIFACT_COLS: &'static str =
        "a.uid, a.display_title, a.dump_type, a.crack_group, a.trainer, a.year, a.verified,
         a.tosec_name, a.blob_sha1, e.version, e.language, e.disk_no, e.disk_count,
         a.crc32, a.md5, a.alt_index";

    pub fn get_artifact(&self, uid: &str) -> Result<Option<ArtifactView>> {
        let sql = format!(
            "SELECT {} FROM artifact a LEFT JOIN edition e ON a.edition_id = e.id WHERE a.uid = ?1",
            Self::ARTIFACT_COLS
        );
        let row = self
            .conn
            .query_row(&sql, [uid], Self::map_artifact)
            .optional()?;
        Ok(row)
    }

    pub fn edition_variants(&self, edition_id: i64) -> Result<Vec<ArtifactView>> {
        let sql = format!(
            "SELECT {} FROM artifact a LEFT JOIN edition e ON a.edition_id = e.id
             WHERE a.edition_id = ?1 ORDER BY a.uid",
            Self::ARTIFACT_COLS
        );
        let primary: Option<String> = self
            .conn
            .query_row(
                "SELECT primary_artifact_uid FROM edition WHERE id = ?1",
                [edition_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let mut stmt = self.conn.prepare(&sql)?;
        let mut views = stmt
            .query_map([edition_id], Self::map_artifact)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for v in &mut views {
            v.is_primary = primary.as_deref() == Some(v.uid.as_str());
        }
        Ok(views)
    }

    /// Browse Editions, optionally filtered by a title substring, category,
    /// language, or identification status (`verified` | `unverified` | `quarantined`).
    pub fn browse(
        &self,
        q: Option<&str>,
        category: Option<&str>,
        language: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<EditionView>> {
        // Bind exactly three params, always referenced; empty strings are no-ops.
        let like = q
            .map(|s| format!("%{s}%"))
            .unwrap_or_else(|| "%".to_string());
        let cat = category.unwrap_or("").to_string();
        let lang = language.unwrap_or("").to_string();
        let mut sql = String::from(
            "SELECT e.id, t.id, t.name, t.category, e.version, e.language, e.publisher, e.qualifier,
                    (SELECT MIN(a.year) FROM artifact a WHERE a.edition_id = e.id AND a.year IS NOT NULL) AS yr,
                    e.disk_no, e.disk_count, e.primary_artifact_uid,
                    (SELECT COUNT(*) FROM artifact a WHERE a.edition_id = e.id) AS vc
             FROM edition e JOIN title t ON e.title_id = t.id
             WHERE t.name LIKE ?1
               AND (?2 = '' OR t.category = ?2)
               AND (?3 = '' OR e.language = ?3)",
        );
        match status {
            Some("verified") => sql.push_str(
                " AND EXISTS (SELECT 1 FROM artifact a WHERE a.edition_id = e.id AND a.verified = 1)",
            ),
            Some("unverified") => sql.push_str(
                " AND NOT EXISTS (SELECT 1 FROM artifact a WHERE a.edition_id = e.id AND a.verified = 1)",
            ),
            _ => {}
        }
        sql.push_str(" ORDER BY t.name, e.language, e.disk_no");

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params![like, cat, lang], |r| {
                Ok(EditionView {
                    edition_id: r.get(0)?,
                    title_id: r.get(1)?,
                    title: r.get(2)?,
                    category: r.get(3)?,
                    version: r.get(4)?,
                    language: r.get(5)?,
                    publisher: r.get(6)?,
                    qualifier: r.get(7)?,
                    year: r.get(8)?,
                    disk_no: r.get(9)?,
                    disk_count: r.get(10)?,
                    primary_uid: r.get(11)?,
                    variant_count: r.get(12)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn quarantine_list(&self) -> Result<Vec<ArtifactView>> {
        let sql = format!(
            "SELECT {} FROM artifact a LEFT JOIN edition e ON a.edition_id = e.id
             JOIN quarantine q ON q.artifact_uid = a.uid ORDER BY a.uid",
            Self::ARTIFACT_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let views = stmt
            .query_map([], Self::map_artifact)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(views)
    }

    pub fn set_artifact_edition(&self, uid: &str, edition_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE artifact SET edition_id = ?1 WHERE uid = ?2",
            params![edition_id, uid],
        )?;
        Ok(())
    }

    // --- Re-identification helpers ----------------------------------------

    /// All artifacts that carry a retained TOSEC name, as `(uid, tosec_name)`.
    pub fn all_artifacts_named(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT uid, tosec_name FROM artifact WHERE tosec_name IS NOT NULL ORDER BY uid",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The category of the Title an artifact currently belongs to, if any.
    pub fn artifact_category(&self, uid: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT t.category FROM artifact a
                 JOIN edition e ON a.edition_id = e.id
                 JOIN title t ON e.title_id = t.id
                 WHERE a.uid = ?1",
                [uid],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// The Edition an artifact currently belongs to, if any.
    pub fn artifact_edition(&self, uid: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT edition_id FROM artifact WHERE uid = ?1",
                [uid],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Delete Editions that no longer have any artifacts; returns the count.
    pub fn delete_empty_editions(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM edition WHERE id NOT IN
                 (SELECT edition_id FROM artifact WHERE edition_id IS NOT NULL)",
            [],
        )?)
    }

    /// Delete Titles that no longer have any Editions; returns the count.
    pub fn delete_empty_titles(&self) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM title WHERE id NOT IN (SELECT title_id FROM edition)",
            [],
        )?;
        // Enrichment is keyed by title_id. Drop rows for titles that no longer
        // exist so a later-reused rowid can't inherit stale metadata. (Screenshot
        // blobs are content-addressed and left in place, like ADF blobs.)
        self.conn.execute(
            "DELETE FROM title_meta WHERE title_id NOT IN (SELECT id FROM title)",
            [],
        )?;
        self.conn.execute(
            "DELETE FROM title_screenshot WHERE title_id NOT IN (SELECT id FROM title)",
            [],
        )?;
        Ok(n)
    }

    // --- Enrichment --------------------------------------------------------

    /// Titles to enrich: `only = Some(id)` targets one title, `None` all titles.
    /// `skip_fetched` excludes titles that already carry a `title_meta` row.
    /// Returns `(title_id, name, category, year)`; `year` is the earliest known
    /// artifact year for the title, a matching hint for providers.
    pub fn titles_for_enrich(
        &self,
        only: Option<i64>,
        skip_fetched: bool,
    ) -> Result<Vec<EnrichTarget>> {
        // `?1 IS NULL` (not `= 0`) means "no id filter"; binding `only` directly
        // keeps 0 a normal id, so `Some(0)` can't accidentally match every title.
        let mut stmt = self.conn.prepare(
            "SELECT t.id, t.name, t.category,
                    (SELECT MIN(a.year) FROM artifact a JOIN edition e ON a.edition_id = e.id
                     WHERE e.title_id = t.id AND a.year IS NOT NULL) AS yr
             FROM title t
             WHERE (?1 IS NULL OR t.id = ?1)
               AND (?2 = 0 OR t.id NOT IN (SELECT title_id FROM title_meta))
             ORDER BY t.name",
        )?;
        let rows = stmt
            .query_map(params![only, i64::from(skip_fetched)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Persist a title's merged metadata and (optionally) replace its screenshots
    /// in a single transaction, so the two halves of one enrichment record can't
    /// be left inconsistent. `shots = None` leaves the existing screenshots
    /// untouched (the caller uses this when a re-enrich downloaded none, so a
    /// transient image-fetch failure doesn't wipe good screenshots); `Some(&[])`
    /// clears them.
    #[allow(clippy::too_many_arguments)]
    pub fn save_enrichment(
        &self,
        title_id: i64,
        genre: Option<&str>,
        description: Option<&str>,
        year: Option<i32>,
        sources: Option<&str>,
        external_url: Option<&str>,
        match_score: Option<f64>,
        fetched_at: i64,
        shots: Option<&[StoredShot]>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO title_meta
                 (title_id, genre, description, year, sources, external_url, match_score, fetched_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(title_id) DO UPDATE SET
                 genre=excluded.genre, description=excluded.description, year=excluded.year,
                 sources=excluded.sources, external_url=excluded.external_url,
                 match_score=excluded.match_score, fetched_at=excluded.fetched_at",
            params![title_id, genre, description, year, sources, external_url, match_score, fetched_at],
        )?;
        if let Some(shots) = shots {
            tx.execute(
                "DELETE FROM title_screenshot WHERE title_id = ?1",
                [title_id],
            )?;
            for (sha1, mime, caption, source, ord) in shots {
                tx.execute(
                    "INSERT INTO title_screenshot (title_id, blob_sha1, mime, caption, source, ord)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![title_id, sha1, mime, caption, source, ord],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Merged metadata (with screenshots) for a single title, if enriched.
    pub fn title_meta(&self, title_id: i64) -> Result<Option<TitleMeta>> {
        let mut meta = self
            .conn
            .query_row(
                "SELECT title_id, genre, description, year, sources, external_url
                 FROM title_meta WHERE title_id = ?1",
                [title_id],
                Self::map_meta,
            )
            .optional()?;
        if let Some(m) = meta.as_mut() {
            m.screenshots = self.screenshots(title_id)?;
        }
        Ok(meta)
    }

    /// Metadata (with screenshots) for the given titles, keyed by title_id — a
    /// batch load for the browse listing that reads only the rows it needs. `ids`
    /// are i64s already sourced from the database, so inlining them into the `IN`
    /// list is injection-safe.
    pub fn title_meta_for(&self, ids: &[i64]) -> Result<std::collections::HashMap<i64, TitleMeta>> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        let mut by_title: std::collections::HashMap<i64, TitleMeta> = self
            .conn
            .prepare(&format!(
                "SELECT title_id, genre, description, year, sources, external_url
                 FROM title_meta WHERE title_id IN ({list})"
            ))?
            .query_map([], Self::map_meta)?
            .filter_map(std::result::Result::ok)
            .map(|m| (m.title_id, m))
            .collect();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT title_id, blob_sha1, mime, caption, source FROM title_screenshot
             WHERE title_id IN ({list}) ORDER BY title_id, ord, id"
        ))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, Self::map_shot(r)?)))?;
        for row in rows {
            let (tid, shot) = row?;
            if let Some(m) = by_title.get_mut(&tid) {
                m.screenshots.push(shot);
            }
        }
        Ok(by_title)
    }

    /// A title's screenshots, ordered.
    pub fn screenshots(&self, title_id: i64) -> Result<Vec<Screenshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT title_id, blob_sha1, mime, caption, source FROM title_screenshot
             WHERE title_id = ?1 ORDER BY ord, id",
        )?;
        let rows = stmt
            .query_map([title_id], Self::map_shot)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The MIME type of a stored screenshot blob, for the `/media` route.
    pub fn screenshot_mime(&self, sha1: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT mime FROM title_screenshot WHERE blob_sha1 = ?1 LIMIT 1",
                [sha1],
                |r| r.get(0),
            )
            .optional()?)
    }

    fn map_meta(r: &rusqlite::Row<'_>) -> rusqlite::Result<TitleMeta> {
        Ok(TitleMeta {
            title_id: r.get(0)?,
            genre: r.get(1)?,
            description: r.get(2)?,
            year: r.get(3)?,
            sources: r.get(4)?,
            external_url: r.get(5)?,
            screenshots: Vec::new(),
        })
    }

    fn map_shot(r: &rusqlite::Row<'_>) -> rusqlite::Result<Screenshot> {
        Ok(Screenshot {
            sha1: r.get(1)?,
            mime: r.get(2)?,
            caption: r.get(3)?,
            source: r.get(4)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_and_uid_uniqueness() {
        let db = Db::open_memory().unwrap();
        let sha = "abcdef0123456789abcdef0123456789abcdef01";
        let uid = db.unique_uid_for(sha).unwrap();
        assert_eq!(uid, &sha[..UID_LEN]);

        let mut a = NewArtifact {
            uid: uid.clone(),
            blob_sha1: sha.to_string(),
            container: "adf".into(),
            ..Default::default()
        };
        a.hashes = Hashes {
            sha1: sha.into(),
            crc32: "c".into(),
            md5: "m".into(),
        };
        db.insert_artifact(&a).unwrap();

        assert_eq!(
            db.artifact_uid_by_sha1(sha).unwrap().as_deref(),
            Some(uid.as_str())
        );
    }

    #[test]
    fn migrate_rebuilds_pre_qualifier_edition_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite");
        // Simulate a database created before `qualifier`: the OLD edition schema
        // whose UNIQUE constraint omits qualifier.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE title (id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'game', UNIQUE(name, category));
                 CREATE TABLE edition (id INTEGER PRIMARY KEY, title_id INTEGER NOT NULL,
                    version TEXT, language TEXT, publisher TEXT, disk_no INTEGER,
                    disk_count INTEGER, primary_artifact_uid TEXT,
                    UNIQUE(title_id, version, language, publisher, disk_no, disk_count));",
            )
            .unwrap();
        }

        // Opening runs migrate(), which must rebuild `edition` with `qualifier`
        // in the UNIQUE constraint.
        let db = Db::open(path.to_str().unwrap()).unwrap();
        let title_id = db.upsert_title("Agony", "demo").unwrap();
        let k1 = EditionKey {
            title: "Agony".into(),
            version: Some("v1".into()),
            language: Some("en".into()),
            publisher: Some("P".into()),
            qualifier: Some("demo-playable".into()),
            disk_no: Some(1),
            disk_count: Some(2),
        };
        let k2 = EditionKey {
            qualifier: Some("demo-rolling".into()),
            ..k1.clone()
        };
        // On the old (un-rebuilt) index these would collide on the non-qualifier
        // columns; after the rebuild they are two distinct editions.
        let e1 = db.upsert_edition(title_id, &k1).unwrap();
        let e2 = db.upsert_edition(title_id, &k2).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn enrichment_roundtrip_sentinel_and_no_wipe() {
        let db = Db::open_memory().unwrap();
        let tid = db.upsert_title("A-10 Tank Killer", "game").unwrap();

        // `only = Some(0)` is a real (absent) id, NOT a match-everything wildcard.
        assert!(db.titles_for_enrich(Some(0), false).unwrap().is_empty());
        assert_eq!(db.titles_for_enrich(None, false).unwrap().len(), 1);
        assert_eq!(db.titles_for_enrich(Some(tid), false).unwrap().len(), 1);

        let shots: Vec<StoredShot> = vec![
            ("aa".into(), "image/png".into(), None, "openretro".into(), 0),
            ("bb".into(), "image/png".into(), None, "openretro".into(), 1),
        ];
        db.save_enrichment(
            tid,
            Some("flight"),
            Some("desc"),
            Some(1990),
            Some("openretro"),
            Some("url"),
            Some(0.9),
            1,
            Some(&shots),
        )
        .unwrap();
        let m = db.title_meta(tid).unwrap().unwrap();
        assert_eq!(m.genre.as_deref(), Some("flight"));
        assert_eq!(m.screenshots.len(), 2);

        // Re-enrich with `None` keeps existing screenshots (transient fetch fail),
        // while metadata still updates — the two are one atomic write.
        db.save_enrichment(tid, Some("shooter"), None, None, None, None, None, 2, None)
            .unwrap();
        let m = db.title_meta(tid).unwrap().unwrap();
        assert_eq!(m.genre.as_deref(), Some("shooter"), "meta updated");
        assert_eq!(m.screenshots.len(), 2, "screenshots preserved on None");

        // `Some(&[])` explicitly clears them.
        db.save_enrichment(
            tid,
            Some("shooter"),
            None,
            None,
            None,
            None,
            None,
            3,
            Some(&[]),
        )
        .unwrap();
        assert_eq!(db.title_meta(tid).unwrap().unwrap().screenshots.len(), 0);

        // Now enriched, skip_fetched excludes it.
        assert!(db.titles_for_enrich(None, true).unwrap().is_empty());
    }
}
