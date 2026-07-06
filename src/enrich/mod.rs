/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Enrichment: pull editorial metadata (description, genre, screenshots) for a
//! logical work from online Amiga libraries and attach it to the `title` row.
//!
//! A pluggable [`MetadataProvider`] layer queries each configured source; results
//! are fuzzy-matched by title name, merged (Amiga-native sources first), and
//! persisted — screenshot bytes into the content-addressed blob store.
//!
//! The orchestrator ([`run`]) is async and holds the [`Vault`] mutex only for the
//! brief synchronous reads/writes, never across network I/O, so the server stays
//! responsive during a bulk enrich.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::service::Vault;
use crate::Result;

pub mod openretro;

/// A title to look up, with matching hints.
#[derive(Debug, Clone)]
pub struct TitleQuery {
    pub title_id: i64,
    pub name: String,
    pub year: Option<i32>,
    pub category: String,
}

/// One screenshot reference returned by a provider (a remote image URL).
#[derive(Debug, Clone)]
pub struct Shot {
    pub url: String,
    pub caption: Option<String>,
    pub source: String,
}

/// A single provider's result for a title.
#[derive(Debug, Clone)]
pub struct ProviderResult {
    pub source: String,
    pub external_url: Option<String>,
    pub description: Option<String>,
    pub genre: Option<String>,
    pub year: Option<i32>,
    pub shots: Vec<Shot>,
    /// Fuzzy name-match confidence of this result (0..1).
    pub score: f32,
}

/// The merged editorial record for a title, ready to persist.
#[derive(Debug, Clone)]
pub struct Merged {
    pub genre: Option<String>,
    pub description: Option<String>,
    pub year: Option<i32>,
    pub sources: String,
    pub external_url: Option<String>,
    pub score: f32,
    pub shots: Vec<Shot>,
}

/// A downloaded screenshot ready to persist: `(bytes, mime, caption, source, ord)`.
pub type ScreenshotBytes = (Vec<u8>, String, Option<String>, String, i64);

/// Summary of an enrichment run.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EnrichReport {
    /// Titles that got a merged record written.
    pub enriched: usize,
    /// Titles considered but with no confident match.
    pub skipped: usize,
}

/// Minimum name-match score for a provider result to be accepted.
const SCORE_FLOOR: f32 = 0.55;
/// Cap on screenshots stored per title.
const MAX_SHOTS: usize = 6;

/// A pluggable metadata source.
#[async_trait::async_trait]
pub trait MetadataProvider: Send + Sync {
    /// Stable identifier recorded in `title_meta.sources`.
    fn name(&self) -> &'static str;
    /// Whether the provider is usable (credentials/config present). Providers that
    /// need an API key report `false` until it is configured, and are skipped.
    fn available(&self) -> bool;
    /// Look a title up. `Ok(None)` means "no confident match", not an error.
    async fn lookup(&self, q: &TitleQuery, http: &Http) -> Result<Option<ProviderResult>>;
}

/// The set of providers to query, in priority order (Amiga-native first).
///
/// Only OpenRetro ships enabled today; Hall of Light, MobyGames and IGDB slot in
/// here as later phases, each gating itself via [`MetadataProvider::available`].
fn providers() -> Vec<Box<dyn MetadataProvider>> {
    vec![Box::new(openretro::OpenRetro::default())]
}

// --- HTTP -----------------------------------------------------------------

/// A thin async HTTP client shared across providers within one run.
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("amiga-disk-vault/0.1 (+https://github.com/no42-org/amiga-disk-vault)")
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| crate::Error::Invalid(format!("http client: {e}")))?;
        Ok(Self { client })
    }

    /// GET a URL as text. `Ok(None)` for a 404 (a missing page is not an error).
    pub async fn get_text(&self, url: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| crate::Error::Invalid(format!("GET {url}: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(crate::Error::Invalid(format!(
                "GET {url}: HTTP {}",
                resp.status()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| crate::Error::Invalid(format!("body {url}: {e}")))?;
        Ok(Some(text))
    }

    /// GET a URL as image bytes, returning `(bytes, mime)`.
    pub async fn get_image(&self, url: &str) -> Result<(Vec<u8>, String)> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| crate::Error::Invalid(format!("GET image {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Invalid(format!(
                "GET image {url}: HTTP {}",
                resp.status()
            )));
        }
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string())
            .filter(|m| m.starts_with("image/"))
            .unwrap_or_else(|| "image/jpeg".to_string());
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::Error::Invalid(format!("image body {url}: {e}")))?;
        Ok((bytes.to_vec(), mime))
    }
}

// --- Orchestrator ---------------------------------------------------------

/// Enrich titles: `only = Some(id)` targets one title (and re-fetches it even if
/// already enriched); `None` enriches the whole catalog, and with `skip_fetched`
/// leaves already-enriched titles untouched.
///
/// The `Vault` mutex is taken only for the short synchronous reads (work-list)
/// and writes (persist), never across an `.await` on the network.
pub async fn run(
    state: Arc<Mutex<Vault>>,
    only: Option<i64>,
    skip_fetched: bool,
) -> Result<EnrichReport> {
    let queries: Vec<TitleQuery> = {
        let v = state.lock().expect("vault mutex poisoned");
        v.titles_for_enrich(only, skip_fetched)?
    };
    let http = Http::new()?;
    let provs = providers();
    let mut report = EnrichReport::default();

    for q in queries {
        let mut results = Vec::new();
        for p in &provs {
            if !p.available() {
                continue;
            }
            match p.lookup(&q, &http).await {
                Ok(Some(r)) => results.push(r),
                Ok(None) => {}
                Err(e) => eprintln!("enrich: {} lookup for {:?} failed: {e}", p.name(), q.name),
            }
        }
        let Some(merged) = merge(results) else {
            report.skipped += 1;
            continue;
        };
        // Download screenshot bytes (lock-free).
        let mut images: Vec<ScreenshotBytes> = Vec::new();
        for (i, shot) in merged.shots.iter().take(MAX_SHOTS).enumerate() {
            match http.get_image(&shot.url).await {
                Ok((bytes, mime)) => images.push((
                    bytes,
                    mime,
                    shot.caption.clone(),
                    shot.source.clone(),
                    i as i64,
                )),
                Err(e) => eprintln!("enrich: screenshot {} failed: {e}", shot.url),
            }
        }
        {
            let v = state.lock().expect("vault mutex poisoned");
            v.save_enrichment(q.title_id, &merged, &images)?;
        }
        report.enriched += 1;
    }
    Ok(report)
}

/// Current unix time in seconds (for `title_meta.fetched_at`).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Merge provider results (already in priority order) into one record. Takes the
/// first non-empty field per attribute and unions screenshots (deduped by URL).
/// Returns `None` when no result clears [`SCORE_FLOOR`].
fn merge(results: Vec<ProviderResult>) -> Option<Merged> {
    let kept: Vec<ProviderResult> = results
        .into_iter()
        .filter(|r| r.score >= SCORE_FLOOR)
        .collect();
    if kept.is_empty() {
        return None;
    }
    let first_str = |pick: fn(&ProviderResult) -> Option<&str>| {
        kept.iter().find_map(|r| pick(r).map(str::to_string))
    };
    let genre = first_str(|r| r.genre.as_deref());
    let description = first_str(|r| r.description.as_deref());
    let external_url = first_str(|r| r.external_url.as_deref());
    let year = kept.iter().find_map(|r| r.year);
    let score = kept.iter().map(|r| r.score).fold(0.0f32, f32::max);

    let mut sources: Vec<String> = Vec::new();
    for r in &kept {
        if !sources.contains(&r.source) {
            sources.push(r.source.clone());
        }
    }
    let mut shots: Vec<Shot> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in &kept {
        for s in &r.shots {
            if seen.insert(s.url.clone()) {
                shots.push(s.clone());
            }
        }
    }
    Some(Merged {
        genre,
        description,
        year,
        sources: sources.join(","),
        external_url,
        score,
        shots,
    })
}

// --- Name matching --------------------------------------------------------

/// Normalize a title for comparison: lowercase, alphanumeric words only, with a
/// leading `"the"` dropped. Reuses the vault's title sanitizer as the base.
///
/// Only `"the"` is stripped — never `"a"`/`"an"`, which are part of real titles
/// (`A-10`, `A-Train`) far more often than they are articles here.
pub fn normalize(name: &str) -> String {
    let kebab = crate::naming::sanitize_title(name).to_ascii_lowercase();
    let words: Vec<&str> = kebab.split('-').filter(|w| !w.is_empty()).collect();
    let start = usize::from(words.first() == Some(&"the") && words.len() > 1);
    words[start..].join(" ")
}

/// Similarity of two titles in `0..1`: half token-Jaccard over the normalized
/// words, half edit-distance ratio over the *separator-collapsed* forms (so
/// `A-10` and `A10` compare as identical). `1.0` on an exact collapsed match.
pub fn similarity(a: &str, b: &str) -> f32 {
    let na = normalize(a);
    let nb = normalize(b);
    if na.is_empty() || nb.is_empty() {
        return 0.0;
    }
    let sa: String = na.split(' ').collect();
    let sb: String = nb.split(' ').collect();
    if sa == sb {
        return 1.0;
    }
    let ta: std::collections::HashSet<&str> = na.split(' ').collect();
    let tb: std::collections::HashSet<&str> = nb.split(' ').collect();
    let inter = ta.intersection(&tb).count() as f32;
    let uni = ta.union(&tb).count() as f32;
    let jaccard = if uni > 0.0 { inter / uni } else { 0.0 };

    let dist = levenshtein(&sa, &sb) as f32;
    let maxlen = sa.chars().count().max(sb.chars().count()) as f32;
    let edit_ratio = if maxlen > 0.0 {
        1.0 - dist / maxlen
    } else {
        0.0
    };

    0.5 * jaccard + 0.5 * edit_ratio.max(0.0)
}

/// Classic Levenshtein edit distance (byte-wise; inputs are lowercase ASCII-ish).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_drops_articles_and_punctuation() {
        assert_eq!(normalize("The Addams Family"), "addams family");
        assert_eq!(normalize("A-10 Tank Killer"), "a 10 tank killer");
        assert_eq!(normalize("Bubble Bobble!"), "bubble bobble");
    }

    #[test]
    fn similarity_scores_matches_high_and_mismatches_low() {
        assert!((similarity("A-10 Tank Killer", "A-10 Tank Killer") - 1.0).abs() < 1e-6);
        assert!(similarity("A-10 Tank Killer", "A10 Tank Killer") > 0.8);
        assert!(similarity("Turrican", "Turrican II") > 0.55);
        assert!(similarity("Turrican", "Lemmings") < 0.4);
    }

    #[test]
    fn merge_prefers_priority_order_and_unions_shots() {
        let r1 = ProviderResult {
            source: "openretro".into(),
            external_url: Some("u1".into()),
            description: Some("desc1".into()),
            genre: None,
            year: Some(1990),
            shots: vec![Shot {
                url: "a".into(),
                caption: None,
                source: "openretro".into(),
            }],
            score: 0.9,
        };
        let r2 = ProviderResult {
            source: "hol".into(),
            external_url: Some("u2".into()),
            description: Some("desc2".into()),
            genre: Some("shooter".into()),
            year: Some(1991),
            shots: vec![
                Shot {
                    url: "a".into(),
                    caption: None,
                    source: "hol".into(),
                },
                Shot {
                    url: "b".into(),
                    caption: None,
                    source: "hol".into(),
                },
            ],
            score: 0.7,
        };
        let m = merge(vec![r1, r2]).expect("merged");
        assert_eq!(m.description.as_deref(), Some("desc1")); // priority first
        assert_eq!(m.genre.as_deref(), Some("shooter")); // first non-empty
        assert_eq!(m.year, Some(1990));
        assert_eq!(m.sources, "openretro,hol");
        assert_eq!(m.shots.len(), 2); // "a" deduped, "b" added
    }

    #[test]
    fn merge_rejects_below_floor() {
        let weak = ProviderResult {
            source: "openretro".into(),
            external_url: None,
            description: Some("d".into()),
            genre: None,
            year: None,
            shots: vec![],
            score: 0.2,
        };
        assert!(merge(vec![weak]).is_none());
    }
}
