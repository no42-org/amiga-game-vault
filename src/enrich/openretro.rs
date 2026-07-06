/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! OpenRetro provider: the Open Amiga Game Database (openretro.org).
//!
//! Amiga-native and credential-free. There is no published JSON API, so this
//! scrapes the public game pages: a title maps to a slug at `/amiga/{slug}`, with
//! a fallback search through the per-letter browse index. Parsing is defensive —
//! any structural drift degrades to "no result", never a panic.

use super::{Http, MetadataProvider, ProviderResult, Shot, TitleQuery};
use crate::naming::sanitize_title;
use crate::Result;

const BASE: &str = "https://openretro.org";
const SOURCE: &str = "openretro";

pub struct OpenRetro {
    base: String,
}

impl Default for OpenRetro {
    fn default() -> Self {
        Self {
            base: BASE.to_string(),
        }
    }
}

/// OpenRetro slug for a title: the kebab sanitizer, lowercased (e.g.
/// `A-10 Tank Killer` -> `a-10-tank-killer`, `The Addams Family` -> `the-addams-family`).
fn slug(name: &str) -> String {
    sanitize_title(name).to_ascii_lowercase()
}

/// First index letter for the browse fallback: the leading normalized letter,
/// else `0` (OpenRetro groups non-alphabetic titles under `0`).
fn index_letter(name: &str) -> char {
    super::normalize(name)
        .chars()
        .find(|c| c.is_ascii_alphabetic())
        .unwrap_or('0')
}

#[async_trait::async_trait]
impl MetadataProvider for OpenRetro {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn available(&self) -> bool {
        true
    }

    async fn lookup(&self, q: &TitleQuery, http: &Http) -> Result<Option<ProviderResult>> {
        // 1. Direct slug hit.
        let url = format!("{}/amiga/{}", self.base, slug(&q.name));
        if let Some(html) = http.get_text(&url).await? {
            if let Some(r) = parse_game_page(&html, &self.base, &q.name, &url) {
                return Ok(Some(r));
            }
        }
        // 2. Fallback: scan the per-letter browse index for the best-scoring title.
        let browse = format!("{}/browse/amiga/{}", self.base, index_letter(&q.name));
        let Some(index_html) = http.get_text(&browse).await? else {
            return Ok(None);
        };
        let Some(best_slug) = best_match_slug(&index_html, &q.name) else {
            return Ok(None);
        };
        let url = format!("{}/amiga/{}", self.base, best_slug);
        if let Some(html) = http.get_text(&url).await? {
            if let Some(r) = parse_game_page(&html, &self.base, &q.name, &url) {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }
}

/// Pick the best-scoring `/amiga/{slug}` link from a browse index page.
fn best_match_slug(html: &str, name: &str) -> Option<String> {
    use scraper::{Html, Selector};
    let doc = Html::parse_document(html);
    let a = Selector::parse(r#"a[href^="/amiga/"]"#).ok()?;
    let mut best: Option<(f32, String)> = None;
    for el in doc.select(&a) {
        let href = el.value().attr("href").unwrap_or("");
        let s = href.trim_start_matches("/amiga/").trim_matches('/');
        if s.is_empty() || s.contains('/') {
            continue;
        }
        let text: String = el.text().collect::<String>();
        // Cover links carry no text; use the slug itself as a fallback label.
        let label = if text.trim().is_empty() {
            s.replace('-', " ")
        } else {
            text
        };
        let score = super::similarity(name, &label);
        if best.as_ref().map(|(b, _)| score > *b).unwrap_or(true) {
            best = Some((score, s.to_string()));
        }
    }
    best.filter(|(score, _)| *score >= super::SCORE_FLOOR)
        .map(|(_, s)| s)
}

/// Parse an OpenRetro game page into a [`ProviderResult`], scoring the page's own
/// title against the query. Returns `None` if the page title is too weak a match.
fn parse_game_page(html: &str, base: &str, query_name: &str, url: &str) -> Option<ProviderResult> {
    let doc = scraper::Html::parse_document(html);

    let page_title = extract_page_title(&doc);
    let score = super::similarity(query_name, &page_title);
    if score < super::SCORE_FLOOR {
        return None;
    }

    let genre = extract_genre(&doc);
    let description = extract_description(&doc);
    let shots = extract_shots(&doc, base);

    Some(ProviderResult {
        source: SOURCE.to_string(),
        external_url: Some(url.to_string()),
        description,
        genre,
        year: None,
        shots,
        score,
    })
}

/// The game's own title: prefer `<h1>`, else the `<title>` element, with the
/// trailing " Amiga" platform tag and any " | Site" suffix stripped.
fn extract_page_title(doc: &scraper::Html) -> String {
    use scraper::Selector;
    let raw = Selector::parse("h1")
        .ok()
        .and_then(|s| doc.select(&s).next().map(|e| e.text().collect::<String>()))
        .filter(|t| !t.trim().is_empty())
        .or_else(|| {
            Selector::parse("title")
                .ok()
                .and_then(|s| doc.select(&s).next().map(|e| e.text().collect::<String>()))
        })
        .unwrap_or_default();
    let head = raw.split('|').next().unwrap_or(&raw).trim();
    head.strip_suffix(" Amiga")
        .unwrap_or(head)
        .trim()
        .to_string()
}

/// Description: the game summary from OpenRetro's `.game-about` block, falling
/// back to `.game-description` or an `og:description`/`meta description`. The blurb
/// is targeted deliberately — a generic "longest paragraph" would pick up the
/// page's footer/copyright boilerplate instead.
fn extract_description(doc: &scraper::Html) -> Option<String> {
    use scraper::Selector;
    for q in [".game-about", ".game-description"] {
        if let Ok(sel) = Selector::parse(q) {
            if let Some(el) = doc.select(&sel).next() {
                let text = el.text().collect::<String>();
                let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                if text.len() >= 40 {
                    return Some(text);
                }
            }
        }
    }
    for q in [
        r#"meta[property="og:description"]"#,
        r#"meta[name="description"]"#,
    ] {
        if let Ok(sel) = Selector::parse(q) {
            if let Some(c) = doc
                .select(&sel)
                .next()
                .and_then(|e| e.value().attr("content"))
            {
                let c = c.trim();
                if c.len() >= 40 {
                    return Some(c.to_string());
                }
            }
        }
    }
    None
}

/// Genre: the tags from OpenRetro's `Tags:` info row only. Scoping to that row is
/// deliberate — collecting every `/browse/` link would also pull in publisher,
/// developer and year facets (e.g. `/browse/1990`) and write them into the genre.
fn extract_genre(doc: &scraper::Html) -> Option<String> {
    use scraper::Selector;
    let row_sel = Selector::parse(".game-info-row").ok()?;
    let a_sel = Selector::parse(r#"a[href^="/browse/"]"#).ok()?;
    for row in doc.select(&row_sel) {
        let label = row.text().collect::<String>();
        if !label.trim_start().to_ascii_lowercase().starts_with("tags") {
            continue;
        }
        let mut genres: Vec<String> = Vec::new();
        for a in row.select(&a_sel) {
            let text = a.text().collect::<String>().trim().to_string();
            let g = if text.is_empty() {
                let href = a.value().attr("href").unwrap_or("");
                href.trim_start_matches("/browse/").replace('-', " ")
            } else {
                text
            };
            if !g.is_empty() && !genres.iter().any(|x| x.eq_ignore_ascii_case(&g)) {
                genres.push(g);
            }
        }
        if !genres.is_empty() {
            return Some(genres.join(", "));
        }
    }
    None
}

/// Screenshot image URLs from the page's lightbox links. Screenshots are wrapped
/// in `<a href="/image/{hash}?s=2x">`; cover art uses a different size param
/// (`?s=512`), so keying on `s=2x` excludes covers, avatars, logos and related-
/// game thumbnails. Dedup by hash; download the full-size original.
fn extract_shots(doc: &scraper::Html, base: &str) -> Vec<Shot> {
    use scraper::Selector;
    let Ok(a) = Selector::parse(r#"a[href*="/image/"]"#) else {
        return Vec::new();
    };
    let mut shots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for el in doc.select(&a) {
        let href = el.value().attr("href").unwrap_or("");
        if !href.contains("s=2x") {
            continue; // not a screenshot enlarge link (covers use s=512, etc.)
        }
        let Some(rest) = href.split("/image/").nth(1) else {
            continue;
        };
        let hash = rest.split(['?', '/']).next().unwrap_or("");
        if hash.is_empty() || !seen.insert(hash.to_string()) {
            continue;
        }
        shots.push(Shot {
            url: format!("{base}/image/{hash}"),
            caption: None,
            source: SOURCE.to_string(),
        });
    }
    shots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_matches_openretro_convention() {
        assert_eq!(slug("A-10 Tank Killer"), "a-10-tank-killer");
        assert_eq!(slug("The Addams Family"), "the-addams-family");
        assert_eq!(slug("Zool 2"), "zool-2");
    }

    #[test]
    fn parses_a_representative_game_page() {
        // A trimmed page mirroring OpenRetro's real structure: a `Tags:` info row
        // (genres), a decoy `Publisher:` row that is ALSO a /browse/ link, the
        // `.game-about` blurb, a cover (lightbox `s=512`) + screenshots (lightbox
        // `s=2x`), and a footer paragraph the description must NOT pick up.
        let html = r##"<!doctype html><html><head>
            <title>A-10 Tank Killer Amiga | OpenRetro Game Database</title>
            </head><body>
            <h1>A-10 Tank Killer</h1>
            <div class="game-info-row"><span>Publisher:</span><a href="/browse/dynamix">Dynamix</a></div>
            <div class="game-info-row"><span>Tags:</span><a href="/browse/flight">flight</a>,
                 <a href="/browse/simulation">simulation</a>, <a href="/browse/war">war</a></div>
            <a href="/browse/amiga/a">back to A</a>
            <div class="game-about"><p>This simulation puts you in the cockpit of the
                 A-10 Thunderbolt II, also known as the "Warthog".</p></div>
            <a href="/image/cover0001?s=512&f=jpg"><img src="/image/cover0001?w=200&h=266&t=lbcover" alt="front image"></a>
            <a href="/image/shot0001?s=2x"><img src="/image/shot0001?w=332&h=208" alt=""></a>
            <a href="/image/shot0002?s=2x"><img src="/image/shot0002?w=332&h=208" alt=""></a>
            <p>Page generated in 0.05 seconds. All times are in UTC. By submitting information you
               disclaim copyright to your work related to preparing this database entry footer.</p>
            </body></html>"##;
        let r = parse_game_page(html, "https://openretro.org", "A-10 Tank Killer", "u")
            .expect("parsed");
        assert_eq!(
            r.genre.as_deref(),
            Some("flight, simulation, war"),
            "only the Tags row, not the Publisher /browse/ link"
        );
        let desc = r.description.as_ref().unwrap();
        assert!(desc.contains("Warthog"), "took the game blurb");
        assert!(
            !desc.contains("Page generated"),
            "not the footer boilerplate"
        );
        assert_eq!(
            r.shots.len(),
            2,
            "cover (s=512) excluded, two screenshots (s=2x) kept"
        );
        assert_eq!(r.shots[0].url, "https://openretro.org/image/shot0001");
        assert!(r.score > 0.9);
    }

    #[test]
    fn rejects_a_wrong_title_page() {
        let html =
            "<html><head><title>Lemmings Amiga</title></head><body><h1>Lemmings</h1></body></html>";
        assert!(parse_game_page(html, "https://openretro.org", "A-10 Tank Killer", "u").is_none());
    }

    #[test]
    fn browse_index_picks_best_slug() {
        let html = r#"<html><body>
            <a href="/amiga/a-320-airbus">A-320 Airbus</a>
            <a href="/amiga/a-10-tank-killer">A-10 Tank Killer</a>
            <a href="/amiga/aaargh">Aaargh</a>
            </body></html>"#;
        assert_eq!(
            best_match_slug(html, "A-10 Tank Killer").as_deref(),
            Some("a-10-tank-killer")
        );
    }
}
