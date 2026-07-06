/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! HTTP layer (Axum): browse, search, upload, quarantine, download and export.
//!
//! Single-user and self-hosted, so there is no auth. The [`Vault`] is guarded by
//! a mutex; handlers take the lock, do their synchronous work, and release it.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::service::{ResolveMeta, Vault};
use crate::Error;

pub type AppState = Arc<Mutex<Vault>>;

/// Build the application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/logo.png", get(logo))
        .route("/api/editions", get(editions))
        .route("/api/works", get(works))
        .route("/api/sets", get(sets))
        .route("/api/sets/{id}/lineages", get(set_lineages))
        .route("/api/sets/{id}/playable", get(playable))
        .route("/export/set/{id}/{lineage}", get(export_set))
        .route("/api/editions/{id}/variants", get(variants))
        .route("/api/editions/{id}/primary", post(set_primary))
        .route("/api/artifact/{uid}", get(artifact))
        .route("/api/upload", post(upload))
        .route("/api/import-dat", post(import_dat))
        .route("/api/quarantine", get(quarantine))
        .route("/api/reidentify", post(reidentify))
        .route("/api/quarantine/{uid}/resolve", post(resolve))
        .route("/download/{uid}", get(download))
        .route("/export/edition/{id}", get(export_edition))
        .with_state(state)
}

/// Serve the app on `addr`.
pub async fn serve(state: AppState, addr: &str) -> crate::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state))
        .await
        .map_err(Error::Io)?;
    Ok(())
}

// --- Error mapping ---------------------------------------------------------

struct AppErr(Error);

impl From<Error> for AppErr {
    fn from(e: Error) -> Self {
        AppErr(e)
    }
}

impl IntoResponse for AppErr {
    fn into_response(self) -> Response {
        let code = match self.0 {
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::UnsupportedType(_) | Error::Invalid(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.0.to_string()).into_response()
    }
}

fn lock(state: &AppState) -> std::sync::MutexGuard<'_, Vault> {
    state.lock().expect("vault mutex poisoned")
}

// --- Handlers --------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BrowseParams {
    q: Option<String>,
    category: Option<String>,
    language: Option<String>,
    status: Option<String>,
}

async fn editions(
    State(state): State<AppState>,
    Query(p): Query<BrowseParams>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    let rows = v.browse(
        p.q.as_deref(),
        p.category.as_deref(),
        p.language.as_deref(),
        p.status.as_deref(),
    )?;
    Ok(Json(serde_json::json!({ "editions": rows })))
}

async fn variants(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    Ok(Json(serde_json::json!({ "variants": v.variants(id)? })))
}

async fn sets(
    State(state): State<AppState>,
    Query(p): Query<BrowseParams>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    let incomplete = p.status.as_deref() == Some("incomplete");
    let rows = v.list_sets(
        p.q.as_deref(),
        p.category.as_deref(),
        p.language.as_deref(),
        incomplete,
    )?;
    Ok(Json(serde_json::json!({ "sets": rows })))
}

async fn works(
    State(state): State<AppState>,
    Query(p): Query<BrowseParams>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    let rows = v.list_works(p.q.as_deref(), p.category.as_deref(), p.language.as_deref())?;
    Ok(Json(serde_json::json!({ "works": rows })))
}

async fn playable(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    Ok(Json(serde_json::json!({ "sets": v.playable_sets(id)? })))
}

async fn set_lineages(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    let disks: Vec<serde_json::Value> = v
        .set_disks(id)?
        .into_iter()
        .map(|(disk_no, edition_id)| serde_json::json!({ "disk_no": disk_no, "edition_id": edition_id }))
        .collect();
    Ok(Json(serde_json::json!({
        "lineages": v.set_lineages(id)?,
        "disks": disks,
    })))
}

#[derive(Debug, Deserialize)]
struct BootParam {
    boot: Option<String>,
}

async fn export_set(
    State(state): State<AppState>,
    Path((id, lineage)): Path<(i64, String)>,
    Query(p): Query<BootParam>,
) -> Result<Response, AppErr> {
    // "-" is the reserved segment for the original (no-group) set — its stored
    // lineage tag is the empty string, which can't be an empty path segment.
    let tag = if lineage == "-" { "" } else { lineage.as_str() };
    let files = {
        let v = lock(&state);
        v.export_set_with(id, tag, p.boot.as_deref())?
    };
    let safe: String = if tag.is_empty() {
        "original".to_string()
    } else {
        tag.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    };
    let zip = build_zip(&files)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"set-{id}-{safe}.zip\""),
            ),
        ],
        zip,
    )
        .into_response())
}

async fn artifact(
    State(state): State<AppState>,
    Path(uid): Path<String>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    match v.get_artifact(&uid)? {
        Some(a) => Ok(Json(serde_json::to_value(a).unwrap())),
        None => Err(AppErr(Error::NotFound(format!("artifact {uid}")))),
    }
}

#[derive(Debug, Deserialize)]
struct UploadParams {
    filename: String,
}

async fn upload(
    State(state): State<AppState>,
    Query(p): Query<UploadParams>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    let outcomes = v.ingest(&p.filename, &body)?;
    Ok(Json(serde_json::json!({ "outcomes": outcomes })))
}

#[derive(Debug, Deserialize)]
struct ImportParams {
    source: Option<String>,
}

async fn import_dat(
    State(state): State<AppState>,
    Query(p): Query<ImportParams>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppErr> {
    let xml = String::from_utf8_lossy(&body);
    let v = lock(&state);
    let count = v.import_dat_xml(&xml, p.source.as_deref().unwrap_or("TOSEC"))?;
    Ok(Json(serde_json::json!({ "imported": count })))
}

async fn quarantine(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    Ok(Json(
        serde_json::json!({ "quarantine": v.quarantine_list()? }),
    ))
}

async fn reidentify(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    Ok(Json(serde_json::to_value(v.reidentify()?).unwrap()))
}

#[derive(Debug, Deserialize)]
struct ResolveBody {
    title: String,
    #[serde(default)]
    category: String,
    version: Option<String>,
    language: Option<String>,
    publisher: Option<String>,
    disk_no: Option<u32>,
    disk_count: Option<u32>,
}

async fn resolve(
    State(state): State<AppState>,
    Path(uid): Path<String>,
    Json(b): Json<ResolveBody>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let meta = ResolveMeta {
        title: b.title,
        category: b.category,
        version: b.version,
        language: b.language,
        publisher: b.publisher,
        disk_no: b.disk_no,
        disk_count: b.disk_count,
    };
    let v = lock(&state);
    v.resolve_quarantine(&uid, &meta)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct PrimaryParams {
    uid: String,
}

async fn set_primary(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(p): Query<PrimaryParams>,
) -> Result<Json<serde_json::Value>, AppErr> {
    let v = lock(&state);
    v.set_primary(id, &p.uid)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn download(
    State(state): State<AppState>,
    Path(uid): Path<String>,
) -> Result<Response, AppErr> {
    let v = lock(&state);
    match v.blob_for(&uid)? {
        Some((name, bytes)) => Ok((
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
            ],
            bytes,
        )
            .into_response()),
        None => Err(AppErr(Error::NotFound(format!("artifact {uid}")))),
    }
}

async fn export_edition(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppErr> {
    let files = {
        let v = lock(&state);
        v.export_edition(id)?
    };
    let zip = build_zip(&files)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"edition-{id}.zip\""),
            ),
        ],
        zip,
    )
        .into_response())
}

/// Build an in-memory zip of `(name, bytes)` files, each already canonically named.
fn build_zip(files: &[(String, Vec<u8>)]) -> crate::Result<Vec<u8>> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in files {
            zw.start_file(name, opts)?;
            zw.write_all(bytes)?;
        }
        zw.finish()?;
    }
    Ok(buf)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// The application logo, embedded into the binary and served statically.
async fn logo() -> Response {
    const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO_PNG,
    )
        .into_response()
}

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Amiga Disk Vault</title>
<style>
  /* Design tokens ported from the visual spec (dark navy-teal + warm orange,
     keyed to the logo). OKLCH throughout. */
  :root {
    color-scheme: dark;
    --background: oklch(0.19 0.026 232);
    --foreground: oklch(0.93 0.012 230);
    --card: oklch(0.23 0.03 233);
    --primary: oklch(0.64 0.1 228);
    --secondary: oklch(0.29 0.03 233);
    --muted-foreground: oklch(0.68 0.02 230);
    --accent: oklch(0.7 0.16 52);
    --border: oklch(1 0 0 / 10%);
    --input: oklch(1 0 0 / 13%);
    --ring: oklch(0.64 0.1 228);
    --link: oklch(0.72 0.11 232);
    --original: oklch(0.72 0.14 155);
    --cracked: oklch(0.7 0.18 30);
    --hacked: oklch(0.7 0.17 335);
    --radius: 0.625rem;
  }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 system-ui, -apple-system, sans-serif; margin: 0;
    background: var(--background); color: var(--foreground); }
  svg { display: inline-block; vertical-align: -0.125em; }

  header { position: sticky; top: 0; z-index: 20; padding: 12px 20px;
    background: color-mix(in oklch, var(--background) 92%, transparent);
    backdrop-filter: blur(8px); border-bottom: 1px solid var(--border); }
  .head-top { display: flex; align-items: center; gap: 12px; }
  header .logo { height: 40px; width: auto; display: block; flex: none; }
  .head-titles { min-width: 0; }
  h1 { font-size: 15px; font-weight: 600; margin: 0; line-height: 1.2; }
  .subtitle { margin: 1px 0 0; font-size: 12px; color: var(--muted-foreground); }
  .head-actions { margin-left: auto; display: flex; gap: 8px; }

  main { padding: 16px 20px; max-width: 1000px; margin: 0 auto; }
  input, select, button { font: inherit; }
  input, select { padding: 6px 9px; background: var(--card); color: inherit;
    border: 1px solid var(--input); border-radius: calc(var(--radius) * 0.8); }
  input:focus, select:focus { outline: none; border-color: var(--ring);
    box-shadow: 0 0 0 1px var(--ring); }
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 6px 11px;
    background: var(--card); color: var(--foreground); border: 1px solid var(--input);
    border-radius: calc(var(--radius) * 0.8); font-weight: 600; font-size: 12px;
    cursor: pointer; }
  .btn:hover { background: var(--secondary); }

  .controls { display: flex; gap: 8px; margin: 12px 0 0; flex-wrap: wrap; align-items: center; }
  .search { position: relative; flex: 1; min-width: 200px; display: flex; align-items: center; }
  .search svg { position: absolute; left: 9px; color: var(--muted-foreground);
    pointer-events: none; }
  .search input { width: 100%; padding-left: 30px; }
  /* Segmented type filter */
  .seg { display: inline-flex; padding: 2px; gap: 2px; background: var(--card);
    border: 1px solid var(--input); border-radius: calc(var(--radius) * 0.8); }
  .seg-btn { padding: 4px 10px; background: transparent; color: var(--muted-foreground);
    border: 0; border-radius: calc(var(--radius) * 0.6); font-size: 12px; font-weight: 500;
    cursor: pointer; }
  .seg-btn:hover { color: var(--foreground); }
  .seg-btn.active { background: var(--secondary); color: var(--foreground); }

  .legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 12px 0 0;
    font-size: 11px; color: var(--muted-foreground); }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .t-original { color: var(--original); }
  .t-cracked { color: var(--cracked); }
  .t-hacked { color: var(--hacked); }

  /* Work cards */
  .edition { border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--card); margin: 6px 0; overflow: hidden; }
  .card-head { display: flex; align-items: center; gap: 10px; width: 100%;
    padding: 10px 12px; background: none; border: 0; color: inherit; cursor: pointer;
    text-align: left; }
  .card-head:hover { background: color-mix(in oklch, var(--secondary) 40%, transparent); }
  .chevron { flex: none; color: var(--muted-foreground); transition: transform .15s; }
  .card-head[aria-expanded="true"] .chevron { transform: rotate(90deg); }
  .card-title { min-width: 0; flex: 1; }
  .title-line { display: block; font-weight: 600; font-size: 14px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub-line { display: block; font-size: 12px; color: var(--muted-foreground);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .chips { flex: none; display: inline-flex; gap: 8px; }
  .chip { display: inline-flex; align-items: center; gap: 3px; font-size: 11px;
    font-weight: 600; }
  .chip.original { color: var(--original); }
  .chip.cracked { color: var(--cracked); }
  .chip.hacked { color: var(--hacked); }
  .chip.trainer { gap: 2px; padding: 1px 5px; border-radius: 4px; font-size: 10px;
    color: var(--accent); background: color-mix(in oklch, var(--accent) 15%, transparent); }

  /* Type badge on a lineage row */
  .badge { display: inline-flex; align-items: center; gap: 3px; padding: 1px 6px;
    border-radius: 5px; font-size: 11px; font-weight: 600; }
  .badge.original { color: var(--original); background: color-mix(in oklch, var(--original) 15%, transparent); }
  .badge.cracked { color: var(--cracked); background: color-mix(in oklch, var(--cracked) 15%, transparent); }
  .badge.hacked { color: var(--hacked); background: color-mix(in oklch, var(--hacked) 15%, transparent); }

  .card-body { border-top: 1px solid var(--border); padding: 2px 12px 8px; }
  /* Quarantine rows render a .meta directly inside a bare .edition card. */
  .edition > .meta { padding: 10px 12px; }
  #list h3 { font-size: 14px; margin: 10px 0 6px; }
  .meta { color: var(--muted-foreground); font-size: 12px; }
  .variants { display: none; }
  .variants.open { display: block; }
  .variant { padding: 5px 0; border-top: 1px solid var(--border);
    display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
  .primary { color: var(--original); }
  .variant.vcol { display: block; }
  .vrow { display: flex; justify-content: space-between; gap: 12px; }
  .vsub { padding-left: 2px; margin-top: 2px; }
  .vnode { padding: 8px 0 2px; border-top: 1px solid var(--border); }
  .vnode:first-child { border-top: 0; }
  .vnode .vyear { color: var(--muted-foreground); font-size: 12px; }
  .variant.lang { padding-left: 16px; }
  .demos-split { margin-top: 10px; padding-top: 6px; border-top: 1px dashed var(--border);
    color: var(--muted-foreground); font-size: 12px; }
  code { color: color-mix(in oklch, var(--foreground) 85%, transparent);
    font-family: ui-monospace, monospace; }
  a { color: var(--link); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .upload-panel { border: 1px solid var(--border); border-radius: var(--radius);
    margin: 6px 0 16px; padding: 10px 12px;
    background: color-mix(in oklch, var(--card) 70%, var(--background)); }
  /* Upload progress: a bar for the bulk + a processed/total counter. */
  .u-head { display: flex; align-items: center; gap: 10px; margin: 0 0 8px; }
  .u-bar { flex: 1; height: 8px; border: 0; border-radius: 999px;
    background: var(--secondary); appearance: none; -webkit-appearance: none; overflow: hidden; }
  .u-bar::-webkit-progress-bar { background: var(--secondary); border-radius: 999px; }
  .u-bar::-webkit-progress-value { background: var(--primary); border-radius: 999px; }
  .u-bar::-moz-progress-bar { background: var(--primary); border-radius: 999px; }
  .u-count { flex: none; font-size: 12px; color: var(--muted-foreground);
    font-variant-numeric: tabular-nums; }
  .u-row { display: flex; justify-content: space-between; gap: 12px; padding: 3px 0;
    border-top: 1px solid var(--border); font-size: 12px; }
  .u-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .u-status { flex: none; }
  .s-quarantined { color: var(--accent); }
  .s-rejected { color: var(--cracked); }
  .s-error { color: var(--cracked); }
  .u-summary { margin-top: 8px; font-size: 12px;
    color: color-mix(in oklch, var(--foreground) 85%, transparent); }
  .drop-overlay { position: fixed; inset: 0; display: none; align-items: center;
    justify-content: center; text-align: center; padding: 20px; z-index: 50;
    background: color-mix(in oklch, var(--background) 85%, transparent);
    border: 3px dashed var(--primary); color: var(--foreground); font-size: 20px; }
  .drop-overlay.show { display: flex; }
</style>
</head>
<body>
<header>
  <div class="head-top">
    <img src="/logo.png" alt="Amiga Disk Vault logo" class="logo">
    <div class="head-titles">
      <h1>Amiga Disk Vault</h1>
      <p class="subtitle" id="subtitle">catalog</p>
    </div>
    <div class="head-actions">
      <button class="btn" data-ic-pre="plus" onclick="document.getElementById('filePick').click()">Add ADF</button>
      <button class="btn" data-ic-pre="folder" onclick="document.getElementById('dirPick').click()">Upload folder</button>
    </div>
  </div>
  <div class="controls">
    <label class="search"><span data-ic="search"></span>
      <input id="q" placeholder="Search titles, groups, ADF files…" aria-label="Search the vault"></label>
    <select id="category"><option value="">all categories</option>
      <option>game</option><option>tool</option><option>demo</option></select>
    <input id="language" placeholder="lang (en, es…)" size="8" aria-label="Filter by language">
    <div class="seg" id="typeSeg" role="group" aria-label="Filter by type">
      <button class="seg-btn active" data-t="all" onclick="setType('all')">All</button>
      <button class="seg-btn" data-t="original" onclick="setType('original')">Original</button>
      <button class="seg-btn" data-t="cracked" onclick="setType('cracked')">Cracked</button>
      <button class="seg-btn" data-t="hacked" onclick="setType('hacked')">Hacked</button>
    </div>
    <button class="btn" onclick="load()">Search</button>
    <a href="#" onclick="loadQuarantine();return false">Quarantine</a>
    <a href="#" onclick="reidentify();return false">Re-identify</a>
  </div>
  <div class="legend">
    <span class="t-original"><span data-ic="shield"></span>Original — untouched factory image</span>
    <span class="t-cracked"><span data-ic="skull"></span>Cracked — protection removed, game unchanged</span>
    <span class="t-hacked"><span data-ic="wrench"></span>Hacked — game modified (trainer / fixes)</span>
  </div>
</header>
<main>
  <input id="filePick" type="file" multiple hidden>
  <input id="dirPick" type="file" webkitdirectory multiple hidden>
  <div id="uploadPanel" class="upload-panel" hidden></div>
  <div id="list"></div>
</main>
<div id="dropOverlay" class="drop-overlay">Drop ADF files or a folder to upload
  <span class="meta" id="dropHint"></span></div>
<script>
// Inline SVG icon set (lucide, MIT) — kept in the binary, no CDN or web font.
const svg = (w, inner) => `<svg width="${w}" height="${w}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
const ICON = {
  chevron: svg(16, '<path d="m9 18 6-6-6-6"/>'),
  shield: svg(13, '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'),
  skull: svg(13, '<circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><path d="M8 20v2h8v-2"/><path d="M16 20a2 2 0 0 0 1.56-3.25 8 8 0 1 0-11.12 0A2 2 0 0 0 8 20"/>'),
  wrench: svg(13, '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'),
  zap: svg(11, '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>'),
  search: svg(15, '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'),
  plus: svg(14, '<path d="M5 12h14"/><path d="M12 5v14"/>'),
  folder: svg(14, '<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>'),
};
const TYPE_ICON = { original: ICON.shield, cracked: ICON.skull, hacked: ICON.wrench };
function initIcons() {
  for (const el of document.querySelectorAll('[data-ic]')) el.innerHTML = ICON[el.dataset.ic] || '';
  for (const el of document.querySelectorAll('[data-ic-pre]')) el.insertAdjacentHTML('afterbegin', ICON[el.dataset.icPre] || '');
}

// Colour-coded original/cracked/hacked summary chips for a Work card header.
function typeChips(x) {
  let h = '';
  if (x.original_count) h += `<span class="chip original" title="Original releases">${ICON.shield}${x.original_count}</span>`;
  if (x.cracked_count) h += `<span class="chip cracked" title="Cracked releases">${ICON.skull}${x.cracked_count}</span>`;
  if (x.hacked_count) h += `<span class="chip hacked" title="Hacked releases">${ICON.wrench}${x.hacked_count}</span>`;
  return h;
}
// A type badge for one lineage row (original / cracked / hacked).
function kindBadge(kind) {
  const label = kind ? kind.charAt(0).toUpperCase() + kind.slice(1) : '';
  return `<span class="badge ${kind}">${TYPE_ICON[kind] || ''}${label}</span>`;
}
// A "+N TRAINER" chip showing the scene trainer tag (e.g. "+3 DC").
function trainerChip(text) {
  return `<span class="chip trainer" title="Includes a cheat trainer">${ICON.zap}${text ? esc(text) : 'TRAINER'}</span>`;
}

// The works fetched by the last search, and the active client-side type filter.
let LAST_WORKS = [];
let TYPE_FILTER = 'all';

async function load() {
  const p = new URLSearchParams();
  for (const k of ['q','category','language']) {
    const val = document.getElementById(k).value.trim();
    if (val) p.set(k, val);
  }
  const { works } = await (await fetch('/api/works?' + p)).json();
  LAST_WORKS = works;
  // A fresh fetch (search, upload refresh, re-identify) resets the client-side
  // type filter, so a just-changed title is never hidden by a stale segment.
  TYPE_FILTER = 'all';
  for (const b of document.querySelectorAll('.seg-btn')) b.classList.toggle('active', b.dataset.t === 'all');
  renderWorks();
}
// Render (or re-render) the Work cards, applying the client-side type filter.
function renderWorks() {
  const works = TYPE_FILTER === 'all'
    ? LAST_WORKS
    : LAST_WORKS.filter(w => w[TYPE_FILTER + '_count'] > 0);
  const total = LAST_WORKS.length;
  document.getElementById('subtitle').textContent = TYPE_FILTER === 'all'
    ? `${total} ${total === 1 ? 'title' : 'titles'} in catalog`
    : `${works.length} of ${total} · ${TYPE_FILTER}`;
  const list = document.getElementById('list');
  list.innerHTML = works.length ? '' : (LAST_WORKS.length
    ? '<p class=meta>No titles match the current type filter.</p>'
    : '<p class=meta>Nothing here. Use "Add ADF"/"Upload folder" above, or drag ADFs onto the page.</p>');
  for (const w of works) {
    const div = document.createElement('div');
    div.className = 'edition';
    const counts = [];
    if (w.game_count) counts.push(w.game_count + ' game');
    if (w.demo_count) counts.push(w.demo_count + ' demo');
    if (w.tool_count) counts.push(w.tool_count + ' tool');
    div.innerHTML = `<button class="card-head" aria-expanded="false">
        <span class="chevron">${ICON.chevron}</span>
        <span class="card-title">
          <span class="title-line">${esc(w.name)}</span>
          <span class="sub-line">${counts.join(' · ')}</span>
        </span>
        <span class="chips">${typeChips(w)}</span>
      </button>
      <div class="card-body variants"></div>`;
    const head = div.querySelector('.card-head');
    const box = div.querySelector('.variants');
    head.onclick = () => {
      const open = box.classList.toggle('open');
      head.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (box.dataset.loaded) return;
      box.innerHTML = renderWork(w);
      box.dataset.loaded = '1';
    };
    list.appendChild(div);
  }
}
// Segmented all/original/cracked/hacked filter: re-render from the fetched works.
function setType(t) {
  TYPE_FILTER = t;
  for (const b of document.querySelectorAll('.seg-btn')) b.classList.toggle('active', b.dataset.t === t);
  renderWorks();
}
// A Work expands to a version timeline for its game releases (one node per
// version, newest-first, year as a badge; language nests as rows), with demos
// and any other releases listed flat below.
function renderWork(w) {
  const games = w.releases.filter(r => r.category === 'game');
  const others = w.releases.filter(r => r.category !== 'game');
  let html = versionNodes(games).map(node => {
    const ver = node.hasVer ? esc(node.version || 'v?') : 'no version';
    const yr = node.year != null ? node.year : '19xx';
    return `<div class="vnode"><b>${ver}</b> <span class="vyear">·${yr}</span></div>`
      + node.rels.map(renderLangRow).join('');
  }).join('');
  if (others.length) {
    html += `<div class="demos-split">other releases</div>` + others.map(renderReleaseRow).join('');
  }
  return html;
}
// Group game releases into version nodes, ordered (year desc, version desc);
// version-less releases group by year and slot in inline, unknown year last.
function versionNodes(games) {
  const map = new Map();
  for (const r of games) {
    const hasVer = r.version_key != null && r.version_key !== '';
    const key = hasVer ? 'v:' + r.version_key : 'n:' + (r.year != null ? r.year : '');
    let node = map.get(key);
    if (!node) { node = { hasVer, vkey: r.version_key || '', version: r.version, year: null, rels: [] }; map.set(key, node); }
    node.rels.push(r);
    if (r.year != null && (node.year == null || r.year < node.year)) node.year = r.year;
    if (!node.version && r.version) node.version = r.version;
  }
  const nodes = [...map.values()];
  nodes.forEach(n => n.rels.sort((a, b) =>
    (a.language || '').localeCompare(b.language || '') || a.rep_edition_id - b.rep_edition_id));
  nodes.sort((a, b) => {
    if (a.year !== b.year) {
      if (a.year == null) return 1;
      if (b.year == null) return -1;
      return b.year - a.year;
    }
    if (a.hasVer !== b.hasVer) return a.hasVer ? -1 : 1;
    if (a.vkey !== b.vkey) return a.vkey < b.vkey ? 1 : -1;
    return 0;
  });
  return nodes;
}
// One language row under a version node: leads with language, then the coherent
// playable-sets picker (reused). A single no-number disk reads "disk".
function renderLangRow(r) {
  const bits = [];
  if (r.language) bits.push(r.language);
  if (r.qualifier) bits.push(esc(r.qualifier));
  if (r.publisher) bits.push(esc(r.publisher));
  const total = r.disk_count || r.disks_present.length;
  bits.push(total > 1 ? `${r.disks_present.length}/${total} disks` : 'disk');
  return `<div class="variant lang">
      <span style="cursor:pointer" onclick="togglePlayable(${r.rep_edition_id})">${bits.join(' · ')} ▸</span>
      <span class="meta">${r.complete_lineages} playable set(s)</span></div>
    <div class="variants" id="pl${r.rep_edition_id}"></div>`;
}
// A non-game release (demo/tool): a flat, directly-downloadable row.
function renderReleaseRow(r) {
  const bits = [];
  if (r.qualifier) bits.push(esc(r.qualifier));
  if (r.publisher) bits.push(esc(r.publisher));
  if (r.year) bits.push(r.year);
  if (r.version) bits.push(esc(r.version));
  if (r.language) bits.push(r.language);
  const meta = bits.length ? ' · ' + bits.join(' · ') : '';
  return `<div class="variant">
      <span><b>${esc(r.category)}</b>${meta}</span>
      <span class="meta">${r.variant_count} variant(s) · <a href="/export/edition/${r.rep_edition_id}">download</a></span></div>`;
}
async function togglePlayable(rep) {
  const box = document.getElementById('pl' + rep);
  box.classList.toggle('open');
  if (box.dataset.loaded) return;
  box.innerHTML = await renderPlayable(rep);
  box.dataset.loaded = '1';
}
async function renderPlayable(rep) {
  const { sets } = await (await fetch(`/api/sets/${rep}/playable`)).json();
  const rows = sets.map(s => {
    const name = s.lineage ? esc(s.lineage) : 'original';
    const star = s.is_recommended ? '★ ' : '';
    const badge = kindBadge(s.kind) + ' ';
    const tc = s.trainer ? ' ' + trainerChip(s.trainer) : '';
    if (!s.complete) {
      return `<div class="variant"><span style="opacity:.55">${badge}<code>${name}</code></span>
        <span class="meta s-rejected">missing disk ${s.missing_disks.join(',')}</span></div>`;
    }
    const enc = s.lineage ? encodeURIComponent(s.lineage) : '-';
    if (s.trainer_options && s.trainer_options.length) {
      const key = 'tr' + rep + '_' + (s.lineage || 'orig').replace(/[^A-Za-z0-9]/g, '');
      const opts = s.trainer_options.map(t =>
        `<option value="${esc(t.uid)}"${t.is_default ? ' selected' : ''}>${t.trainer ? esc(t.trainer) : 'no trainer'}</option>`).join('');
      return `<div class="variant"><span class="${s.is_recommended ? 'primary' : ''}">${star}${badge}<code>${name}</code>${tc} <select id="${key}">${opts}</select></span>
        <span class="meta"><span class="primary">complete</span> · <a href="#" onclick="downloadSet(${rep},'${enc}','${key}');return false">download set</a></span></div>`;
    }
    return `<div class="variant"><span class="${s.is_recommended ? 'primary' : ''}">${star}${badge}<code>${name}</code>${tc}</span>
      <span class="meta"><span class="primary">complete</span> · <a href="/export/set/${rep}/${enc}">download set</a></span></div>`;
  }).join('');
  return rows +
    `<div class="meta" style="margin-top:6px"><a href="#" onclick="toggleDisks(${rep});return false">inspect disks</a></div>` +
    `<div class="variants" id="disks${rep}"></div>`;
}
function downloadSet(rep, encLineage, selId) {
  const uid = document.getElementById(selId).value;
  window.location = `/export/set/${rep}/${encLineage}?boot=${encodeURIComponent(uid)}`;
}
async function toggleDisks(rep) {
  const box = document.getElementById('disks' + rep);
  box.classList.toggle('open');
  if (box.dataset.loaded) return;
  const { disks } = await (await fetch(`/api/sets/${rep}/lineages`)).json();
  box.innerHTML = (disks || []).map(d => `<div class="variant">
      <span style="cursor:pointer" onclick="expandDisk(${d.edition_id})">${d.disk_no ? 'Disk ' + d.disk_no : 'disk'} ▸</span>
      <span class="meta"><a href="/export/edition/${d.edition_id}">export disk</a></span></div>
    <div class="variants" id="dv${d.edition_id}"></div>`).join('');
  box.dataset.loaded = '1';
}
// alt_index → TOSEC-style badge: 0 = base dump, 1 = [a], n = [a{n}].
function altBadge(i) { return i === 0 ? 'base' : i === 1 ? '[a]' : `[a${i}]`; }
async function renderVariants(id) {
  const { variants } = await (await fetch(`/api/editions/${id}/variants`)).json();
  return variants.map(v => {
    const head = [v.dump_type || '?'];
    if (v.crack_group) head.push(esc(v.crack_group));
    head.push(altBadge(v.alt_index));
    if (v.verified) head.push('verified');
    const fp = [`crc ${v.crc32}`, `md5 ${(v.md5 || '').slice(0, 8)}…`];
    if (v.byte_len != null) fp.push(`${v.byte_len.toLocaleString()} B`);
    return `<div class="variant vcol">
      <div class="vrow"><span class="${v.is_primary ? 'primary' : ''}">${v.is_primary ? '★ ' : ''}<code>${esc(v.canonical_name)}</code></span>
        <span class="meta">${head.join(' · ')}</span></div>
      ${v.tosec_name ? `<div class="meta vsub"><code>${esc(v.tosec_name)}</code></div>` : ''}
      <div class="meta vsub">${fp.join(' · ')} · <a href="/download/${v.uid}">download</a></div>
    </div>`;
  }).join('');
}
async function expandDisk(ed) {
  const box = document.getElementById('dv' + ed);
  box.classList.toggle('open');
  if (box.dataset.loaded) return;
  box.innerHTML = await renderVariants(ed);
  box.dataset.loaded = '1';
}
async function loadQuarantine() {
  const r = await fetch('/api/quarantine');
  const { quarantine } = await r.json();
  const list = document.getElementById('list');
  list.innerHTML = '<h3>Quarantine</h3>' + (quarantine.length ? '' : '<p class=meta>Empty.</p>');
  for (const v of quarantine) {
    const div = document.createElement('div');
    div.className = 'edition';
    div.innerHTML = `<div class="meta"><code>${esc(v.uid)}</code> · ${esc(v.canonical_name)}
      · <a href="/download/${v.uid}">download</a></div>`;
    list.appendChild(div);
  }
}
async function reidentify() {
  const rep = await (await fetch('/api/reidentify', { method: 'POST' })).json();
  await load();
  const note = document.createElement('p');
  note.className = 'meta';
  note.textContent = `Re-identified — scanned ${rep.scanned}, moved ${rep.moved}, removed ${rep.editions_removed} edition(s) / ${rep.titles_removed} title(s).`;
  document.getElementById('list').prepend(note);
}
function esc(s){ return (s||'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// --- Upload: drag-and-drop + file/folder picker ---------------------------
const ALLOWED = ['.adf', '.adz', '.dms', '.zip'];
const hasExt = n => ALLOWED.some(e => n.toLowerCase().endsWith(e));
const OUT_LABELS = { stored: 'stored', duplicate: 'duplicate', quarantined: 'quarantined', rejected: 'rejected', error: 'error' };
const fmtCounts = (t, keys, sep) => keys.filter(k => t[k]).map(k => t[k] + ' ' + OUT_LABELS[k]).join(sep);

// Single source of truth for accepted types: drives the picker filter + hint.
document.getElementById('filePick').accept = ALLOWED.join(',');
document.getElementById('dropHint').textContent = '(' + ALLOWED.join(' ') + ' — folder drop needs Chromium/Firefox)';
for (const id of ['filePick', 'dirPick']) {
  document.getElementById(id).addEventListener('change', e => { uploadAll([...e.target.files]); e.target.value = ''; });
}

const overlay = document.getElementById('dropOverlay');
let dragDepth = 0;
const dragHasFiles = e => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
const resetDrag = () => { dragDepth = 0; overlay.classList.remove('show'); };
window.addEventListener('dragenter', e => { if (!dragHasFiles(e)) return; e.preventDefault(); dragDepth++; overlay.classList.add('show'); });
window.addEventListener('dragover', e => { if (dragHasFiles(e)) e.preventDefault(); });
window.addEventListener('dragleave', e => { if (!dragHasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) resetDrag(); });
window.addEventListener('dragend', resetDrag);
window.addEventListener('drop', async e => {
  if (!dragHasFiles(e)) return;
  e.preventDefault(); resetDrag();
  const { files, errors } = await filesFromDrop(e.dataTransfer);
  uploadAll(files, errors);
});
// A drag canceled with Esc fires no dragleave/drop in some browsers.
window.addEventListener('keydown', e => { if (e.key === 'Escape') resetDrag(); });

// Collect dropped files, recursing folders where the directory API exists.
// Unreadable files/dirs are surfaced as errors, not silently dropped.
async function filesFromDrop(dt) {
  const items = dt.items;
  const canDir = items && items.length && typeof items[0].webkitGetAsEntry === 'function';
  if (!canDir) return { files: [...dt.files], errors: [] };
  const files = [], errors = [], entries = [];
  for (const it of items) { const en = it.webkitGetAsEntry(); if (en) entries.push(en); }
  for (const en of entries) await walkEntry(en, files, errors);
  return { files, errors };
}
function walkEntry(entry, files, errors) {
  return new Promise(resolve => {
    if (entry.isFile) {
      entry.file(f => { files.push(f); resolve(); }, () => { errors.push(entry.fullPath || entry.name); resolve(); });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const readBatch = () => reader.readEntries(async ents => {
        if (!ents.length) { resolve(); return; }
        for (const e of ents) await walkEntry(e, files, errors);
        readBatch();
      }, () => { errors.push((entry.fullPath || entry.name) + '/'); resolve(); });
      readBatch();
    } else resolve();
  });
}

// Sequential upload via a single-worker queue, so overlapping batches append to
// one panel instead of clobbering each other's rows/summary.
let uQueue = [], uRunning = false, uRows = null, uTally = null;
function uploadAll(files, errorNames) {
  for (const name of errorNames || []) uQueue.push({ name, kind: 'error', status: 'unreadable' });
  for (const f of files || []) uQueue.push(hasExt(f.name) ? { file: f } : { name: f.name, kind: 'rejected', status: 'unsupported' });
  if (!uRunning && uQueue.length) runQueue();
}
async function runQueue() {
  uRunning = true;
  const panel = document.getElementById('uploadPanel');
  panel.hidden = false;
  // A progress bar for the bulk; rows are added only for files needing attention.
  panel.innerHTML = '<div class="u-head"><progress id="uBar" class="u-bar" value="0" max="1"></progress>'
    + '<span class="u-count" id="uCount"></span></div>'
    + '<div id="uRows"></div><div class="u-summary" id="uSummary">…</div>';
  uRows = document.getElementById('uRows');
  const uBar = document.getElementById('uBar');
  const uCount = document.getElementById('uCount');
  const uSummary = document.getElementById('uSummary');
  uTally = { stored: 0, duplicate: 0, quarantined: 0, rejected: 0, error: 0 };
  let processed = 0;
  // Progress is processed/total; total = done + still-queued, recomputed each step
  // so a batch that appends mid-run grows the denominator honestly.
  const setBar = (total) => {
    uBar.value = processed;
    uBar.max = Math.max(total, 1);
    uCount.textContent = `${processed} / ${total}`;
  };
  setBar(uQueue.length); // 0 / N before the first file
  while (uQueue.length) {
    const item = uQueue.shift();
    if (item.kind) {
      // Pre-classified unsupported/unreadable items are exceptions — always shown.
      uTally[item.kind]++;
      addRow(item.name, item.kind, item.status);
    } else {
      const f = item.file;
      try {
        const r = await fetch('/api/upload?filename=' + encodeURIComponent(f.name), { method: 'POST', body: f });
        if (!r.ok) {
          if (r.status >= 400 && r.status < 500) { uTally.rejected++; addRow(f.name, 'rejected', 'rejected'); }
          else { uTally.error++; addRow(f.name, 'error', 'error ' + r.status); }
        } else {
          const outs = (await r.json()).outcomes || [];
          const c = { stored: 0, duplicate: 0, quarantined: 0 };
          let bad = !outs.length; // empty response is not a success
          for (const o of outs) {
            if (o.kind === 'duplicate') c.duplicate++;
            else if (o.kind === 'stored') (o.quarantined ? c.quarantined++ : c.stored++);
            else bad = true; // unknown kind → not a success
          }
          // Count any real outcomes even if an unknown kind also appeared.
          uTally.stored += c.stored; uTally.duplicate += c.duplicate; uTally.quarantined += c.quarantined;
          // Only outcomes needing attention get a row; stored/duplicate advance the bar only.
          if (bad) { uTally.error++; addRow(f.name, 'error', 'unexpected response'); }
          else if (c.quarantined) {
            addRow(f.name, 'quarantined', outs.length > 1 ? fmtCounts(c, ['stored', 'duplicate', 'quarantined'], ', ') : 'quarantined');
          }
        }
      } catch (err) { uTally.error++; addRow(f.name, 'error', 'error'); }
    }
    processed++;
    setBar(processed + uQueue.length); // advance as each file completes
  }
  const summary = fmtCounts(uTally, ['stored', 'duplicate', 'quarantined', 'rejected', 'error'], ' · ') || 'nothing to upload';
  uSummary.innerHTML = 'Done — ' + summary +
    (uTally.quarantined ? ' · <a href="#" onclick="loadQuarantine();return false">review quarantine</a>' : '');
  uRunning = false;
  load(); // refresh the Edition listing once, after the queue drains
}
function addRow(name, cls, status) {
  const div = document.createElement('div');
  div.className = 'u-row';
  div.innerHTML = `<span class="u-name">${esc(name)}</span><span class="u-status s-${cls}">${esc(status)}</span>`;
  uRows.appendChild(div);
  return div;
}
initIcons();
load();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_builds_without_panicking() {
        // Constructing the Router panics if any route uses invalid capture
        // syntax (e.g. axum 0.7 `:id` vs 0.8 `{id}`). This guards a class of
        // failure the handler tests never exercise.
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_memory(dir.path()).unwrap();
        let _router = router(Arc::new(Mutex::new(vault)));
    }

    #[test]
    fn index_html_surfaces_type_badges_and_preserves_features() {
        // The redesign's type surfacing (summary chips, per-lineage badge, trainer
        // chip, segmented filter) and every preserved surface are in the served UI.
        for marker in [
            "typeChips",        // per-Work summary chips
            "kindBadge",        // per-lineage type badge
            "trainerChip",      // "+N TRAINER" chip
            "seg-btn",          // segmented type filter
            "setType(",         // filter behaviour
            "renderPlayable",   // playable multi-disk sets preserved
            "renderVariants",   // per-variant fingerprint inspect preserved
            "loadQuarantine",   // quarantine preserved
            "reidentify",       // re-identify preserved
            "filesFromDrop",    // drag-drop upload preserved
            "class=\"legend\"", // original/cracked/hacked legend
            "--original",
            "--cracked",
            "--hacked",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "served index missing `{marker}`"
            );
        }
    }

    #[test]
    fn index_html_upload_uses_progress_bar_with_exceptions_only() {
        // The upload panel drives a <progress> bar + processed/total counter...
        for marker in [
            "<progress", // the bar element
            "class=\"u-bar\"",
            "id=\"uCount\"", // the processed/total counter
            "setBar(",       // the bar update
            "review quarantine",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "served index missing `{marker}`"
            );
        }
        // ...and only exception outcomes render a row: successes advance the bar
        // without a pending row, so the old pending-row machinery is gone.
        assert!(
            !INDEX_HTML.contains("'pending'"),
            "upload should no longer create pending rows"
        );
        assert!(
            !INDEX_HTML.contains("function setRow"),
            "setRow is orphaned once rows are added only on the final outcome"
        );
    }

    #[test]
    fn index_html_is_self_contained() {
        // No external/CDN dependency: styles, scripts, icons and fonts are inline
        // or served locally, so the binary embeds the entire UI.
        for forbidden in ["http://", "https://", "cdn.", "<script src", "<link "] {
            assert!(
                !INDEX_HTML.contains(forbidden),
                "served index has an external reference: `{forbidden}`"
            );
        }
    }
}
