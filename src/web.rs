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
        .route("/api/editions", get(editions))
        .route("/api/editions/:id/variants", get(variants))
        .route("/api/editions/:id/primary", post(set_primary))
        .route("/api/artifact/:uid", get(artifact))
        .route("/api/upload", post(upload))
        .route("/api/import-dat", post(import_dat))
        .route("/api/quarantine", get(quarantine))
        .route("/api/quarantine/:uid/resolve", post(resolve))
        .route("/download/:uid", get(download))
        .route("/export/edition/:id", get(export_edition))
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
        let opts: zip::write::FileOptions =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
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

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Amiga Game Vault</title>
<style>
  :root { color-scheme: dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 0; background: #14161a; color: #e6e8ec; }
  header { padding: 12px 20px; background: #1c1f26; border-bottom: 1px solid #2a2e37; }
  h1 { font-size: 16px; margin: 0; }
  main { padding: 16px 20px; max-width: 1000px; }
  input, select, button { font: inherit; padding: 6px 8px; background: #22262e; color: inherit;
    border: 1px solid #333; border-radius: 6px; }
  .controls { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .edition { border: 1px solid #2a2e37; border-radius: 8px; margin: 8px 0; padding: 10px 12px; }
  .edition .title { font-weight: 600; }
  .meta { color: #9aa0aa; font-size: 12px; }
  .variants { margin-top: 8px; display: none; }
  .variants.open { display: block; }
  .variant { padding: 4px 0; border-top: 1px solid #23262d; display: flex; justify-content: space-between; }
  .primary { color: #7ee081; }
  code { color: #c8cdd6; }
  a { color: #6db3f2; }
</style>
</head>
<body>
<header><h1>Amiga Game Vault</h1></header>
<main>
  <div class="controls">
    <input id="q" placeholder="search title…">
    <select id="category"><option value="">all categories</option>
      <option>game</option><option>tool</option><option>demo</option></select>
    <input id="language" placeholder="lang (en, es…)" size="8">
    <select id="status"><option value="">any status</option>
      <option value="verified">verified</option><option value="unverified">unverified</option></select>
    <button onclick="load()">Search</button>
    <a href="#" onclick="loadQuarantine();return false">Quarantine</a>
  </div>
  <div id="list"></div>
</main>
<script>
async function load() {
  const p = new URLSearchParams();
  for (const k of ['q','category','language','status']) {
    const val = document.getElementById(k).value.trim();
    if (val) p.set(k, val);
  }
  const r = await fetch('/api/editions?' + p);
  const { editions } = await r.json();
  const list = document.getElementById('list');
  list.innerHTML = editions.length ? '' : '<p class=meta>No editions yet. Upload ADFs via POST /api/upload.</p>';
  for (const e of editions) {
    const div = document.createElement('div');
    div.className = 'edition';
    const lang = e.language ? ' · ' + e.language : '';
    const disk = e.disk_no ? ` · disk ${e.disk_no} of ${e.disk_count}` : '';
    div.innerHTML = `<div class="title">${esc(e.title)} <span class="meta">${e.category}${lang}${disk}</span></div>
      <div class="meta">${e.variant_count} variant(s)` +
      (e.primary_uid ? ` · primary <code>${e.primary_uid}</code>` : '') +
      ` · <a href="/export/edition/${e.edition_id}">export</a></div>
      <div class="variants" id="v${e.edition_id}"></div>`;
    div.querySelector('.title').style.cursor = 'pointer';
    div.querySelector('.title').onclick = () => toggle(e.edition_id);
    list.appendChild(div);
  }
}
async function toggle(id) {
  const box = document.getElementById('v' + id);
  box.classList.toggle('open');
  if (box.dataset.loaded) return;
  const r = await fetch(`/api/editions/${id}/variants`);
  const { variants } = await r.json();
  box.innerHTML = variants.map(v => `<div class="variant">
      <span class="${v.is_primary ? 'primary' : ''}">${v.is_primary ? '★ ' : ''}<code>${esc(v.canonical_name)}</code></span>
      <span class="meta">${v.dump_type || '?'}${v.crack_group ? ' · ' + esc(v.crack_group) : ''}${v.verified ? ' · verified' : ''}
        · <a href="/download/${v.uid}">download</a></span></div>`).join('');
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
function esc(s){ return (s||'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
load();
</script>
</body>
</html>
"##;
