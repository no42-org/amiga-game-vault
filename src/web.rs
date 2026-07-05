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
        .route("/api/sets", get(sets))
        .route("/api/sets/{id}/lineages", get(set_lineages))
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

async fn export_set(
    State(state): State<AppState>,
    Path((id, lineage)): Path<(i64, String)>,
) -> Result<Response, AppErr> {
    let files = {
        let v = lock(&state);
        v.export_set(id, &lineage)?
    };
    let safe: String = lineage
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
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
<title>Amiga Game Vault</title>
<style>
  :root { color-scheme: dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 0; background: #14161a; color: #e6e8ec; }
  header { display: flex; align-items: center; gap: 12px; padding: 10px 20px;
    background: #1c1f26; border-bottom: 1px solid #2a2e37; }
  header .logo { height: 40px; width: auto; display: block; }
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
  .upload-panel { border: 1px solid #2a2e37; border-radius: 8px; margin: 8px 0 16px;
    padding: 10px 12px; background: #191c22; }
  .upload-panel h3 { margin: 0 0 8px; font-size: 13px; }
  .u-row { display: flex; justify-content: space-between; gap: 12px; padding: 3px 0;
    border-top: 1px solid #23262d; font-size: 12px; }
  .u-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .u-status { flex: none; }
  .s-stored { color: #7ee081; }
  .s-duplicate { color: #9aa0aa; }
  .s-quarantined { color: #e0c56e; }
  .s-rejected { color: #e08a6e; }
  .s-error { color: #e06e6e; }
  .s-pending { color: #6b7280; }
  .u-summary { margin-top: 8px; font-size: 12px; color: #c8cdd6; }
  .drop-overlay { position: fixed; inset: 0; display: none; align-items: center;
    justify-content: center; text-align: center; padding: 20px; z-index: 50;
    background: rgba(20,22,26,0.85); border: 3px dashed #6db3f2; color: #e6e8ec; font-size: 20px; }
  .drop-overlay.show { display: flex; }
</style>
</head>
<body>
<header>
  <img src="/logo.png" alt="Amiga Game Vault logo" class="logo">
  <h1>Amiga Game Vault</h1>
</header>
<main>
  <div class="controls">
    <input id="q" placeholder="search title…">
    <select id="category"><option value="">all categories</option>
      <option>game</option><option>tool</option><option>demo</option></select>
    <input id="language" placeholder="lang (en, es…)" size="8">
    <select id="status"><option value="">all sets</option>
      <option value="incomplete">incomplete sets</option></select>
    <button onclick="load()">Search</button>
    <a href="#" onclick="loadQuarantine();return false">Quarantine</a>
    <a href="#" onclick="reidentify();return false">Re-identify</a>
    <span style="flex:1"></span>
    <button onclick="document.getElementById('filePick').click()">Upload files</button>
    <button onclick="document.getElementById('dirPick').click()">Upload folder</button>
  </div>
  <input id="filePick" type="file" multiple hidden>
  <input id="dirPick" type="file" webkitdirectory multiple hidden>
  <div id="uploadPanel" class="upload-panel" hidden></div>
  <div id="list"></div>
</main>
<div id="dropOverlay" class="drop-overlay">Drop ADF files or a folder to upload
  <span class="meta" id="dropHint"></span></div>
<script>
async function load() {
  const p = new URLSearchParams();
  for (const k of ['q','category','language','status']) {
    const val = document.getElementById(k).value.trim();
    if (val) p.set(k, val);
  }
  const { sets } = await (await fetch('/api/sets?' + p)).json();
  const list = document.getElementById('list');
  list.innerHTML = sets.length ? '' : '<p class=meta>Nothing here. Use "Upload files"/"Upload folder" above, or drag ADFs onto the page.</p>';
  for (const s of sets) {
    const div = document.createElement('div');
    div.className = 'edition';
    const bits = [s.category];
    if (s.qualifier) bits.push(esc(s.qualifier));
    if (s.publisher) bits.push(esc(s.publisher));
    if (s.year) bits.push(s.year);
    if (s.language) bits.push(s.language);
    let sub;
    if (s.multi) {
      const have = s.disks_present.length, need = s.disk_count || have;
      bits.push(`${have}/${need} disks`);
      sub = s.complete_lineages > 0
        ? `<span class="primary">${s.complete_lineages} complete set(s)</span>` + (s.primary_lineage ? ` · ★ ${esc(s.primary_lineage)}` : '')
        : `<span class="s-rejected">no complete set — missing a disk</span>`;
    } else {
      sub = `${s.variant_count} variant(s) · <a href="/export/edition/${s.rep_edition_id}">export</a>`;
    }
    div.innerHTML = `<div class="title">${esc(s.title)} <span class="meta">${bits.join(' · ')}</span></div>
      <div class="meta">${sub}</div>
      <div class="variants" id="v${s.rep_edition_id}"></div>`;
    div.querySelector('.title').style.cursor = 'pointer';
    div.querySelector('.title').onclick = () => toggle(s.rep_edition_id, s.multi);
    list.appendChild(div);
  }
}
async function toggle(id, multi) {
  const box = document.getElementById('v' + id);
  box.classList.toggle('open');
  if (box.dataset.loaded) return;
  box.innerHTML = multi ? await renderLineages(id) : await renderVariants(id);
  box.dataset.loaded = '1';
}
async function renderVariants(id) {
  const { variants } = await (await fetch(`/api/editions/${id}/variants`)).json();
  return variants.map(v => `<div class="variant">
      <span class="${v.is_primary ? 'primary' : ''}">${v.is_primary ? '★ ' : ''}<code>${esc(v.canonical_name)}</code></span>
      <span class="meta">${v.dump_type || '?'}${v.crack_group ? ' · ' + esc(v.crack_group) : ''}${v.verified ? ' · verified' : ''}
        · <a href="/download/${v.uid}">download</a></span></div>`).join('');
}
async function renderLineages(id) {
  const { lineages, disks } = await (await fetch(`/api/sets/${id}/lineages`)).json();
  // Disks section — always reachable, even when no lineage is complete.
  const diskRows = (disks || []).map(d => `<div class="variant">
      <span style="cursor:pointer" onclick="expandDisk(${d.edition_id})">Disk ${d.disk_no} ▸</span>
      <span class="meta"><a href="/export/edition/${d.edition_id}">export disk</a></span></div>
    <div class="variants" id="dv${d.edition_id}"></div>`).join('');
  const linRows = lineages.map(l => {
    const name = l.lineage ? esc(l.lineage) : '(no group)';
    const badge = l.complete
      ? '<span class="primary">complete</span>'
      : `<span class="s-rejected">disks ${l.disks_covered.join(',')}</span>`;
    const exp = (l.complete && l.lineage)
      ? ` · <a href="/export/set/${id}/${encodeURIComponent(l.lineage)}">export set</a>` : '';
    return `<div class="variant">
      <span class="${l.is_primary ? 'primary' : ''}">${l.is_primary ? '★ ' : ''}<code>${name}</code></span>
      <span class="meta">${badge}${exp}</span></div>`;
  }).join('');
  return `<div class="meta" style="margin:2px 0">Disks</div>${diskRows}` +
    `<div class="meta" style="margin:6px 0 2px">Coherent sets</div>${linRows}`;
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
  panel.innerHTML = '<h3 id="uHead"></h3><div id="uRows"></div><div class="u-summary" id="uSummary">…</div>';
  uRows = document.getElementById('uRows');
  const uHead = document.getElementById('uHead');
  const uSummary = document.getElementById('uSummary');
  uTally = { stored: 0, duplicate: 0, quarantined: 0, rejected: 0, error: 0 };
  let done = 0;
  while (uQueue.length) {
    const item = uQueue.shift();
    done++;
    uHead.textContent = `Uploading ${done + uQueue.length} file(s)`;
    if (item.kind) { uTally[item.kind]++; addRow(item.name, item.kind, item.status); continue; }
    const f = item.file;
    const row = addRow(f.name, 'pending', '…');
    try {
      const r = await fetch('/api/upload?filename=' + encodeURIComponent(f.name), { method: 'POST', body: f });
      if (!r.ok) {
        if (r.status >= 400 && r.status < 500) { uTally.rejected++; setRow(row, 'rejected', 'rejected'); }
        else { uTally.error++; setRow(row, 'error', 'error ' + r.status); }
        continue;
      }
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
      if (bad) { uTally.error++; setRow(row, 'error', 'unexpected response'); continue; }
      const cls = c.quarantined ? 'quarantined' : c.stored ? 'stored' : 'duplicate';
      setRow(row, cls, outs.length > 1 ? fmtCounts(c, ['stored', 'duplicate', 'quarantined'], ', ') : cls);
    } catch (err) { uTally.error++; setRow(row, 'error', 'error'); }
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
function setRow(row, cls, status) {
  const s = row.querySelector('.u-status');
  s.className = 'u-status s-' + cls;
  s.textContent = status;
}
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
}
