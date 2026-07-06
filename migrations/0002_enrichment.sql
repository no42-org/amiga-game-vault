-- Copyright 2026 Ronny Trommer <ronny@no42.org>
-- SPDX-License-Identifier: MIT

-- Enrichment: editorial metadata for a logical work, pulled from online Amiga
-- libraries and merged across providers. Attaches to `title` (the work), not to
-- any one dumped variant, so it applies to every crack/language/disk underneath.

-- Merged editorial metadata for a title. One row per title.
CREATE TABLE IF NOT EXISTS title_meta (
    title_id     INTEGER PRIMARY KEY REFERENCES title(id) ON DELETE CASCADE,
    genre        TEXT,
    description  TEXT,
    year         INTEGER,
    sources      TEXT,          -- comma-joined providers that contributed
    external_url TEXT,          -- canonical page on the winning provider
    match_score  REAL,          -- fuzzy score of the accepted match (0..1)
    fetched_at   INTEGER        -- unix seconds
);

-- Screenshots for a title; bytes live in the content-addressed BlobStore keyed
-- by sha1 (reuses store.put), so identical images dedupe for free.
CREATE TABLE IF NOT EXISTS title_screenshot (
    id        INTEGER PRIMARY KEY,
    title_id  INTEGER NOT NULL REFERENCES title(id) ON DELETE CASCADE,
    blob_sha1 TEXT NOT NULL,    -- key into BlobStore
    mime      TEXT NOT NULL,    -- e.g. image/png, image/jpeg
    caption   TEXT,
    source    TEXT NOT NULL,    -- provenance of this image
    ord       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_shot_title ON title_screenshot(title_id);
