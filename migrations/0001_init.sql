-- Copyright 2026 Ronny Trommer <ronny@no42.org>
-- SPDX-License-Identifier: MIT

-- Title: the logical work (a game, tool, or demo).
CREATE TABLE IF NOT EXISTS title (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'game',   -- game | tool | demo
    UNIQUE (name, category)
);

-- Edition: the dedup grouping key. Scene flags (crack/trainer/hack/dump) are
-- stripped from this key; version, language, publisher, and disk number are kept.
CREATE TABLE IF NOT EXISTS edition (
    id                   INTEGER PRIMARY KEY,
    title_id             INTEGER NOT NULL REFERENCES title(id),
    version              TEXT,
    language             TEXT,
    publisher            TEXT,
    disk_no              INTEGER,
    disk_count           INTEGER,
    primary_artifact_uid TEXT,
    UNIQUE (title_id, version, language, publisher, disk_no, disk_count)
);

-- Artifact: the specific bytes held, keyed by content-derived UID (sha1[:10]).
CREATE TABLE IF NOT EXISTS artifact (
    uid           TEXT PRIMARY KEY,          -- sha1[:10] (extended on prefix collision)
    sha1          TEXT NOT NULL UNIQUE,       -- full sha1 of the raw ADF
    crc32         TEXT NOT NULL,
    md5           TEXT NOT NULL,
    edition_id    INTEGER REFERENCES edition(id),
    display_title TEXT,
    year          INTEGER,
    dump_type     TEXT,                       -- original | cracked | hacked | modified | trainer
    crack_group   TEXT,
    trainer       TEXT,
    bad           INTEGER NOT NULL DEFAULT 0,
    virus         INTEGER NOT NULL DEFAULT 0,
    over          INTEGER NOT NULL DEFAULT 0,
    under         INTEGER NOT NULL DEFAULT 0,
    alt_index     INTEGER NOT NULL DEFAULT 0, -- 0 = base dump, 1 = [a], 2 = [a2], ...
    modifications INTEGER NOT NULL DEFAULT 0, -- count of cr/h/f/m/t flags (ranking input)
    verified_good INTEGER NOT NULL DEFAULT 0, -- [!] verified-good marker (ranking input)
    lineage       TEXT,                       -- crack lineage tag for multi-disk coherence
    verified      INTEGER NOT NULL DEFAULT 0, -- 1 = hash-matched a DAT, 0 = name-parsed only
    tosec_name    TEXT,                       -- original TOSEC name, kept for interop/export
    orig_filename TEXT,
    container     TEXT NOT NULL DEFAULT 'adf',-- adf | adz | dms | zip
    decoded_sha1  TEXT,                        -- sha1 of decoded ADF when from a container
    blob_sha1     TEXT NOT NULL               -- key into the content-addressed blob store
);

CREATE INDEX IF NOT EXISTS idx_artifact_edition ON artifact(edition_id);
CREATE INDEX IF NOT EXISTS idx_artifact_crc32   ON artifact(crc32);

-- InnerFile: per-artifact filesystem contents, for the deferred fuzzy matcher.
CREATE TABLE IF NOT EXISTS inner_file (
    id           INTEGER PRIMARY KEY,
    artifact_uid TEXT NOT NULL REFERENCES artifact(uid),
    path         TEXT NOT NULL,
    size         INTEGER NOT NULL,
    sha1         TEXT NOT NULL
);

-- DatSource / entries: imported reference database records (TOSEC, WHDLoad).
CREATE TABLE IF NOT EXISTS dat_entry (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,               -- e.g. TOSEC, WHDLoad
    name        TEXT NOT NULL,               -- canonical (TOSEC) name
    sha1        TEXT,
    crc32       TEXT,
    md5         TEXT,
    title       TEXT,
    version     TEXT,
    language    TEXT,
    publisher   TEXT,
    year        INTEGER,
    disk_no     INTEGER,
    disk_count  INTEGER,
    dump_type   TEXT,
    crack_group TEXT
);

CREATE INDEX IF NOT EXISTS idx_dat_sha1  ON dat_entry(sha1);
CREATE INDEX IF NOT EXISTS idx_dat_crc32 ON dat_entry(crc32);

-- Quarantine: artifacts with no assigned canonical identity, awaiting manual tag.
CREATE TABLE IF NOT EXISTS quarantine (
    artifact_uid TEXT PRIMARY KEY REFERENCES artifact(uid),
    reason       TEXT NOT NULL
);
