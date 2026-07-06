-- Copyright 2026 Ronny Trommer <ronny@no42.org>
-- SPDX-License-Identifier: MIT

-- Distinguish a title's stored images: 'cover' (front box art, one per title,
-- drives the browse grid) from 'screenshot' (gameplay, the detail strip).
-- Applied by Db::migrate only when the column is absent (ALTER is not idempotent);
-- pre-existing rows were all screenshots, so 'screenshot' is the correct default.
ALTER TABLE title_screenshot ADD COLUMN kind TEXT NOT NULL DEFAULT 'screenshot';
