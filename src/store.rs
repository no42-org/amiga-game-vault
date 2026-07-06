/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Content-addressed blob store.
//!
//! Bytes are stored under their full SHA1, sharded two levels deep
//! (`<root>/ab/cd/<sha1>`). Because the path is derived from content, writing the
//! same bytes twice is idempotent — which is exactly what makes exact
//! deduplication automatic: identical uploads resolve to one blob.

use std::fs;
use std::path::{Path, PathBuf};

use crate::identity::{hash_bytes, Hashes};
use crate::Result;

/// A content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open (creating if needed) a blob store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The on-disk path for a given SHA1 (whether or not it exists yet).
    pub fn path_for(&self, sha1: &str) -> PathBuf {
        let (a, b) = (&sha1[0..2], &sha1[2..4]);
        self.root.join(a).join(b).join(sha1)
    }

    /// True if a blob with this SHA1 is already stored.
    pub fn exists(&self, sha1: &str) -> bool {
        self.path_for(sha1).is_file()
    }

    /// Store `bytes`, returning their hashes. Idempotent: identical bytes are
    /// written once. Returns `(hashes, is_new)`.
    pub fn put(&self, bytes: &[u8]) -> Result<(Hashes, bool)> {
        let hashes = hash_bytes(bytes);
        let path = self.path_for(&hashes.sha1);
        if path.is_file() {
            return Ok((hashes, false));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
        Ok((hashes, true))
    }

    /// Read the bytes of a stored blob.
    pub fn get(&self, sha1: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.path_for(sha1))?)
    }

    /// The byte size of a stored blob, from a filesystem stat — without reading
    /// its contents into memory.
    pub fn byte_len(&self, sha1: &str) -> Result<u64> {
        Ok(fs::metadata(self.path_for(sha1))?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_is_idempotent_for_identical_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();

        let (h1, new1) = store.put(b"the same disk bytes").unwrap();
        assert!(new1, "first write is new");
        let (h2, new2) = store.put(b"the same disk bytes").unwrap();
        assert!(!new2, "second identical write is not new");
        assert_eq!(h1, h2);

        assert!(store.exists(&h1.sha1));
        assert_eq!(store.get(&h1.sha1).unwrap(), b"the same disk bytes");
    }

    #[test]
    fn distinct_bytes_distinct_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let (a, _) = store.put(b"disk one").unwrap();
        let (b, _) = store.put(b"disk two").unwrap();
        assert_ne!(a.sha1, b.sha1);
        assert!(store.exists(&a.sha1) && store.exists(&b.sha1));
    }
}
