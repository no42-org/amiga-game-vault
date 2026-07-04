/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Content hashing and the content-derived UID.
//!
//! Every stored ADF is identified by the SHA1, CRC32 and MD5 of its bytes. The
//! public, human-facing identity is `uid = sha1[:10]` — portable, self-verifying,
//! and the same key used for exact deduplication.

use md5::Md5;
use sha1::{Digest, Sha1};

/// The default display length of a UID (hex characters of the SHA1 prefix).
pub const UID_LEN: usize = 10;

/// The three content hashes of an artifact, as lowercase hex strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hashes {
    pub sha1: String,
    pub crc32: String,
    pub md5: String,
}

impl Hashes {
    /// The default display UID: the first [`UID_LEN`] hex chars of the SHA1.
    pub fn uid(&self) -> String {
        uid_from_sha1(&self.sha1, UID_LEN)
    }
}

/// Compute the SHA1, CRC32 and MD5 of `bytes`.
pub fn hash_bytes(bytes: &[u8]) -> Hashes {
    let sha1 = {
        let mut h = Sha1::new();
        h.update(bytes);
        hex::encode(h.finalize())
    };
    let md5 = {
        let mut h = Md5::new();
        h.update(bytes);
        hex::encode(h.finalize())
    };
    let crc32 = format!("{:08x}", crc32fast::hash(bytes));
    Hashes { sha1, crc32, md5 }
}

/// Derive a UID of `len` hex chars from a full SHA1 hex string.
pub fn uid_from_sha1(sha1: &str, len: usize) -> String {
    let len = len.min(sha1.len());
    sha1[..len].to_string()
}

/// Resolve a unique UID for `sha1` given the prefixes already in use.
///
/// Starts at [`UID_LEN`] and extends the prefix one hex char at a time until it
/// no longer collides with a *different* SHA1. `existing` maps an in-use UID to
/// the full SHA1 that owns it; a UID already owned by `sha1` is not a collision.
pub fn unique_uid<'a, F>(sha1: &str, mut owner_of: F) -> String
where
    F: FnMut(&str) -> Option<&'a str>,
{
    let mut len = UID_LEN;
    loop {
        let candidate = uid_from_sha1(sha1, len);
        match owner_of(&candidate) {
            Some(owner) if owner != sha1 => {
                if len >= sha1.len() {
                    // Full SHA1 collision is astronomically unlikely; return as-is.
                    return candidate;
                }
                len += 1;
            }
            _ => return candidate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn hashes_are_stable_and_hex() {
        let h = hash_bytes(b"amiga");
        // Deterministic: hashing the same bytes twice yields the same digests.
        assert_eq!(h, hash_bytes(b"amiga"));
        assert_eq!(h.sha1.len(), 40);
        assert_eq!(h.md5.len(), 32);
        assert_eq!(h.crc32.len(), 8);
        assert!(h.sha1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(h.md5.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(h.crc32.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn identical_bytes_same_uid() {
        let a = hash_bytes(b"the same disk");
        let b = hash_bytes(b"the same disk");
        assert_eq!(a.uid(), b.uid());
        assert_eq!(a.uid().len(), UID_LEN);
    }

    #[test]
    fn different_bytes_different_hash() {
        let a = hash_bytes(b"disk one");
        let b = hash_bytes(b"disk two");
        assert_ne!(a.sha1, b.sha1);
    }

    #[test]
    fn uid_extends_on_prefix_collision() {
        // Two distinct SHA1s that share the first UID_LEN chars.
        let sha_a = "abcdef0123456789000000000000000000000000";
        let sha_b = "abcdef0123999999999999999999999999999999";
        let mut owners: HashMap<String, String> = HashMap::new();

        let uid_a = unique_uid(sha_a, |u| owners.get(u).map(|s| s.as_str()));
        owners.insert(uid_a.clone(), sha_a.to_string());
        assert_eq!(uid_a, "abcdef0123");

        let uid_b = unique_uid(sha_b, |u| owners.get(u).map(|s| s.as_str()));
        owners.insert(uid_b.clone(), sha_b.to_string());
        // Must extend past the shared 10-char prefix.
        assert!(uid_b.len() > UID_LEN, "expected extension, got {uid_b}");
        assert_ne!(uid_a, uid_b);
    }

    #[test]
    fn uid_stable_for_same_sha() {
        let sha = "abcdef0123456789000000000000000000000000";
        let owners: HashMap<String, String> = [("abcdef0123".to_string(), sha.to_string())]
            .into_iter()
            .collect();
        // Same owner -> not a collision -> keeps the short form.
        let uid = unique_uid(sha, |u| owners.get(u).map(|s| s.as_str()));
        assert_eq!(uid, "abcdef0123");
    }
}
