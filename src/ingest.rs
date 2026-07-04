/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Container decoding and the ingest pipeline.
//!
//! Uploads arrive as raw `.adf` or as containers (`.adz` gzip, `.dms` DiskMasher,
//! `.zip`). The [`DiskImage`] trait is the "Path C" subprocess boundary: raw
//! formats are handled in-process, while `.dms` decoding and filesystem walking
//! are delegated to external tools and degrade gracefully when those are absent.

use std::io::Read;

use crate::error::Error;
use crate::identity::{hash_bytes, Hashes};
use crate::Result;

/// A recognized upload container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Adf,
    Adz,
    Dms,
    Zip,
}

impl Container {
    pub fn as_str(&self) -> &'static str {
        match self {
            Container::Adf => "adf",
            Container::Adz => "adz",
            Container::Dms => "dms",
            Container::Zip => "zip",
        }
    }
}

/// One raw ADF produced by decoding an upload.
#[derive(Debug, Clone)]
pub struct DecodedAdf {
    /// Raw ADF bytes.
    pub adf: Vec<u8>,
    /// The top-level container the upload arrived in.
    pub container: Container,
    /// A per-image name (the entry name for zips, else the upload filename).
    pub name: String,
}

/// A file entry found inside an ADF filesystem (for the deferred fuzzy matcher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerFile {
    pub path: String,
    pub size: u64,
    pub sha1: String,
}

/// The subprocess boundary: decode containers, hash, and walk filesystems.
pub trait DiskImage {
    /// Decode a container's bytes into one or more raw ADFs.
    fn decode(&self, container: Container, bytes: &[u8], name: &str) -> Result<Vec<DecodedAdf>>;
    /// Compute the content hashes of a raw ADF.
    fn hash(&self, adf: &[u8]) -> Hashes;
    /// Walk an ADF's filesystem via an external tool; empty when unavailable.
    fn walk_files(&self, adf: &[u8]) -> Result<Vec<InnerFile>>;
}

/// Detect the container of an upload from its filename extension and magic bytes.
pub fn detect_container(filename: &str, bytes: &[u8]) -> Result<Container> {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    let is_gzip = bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
    let is_zip = bytes.len() >= 2 && &bytes[0..2] == b"PK";
    let is_dms = bytes.len() >= 4 && &bytes[0..4] == b"DMS!";

    match ext.as_str() {
        "adf" => Ok(Container::Adf),
        "adz" => Ok(Container::Adz),
        "dms" => Ok(Container::Dms),
        "zip" => Ok(Container::Zip),
        _ if is_gzip => Ok(Container::Adz),
        _ if is_zip => Ok(Container::Zip),
        _ if is_dms => Ok(Container::Dms),
        // A raw ADF is a headerless sector dump; accept the standard DD size.
        _ if bytes.len() == 901_120 => Ok(Container::Adf),
        other => Err(Error::UnsupportedType(format!(
            "{other:?} ({} bytes)",
            bytes.len()
        ))),
    }
}

/// Gunzip `.adz` bytes into a raw ADF.
fn gunzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .map_err(|e| Error::Decode(format!("adz gunzip failed: {e}")))?;
    Ok(out)
}

/// The default [`DiskImage`] implementation: in-process for raw/gzip/zip,
/// subprocess (`xdms`, `xdftool`) for DMS and filesystem walking.
#[derive(Debug, Default, Clone)]
pub struct Tools;

impl DiskImage for Tools {
    fn decode(&self, container: Container, bytes: &[u8], name: &str) -> Result<Vec<DecodedAdf>> {
        match container {
            Container::Adf => Ok(vec![DecodedAdf {
                adf: bytes.to_vec(),
                container,
                name: name.to_string(),
            }]),
            Container::Adz => Ok(vec![DecodedAdf {
                adf: gunzip(bytes)?,
                container,
                name: name.to_string(),
            }]),
            Container::Dms => Ok(vec![DecodedAdf {
                adf: decode_dms(bytes)?,
                container,
                name: name.to_string(),
            }]),
            Container::Zip => decode_zip(bytes),
        }
    }

    fn hash(&self, adf: &[u8]) -> Hashes {
        hash_bytes(adf)
    }

    fn walk_files(&self, adf: &[u8]) -> Result<Vec<InnerFile>> {
        walk_with_xdftool(adf)
    }
}

/// Expand a zip archive, decoding each ADF/ADZ entry to a raw ADF.
fn decode_zip(bytes: &[u8]) -> Result<Vec<DecodedAdf>> {
    let reader = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(reader)?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if !entry.is_file() {
            continue;
        }
        let entry_name = entry.name().to_string();
        let lower = entry_name.to_ascii_lowercase();
        let mut data = Vec::new();
        if lower.ends_with(".adf") {
            entry.read_to_end(&mut data)?;
            out.push(DecodedAdf {
                adf: data,
                container: Container::Zip,
                name: entry_name,
            });
        } else if lower.ends_with(".adz") {
            entry.read_to_end(&mut data)?;
            out.push(DecodedAdf {
                adf: gunzip(&data)?,
                container: Container::Zip,
                name: entry_name,
            });
        }
    }
    if out.is_empty() {
        return Err(Error::Decode("zip archive contained no ADF files".into()));
    }
    Ok(out)
}

/// Decode a `.dms` (DiskMasher) archive via the external `xdms` tool.
///
/// Preserving the original container is the caller's job; this only produces the
/// raw ADF. Returns a clear error if `xdms` is not installed.
fn decode_dms(bytes: &[u8]) -> Result<Vec<u8>> {
    use std::process::Command;

    let dir = tempfile::tempdir()?;
    let dms_path = dir.path().join("input.dms");
    std::fs::write(&dms_path, bytes)?;

    let status = Command::new("xdms")
        .arg("u")
        .arg(&dms_path)
        .current_dir(dir.path())
        .status();

    match status {
        Ok(s) if s.success() => {
            // xdms writes input.adf alongside the .dms.
            let adf_path = dir.path().join("input.adf");
            std::fs::read(&adf_path)
                .map_err(|e| Error::Decode(format!("xdms produced no readable ADF: {e}")))
        }
        Ok(s) => Err(Error::Decode(format!("xdms exited with status {s}"))),
        Err(e) => Err(Error::Decode(format!(
            "xdms not available to decode .dms ({e}); install xdms to ingest DiskMasher archives"
        ))),
    }
}

/// Walk an ADF filesystem via `xdftool`. Returns an empty list (not an error)
/// when the tool is absent, so ingestion still succeeds without it.
fn walk_with_xdftool(adf: &[u8]) -> Result<Vec<InnerFile>> {
    use std::process::Command;

    let dir = tempfile::tempdir()?;
    let adf_path = dir.path().join("image.adf");
    std::fs::write(&adf_path, adf)?;

    // `xdftool <image> list` prints the directory tree; absence/errors -> empty.
    let output = Command::new("xdftool").arg(&adf_path).arg("list").output();
    let Ok(out) = output else {
        return Ok(Vec::new());
    };
    if !out.status.success() {
        return Ok(Vec::new());
    }
    // Parsing xdftool's listing is deferred with the fuzzy matcher; for now we
    // record only that a walk was possible. Inner-file extraction lands in a
    // later change.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detect_by_extension_and_magic() {
        assert_eq!(
            detect_container("x.adf", &[0u8; 10]).unwrap(),
            Container::Adf
        );
        assert_eq!(
            detect_container("x.adz", &[0x1f, 0x8b, 0, 0]).unwrap(),
            Container::Adz
        );
        assert_eq!(
            detect_container("x.dms", b"DMS!....").unwrap(),
            Container::Dms
        );
        assert_eq!(
            detect_container("x.zip", b"PK\x03\x04").unwrap(),
            Container::Zip
        );
        // Magic wins when the extension is unknown.
        assert_eq!(
            detect_container("mystery", &[0x1f, 0x8b]).unwrap(),
            Container::Adz
        );
        assert!(detect_container("mystery.txt", b"hello").is_err());
    }

    #[test]
    fn decode_raw_adf_passthrough() {
        let tools = Tools;
        let out = tools
            .decode(Container::Adf, b"raw-adf-bytes", "Game.adf")
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].adf, b"raw-adf-bytes");
        assert_eq!(out[0].container, Container::Adf);
    }

    #[test]
    fn decode_adz_gunzips() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"decoded adf payload").unwrap();
        let gz = enc.finish().unwrap();

        let tools = Tools;
        let out = tools.decode(Container::Adz, &gz, "Game.adz").unwrap();
        assert_eq!(out[0].adf, b"decoded adf payload");
        assert_eq!(out[0].container, Container::Adz);
    }

    #[test]
    fn decode_zip_extracts_adf_entries() {
        // Build an in-memory zip with one .adf and one ignored .txt.
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::FileOptions = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("A-10.adf", opts).unwrap();
            zw.write_all(b"adf-in-zip").unwrap();
            zw.start_file("readme.txt", opts).unwrap();
            zw.write_all(b"ignore me").unwrap();
            zw.finish().unwrap();
        }
        let tools = Tools;
        let out = tools.decode(Container::Zip, &buf, "pack.zip").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].adf, b"adf-in-zip");
        assert_eq!(out[0].name, "A-10.adf");
    }
}
