/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Amiga Game Vault: a self-hosted ROM manager for ADF disk images.
//!
//! The crate is organized around a small set of composable pieces:
//! - [`identity`]: content hashing and the content-derived UID.
//! - [`naming`]: TOSEC filename parsing, title sanitization, and the canonical
//!   filename schema (`Title-Kebab_vVer_lang_dNNofMM_uid.adf`).
//! - [`edition`]: the Title -> Edition -> Artifact identity model and dump flags.
//! - [`ranking`]: non-destructive primary selection within an Edition.
//! - [`store`]: the content-addressed blob store.
//! - [`dat`]: reference DAT import and hash lookup.
//! - [`ingest`]: container decoding and the ingest pipeline.
//! - [`db`] / [`service`] / [`web`]: persistence, orchestration, and the HTTP layer.

pub mod dat;
pub mod db;
pub mod edition;
pub mod error;
pub mod identity;
pub mod ingest;
pub mod naming;
pub mod ranking;
pub mod service;
pub mod store;
pub mod web;

pub use error::{Error, Result};
