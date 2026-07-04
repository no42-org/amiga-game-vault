/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Binary entry point: open the vault and serve the web app.

use std::sync::{Arc, Mutex};

use amiga_game_vault::service::Vault;
use amiga_game_vault::web;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::env::var("VAULT_DATA").unwrap_or_else(|_| "data".to_string());
    let addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let vault = Vault::open(&data_dir)?;
    let state = Arc::new(Mutex::new(vault));

    println!("Amiga Game Vault listening on http://{addr}  (data: {data_dir})");
    web::serve(state, &addr).await?;
    Ok(())
}
