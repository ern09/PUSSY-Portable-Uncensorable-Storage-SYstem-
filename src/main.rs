/*
PUSSY — Portable Uncensorable Storage SYstem (on Nostr)
Rust CLI: encrypt+chunk files, store as Nostr events, retrieve+decrypt later.

====================================
Cargo.toml (put this in your project root)
====================================
[package]
name = "pussy"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
base64 = "0.22"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
rand = "0.8"
sha2 = "0.10"
# Crypto
aes-gcm = { version = "0.10", features = ["aes256"] }
scrypt = "0.11"
zeroize = "1"

# Nostr
nostr = "0.35"           # low-level types
nostr-sdk = { version = "0.35", default-features = false, features = ["all-nips", "blocking"] }
url = "2"

# Filesystem helpers
directories = "5"

------------------------------------
Project layout
------------------------------------
Cargo.toml
src/main.rs  ← (this file)

Build & run:
  cargo run -- init
  cargo run -- upload ./path/to/file --passphrase "secret" [--mime "application/octet-stream"]
  cargo run -- download <manifest-id-or-nevent> ./out.file --passphrase "secret"

Notes:
- AES-256-GCM with per-file random salt + IV; key from scrypt(passphrase, salt, N=2^15,r=8,p=1, dkLen=32).
- Chunks are posted as custom kind 30078; manifest as custom kind 30079.
- Default chunk size ~ 8 KiB ciphertext per event (conservative for relay limits). Adjust CHUNK_BYTES as needed.
- This is a PoC: relay acceptance varies; use permissive relays for larger files.
*/

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use aes_gcm::{Aead, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{generic_array::GenericArray, OsRng, AeadCore, KeyInit};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use nostr::{Event, EventBuilder, Kind, Tag, Timestamp};
use nostr::prelude::{Keys};
use nostr_sdk::{Client, RelayPoolNotifications, Options};
use rand::RngCore;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const CHUNK_BYTES: usize = 8 * 1024; // 8 KiB per chunk (ciphertext)
const CONFIG_NAME: &str = "pussy.config.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    sk: String,   // hex
    pk: String,   // hex
    relays: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ManifestV1 {
    v: u8,              // 1
    name: String,
    mime: Option<String>,
    size: usize,
    salt_b64: String,   // scrypt salt
    iv_b64: String,     // AES-GCM nonce
    tag_b64: String,    // AES-GCM auth tag (redundant; kept for symmetry)
    chunks: Vec<String> // event ids (hex)
}

#[derive(Parser, Debug)]
#[command(name = "pussy", version, about = "PUSSY — Portable Uncensorable Storage SYstem (on Nostr)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create config + keypair
    Init,
    /// Upload a file (encrypt → chunk → publish) and print manifest id + nevent
    Upload {
        /// Path to the file to upload
        file: PathBuf,
        /// Passphrase to derive encryption key
        #[arg(long)]
        passphrase: String,
        /// Optional MIME type to embed in manifest
        #[arg(long)]
        mime: Option<String>,
    },
    /// Download (fetch chunks → reassemble → decrypt)
    Download {
        /// Manifest id (hex) or nevent
        manifest: String,
        /// Output file path
        out: PathBuf,
        /// Passphrase used during upload
        #[arg(long)]
        passphrase: String,
    },
}

fn default_relays() -> Vec<String> {
    vec![
        "wss://relay.damus.io".to_string(),
        "wss://nos.lol".to_string(),
        "wss://relay.snort.social".to_string(),
    ]
}

fn cfg_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("org", "pussy", "pussy")
        .ok_or_else(|| anyhow!("cannot resolve config directory"))?;
    let dir = proj.config_dir().to_path_buf();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn cfg_path() -> Result<PathBuf> { Ok(cfg_dir()?.join(CONFIG_NAME)) }

fn load_config() -> Result<Config> {
    let p = cfg_path()?;
    let s = fs::read_to_string(&p)
        .map_err(|_| anyhow!("config not found; run `pussy init`"))?;
    let mut cfg: Config = serde_json::from_str(&s)?;
    if cfg.relays.is_empty() { cfg.relays = default_relays(); }
    Ok(cfg)
}

fn save_config(cfg: &Config) -> Result<()> {
    let p = cfg_path()?;
    let s = serde_json::to_string_pretty(cfg)?;
    fs::write(p, s)?;
    Ok(())
}

fn derive_key(pass: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = ScryptParams::new(15, 8, 1)?; // N=2^15, r=8, p=1
    let mut dk = [0u8; 32];
    scrypt(pass.as_bytes(), salt, &params, &mut dk)?;
    Ok(dk)
}

fn encrypt_all(plain: &[u8], passphrase: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // returns (salt, nonce, ciphertext, auth_tag)
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key_bytes = derive_key(passphrase, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = vec![0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher.encrypt(nonce, plain)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    // aes-gcm in this API appends tag to ciphertext; but to keep manifest explicit we split
    // Here, aes-gcm crate returns combined [ciphertext || tag]? Actually it returns ciphertext only; tag is internal.
    // We'll compute tag by decrypting a zero slice to get tag — not available. Simpler: store tag implicitly (not needed).
    // To keep API consistent with TS PoC, we set tag empty and rely on AES-GCM integrated tag.
    let tag: Vec<u8> = Vec::new();

    // zeroize key material
    let mut key_bytes_mut = key_bytes;
    key_bytes_mut.zeroize();

    Ok((salt, nonce_bytes, ct, tag))
}

fn decrypt_all(ciphertext: &[u8], salt: &[u8], nonce_bytes: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let key_bytes = derive_key(passphrase, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed: {e}"))?;
    Ok(pt)
}

fn chunk_bytes(buf: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let end = (i + CHUNK_BYTES).min(buf.len());
        v.push(&buf[i..end]);
        i = end;
    }
    v
}

async fn client_from_cfg(cfg: &Config) -> Result<Client> {
    let mut opts = Options::default();
    opts.connection_timeout = Some(std::time::Duration::from_secs(5));
    let client = Client::with_opts(Keys::from_hex(&cfg.sk)?, opts);
    for r in &cfg.relays { client.add_relay(r).await.ok(); }
    client.connect().await;
    Ok(client)
}

async fn cmd_init() -> Result<()> {
    let keys = Keys::generate();
    let sk = keys.secret_key()?.to_string();
    let pk = keys.public_key().to_string();
    let cfg = Config { sk, pk, relays: default_relays() };
    save_config(&cfg)?;
    println!("Created config at {:?}", cfg_path()?);
    println!("pubkey (hex): {}", cfg.pk);
    println!("npub: {}", nostr::nips::nip19::ToBech32::to_bech32(&keys.public_key()));
    Ok(())
}

async fn cmd_upload(file: PathBuf, passphrase: String, mime: Option<String>) -> Result<()> {
    let cfg = load_config()?;
    let client = client_from_cfg(&cfg).await?;

    let plain = fs::read(&file)?;
    let (salt, iv, ciphertext, _tag) = encrypt_all(&plain, &passphrase)?;

    let chunks = chunk_bytes(&ciphertext);
    let mut chunk_ids: Vec<String> = Vec::with_capacity(chunks.len());

    for (i, ch) in chunks.iter().enumerate() {
        let content_b64 = general_purpose::STANDARD.encode(ch);
        let mut tags = vec![
            Tag::Hashtag("pussy".into()),
            Tag::Generic(vec!["file".into(), file.file_name().unwrap().to_string_lossy().to_string()]),
            Tag::Generic(vec!["c".into(), format!("{}/{}", i + 1, chunks.len())]),
        ];
        if let Some(m) = &mime { tags.push(Tag::Generic(vec!["mime".into(), m.clone()])); }
        let evt = EventBuilder::new(Kind::Custom(30078), content_b64, &tags)
            .to_event(&Keys::from_hex(&cfg.sk)?)?;
        client.send_event(evt.clone()).await?;
        chunk_ids.push(evt.id.to_string());
        print!("Uploaded chunk {}/{}\r", i + 1, chunks.len());
        std::io::stdout().flush().ok();
    }
    println!();

    // manifest
    let manifest = ManifestV1 {
        v: 1,
        name: file.file_name().unwrap().to_string_lossy().to_string(),
        mime,
        size: plain.len(),
        salt_b64: general_purpose::STANDARD.encode(&salt),
        iv_b64: general_purpose::STANDARD.encode(&iv),
        tag_b64: String::new(),
        chunks: chunk_ids.clone(),
    };
    let manifest_json = serde_json::to_string(&manifest)?;
    let tags = vec![
        Tag::Hashtag("pussy".into()),
        Tag::Generic(vec!["type".into(), "manifest".into()]),
        Tag::Generic(vec!["file".into(), manifest.name.clone()]),
        Tag::Generic(vec!["chunks".into(), format!("{}", chunk_ids.len())]),
    ];
    let evt = EventBuilder::new(Kind::Custom(30079), manifest_json, &tags)
        .to_event(&Keys::from_hex(&cfg.sk)?)?;
    client.send_event(evt.clone()).await?;

    let nevent = nostr::nips::nip19::NostrBech32::from_event(&evt, Some(cfg.relays.iter().map(|s| s.parse().unwrap()).collect()))?;

    println!("Manifest id: {}", evt.id.to_string());
    println!("nevent: {}", nevent.to_string());
    println!("Keep this id safe. Anyone with the id and passphrase can reconstruct the file.");

    Ok(())
}

async fn fetch_events_by_ids(client: &Client, ids: &[nostr::EventId]) -> Result<Vec<Event>> {
    use nostr_sdk::Filter;
    let mut filter = Filter::new();
    filter = filter.ids(ids.to_vec());
    let events = client.get_events_of(vec![filter], None).await?;
    Ok(events)
}

async fn fetch_one_event(client: &Client, id: &nostr::EventId) -> Result<Event> {
    let v = fetch_events_by_ids(client, &[*id]).await?;
    v.into_iter().find(|e| &e.id == id).ok_or_else(|| anyhow!("manifest not found"))
}

async fn cmd_download(manifest_in: String, out: PathBuf, passphrase: String) -> Result<()> {
    let cfg = load_config()?;
    let client = client_from_cfg(&cfg).await?;

    // decode nevent or hex
    let manifest_id = if manifest_in.starts_with("nevent1") {
        let d = nostr::nips::nip19::FromBech32::from_bech32(&manifest_in)?;
        match d { nostr::nips::nip19::NostrBech32::Event(ev) => ev.event_id, _ => return Err(anyhow!("not an nevent")) }
    } else {
        manifest_in.parse::<nostr::EventId>()?
    };

    let manifest_evt = fetch_one_event(&client, &manifest_id).await?;
    let manifest: ManifestV1 = serde_json::from_str(&manifest_evt.content)?;

    // fetch chunk events by id list
    let chunk_ids: Vec<nostr::EventId> = manifest.chunks.iter().map(|s| s.parse().unwrap()).collect();
    let mut chunk_events = fetch_events_by_ids(&client, &chunk_ids).await?;
    // order by c-tag index
    chunk_events.sort_by_key(|e| {
        let idx = e.tags.iter().find_map(|t| match t { Tag::Generic(v) if v.get(0).map(|x| x.as_str()) == Some("c") => v.get(1).cloned(), _ => None });
        idx.and_then(|v| v.split('/').next().and_then(|n| n.parse::<usize>().ok())).unwrap_or(0)
    });

    // reassemble
    let mut cipher_all: Vec<u8> = Vec::new();
    for e in &chunk_events {
        let b = general_purpose::STANDARD.decode(&e.content)?;
        cipher_all.extend_from_slice(&b);
    }

    let salt = general_purpose::STANDARD.decode(&manifest.salt_b64)?;
    let iv = general_purpose::STANDARD.decode(&manifest.iv_b64)?;
    let plain = decrypt_all(&cipher_all, &salt, &iv, &passphrase)?;

    fs::write(&out, &plain)?;
    println!("Wrote {:?} ({} bytes)", out, plain.len());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => cmd_init().await?,
        Commands::Upload { file, passphrase, mime } => cmd_upload(file, passphrase, mime).await?,
        Commands::Download { manifest, out, passphrase } => cmd_download(manifest, out, passphrase).await?,
    }
    Ok(())
}
