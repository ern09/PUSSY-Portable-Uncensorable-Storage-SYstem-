# PUSSY — Portable Uncensorable Storage SYstem (on Nostr)

PUSSY is a proof‑of‑concept CLI tool to **encrypt, chunk, and store files on the Nostr network**, then retrieve and decrypt them later. It uses AES‑256‑GCM with passphrase‑derived keys and publishes data as Nostr events.

## Features

* 🔐 **End‑to‑end encryption** with AES‑256‑GCM + scrypt key derivation
* 📦 **Chunking** of files into small Nostr events (default: 8 KiB per chunk)
* 📝 **Manifest events** that list chunk IDs for reassembly
* 🌐 **Relay‑agnostic**: works with public or private Nostr relays
* 🖥️ **Rust binary**: no runtime dependencies

## Build

```bash
# Clone your repo
git clone https://github.com/yourname/pussy.git
cd pussy

# Build\ ncargo build --release

# Binary will be in
target/release/pussy
```

## Quick Start

```bash
# Initialize config + keypair
./target/release/pussy init

# Upload a file (encrypt → chunk → publish)
./target/release/pussy upload ./path/to/file --passphrase "your secret"

# Output will print manifest ID + nevent string
# Save this, you’ll need it for downloading.

# Download + decrypt
./target/release/pussy download <manifest-id-or-nevent> ./out.file --passphrase "your secret"
```

## How it Works

1. **Encrypt**: File is encrypted with AES‑256‑GCM. The key is derived from your passphrase via scrypt.
2. **Chunk**: Ciphertext is split into 8 KiB chunks.
3. **Publish**: Each chunk is posted as a custom Nostr event (kind `30078`).
4. **Manifest**: A final manifest event (kind `30079`) contains metadata (filename, size, salt, IV, and chunk IDs).
5. **Retrieve**: To reconstruct, fetch manifest + chunk events, reassemble, and decrypt with the same passphrase.

## Config

Config is created on first run (`pussy init`) and stored in your OS config directory. It contains:

* Hex‑encoded secret key + public key
* Default relay list

## Security Notes

* Anyone with the **manifest ID** *and* the **passphrase** can reconstruct the file.
* For better security, use strong passphrases.
* Public relays may prune or reject large payloads — use permissive or private relays for serious storage.

## Roadmap

* [ ] Parallel chunk publishing
* [ ] Smarter relay probing for size limits
* [ ] GitHub Actions CI to build binaries for Linux/macOS/Windows
* [ ] Optional progress bar and resume support

## License

MIT — free to use, modify, and share.










