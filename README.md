# CryptoZoid-gd 🦞🔐

A Godot 4.x GDExtension providing Ed25519 cryptography, SHA-256, and base64url encoding — backed by pure Rust. Zero system dependencies.

Built to support [OpenClaw](https://github.com/ClawfficeOrg) device pairing in [Clawffice-Space](https://github.com/ClawfficeOrg/Clawffice-Space).

> Godot's built-in `Crypto` class only supports RSA. CryptoZoid fills the gap.

---

## Features

- **Ed25519** key generation, signing, and verification
- **SHA-256** hashing (raw bytes and hex string)
- **base64url** encode/decode (no padding, RFC 4648 §5)
- **Secure random bytes**
- Pure Rust — no OpenSSL, no system crypto dependencies
- Works on Linux, Windows, macOS (mobile/web: coming soon)

---

## API

```gdscript
# Key generation
var keypair: Dictionary = CryptoZoid.generate_ed25519_keypair()
# keypair["private_key"] -> PackedByteArray (32-byte seed)
# keypair["public_key"]  -> PackedByteArray (32 bytes)

# Signing
var sig: PackedByteArray = CryptoZoid.ed25519_sign(private_key, message)

# Derive public key from private key
var pub: PackedByteArray = CryptoZoid.ed25519_public_key(private_key)

# Verification
var ok: bool = CryptoZoid.ed25519_verify(public_key, message, signature)

# Hashing
var hash: PackedByteArray = CryptoZoid.sha256(data)
var hex: String = CryptoZoid.sha256_hex(data)

# base64url
var encoded: String = CryptoZoid.base64url_encode(data)
var decoded: PackedByteArray = CryptoZoid.base64url_decode(encoded)

# Random
var bytes: PackedByteArray = CryptoZoid.random_bytes(32)
```

---

## Installation

### From GitHub Release (recommended)

1. Download the latest release from [Releases](https://github.com/ClawfficeOrg/CryptoZoid-gd/releases)
2. Extract and copy `addons/crypto_zoid/` into your Godot project's `addons/` folder
3. In Godot: **Project → Project Settings → Plugins** → enable **CryptoZoid**

### From Source

Requires Rust toolchain (`cargo`).

```bash
git clone https://github.com/ClawfficeOrg/CryptoZoid-gd
cd CryptoZoid-gd
cargo build --release
# Copy target/release/libcrypto_zoid.so (or .dll / .dylib) to your project's addons/crypto_zoid/bin/
```

---

## Rust Crates

| Crate | Purpose |
|-------|---------|
| [gdext](https://github.com/godot-rust/gdext) | Godot 4 Rust binding |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | Ed25519 sign/verify |
| [sha2](https://github.com/RustCrypto/hashes) | SHA-256 |
| [rand](https://github.com/rust-random/rand) | Secure random (OsRng) |
| [base64](https://github.com/marshallpierce/rust-base64) | base64url encoding |

---

## Compatibility

| Platform | Status |
|----------|--------|
| Linux x86_64 | ✅ Supported |
| Windows x86_64 | ✅ Supported |
| macOS (Intel + Apple Silicon) | ✅ Supported |
| Android | 🔜 Planned |
| iOS | 🔜 Planned |
| Web (WASM) | 🔜 Investigating |

Minimum Godot version: **4.1**

---

## License

MIT © ClawfficeOrg

---

*Why not Zoidborg? 🦞🤖*
