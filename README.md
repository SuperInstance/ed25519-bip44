# Ed25519 BIP-44

**A Rust library for hierarchical deterministic (HD) key derivation using Ed25519 signatures with BIP-44 multi-account paths** — enabling a single seed to generate deterministic key pairs for multiple Ed25519-based blockchains (Solana, Cardano, Stellar, NEAR, MINA).

## Why It Matters

HD wallets are the backbone of modern cryptocurrency security. The principle: instead of storing many private keys, you store one master seed and derive unlimited keys from it deterministically. BIP-32 defined hierarchical derivation, BIP-44 standardized the path format: `m/purpose'/coin'/account'/change'/index'`.

Ed25519 is the signature scheme used by Solana, Cardano, Stellar, and other modern blockchains. Unlike ECDSA (used by Bitcoin/Ethereum), Ed25519 is faster, simpler, and doesn't require cryptographically secure random number generation during signing — making it resistant to the class of RNG-based private key leaks that affected early Bitcoin wallets.

**BIP-44 path structure:** `m/44'/coin'/account'/change'/index'`
- `44'` — Purpose (BIP-44)
- `coin'` — Cryptocurrency (501=Solana, 1815=Cardano, 148=Stellar)
- `account'` — Wallet account number
- `change'` — 0=external/receiving, 1=internal/change
- `index'` — Address index

The prime symbol (') indicates **hardened derivation** — the child key cannot be used to derive the parent, protecting the master seed if a child key is compromised.

## How It Works

The library provides:

**Key derivation:** `from_seed` takes a 32-byte master seed and a 5-level BIP-44 path. Each path component is hardened (OR'd with `0x80000000`). The simplified derivation mixes the seed with path components using wrapping arithmetic. Production use would implement SLIP-0010 (HMAC-SHA512 based derivation for Ed25519 curves).

**Chain presets:** Convenience constructors for common Ed25519 blockchains:
- `solana(seed)` → `m/44'/501'/0'/0'/0'`
- `cardano(seed)` → `m/44'/1815'/0'/0'/0'`
- `stellar(seed)` → `m/44'/148'/0'/0'/0'`

**Signing and verification:** Ed25519 produces 64-byte signatures. The signing function combines the private key with the message deterministically (no random nonce needed — a key security property of Ed25519's Schnorr-based construction).

**Note:** The cryptographic operations are simplified stubs for educational purposes. Production use requires a audited Ed25519 implementation (like `ed25519-dalek`) with proper curve arithmetic on Curve25519.

## Quick Start

```rust
use ed25519_bip44::{Ed25519Bip44, coins};

let seed = [0x42u8; 32]; // In production: derive from BIP-39 mnemonic

// Derive Solana keypair
let sol = Ed25519Bip44::solana(&seed);
println!("Path: {}", sol.path_string());
println!("Public key: {:02X?}", &sol.public_key()[..8]);

// Derive Cardano keypair (different coin → different keys from same seed)
let ada = Ed25519Bip44::cardano(&seed);
assert_ne!(sol.public_key(), ada.public_key());

// Sign and verify messages
let msg = b"transfer 100 SOL";
let sig = sol.sign(msg);
assert!(Ed25519Bip44::verify(msg, &sig, sol.public_key()));

// Custom derivation path: m/44'/397'/0'/0'/0' (NEAR protocol)
let near = Ed25519Bip44::from_seed(&seed, 44, coins::NEAR, 0, 0, 0);
```

## API

### `Ed25519Bip44`
- `from_seed(seed, purpose, coin, account, change, index) -> Self` — Derive key at BIP-44 path
- `solana(seed) / cardano(seed) / stellar(seed)` — Preset derivations
- `public_key() -> &[u8; 32]` — 32-byte Ed25519 public key
- `private_key() -> &[u8; 32]` — 32-byte private key
- `path_string() -> String` — Human-readable derivation path
- `sign(message) -> [u8; 64]` — Deterministic 64-byte signature
- `verify(message, signature, public_key) -> bool` — Verify signature

### `coins` (module)
- `SOLANA = 501`, `CARDANO = 1815`, `STELLAR = 148`, `NEAR = 397`, `MINA = 860`

## Architecture Notes

This library provides wallet key management for SuperInstance's blockchain integration layer. It demonstrates BIP-44 hierarchical derivation for Ed25519-based chains, the same pattern used by Phantom (Solana), Yoroi (Cardano), and other production wallets.

See the full architecture: [ARCHITECTURE.md](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md)

## License

MIT
