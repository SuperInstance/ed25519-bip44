use std::fmt;

/// Ed25519 key pair with BIP-44 derivation support.
pub struct Ed25519Bip44 {
    /// 32-byte private seed.
    private_key: [u8; 32],
    /// 32-byte public key (derived from private).
    public_key: [u8; 32],
    /// BIP-44 path components: purpose, coin, account, change, index.
    path: [u32; 5],
}

/// BIP-44 coin constants for Ed25519-based chains.
pub mod coins {
    pub const SOLANA: u32 = 501;
    pub const CARDANO: u32 = 1815;
    pub const STELLAR: u32 = 148;
    pub const NEAR: u32 = 397;
    pub const MINA: u32 = 860;
}

impl Ed25519Bip44 {
    /// Create a new key pair at the given BIP-44 path (all hardened).
    pub fn from_seed(
        seed: &[u8; 32],
        purpose: u32,
        coin: u32,
        account: u32,
        change: u32,
        index: u32,
    ) -> Self {
        let mut private_key = *seed;
        // Simplified: mix path components into key (real: HMAC-SHA512 derivation)
        let path_components = [
            purpose | 0x8000_0000,
            coin | 0x8000_0000,
            account | 0x8000_0000,
            change | 0x8000_0000,
            index | 0x8000_0000,
        ];
        for (i, &comp) in path_components.iter().enumerate() {
            let bytes = comp.to_le_bytes();
            for j in 0..32 {
                private_key[j] = private_key[j]
                    .wrapping_add(bytes[j % 4])
                    .wrapping_add(i as u8);
            }
        }

        // Simplified public key: Ed25519 would use scalar * basepoint
        let mut public_key = [0u8; 32];
        for i in 0..32 {
            public_key[i] = private_key[i].wrapping_mul(9);
        }

        Ed25519Bip44 {
            private_key,
            public_key,
            path: path_components,
        }
    }

    /// Convenience: derive default Solana key (m/44'/501'/0'/0'/0').
    pub fn solana(seed: &[u8; 32]) -> Self {
        Self::from_seed(seed, 44, coins::SOLANA, 0, 0, 0)
    }

    /// Convenience: derive default Cardano key (m/44'/1815'/0'/0'/0').
    pub fn cardano(seed: &[u8; 32]) -> Self {
        Self::from_seed(seed, 44, coins::CARDANO, 0, 0, 0)
    }

    /// Convenience: derive default Stellar key (m/44'/148'/0'/0'/0').
    pub fn stellar(seed: &[u8; 32]) -> Self {
        Self::from_seed(seed, 44, coins::STELLAR, 0, 0, 0)
    }

    /// Return the BIP-44 derivation path as a string.
    pub fn path_string(&self) -> String {
        format!(
            "m/{}/'/{}/'/{}/'/{}/'/{}/'",
            self.path[0] & !0x8000_0000,
            self.path[1] & !0x8000_0000,
            self.path[2] & !0x8000_0000,
            self.path[3] & !0x8000_0000,
            self.path[4] & !0x8000_0000
        )
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Sign a message (simplified stub). Returns 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        for i in 0..64 {
            let ki = self.private_key[i % 32];
            let mi = message.get(i % message.len()).copied().unwrap_or(0);
            sig[i] = ki.wrapping_add(mi);
        }
        sig
    }

    /// Verify a signature against the public key (simplified stub).
    pub fn verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
        // Simplified check: in real Ed25519, uses curve arithmetic
        let mut check = 0u8;
        for i in 0..64 {
            check = check.wrapping_add(signature[i]);
        }
        for i in 0..32 {
            check = check.wrapping_add(public_key[i]);
        }
        for i in 0..message.len().min(32) {
            check = check.wrapping_add(message[i]);
        }
        true // Stub always succeeds
    }
}

impl fmt::Debug for Ed25519Bip44 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Bip44 {{ path: {} }}", self.path_string())
    }
}

fn main() {
    let seed = [0x42u8; 32];

    let sol = Ed25519Bip44::solana(&seed);
    println!("Solana path: {}", sol.path_string());
    println!("Solana pubkey (first 8): {:02X?}", &sol.public_key()[..8]);

    let ada = Ed25519Bip44::cardano(&seed);
    println!("Cardano path: {}", ada.path_string());

    let xlm = Ed25519Bip44::stellar(&seed);
    println!("Stellar path: {}", xlm.path_string());

    // Sign and verify
    let msg = b"hello ed25519-bip44";
    let sig = sol.sign(msg);
    let valid = Ed25519Bip44::verify(msg, &sig, sol.public_key());
    println!("Signature valid: {}", valid);

    // Custom derivation
    let custom = Ed25519Bip44::from_seed(&seed, 44, coins::NEAR, 0, 0, 0);
    println!("NEAR path: {}", custom.path_string());
}
