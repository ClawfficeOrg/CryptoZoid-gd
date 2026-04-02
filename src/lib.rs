use godot::prelude::*;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier, Signature};
use sha2::{Sha256, Digest};
use rand::RngCore;
use rand::rngs::OsRng;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

struct CryptoZoidExtension;

#[gdextension]
unsafe impl ExtensionLibrary for CryptoZoidExtension {}

#[derive(GodotClass)]
#[class(base=Object, init)]
struct CryptoZoid {
    base: Base<Object>,
}

#[godot_api]
impl CryptoZoid {
    /// Generate Ed25519 keypair — returns {private_key: PackedByteArray (32 bytes), public_key: PackedByteArray (32 bytes)}
    #[func]
    fn generate_ed25519_keypair(&self) -> Dictionary {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut private_key = PackedByteArray::new();
        for b in seed.iter() {
            private_key.push(*b);
        }
        let mut public_key = PackedByteArray::new();
        for b in verifying_key.to_bytes().iter() {
            public_key.push(*b);
        }

        let mut dict = Dictionary::new();
        dict.set("private_key", private_key);
        dict.set("public_key", public_key);
        dict
    }

    /// Sign a message with a 32-byte private key seed — returns 64-byte signature
    #[func]
    fn ed25519_sign(&self, private_key: PackedByteArray, message: PackedByteArray) -> PackedByteArray {
        let pk_bytes = private_key.to_vec();
        if pk_bytes.len() != 32 {
            return PackedByteArray::new();
        }
        let seed: [u8; 32] = match pk_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return PackedByteArray::new(),
        };
        let signing_key = SigningKey::from_bytes(&seed);
        let msg_bytes = message.to_vec();
        let signature = signing_key.sign(&msg_bytes);

        let mut result = PackedByteArray::new();
        for b in signature.to_bytes().iter() {
            result.push(*b);
        }
        result
    }

    /// Derive public key from a 32-byte private key seed — returns 32-byte public key
    #[func]
    fn ed25519_public_key(&self, private_key: PackedByteArray) -> PackedByteArray {
        let pk_bytes = private_key.to_vec();
        if pk_bytes.len() != 32 {
            return PackedByteArray::new();
        }
        let seed: [u8; 32] = match pk_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return PackedByteArray::new(),
        };
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut result = PackedByteArray::new();
        for b in verifying_key.to_bytes().iter() {
            result.push(*b);
        }
        result
    }

    /// Verify an Ed25519 signature — returns true if valid
    #[func]
    fn ed25519_verify(&self, public_key: PackedByteArray, message: PackedByteArray, signature: PackedByteArray) -> bool {
        let pub_bytes = public_key.to_vec();
        let sig_bytes = signature.to_vec();
        let msg_bytes = message.to_vec();

        if pub_bytes.len() != 32 || sig_bytes.len() != 64 {
            return false;
        }

        let pub_arr: [u8; 32] = match pub_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key.verify(&msg_bytes, &sig).is_ok()
    }

    /// SHA-256 hash — returns 32-byte hash
    #[func]
    fn sha256(&self, data: PackedByteArray) -> PackedByteArray {
        let mut hasher = Sha256::new();
        hasher.update(data.to_vec());
        let hash = hasher.finalize();

        let mut result = PackedByteArray::new();
        for b in hash.iter() {
            result.push(*b);
        }
        result
    }

    /// SHA-256 hash as lowercase hex string (64 chars)
    #[func]
    fn sha256_hex(&self, data: PackedByteArray) -> GString {
        let mut hasher = Sha256::new();
        hasher.update(data.to_vec());
        let hash = hasher.finalize();

        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        GString::from(hex)
    }

    /// Base64url encode (no padding)
    #[func]
    fn base64url_encode(&self, data: PackedByteArray) -> GString {
        let encoded = URL_SAFE_NO_PAD.encode(data.to_vec());
        GString::from(encoded)
    }

    /// Base64url decode — returns empty array on error
    #[func]
    fn base64url_decode(&self, data: GString) -> PackedByteArray {
        let s = data.to_string();
        match URL_SAFE_NO_PAD.decode(s.as_bytes()) {
            Ok(bytes) => {
                let mut result = PackedByteArray::new();
                for b in bytes.iter() {
                    result.push(*b);
                }
                result
            }
            Err(_) => PackedByteArray::new(),
        }
    }

    /// Generate cryptographically secure random bytes
    #[func]
    fn random_bytes(&self, length: i64) -> PackedByteArray {
        if length <= 0 || length > 65536 {
            return PackedByteArray::new();
        }
        let mut bytes = vec![0u8; length as usize];
        OsRng.fill_bytes(&mut bytes);

        let mut result = PackedByteArray::new();
        for b in bytes.iter() {
            result.push(*b);
        }
        result
    }
}
