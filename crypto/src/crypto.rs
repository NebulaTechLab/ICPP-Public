#![allow(non_snake_case)]

/// ===================================================
/// Cryptographic primitives (HKDF, HMAC-SHA3, 
/// ChaCha20-Poly1305)
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.03
/// Date    -> 3 December 2025
/// Status  -> Public release ver:2 subver:0 release:03
///
/// Code developed by @Troesma
/// ===================================================

use hmac::{Hmac, Mac};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
    AeadCore,
};
use sha3::{Sha3_256, Digest};
use rand;

use zeroize::Zeroize;

type HmacSha3_256 = Hmac<Sha3_256>;

/// HKDF (HMAC-based Key 
/// Derivation Function)
pub struct HKDF;

impl HKDF {
    /// Derive transport keys (K_enc, K_auth) 
    /// from shared secret
    pub fn derive_transport_keys(
        ikm: &[u8],                                 // -> Input key material (Z from RDMPF)
        salt: &[u8; 32],                            // -> Nonce
        info: &[u8],                                // -> Context string
    ) -> ([u8; 32], [u8; 32]) {
        // Step 1 -> Extract
        let mut prk = Self::extract(salt, ikm);
        
        // Step 2 -> Expand
        let mut okm = Self::expand(&prk, info, 64);
        
        let mut k_enc = [0u8; 32];
        let mut k_auth = [0u8; 32];
        k_enc.copy_from_slice(&okm[0..32]);
        k_auth.copy_from_slice(&okm[32..64]);
        
        // Zeroize 
        // intermediates
        prk.zeroize();
        okm.zeroize();
        
        (k_enc, k_auth)
    }
    
    fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        // Use MAC trait
        // method explicitly
        let mut hmac = <HmacSha3_256 as Mac>::new_from_slice(salt)
            .expect("HMAC accepts any key size");
        hmac.update(ikm);
        let result = hmac.finalize();
        let bytes = result.into_bytes();
        
        let mut prk = [0u8; 32];
        prk.copy_from_slice(&bytes[..32]);
        prk
    }
    
    fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(length);
        let mut prev = Vec::new();
        let mut counter: u8 = 1;
        
        while okm.len() < length {
            // Use Mac trait 
            // method explicitly
            let mut hmac = <HmacSha3_256 as Mac>::new_from_slice(prk)
                .expect("HMAC accepts any key size");
            hmac.update(&prev);
            hmac.update(info);
            hmac.update(&[counter]);
            
            let result = hmac.finalize();

            // Zeroize previous 
            // before replacing
            prev.zeroize();

            // Replacing now
            prev = result.into_bytes().to_vec();

            okm.extend_from_slice(&prev);
            counter += 1;
        }
        // Zeroize 
        // last prev
        prev.zeroize();
        
        okm.truncate(length);
        okm
    }
}

/// HMAC-SHA3
pub struct HMACSHA3;

impl HMACSHA3 {
    /// Compute HMAC tag
    pub fn compute_tag(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
        // Use Mac trait 
        // method explicitly
        let mut hmac = <HmacSha3_256 as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key size");
        hmac.update(message);
        let result = hmac.finalize();
        let bytes = result.into_bytes();
        
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[..32]);
        tag
    }
    
    /// Verify HMAC tag 
    /// (constant-time)
    pub fn verify_tag(key: &[u8; 32], message: &[u8], tag: &[u8; 32]) -> bool {
        // Use Mac trait 
        // method explicitly
        let mut hmac = <HmacSha3_256 as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key size");
        hmac.update(message);
        
        // Constant-time verification
        hmac.verify_slice(tag).is_ok()
    }
}

/// AEAD Cipher 
/// (ChaCha20-Poly1305)
pub struct AEADCipher;

impl AEADCipher {
    /// Encrypt with authenticated data
    /// NOTE -> This is intended for off-chain use only
    /// On canisters derive nonces/keys from IC randomness instead
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new(key.into());
        
        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_e| "Encryption failed".to_string())?;
        
        // Prepend nonce to ciphertext 
        // (nonce || ciphertext)
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    /// Decrypt with 
    /// authenticated data
    pub fn decrypt(key: &[u8; 32], data: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 + 16 {
            return Err("Short ciphertext".to_string());
        }
        
        let cipher = ChaCha20Poly1305::new(key.into());
        
        // Extract nonce from first 12 bytes
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };
        
        cipher
            .decrypt(nonce, payload)
            .map_err(|_e| "Decryption failed".to_string())
    }
}

/// SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..32]);
    hash
}

/// Truncate hash to 
/// specified bits (for hints)
pub fn truncate_hash(hash: &[u8; 32], bits: usize) -> Vec<u8> {
    if bits == 0 {
        return Vec::new();
    }

    // We only have 256 bits 
    // available in the input hash
    if bits >= 256 {
        return hash.to_vec();
    }

    // Number of bytes needed 
    // to carry X bits.
    let bytes = (bits + 7) / 8;
    let mut out = hash[..bytes].to_vec();

    // If bits is not a multiple of 8 mask off the unused low bits
    // in the last byte (we keep the most significant X bits)
    let total_bits = bytes * 8;
    let extra_bits = total_bits - bits;
    if extra_bits > 0 {
        let mask: u8 = 0xFF << extra_bits;
        let last = out.len() - 1;
        out[last] &= mask;
    }
    out
}

// ============================================
// CSRN Symmetric Encryption (Storage -> Alice)
// ============================================

/// Derive transit key for CSRN encryption
/// Key = SHA3-256("ICPP:transit:v1" || deposit_id || alice_principal || nonce)
pub fn derive_csrn_transit_key(
    deposit_id: &[u8],
    alice_principal: &[u8],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"ICPP:transit:v1");
    hasher.update(deposit_id);
    hasher.update(alice_principal);
    hasher.update(nonce);
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

/// Encrypt CSRN for Alice using symmetric key
/// Returns -> ciphertext (32 bytes CSRN + 16 bytes auth tag = 48 bytes)
pub fn encrypt_csrn(
    deposit_id: &[u8],
    alice_principal: &[u8],
    nonce: &[u8; 32],
    csrn: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let key = derive_csrn_transit_key(deposit_id, alice_principal, nonce);
    
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    // Use first 12 bytes of nonce 
    // as ChaCha20-Poly1305 nonce
    let chacha_nonce = Nonce::from_slice(&nonce[..12]);
    
    // AAD = deposit_id 
    // for binding
    let payload = Payload {
        msg: csrn,
        aad: deposit_id,
    };
    
    cipher
        .encrypt(chacha_nonce, payload)
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// Decrypt CSRN (Alice client-side)
/// Expects -> ciphertext (48 bytes = 32 bytes data + 16 bytes tag)
pub fn decrypt_csrn(
    deposit_id: &[u8],
    alice_principal: &[u8],
    nonce: &[u8; 32],
    ciphertext: &[u8],
) -> Result<[u8; 32], String> {
    if ciphertext.len() != 48 {
        return Err(format!(
            "Invalid ciphertext length: expected 48, got {}",
            ciphertext.len()
        ));
    }
    
    let key = derive_csrn_transit_key(deposit_id, alice_principal, nonce);
    
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    // Use first 12 bytes of nonce 
    // as ChaCha20-Poly1305 nonce
    let chacha_nonce = Nonce::from_slice(&nonce[..12]);
    
    // AAD = deposit_id 
    // for binding
    let payload = Payload {
        msg: ciphertext,
        aad: deposit_id,
    };
    
    let plaintext = cipher
        .decrypt(chacha_nonce, payload)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    if plaintext.len() != 32 {
        return Err(format!(
            "Invalid plaintext length: expected 32, got {}",
            plaintext.len()
        ));
    }
    
    let mut csrn = [0u8; 32];
    csrn.copy_from_slice(&plaintext);
    Ok(csrn)
}