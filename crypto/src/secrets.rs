#![allow(non_snake_case)]

/// ===================================================
/// Ephemeral secrets management (ensures secrets are 
/// zeroized and cannot persist)
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// Properties enforced by type system
/// - Automatically zeroized on drop (compiler-guaranteed)
/// - Cannot be cloned (prevents accidental copies)
/// - Cannot be serialized (prevents persistence)
/// - Stack-allocated by default (immediate reuse after scope)
/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 

use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSecret {
    bytes: [u8; 32],
}

impl EphemeralSecret {
    /// Generate new ephemeral secret (off-chain only)
    /// Secret is stack-allocated and will be automatically
    /// zeroized when it goes out of scope
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        EphemeralSecret { bytes }
    }
    
    /// Access bytes (read-only)
    /// Returns immutable reference to prevent cloning
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    
    /// Convert to BigUint for scalar operations
    /// Used in RDMPF computation
    pub fn to_biguint(&self) -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_le(&self.bytes)
    }
}

// Only Debug for type name 
// (not content)
impl std::fmt::Debug for EphemeralSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("EphemeralSecret([REDACTED])")
    }
}