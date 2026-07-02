#![allow(non_snake_case)]

/// ===================================================
/// KEA calling methods
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

pub mod params;
pub mod rdmpf;
pub mod crypto;
pub mod verification;
pub mod secrets;
pub mod transfer;
pub mod fe;
pub mod sgp;
pub mod canister;
pub mod codec;
pub mod randomness;

/// Re-export 
/// main types
pub use params::{RDMPFParams, Account, derive_user_bases, generate_W};
pub use rdmpf::{
    rdmpf as compute_rdmpf,
    composition,
    scalar_mult,
    matrices_equal,
    encode_matrix,
    RDMPFError,
};
pub use crypto::{
    HKDF,
    HMACSHA3,
    AEADCipher,
    sha3_256,
    truncate_hash,
};
pub use secrets::EphemeralSecret;
pub use transfer::{TransferCapsule, EncryptedPayload, retrieve_transfer};

/// Type alias 
/// for matrices
pub type Matrix = Vec<Vec<num_bigint::BigUint>>;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_library_exports() {
        // Verify all core 
        // types are accessible
        let _params = RDMPFParams::test();
        let _secret = EphemeralSecret::generate();
        
        let account = Account {
            owner: b"test".to_vec(),
            subaccount: vec![],
        };
        
        let params = RDMPFParams::test();
        let (bx, by) = derive_user_bases(&account, &params).unwrap();
        
        assert_eq!(bx.len(), params.dim);
        assert_eq!(by.len(), params.dim);
    }
    
    #[test]
    fn test_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}

/// Runtime Security Guard
/// ======================
/// This function verifies compilation
/// to production-grade standards
pub fn assert_production_configuration() {
    // Access the constant 
    // from the params module
    let bits = params::RDMPFParams::SGP_FE_ENTRY_BITS;
    if bits < 4 {
        panic!(
            "FATAL SECURITY ERROR: The crypto library is running in TEST MODE \
             Deployment aborted to prevent security degradation"
        );
    }
}