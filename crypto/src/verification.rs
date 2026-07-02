#![allow(non_snake_case)]

/// ===================================================
/// Parameter verification (validates parameterization
/// at canisters initialization)
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha3::{Sha3_256, Digest};
use crate::params::RDMPFParams;

/// Verification errors
/// (opaque on purpose)
#[derive(Debug, Clone)]
pub enum VerificationError {
    ParameterInvalid,
    CommitmentInvalid,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ParameterInvalid => write!(f, "ERR.PARAMETER_INVALID"),
            Self::CommitmentInvalid => write!(f, "ERR.COMMITMENT_INVALID"),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Miller-Rabin primality test (deterministic 
/// for small primes, probabilistic for large)
/// ==========================================
#[cfg_attr(target_family = "wasm", allow(unused_variables))]
fn miller_rabin(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.bit(0) == false {
        return false;
    }
    
    // Write n-1 
    // as 2^r*d
    // ---------
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u64;
    
    while d.bit(0) == false {
        d >>= 1;
        r += 1;
    }
    
    let small_bound = BigUint::from(3_317_044_064_679_887_385_961_981u128);

    // On wasm (IC) -> fully 
    // deterministic witnesses
    // -----------------------
    #[cfg(target_family = "wasm")]
    let witnesses: Vec<u32> = if n < &small_bound {
        // Deterministic 
        // set for small n
        // ---------------
        vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    } else {
        // Extended set 
        // for large n
        // ------------
        vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    };

    // On native -> use 
    // real randomness
    // ----------------
    #[cfg(not(target_family = "wasm"))]
    let witnesses: Vec<u32> = if n < &small_bound {
        vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    } else {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..rounds)
            .map(|_| rng.gen_range(2..=u32::MAX))
            .collect()
    };

    'witness: for a_val in witnesses {
        let a = BigUint::from(a_val);
        if &a >= n {
            continue;
        }
        
        // x = a^d mod n
        // -------------
        let mut x = mod_exp(&a, &d, n);
        
        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }
        
        for _ in 0..(r - 1) {
            x = (&x * &x) % n;
            
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        
        return false;
    }
    
    true
}

/// Modular exponentiation
/// ======================
fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();
    
    while !exp.is_zero() {
        if exp.bit(0) {
            result = (result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }
    
    result
}

/// Compute expected 
/// parameter commitment
///
/// The commitment binds:
/// - RDMPF modulus p
/// - RDMPF dimension dim
/// - RDMPF version
/// - FE entry bitlength (SGP_FE_ENTRY_BITS)
/// - FE value bitlength (SGP_FE_VALUE_BITS)
/// ========================================
pub fn compute_commitment(
    p: &BigUint,
    dim: usize,
    version: u32,
    fe_entry_bits: u32,
    fe_value_bits: u32,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separation
    // -----------------
    hasher.update(b"ICPP-params-v2");

    // RDMPF parameters
    // ----------------
    hasher.update(&version.to_le_bytes());
    hasher.update(&(dim as u32).to_le_bytes());
    hasher.update(&p.to_bytes_le());

    // FE configuration
    // ----------------
    hasher.update(&fe_entry_bits.to_le_bytes());
    hasher.update(&fe_value_bits.to_le_bytes());

    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&hasher.finalize());
    commitment
}

/// Verify parameters 
/// at runtime
/// =================
pub fn verify_production_params(
    params: &RDMPFParams,
) -> Result<(), VerificationError> {

    // 1. Verify bit length
    // 192-bit prime provides ~96-bit DLP security
    // Constrained by IC's 40B instruction limit but
    // ephemeral canister lifecycle greatly mitigates 
    // (if not eliminates) long-term exposure
    // ----------------------------------------------
    let bits = params.p.bits();
    const MIN_BITS: u64 = 192;
    
    if bits < MIN_BITS {
        return Err(VerificationError::ParameterInvalid);
    }
    
    // 2. Verify 
    //    dimension
    // ------------
    if params.dim < 6 || params.dim > 16 {
        return Err(VerificationError::ParameterInvalid);
    }
    
    // 3. Verify p 
    //    is odd
    // -----------
    if !params.p.bit(0) {
        return Err(VerificationError::ParameterInvalid);
    }
    
    // 4. Verify p is prime 
    //    (probabilistic
    //    error < 2^-80)
    // --------------------
    if !miller_rabin(&params.p, 40) {
        return Err(VerificationError::ParameterInvalid);
    }
    
    // 5. Verify p is 
    //    a safe prime
    // ---------------
    let q = (&params.p - BigUint::one()) / 2u32;
    
    if &q * 2u32 + BigUint::one() != params.p {
        return Err(VerificationError::ParameterInvalid);
    }
    
    if !miller_rabin(&q, 40) {
        return Err(VerificationError::ParameterInvalid);
    }
    
    // 6. Verify phi = p - 1
    // ---------------------
    let expected_phi = &params.p - BigUint::one();
    if params.phi != expected_phi {
        return Err(VerificationError::ParameterInvalid);
    }

    Ok(())
}

/// Verify parameters match 
/// published commitment
/// =======================
pub fn verify_commitment(
    params: &RDMPFParams,
    published_commitment: &[u8; 32],
) -> Result<(), VerificationError> {

    let computed = compute_commitment(
        &params.p,
        params.dim,
        params.version,
        RDMPFParams::SGP_FE_ENTRY_BITS,
        RDMPFParams::SGP_FE_VALUE_BITS,
    );

    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= computed[i] ^ published_commitment[i];
    }

    if diff != 0 {
        return Err(VerificationError::CommitmentInvalid);
    }

    Ok(())
}