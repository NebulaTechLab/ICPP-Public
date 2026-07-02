#![allow(non_snake_case)]

/// ===================================================
/// RDMPF Parameters (account-based base derivation for 
/// defense-in-depth)
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.03
/// Date    -> 3 December 2025
/// Status  -> Public release ver:2 subver:0 release:03
///
/// Code developed by @Troesma
/// ===================================================

use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt};
use num_traits::{One, Zero, Signed};
use num_integer::Integer;
use sha3::{Sha3_256, Digest};
use std::ops::Rem;

use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::rdmpf::Matrix;
use crate::fe::{SgpFEParams, SgpFEKey};
use crate::sgp::Sgp;

use miracl_core::rand::{RAND, RAND_impl};

/// Import verification 
/// functions
use crate::verification::verify_production_params;

/// RDMPF system 
/// parameters
#[derive(Clone, Debug)]
pub struct RDMPFParams {
    /// Prime modulus p
    pub p: BigUint,
    
    /// Euler totient phi = p - 1
    pub phi: BigUint,
    
    /// Matrix dimension
    pub dim: usize,
    
    /// Protocol version
    pub version: u32,
}

/// ICP Account identifier
#[derive(Clone, Debug)]
pub struct Account {
    pub owner: Vec<u8>,         // -> Principal bytes (29 bytes typically)
    pub subaccount: Vec<u8>,    // -> Optional subaccount (0 or 32 bytes)
}

/// Public noticeboard hint derived from (Lm_R, Om_R, account, deposit_id)
/// To be stored on-chain next to a capsule so that wallets can quickly 
/// identify transfers for a given account without revealing Lm/Om themselves
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeHint {
    /// Account tag
    /// SHA3-256('ICPP:acct-tag:v1' || version || owner || subaccount)
    pub account_tag: [u8; 32],

    /// Bucket tag
    /// SHA3-256('ICPP:bucket-tag:v1' || version || Lm_R || Om_R || deposit_id)
    pub bucket_tag: [u8; 32],

    /// Short checksum over (account_tag || bucket_tag) 
    /// to detect corruption
    pub checksum: [u8; 16],
}

/// Aggregate cryptographic parameters 
/// used by the pICP crypto engine
#[derive(Clone)]
pub struct CryptoParams {
    pub rdmpf: RDMPFParams,
    pub sgp_fe_pp: Option<SgpFEParams>,
    pub sgp_fe_sk: Option<SgpFEKey>,
}

impl CryptoParams {
    /// Production parameters for 
    /// off-chain and CLI usage
    pub fn production() -> Self {
        let rdmpf = RDMPFParams::production();
        CryptoParams {
            rdmpf,
            sgp_fe_pp: None,
            sgp_fe_sk: None,
        }
    }

    /// Convenience constructor for environments that 
    /// already obtained an SgpFE key pair from some 
    /// high-entropy seed
    pub fn with_sgp_fe(
        rdmpf: RDMPFParams,
        pp: SgpFEParams,
        sk: SgpFEKey,
    ) -> Self {
        CryptoParams {
            rdmpf,
            sgp_fe_pp: Some(pp),
            sgp_fe_sk: Some(sk),
        }
    }

    /// Borrow both SgpFE public parameters 
    /// and master secret
    pub fn sgp_fe(&self) -> Result<(&SgpFEParams, &SgpFEKey), String> {
        match (&self.sgp_fe_pp, &self.sgp_fe_sk) {
            (Some(pp), Some(sk)) => Ok((pp, sk)),
            _ => Err(
                "SgpFE not initialised".to_owned()
            ),
        }
    }
}

/// Derive long-term secrets (Lm_R, Om_R) for a given account 
/// from a  user-specific master key and the current parameters
///
/// master_key ~ PIN-derived secret (never stored on canister)
/// account    ~ ICP ledger account id (owner + subaccount)
///
/// Security:
/// - 'master_key' must be uniformly random (e.g. derived from 
///    BIP-39 mnemonic or equivalent)
/// - Different accounts under the same master_key yield different
///   Lm/Om because account bytes are included
/// - Lm/Om are mapped into [1, phi-1] to avoid zero
pub fn derive_long_term_secrets(
    master_key: &[u8],
    account: &Account,
    rdmpf: &RDMPFParams,
) -> (BigUint, BigUint) {
    // Hash for Lm
    let lambda_hash = {
        let mut hasher = Sha3_256::new();
        hasher.update(master_key);
        hasher.update(b"ICPP:lambda:v1");
        hasher.update(&account.owner);
        hasher.update(&account.subaccount);
        hasher.finalize()
    };

    // Hash for Om
    let omega_hash = {
        let mut hasher = Sha3_256::new();
        hasher.update(master_key);
        hasher.update(b"ICPP:omega:v1");
        hasher.update(&account.owner);
        hasher.update(&account.subaccount);
        hasher.finalize()
    };

    // Map hashes to scalars 
    // in [1, phi-1]
    let one = BigUint::from(1u32);
    let phi_minus_one = &rdmpf.phi - &one;

    let mut lambda = BigUint::from_bytes_be(&lambda_hash);
    lambda %= &phi_minus_one;
    lambda += &one;

    let mut omega = BigUint::from_bytes_be(&omega_hash);
    omega %= &phi_minus_one;
    omega += &one;

    (lambda, omega)
}

/// Derive a noticeboard hint for a given account and deposit
///
/// - Lm and Om are the long-term secrets for the account
///   derived via 'derive_long_term_secrets'
/// - 'account' is the ledger account (owner + subaccount)
/// - 'deposit_id' is a 32-byte identifier extracted from the inner payload
/// - 'rdmpf' provides protocol versioning + domain separation
pub fn derive_notice_hint(
    lambda: &BigUint,
    omega: &BigUint,
    account: &Account,
    deposit_id: &[u8; 32],
    rdmpf: &RDMPFParams,
) -> NoticeHint {
    // account_tag
    // SHA3-256('ICPP:acct-tag:v1' || version || owner || subaccount)
    let mut acct_hasher = Sha3_256::new();
    acct_hasher.update(b"ICPP:acct-tag:v1");
    acct_hasher.update(&rdmpf.version.to_be_bytes());
    acct_hasher.update(&account.owner);
    acct_hasher.update(&account.subaccount);
    let acct_hash = acct_hasher.finalize();
    let mut account_tag = [0u8; 32];
    account_tag.copy_from_slice(&acct_hash[..32]);

    // bucket_tag
    // SHA3-256('ICPP:bucket-tag:v1' || version || Lm_R || Om_R || deposit_id)
    let mut bucket_hasher = Sha3_256::new();
    bucket_hasher.update(b"ICPP:bucket-tag:v1");
    bucket_hasher.update(&rdmpf.version.to_be_bytes());
    bucket_hasher.update(&lambda.to_bytes_be());
    bucket_hasher.update(&omega.to_bytes_be());
    bucket_hasher.update(deposit_id);
    let bucket_hash = bucket_hasher.finalize();
    let mut bucket_tag = [0u8; 32];
    bucket_tag.copy_from_slice(&bucket_hash[..32]);

    // checksum
    // SHA3-256('ICPP:hint-checksum:v1' || account_tag || bucket_tag)[0..16]
    let mut chk_hasher = Sha3_256::new();
    chk_hasher.update(b"ICPP:hint-checksum:v1");
    chk_hasher.update(&account_tag);
    chk_hasher.update(&bucket_tag);
    let chk_hash = chk_hasher.finalize();

    let mut checksum = [0u8; 16];
    checksum.copy_from_slice(&chk_hash[..16]);

    NoticeHint {
        account_tag,
        bucket_tag,
        checksum,
    }
}

/// Derive notice hint from CSRN 
/// (unlinkable version)
pub fn derive_notice_hint_csrn(
    csrn: &[u8; 32],
    deposit_id: &[u8; 32],
    rdmpf: &RDMPFParams,
) -> NoticeHint {
    // csrn_tag -> SHA3-256('ICPP:csrn-tag:v1' || version || csrn)
    let mut csrn_hasher = Sha3_256::new();
    csrn_hasher.update(b"ICPP:csrn-tag:v1");
    csrn_hasher.update(&rdmpf.version.to_be_bytes());
    csrn_hasher.update(csrn);
    let csrn_hash = csrn_hasher.finalize();
    let mut account_tag = [0u8; 32];
    account_tag.copy_from_slice(&csrn_hash[..32]);

    // bucket_tag -> SHA3-256('ICPP:bucket-csrn:v1' || version || csrn || deposit_id)
    let mut bucket_hasher = Sha3_256::new();
    bucket_hasher.update(b"ICPP:bucket-csrn:v1");
    bucket_hasher.update(&rdmpf.version.to_be_bytes());
    bucket_hasher.update(csrn);
    bucket_hasher.update(deposit_id);
    let bucket_hash = bucket_hasher.finalize();
    let mut bucket_tag = [0u8; 32];
    bucket_tag.copy_from_slice(&bucket_hash[..32]);

    // checksum
    let mut chk_hasher = Sha3_256::new();
    chk_hasher.update(b"ICPP:hint-checksum:v1");
    chk_hasher.update(&account_tag);
    chk_hasher.update(&bucket_tag);
    let chk_hash = chk_hasher.finalize();

    let mut checksum = [0u8; 16];
    checksum.copy_from_slice(&chk_hash[..16]);

    NoticeHint {
        account_tag,
        bucket_tag,
        checksum,
    }
}

/// Check whether a given hint matches 
/// Lm_R, Om_R, account and deposit_id
/// under the current RDMPF parameters
pub fn check_notice_hint_for_account(
    hint: &NoticeHint,
    lambda: &BigUint,
    omega: &BigUint,
    account: &Account,
    deposit_id: &[u8; 32],
    rdmpf: &RDMPFParams,
) -> bool {
    let expected = derive_notice_hint(lambda, omega, account, deposit_id, rdmpf);
    hint == &expected
}

impl RDMPFParams {
    /// Number of bits per matrix entry 
    /// exposed to the SGP FE layer
    /// (entries are genuinely sampled 
    /// from [0, 2^6) at generation time)

    pub const SGP_FE_ENTRY_BITS: u32 = 6;

    /// Bitlength of the FE output for 
    /// a single product P[i,ℓ] * Q[m,k]
    pub const SGP_FE_VALUE_BITS: u32 = 2 * Self::SGP_FE_ENTRY_BITS;

    /// Parameterization
    /// dim=64, p=192-bit safe prime
    pub fn production() -> Self {
        // Generated on: 2025-11-12T17:46:30.742308254+00:00
        // Safe prime: p = 2q + 1 where q is also prime
        // Bit length: 192 bits
        // Commitment: 7751e4dd6bad4ea43025df6022a23e1c1870f017f0fe1ca1990fd77e031a190c
        let p = BigUint::parse_bytes(
            b"5849654246768679574805475717474214619312947905955131683963",
            10
        ).expect("Invalid prime constant");

        let phi = &p - BigUint::one();

        let params = RDMPFParams {
            p,
            phi,
            dim: 6,
            version: 1,
        };

        // Verify at runtime
        verify_production_params(&params)
            .expect("Production parameter verification failed");

        params
    }

    /// Initialise SGP-based FE parameters and 
    /// key for these RDMPF parameters
    /// - Uses dim from self (so SGP dimension n = dim^2)
    /// - Uses a CSPRNG (OsRng) to seed MIRACL's RAND
    /// - Returns (public params, secret key) for SgpFE
    pub fn init_sgp_fe(&self, bound: BigInt) -> (SgpFEParams, SgpFEKey) {
        let dim = self.dim;
        let n = dim * dim;

        let mut seed = [0u8; 128];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut seed);

        let mut mir_rng = RAND_impl::new();
        mir_rng.clean();
        mir_rng.seed(seed.len(), &seed);

        let sgp = Sgp::new(n);
        let (msk, pk) = sgp.generate_sec_key(&mut mir_rng);

        let fe_pp = SgpFEParams {
            dim,
            bound,
            sgp,
            pk,
        };

        let fe_sk = SgpFEKey { msk };

        (fe_pp, fe_sk)
    }

    /// Derive a deterministic 32-byte seed for SgpFE from these RDMPF params
    /// Ensures that create_transfer and retrieve_transfer_with_capability
    /// use the SAME FE public params and key as long as 'params' is the same
    pub fn sgp_fe_seed(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        hasher.update(b"ICPP:sgp-fe:rdmpf:v1");
        hasher.update(&self.p.to_bytes_be());
        hasher.update(&self.phi.to_bytes_be());
        hasher.update(&(self.dim as u64).to_be_bytes());
        hasher.update(&self.version.to_be_bytes());

        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        seed
    }

    /// Deterministic SgpFE keygen -> derive seed from
    /// RDMPFParams then call the seeded variant
    pub fn init_sgp_fe_deterministic(&self, bound: BigInt) -> (SgpFEParams, SgpFEKey) {
        let seed = self.sgp_fe_seed();
        self.init_sgp_fe_from_seed(bound, &seed)
    }

    /// Seeded variant of 
    /// SGP-based FE keygen
    pub fn init_sgp_fe_from_seed(
        &self,
        bound: BigInt,
        seed: &[u8],
    ) -> (SgpFEParams, SgpFEKey) {
        let dim = self.dim;
        let n = dim * dim;

        let mut mir_rng = RAND_impl::new();
        mir_rng.clean();
        mir_rng.seed(seed.len(), seed);

        let sgp = Sgp::new(n);
        let (msk, pk) = sgp.generate_sec_key(&mut mir_rng);

        let fe_pp = SgpFEParams {
            dim,
            bound,
            sgp,
            pk,
        };

        let fe_sk = SgpFEKey { msk };

        (fe_pp, fe_sk)
    }

    /// Upper bound on matrix entries 
    /// given to SGP FE
    pub fn sgp_entry_bound() -> BigUint {
        BigUint::from(1u32) << Self::SGP_FE_ENTRY_BITS
    }

    /// Canonical upper bound on |P[i,l] * Q[m,k]| 
    /// given n-bit entries
    pub fn sgp_fe_default_bound() -> BigInt {
        BigInt::from(1u64 << Self::SGP_FE_VALUE_BITS)
    }
}

/// Derive user-specific bases from CSRN seed
/// Provides per-user diversity without storage 
/// overhead or account linkability
pub fn derive_user_bases(
    seed: &[u8; 32],
    params: &RDMPFParams,
) -> Result<(Matrix, Matrix), String> {
    
    // ----------------------------------------------
    // Use provided CSRN seed directly (CSRN already 
    // incorporates domain separation and randomness)
    // ----------------------------------------------
    
    // Generate near-rank-deficient bases
    let mut rng = ChaCha20Rng::from_seed(*seed);
    
    let BaseX = generate_rank_deficient(
        params.dim,
        params.dim - 1, 
        &params.p,
        &mut rng,
    )?;
    
    let BaseY = generate_rank_deficient(
        params.dim,
        params.dim - 1,
        &params.p,
        &mut rng,
    )?;
    
    Ok((BaseX, BaseY))
}

/// Generate rank-deficient matrix
/// Creates matrix with specified 
/// rank by construction
fn generate_rank_deficient(
    dim: usize,
    target_rank: usize,
    p: &BigUint,
    rng: &mut impl rand::Rng,
) -> Result<Matrix, String> {
    // Entries will live in [0, 2^6)
    // independent of p
    let entry_bound = RDMPFParams::sgp_entry_bound();

    // Generate target_rank random 
    // basis vectors with small entries
    let mut basis: Vec<Vec<BigUint>> = Vec::with_capacity(target_rank);
    for _ in 0..target_rank {
        let vec: Vec<BigUint> = (0..dim)
            .map(|_| rng.gen_biguint_below(&entry_bound))
            .collect();
        basis.push(vec);
    }

    // Fill remaining rows as linear combinations 
    // of the basis with small coefficients
    let mut matrix = basis.clone();
    for _ in target_rank..dim {
        let mut row = vec![BigUint::zero(); dim];
        for j in 0..dim {
            let mut sum = BigUint::zero();
            for basis_vec in &basis {
                let coeff = rng.gen_biguint_below(&entry_bound);
                sum += &coeff * &basis_vec[j];
            }
            // Reduce mod p for safety
            // (numerically sum << p anyway)
            row[j] = sum % p;
        }
        matrix.push(row);
    }

    // Shuffle rows
    for i in (1..matrix.len()).rev() {
        let j = rng.gen_biguint_below(&BigUint::from(i + 1)).try_into().unwrap();
        matrix.swap(i, j);
    }
    
    Ok(matrix)
}

/// Map a 32-byte ephemeral seed 
/// into a scalar in [1, phi-1]
/// (Used for per-transfer ephemeral 
/// secrets)
pub fn scalar_from_seed(seed: &[u8], rdmpf: &RDMPFParams) -> BigUint {
    let mut x = BigUint::from_bytes_be(seed);
    let one = BigUint::one();
    let phi_minus_one = &rdmpf.phi - &one;

    // x ∈ [0, phi-2]
    x %= &phi_minus_one;
    // shift into [1, phi-1]
    x += &one;
    x
}

/// Generate ephemeral W from 
/// seed with full-rank guarantee
pub fn generate_W(
    seed: &[u8; 32],
    params: &RDMPFParams,
) -> Result<Matrix, String> {
    
    let mut rng = ChaCha20Rng::from_seed(*seed);
    
    // Generate random matrix 
    // and verify full-rank
    for attempt in 0u8..100 {
        let W = random_matrix(params.dim, &params.p, &mut rng);
        
        // Quick determinant check
        if is_full_rank(&W, &params.p) {
            return Ok(W);
        }
        
        // Mix attempt counter into RNG state for diversity
        // (defense-in-depth against pathological RNG sequences)
        let mut reseed = [0u8; 32];
        rng.fill_bytes(&mut reseed);
        reseed[0] ^= attempt;
        rng = ChaCha20Rng::from_seed(reseed);
    }
    Err("Failed to generate full-rank W".to_string())
}

/// Random matrix 
/// over Z_p
fn random_matrix(
    dim: usize,
    p: &BigUint,
    rng: &mut impl rand::Rng,
) -> Matrix {
    let entry_bound = RDMPFParams::sgp_entry_bound();

    (0..dim)
        .map(|_| {
            (0..dim)
                .map(|_| rng.gen_biguint_below(&entry_bound) % p)
                .collect()
        })
        .collect()
}

/// Check if matrix is full rank
/// (uses simple Gaussian elimination)
fn is_full_rank(matrix: &Matrix, p: &BigUint) -> bool {
    let dim = matrix.len();
    let mut m = matrix.clone();
    
    for i in 0..dim {
        // Find pivot
        let mut pivot_row = i;
        for j in (i + 1)..dim {
            if m[j][i] > m[pivot_row][i] {
                pivot_row = j;
            }
        }
        
        if m[pivot_row][i].is_zero() {
            // Singular
            return false;
        }
        
        // Swap rows
        if pivot_row != i {
            m.swap(i, pivot_row);
        }
        
        // Eliminate below
        let pivot = &m[i][i].clone();
        
        // Handle Option 
        // from mod_inverse
        let pivot_inv = match mod_inverse(pivot, p) {
            Some(inv) => inv,
            // Not invertible
            None => return false, 
        };
        
        for j in (i + 1)..dim {
            let factor = (&m[j][i] * &pivot_inv).rem(p);
            for k in i..dim {
                let sub = (&factor * &m[i][k]).rem(p);
                m[j][k] = if m[j][k] >= sub {
                    (&m[j][k] - &sub).rem(p)
                } else {
                    (p + &m[j][k] - &sub).rem(p)
                };
            }
        }
    }
    
    // Check diagonal 
    // is non-zero
    (0..dim).all(|i| !m[i][i].is_zero())
}

/// Modular inverse 
/// via extended GCD
fn mod_inverse(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    // Convert to BigInt for extended_gcd 
    // (handles negative coefficients)
    let a_int = a.to_bigint()?;
    let p_int = p.to_bigint()?;
    
    let gcd_result = a_int.extended_gcd(&p_int);
    
    if !gcd_result.gcd.is_one() {
        return None;
    }
    
    // x coefficient may be negative 
    // so normalize to [0, p)
    let x = gcd_result.x;
    
    // Ensure positive result mod p
    let result = if x.is_negative() {
        // x < 0: compute p + x (since x is 
        // negative, this is p - |x|)
        (p_int + x).to_biguint()?
    } else {
        // x >= 0: reduce mod p to ensure x < p
        let x_uint = x.to_biguint()?;
        x_uint.rem(p)
    };   
    Some(result)
}