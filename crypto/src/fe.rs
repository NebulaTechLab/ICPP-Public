#![allow(non_snake_case)]

/// ===================================================
/// FE abstraction for RDMPF protocol
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

use num_bigint::{BigUint, BigInt, Sign};
use crate::rdmpf::Matrix;

/// SGP-based FE glue (inspired by Dufour-Sans, 
/// Gay and Pointcheval - NeurIPS 2019)
use crate::sgp::{Sgp, SgpSecKey, SgpPubKey, BigNumMatrix, SgpCipher};
use miracl_core::rand::{RAND, RAND_impl};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::sha3_256;

/// 4D index (j, l, m, k) 
/// for RDMPF exponents
pub type Index4 = (usize, usize, usize, usize);

/// Generic FE engine trait -> given encodings of P and Q, return
/// v_{il,mk} = P[i,l] * Q[m,k] (in the exponent space, e.g. as a BigUint)
pub trait FEEngine {
    type PP;
    type EncMatrix;
    type FuncKey;

    fn enc_matrix(pp: &Self::PP, mat: &Matrix) -> Self::EncMatrix;

    fn eval_entry(
        pp: &Self::PP,
        sk: &Self::FuncKey,
        hat_P: &Self::EncMatrix,
        hat_Q: &Self::EncMatrix,
        idx: Index4,
    ) -> BigUint;
}

// ======================
// PlainFE (testing only)
// ======================

/// PlainFE -> trivial FE engine for testing
/// EncMatrix = Matrix
/// FuncKey = (); eval_entry = P[i,l] * Q[m,k]
pub struct PlainFE;

impl FEEngine for PlainFE {
    type PP = ();              // -> No public params
    type EncMatrix = Matrix;   // -> Just the matrix itself
    type FuncKey = ();         // -> No functional key

    fn enc_matrix(_: &(), mat: &Matrix) -> Self::EncMatrix {
        mat.clone()
    }

    fn eval_entry(
        _: &(),
        _: &(),
        hat_P: &Self::EncMatrix,
        hat_Q: &Self::EncMatrix,
        (i, ell, m, k): Index4,
    ) -> BigUint {
        (&hat_P[i][ell] * &hat_Q[m][k]).clone()
    }
}

/// Active FE backend 
/// used by protocol
pub type ActiveFE = SgpFE;

// ==============================
// SgpFE - SGP-based quadratic FE
// ==============================

/// Public parameters for SgpFE
/// - dim: matrix dimension d, so SGP dimension is n = d**2
/// - bound: upper bound for |x'F y| used in SGP discrete-log decoding
/// - sgp: SGP engine instance configured for n = d**2
/// - pk: SGP public key
#[derive(Clone)]
pub struct SgpFEParams {
    pub dim: usize,
    pub bound: BigInt,
    pub sgp: Sgp,
    pub pk: SgpPubKey,
}

/// Functional key wrapper for SgpFE
/// This wraps the SGP master secret key msk 
/// Later this can become a threshold structure 
/// without changing the FEEngine interface
#[derive(Clone)]
pub struct SgpFEKey {
    pub msk: SgpSecKey,
}

/// Derive a 32-byte symmetric key from the SgpFE master 
/// secret using HKDF-SHA3 (via the existing crypto module)
impl SgpFEKey {
    pub fn derive_symmetric_key(&self, label: &[u8]) -> [u8; 32] {
        // Input key material -> bytes 
        // representing (s || t)
        let ikm = self.msk.to_ikm();

        // Domain-separate via label || IKM
        let mut buf = Vec::with_capacity(label.len() + ikm.len());
        buf.extend_from_slice(label);
        buf.extend_from_slice(&ikm);

        // SHA3-256 gives 
        // us a 32-byte key
        sha3_256(&buf)
    }
}

/// Encoded matrix type for SgpFE
/// Currently this just holds the plaintext Matrix
/// Once the registry moves to FE-encoded (P_R, Q_R)
/// this can be replaced with an actual ciphertext
/// or a handle into a ciphertext store
#[derive(Clone)]
pub struct SgpEncMatrix {
    pub mat: Matrix,
}

/// SgpFE -> FEEngine implementation backed by the SGP 
/// quadratic FE scheme
///
/// This is the vectorise + glue layer that makes SGP’s 
/// x'Fy model match ICPP’s (P, Q) matrices and RDMPF 
/// exponent oracles
pub struct SgpFE;

impl FEEngine for SgpFE {
    type PP = SgpFEParams;
    type EncMatrix = SgpEncMatrix;
    type FuncKey = SgpFEKey;

    fn enc_matrix(pp: &Self::PP, mat: &Matrix) -> Self::EncMatrix {
        let dim = pp.dim;
        assert_eq!(
            mat.len(),
            dim,
            "SgpFE::enc_matrix: unexpected number of rows -> got {}, expected {}",
            mat.len(),
            dim
        );
        for (row_idx, row) in mat.iter().enumerate() {
            assert_eq!(
                row.len(),
                dim,
                "SgpFE::enc_matrix -> row {} has len {}, expected {}",
                row_idx,
                row.len(),
                dim
            );
        }

        SgpEncMatrix { mat: mat.clone() }
    }

    fn eval_entry(
        pp: &Self::PP,
        sk: &Self::FuncKey,
        hat_P: &Self::EncMatrix,
        hat_Q: &Self::EncMatrix,
        (i, ell, m, k): Index4,
    ) -> BigUint {
        let dim = pp.dim;
        debug_assert!(i < dim && ell < dim && m < dim && k < dim);

        let P = &hat_P.mat;
        let Q = &hat_Q.mat;

        // 1. Flatten P and Q into x, y 
        //    (BigInt) in row-major order
        let n = dim * dim;

        let mut x: Vec<BigInt> = Vec::with_capacity(n);
        let mut y: Vec<BigInt> = Vec::with_capacity(n);

        for row in 0..dim {
            for col in 0..dim {
                let bytes = P[row][col].to_bytes_le();
                let bi = BigInt::from_bytes_le(Sign::Plus, &bytes);
                x.push(bi);
            }
        }

        for row in 0..dim {
            for col in 0..dim {
                let bytes = Q[row][col].to_bytes_le();
                let bi = BigInt::from_bytes_le(Sign::Plus, &bytes);
                y.push(bi);
            }
        }

        // 2. Build one-sparse F so that 
        //    x'Fy = x[idx_x] * y[idx_y] = P[i,l]*Q[m,k]
        let idx_x = i * dim + ell;
        let idx_y = m * dim + k;

        let mut coeffs = vec![0i64; n * n];
        let pos = idx_x * n + idx_y;
        coeffs[pos] = 1;

        let F = BigNumMatrix::new_ints(&coeffs, n, n);

        // 3. Generate a MIRACL RNG seeded from 
        //    a cryptographically secure RNG
        //    We use OsRng (which implements CryptoRng + RngCore) 
        //    as the entropy source and derive a MIRACL RAND 
        //    instance from it
        let mut seed = [0u8; 128];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut seed);

        let mut mir_rng = RAND_impl::new();
        mir_rng.clean();
        mir_rng.seed(seed.len(), &seed);

        // 4. Run SGP: ct = Enc(pk, x, y; mir_rng)
        let ct = pp.sgp.encrypt(&x, &y, &pp.pk, &mut mir_rng);

        // 5. FE key for this F
        let dk = pp.sgp.derive_fe_key(&sk.msk, F);

        // 6. Decrypt and convert BigInt -> BigUint
        let val_bigint = pp
            .sgp
            .decrypt(&ct, &dk, &pp.bound)
            .expect("SgpFE -> SGP decryption failed or value out of bound");

        let (sign, bytes) = val_bigint.to_bytes_le();
        debug_assert_ne!(
            sign,
            Sign::Minus,
            "SgpFE -> FE value is negative"
        );

        BigUint::from_bytes_le(&bytes)
    }
}

// Session-level 
// SGP functions
impl SgpFE {
    pub fn create_session_ct(
        pp: &SgpFEParams,
        P: &Matrix,
        Q: &Matrix,
    ) -> SgpCipher {
        let dim = pp.dim;
        let n = dim * dim;
       
        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);
        
        for row in P {
            for val in row {
                x.push(BigInt::from_bytes_le(Sign::Plus, &val.to_bytes_le()));
            }
        }
        
        for row in Q {
            for val in row {
                y.push(BigInt::from_bytes_le(Sign::Plus, &val.to_bytes_le()));
            }
        }

        let mut seed = [0u8; 128];
        OsRng.fill_bytes(&mut seed);
        let mut rng = RAND_impl::new();
        rng.clean();
        rng.seed(seed.len(), &seed);
        
        pp.sgp.encrypt(&x, &y, &pp.pk, &mut rng)

    }
    
    pub fn eval_with_ct(
        pp: &SgpFEParams,
        sk: &SgpFEKey,
        ct: &SgpCipher,
        (i, ell, m, k): Index4,
    ) -> BigUint {
        let dim = pp.dim;
        let n = dim * dim;
        
        let idx_x = i * dim + ell;
        let idx_y = m * dim + k;
        let mut coeffs = vec![0i64; n * n];
        coeffs[idx_x * n + idx_y] = 1;
        let F = BigNumMatrix::new_ints(&coeffs, n, n);
        
        let dk = pp.sgp.derive_fe_key(&sk.msk, F);
        let val = pp.sgp.decrypt(ct, &dk, &pp.bound).expect("SgpFE decrypt failed");
        
        BigUint::from_bytes_le(&val.to_bytes_le().1)
    }
}