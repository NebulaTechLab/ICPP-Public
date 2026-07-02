#![allow(non_snake_case)]

/// ===================================================
/// Transfer creation and retrieval
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.03
/// Date    -> 03 December 2025
/// Status  -> Public release ver:2 subver:0 release:03
///
/// Code developed by @Troesma
/// ===================================================

use num_bigint::BigUint;
use core::convert::TryInto;

use sha3::{Sha3_256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use zeroize::Zeroize;

use crate::{
    secrets::EphemeralSecret,
    params::{
        RDMPFParams,
        CryptoParams,
        NoticeHint,
        derive_user_bases,
        derive_notice_hint_csrn,
        generate_W,
        scalar_from_seed,
    },
    rdmpf::{
        Matrix,
        scalar_mult,
        rdmpf_with_oracle,
        encode_matrix,
        composition,
        RDMPFState,
        rdmpf_state_init,
        rdmpf_step,
    },
    crypto::{HKDF, HMACSHA3, AEADCipher, sha3_256},
    fe::{FEEngine, ActiveFE},
};

const ERR_CRYPTO_FAILED: &str = "ERR.CRYPTO_FAILED";

/// Derive auth_key from RDMPF-derived shared secret
/// and then hash for commitment
///
/// auth_key_raw = HKDF(key_AB, context, "ICPP:auth-key:v1")[0..32]
/// auth_key_hash_hex = hex(SHA3-256(auth_key_raw))
/// 
/// Preserves unlikability by binding auth_key to the cryptographic 
/// capability (successful decryption) rather than to recipient identity
/// ====================================================================
pub fn derive_auth_key_from_shared_secret(
    key_ab: &[u8; 32],
    context: &[u8],
) -> [u8; 32] {
    let (auth_key, _) = HKDF::derive_transport_keys(
        key_ab,
        context.try_into().unwrap_or(&[0u8; 32]),
        b"ICPP:auth-key:v1",
    );
    auth_key
}

/// Extract auth_key from decrypted inner payload
/// Inner format -> amount(8) || deposit_id(32) || i2_len(1) || i2_principal(1-29) || auth_key_hash_hex(64)
/// =======================================================================================================
pub fn extract_auth_key_hash_hex_from_inner(inner: &[u8]) -> Result<String, String> {
    if inner.len() < 64 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    let hex_start = inner.len() - 64;
    String::from_utf8(inner[hex_start..].to_vec())
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())
}

/// Extract amount from decrypted inner payload
/// Inner format -> amount(8) || deposit_id(32) || i2_len(1) || i2_principal(1-29) || auth_key_hash_hex(64)
/// =======================================================================================================
pub fn extract_amount_from_inner(inner: &[u8]) -> Result<u64, String> {
    if inner.len() < 8 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    
    let amount_bytes: [u8; 8] = inner[0..8]
        .try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;
    
    Ok(u64::from_be_bytes(amount_bytes))
}

/// Extract I2 principal from decrypted inner payload
/// Inner format -> amount(8) || deposit_id(32) || i2_len(1) || i2_principal(1-29) || auth_key_hash_hex(64)
/// (IC principals are 1-29 bytes so we reject malformed lengths early)
/// =======================================================================================================
pub fn extract_i2_from_inner(inner: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Minimum -> 8 (amount) + 32 (deposit_id) + 1 (i2_len) + 1 (min principal) + 64 (auth_key_hash_hex) = 106
    if inner.len() < 74 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    
    // Skip amount(8) and extract deposit_id from bytes 8..40
    let deposit_id = inner[8..40].to_vec();
    let i2_len = inner[40] as usize;
    
    if i2_len == 0 || i2_len > 29 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    
    // Verify total length -> 41 + i2_len + 64 (auth_key_hash_hex at end)
    if inner.len() < 41 + i2_len + 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    
    let i2_principal = inner[41..41 + i2_len].to_vec();
    
    Ok((deposit_id, i2_principal))
}

/// Transfer capsule 
/// (public, stored on-chain)
/// =========================
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct TransferCapsule {
    /// SgpFE-protected ephemeral matrices (P_eph, Q_eph)
    /// stored as an AEAD ciphertext under a key derived
    /// from the SgpFE master secret. This is the ONLY
    /// at-rest representation of (P_eph, Q_eph)
    pub eph_matrices_ct: Vec<u8>,

    /// Ephemeral W seed (public and 
    /// allowing Bob to regenerate W)
    pub W_seed: [u8; 32],

    /// Nonce for HKDF 
    /// key derivation
    pub nonce: [u8; 32],

    /// HMAC authentication tag 
    /// binding to context
    pub tag: [u8; 32],
}

/// Inner encrypted payload 
/// (opaque to intermediaries)
/// ==========================
#[derive(Clone, Debug)]
pub struct EncryptedPayload {
    /// AEAD ciphertext (includes 
    /// authentication tag)
    pub ciphertext: Vec<u8>,
}

/// Clamping
/// Use the system constant
/// =======================
fn clamp_matrix_entry_size(mat: &Vec<Vec<BigUint>>, p: &BigUint) -> Vec<Vec<BigUint>> {
    let mask = (BigUint::from(1u32) << RDMPFParams::SGP_FE_ENTRY_BITS) - 1u32;
    
    mat.iter()
        .map(|row|
            row.iter()
               .map(|v| (v & &mask) % p)
               .collect()
        )
        .collect()
}

/// -------------------------------------
/// Bob retrieves and decrypts a transfer
/// -------------------------------------
/// - capsule -> the TransferCapsule from intermediaries
/// - encrypted_payload -> the Inner ciphertext
/// - own_account -> Bob's Account
/// - own_lambda, own_omega -> Bob's long-term private scalars
/// - context -> associated data (must match what Alice used)
/// - params -> global RDMPF parameters
///
/// If 'capability' is non-empty, it is interpreted as
/// proof = HMAC_{K_auth}(context) and verified before the 
/// capsule tag/AEAD decrypt
/// ==========================================================
fn retrieve_transfer_with_capability(
    capsule: &TransferCapsule,
    encrypted_payload: &EncryptedPayload,
    csrn: &[u8; 32],                         // -> CSRN seed for base derivation
    context: &[u8],
    capability: &[u8],
    crypto_params: &CryptoParams,
) -> Result<Vec<u8>, String> {
    let params = &crypto_params.rdmpf;

    // STEP 1 -> Derive own bases
    //           (using CSRN)
    let (BaseX_own, BaseY_own) =
        derive_user_bases(csrn, params)
            .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 2 -> Compute own 
    //           public matrices
    let P_own_full = BaseX_own.clone();
    let Q_own_full = BaseY_own.clone();

    // Enforce 6-bit entries 
    // on own-side matrices
    let P_own = clamp_matrix_entry_size(&P_own_full, &params.p);
    let Q_own = clamp_matrix_entry_size(&Q_own_full, &params.p);

    // STEP 3 -> Regenerate 
    //           W from seed
    let W = generate_W(&capsule.W_seed, params)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 4 -> RDMPF key 
    //           agreement via FE
    //
    // First, recover (P_eph, Q_eph) from the AEAD-protected blob
    // stored in the capsule (at rest only 'eph_matrices_ct' exists)
    let mut k_eph = {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ICPP:eph-matrices:v1");
        hasher.update(csrn);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    };

    let eph_plain = AEADCipher::decrypt(&k_eph, &capsule.eph_matrices_ct, context)
	    .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    k_eph.zeroize();

    // Parse -> [4-byte BE len(P_eph_bytes)] || P_eph_bytes || Q_eph_bytes
    if eph_plain.len() < 4 {
    	return Err(ERR_CRYPTO_FAILED.to_owned());
    }
    let p_len_bytes: [u8; 4] = eph_plain[0..4]
        .try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_owned())?;
    let p_len = u32::from_be_bytes(p_len_bytes) as usize;

    if eph_plain.len() < 4 + p_len {
        return Err("Truncated encoding".to_owned());
    }

    let p_bytes = &eph_plain[4..4 + p_len];
    let q_bytes = &eph_plain[4 + p_len..];

    let P_eph_raw = crate::rdmpf::decode_matrix(p_bytes)
    	.map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;
    let Q_eph_raw = crate::rdmpf::decode_matrix(q_bytes)
    	.map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // Enforce 6-bit entries 
    // on recovered matrices
    let P_eph = clamp_matrix_entry_size(&P_eph_raw, &params.p);
    let Q_eph = clamp_matrix_entry_size(&Q_eph_raw, &params.p);

    // Use the active FE backend to provide 
    // entry-wise products to the RDMPF oracle
    let (pp, sk_master) = crypto_params
        .sgp_fe()
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let hat_P_eph = ActiveFE::enc_matrix(pp, &P_eph);
    let hat_Q_eph = ActiveFE::enc_matrix(pp, &Q_eph);

    let hat_P_own = ActiveFE::enc_matrix(pp, &P_own);
    let hat_Q_own = ActiveFE::enc_matrix(pp, &Q_own);

    let sk_eph_left = sk_master.clone();
    let sk_own_right = sk_master.clone();

    let dim = params.dim;

    // T1 = RDMPF(P_eph, W, Q_own)
    let T1 = rdmpf_with_oracle(dim, &W, &params.p, &params.phi, |j, ell, m, k| {
        ActiveFE::eval_entry(&pp, &sk_eph_left, &hat_P_eph, &hat_Q_own, (j, ell, m, k))
    }).map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // T2 = RDMPF(P_own, W, Q_eph)
    let T2 = rdmpf_with_oracle(dim, &W, &params.p, &params.phi, |j, ell, m, k| {
        ActiveFE::eval_entry(&pp, &sk_own_right, &hat_P_own, &hat_Q_eph, (j, ell, m, k))
    })
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let key_matrix = composition(&T1, &T2, &params.p, &params.phi)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let mut key_AB = sha3_256(&encode_matrix(&key_matrix));

    // STEP 5 -> Derive transport keys
    let (mut K_enc, mut K_auth) = HKDF::derive_transport_keys(&key_AB, &capsule.nonce, b"rdmpf-kem");
    
    // Zeroize shared secret 
    // immediately after key 
    // derivation
    key_AB.zeroize();

    // STEP 6 -> Verify capability 
    //           proof (if any)
    if !capability.is_empty() {
        if capability.len() != 32 {
            K_enc.zeroize();
            K_auth.zeroize();
            return Err(ERR_CRYPTO_FAILED.to_string());
        }

        let tag_bytes: &[u8; 32] = capability
            .try_into()
            .map_err(|_| {
                K_enc.zeroize();
                K_auth.zeroize();
                ERR_CRYPTO_FAILED.to_string()
            })?;

        if !HMACSHA3::verify_tag(&K_auth, context, tag_bytes) {
            K_enc.zeroize();
            K_auth.zeroize();
            return Err(ERR_CRYPTO_FAILED.to_string());
        }
    }

    // STEP 7 -> Verify HMAC tag
    if !HMACSHA3::verify_tag(&K_auth, context, &capsule.tag) {
        K_enc.zeroize();
        K_auth.zeroize();
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    // STEP 8 -> Decrypt payload
    let plaintext =
        AEADCipher::decrypt(&K_enc, &encrypted_payload.ciphertext, context)
            .map_err(|_e| {
                K_enc.zeroize();
                K_auth.zeroize();
                ERR_CRYPTO_FAILED.to_string()
            })?;

    // Zeroize keys 
    // after use
    K_enc.zeroize();
    K_auth.zeroize();

    Ok(plaintext)
}

/// Public API -> No capability proof enforced
/// Uses CSRN for base derivation
/// ==========================================
pub fn retrieve_transfer(
    capsule: &TransferCapsule,
    encrypted_payload: &EncryptedPayload,
    csrn: &[u8; 32],        // -> CSRN seed for base derivation
    context: &[u8],
    params: &CryptoParams,
) -> Result<Vec<u8>, String> {
    retrieve_transfer_with_capability(
        capsule,
        encrypted_payload,
        csrn,
        context,
        &[],                // -> No capability proof
        params,
    )
}

/// Result of verifying and decrypting a transfer capsule
///
/// Wrapper around 'retrieve_transfer_with_capability' that also
/// extracts the application-level 'deposit_id' and computes a 
/// simple transcript digest (it is purely cryptographic 
/// post-processing)
/// ============================================================
#[derive(Clone, Debug)]
pub struct VerifyOutput {
    /// Full decrypted Inner payload 
    /// (opaque to intermediaries)
    pub plaintext_inner: Vec<u8>,

    /// Application-level deposit identifier extracted 
    /// from the Inner payload (first 32 bytes)
    pub deposit_id: Vec<u8>,

    /// I2 canister principal extracted from Inner payload
    /// (bytes 33 to 33+len where len is byte 32)
    pub i2_principal: Vec<u8>,
}

/// Stateful structure used by the canister to split RDMPF+FE verification
/// across multiple update calls without recomputing FE encodings each time
/// =======================================================================
#[derive(Clone)]
pub struct VerifyRDMPFState {
    pub dim: usize,
    pub W: Matrix,

    // Incremental RDMPF state for 
    // T1 = RDMPF(P_eph, W, Q_own)
    pub rdmpf_state_t1: RDMPFState,

    // Incremental RDMPF state for 
    // T2 = RDMPF(P_own, W, Q_eph)
    pub rdmpf_state_t2: RDMPFState,

    // FE parameters and keys
    pub pp: <ActiveFE as FEEngine>::PP,
    pub sk_eph_left: <ActiveFE as FEEngine>::FuncKey,
    pub sk_own_right: <ActiveFE as FEEngine>::FuncKey,

    // FE-encrypted matrices
    pub hat_P_eph: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_Q_eph: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_P_own: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_Q_own: <ActiveFE as FEEngine>::EncMatrix,

    // Transport-layer data 
    // needed for finalization
    pub capsule_nonce: [u8; 32],
    pub capsule_tag: [u8; 32],
    pub encrypted_inner: Vec<u8>,
    pub context: Vec<u8>,
    pub capability: Vec<u8>,

    // Session ct for T1
    pub ct_t1: Option<crate::sgp::SgpCipher>,
    
    // Session ct for T2
    pub ct_t2: Option<crate::sgp::SgpCipher>,
}

/// Stateful structure used by the canister
/// to split RDMPF+FE deposit creation across 
/// multiple update calls
/// =========================================
#[derive(Clone)]
pub struct CreateRDMPFState {
    pub dim: usize,
    pub W: Matrix,

    // Incremental RDMPF state for 
    // T1 = RDMPF(P_eph, W, Q_rec)
    pub rdmpf_state_t1: RDMPFState,

    // Incremental RDMPF state for 
    // T2 = RDMPF(P_rec, W, Q_eph)
    pub rdmpf_state_t2: RDMPFState,

    // FE parameters and keys
    pub pp: <ActiveFE as FEEngine>::PP,
    pub sk_eph_left: <ActiveFE as FEEngine>::FuncKey,
    pub sk_rec_right: <ActiveFE as FEEngine>::FuncKey,

    // FE-encrypted matrices
    pub hat_P_eph: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_Q_eph: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_P_rec: <ActiveFE as FEEngine>::EncMatrix,
    pub hat_Q_rec: <ActiveFE as FEEngine>::EncMatrix,

    // Ephemeral matrices and 
    // seed needed for finalization
    pub P_eph: Matrix,
    pub Q_eph: Matrix,
    pub W_seed: [u8; 32],
    
    // Ephemeral scalars for hint derivation
    // (stored after RAII secrets are dropped)
    pub lambda_eph: BigUint,
    pub omega_eph: BigUint,
    
    // Recipient info for hint derivation
    pub deposit_id: [u8; 32],

    // Session ct for T1
    pub ct_t1: Option<crate::sgp::SgpCipher>,
    
    // Session ct for T2
    pub ct_t2: Option<crate::sgp::SgpCipher>,
}

/// Prepare FE+RDMPF state for multi-message verification on the canister
/// It mirrors the pre-RDMPF part of 'retrieve_transfer_with_capability'
/// - derives own bases
/// - regenerates W
/// - recovers (P_eph, Q_eph)
/// - builds FE encodings and functional keys
/// - initialises two RDMPFState instances for T1 and T2
/// =====================================================================
pub fn prepare_verify_state(
    capsule: &TransferCapsule,
    encrypted_payload: &EncryptedPayload,
    csrn: &[u8; 32],        // -> CSRN seed for base derivation
    context: &[u8],
    capability: &[u8],
    crypto_params: &CryptoParams,
) -> Result<(VerifyRDMPFState, VerifyOutput), String> {
    let params = &crypto_params.rdmpf;

    // STEP 1 -> Derive own bases
    let (BaseX_own, BaseY_own) =
        derive_user_bases(csrn, params)
            .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 2 -> Compute own public matrices 
    //           and clamp for SgpFE
    let P_own_full = BaseX_own.clone();
    let Q_own_full = BaseY_own.clone();

    let P_own = clamp_matrix_entry_size(&P_own_full, &params.p);
    let Q_own = clamp_matrix_entry_size(&Q_own_full, &params.p);

    // STEP 3 -> Regenerate W from seed
    let W = generate_W(&capsule.W_seed, params)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 4 -> Recover (P_eph, Q_eph) from 
    //           the AEAD-protected blob
    let mut k_eph = {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ICPP:eph-matrices:v1");
        hasher.update(csrn);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    };

    let eph_plain = AEADCipher::decrypt(&k_eph, &capsule.eph_matrices_ct, context)
        .map_err(|_e| {
            k_eph.zeroize();
            ERR_CRYPTO_FAILED.to_string()
        })?;
    
    k_eph.zeroize();

    // Parse -> [4-byte BE len(P_eph_bytes)] || P_eph_bytes || Q_eph_bytes
    if eph_plain.len() < 4 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    let p_len_bytes: [u8; 4] = eph_plain[0..4]
        .try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;
    let p_len = u32::from_be_bytes(p_len_bytes) as usize;

    if eph_plain.len() < 4 + p_len {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    let p_bytes = &eph_plain[4..4 + p_len];
    let q_bytes = &eph_plain[4 + p_len..];

    let P_eph_raw = crate::rdmpf::decode_matrix(p_bytes)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;
    let Q_eph_raw = crate::rdmpf::decode_matrix(q_bytes)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let P_eph = clamp_matrix_entry_size(&P_eph_raw, &params.p);
    let Q_eph = clamp_matrix_entry_size(&Q_eph_raw, &params.p);

    // STEP 5 -> FE encodings and functional keys
    let (pp, sk_master) = crypto_params
        .sgp_fe()
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let hat_P_eph = ActiveFE::enc_matrix(pp, &P_eph);
    let hat_Q_eph = ActiveFE::enc_matrix(pp, &Q_eph);
    let hat_P_own = ActiveFE::enc_matrix(pp, &P_own);
    let hat_Q_own = ActiveFE::enc_matrix(pp, &Q_own);

    let sk_eph_left = sk_master.clone();
    let sk_own_right = sk_master.clone();

    // STEP 6 -> Initialise RDMPF state 
    //           machines for T1 and T2
    let dim = params.dim;
    let rdmpf_state_t1 = rdmpf_state_init(dim);
    let rdmpf_state_t2 = rdmpf_state_init(dim);

    let state = VerifyRDMPFState {
        dim,
        W,
        rdmpf_state_t1,
        rdmpf_state_t2,
        pp: pp.clone(),
        sk_eph_left,
        sk_own_right,
        hat_P_eph,
        hat_Q_eph,
        hat_P_own,
        hat_Q_own,
        capsule_nonce: capsule.nonce,
        capsule_tag: capsule.tag,
        encrypted_inner: encrypted_payload.ciphertext.clone(),
        context: context.to_vec(),
        capability: capability.to_vec(),
        ct_t1: None,
        ct_t2: None,
    };

    // Placeholder
    let dummy_output = VerifyOutput {
        plaintext_inner: Vec::new(),
        deposit_id: Vec::new(),
        i2_principal: Vec::new(),
    };

    Ok((state, dummy_output))
}

/// Prepare FE+RDMPF state for multi-message 
/// deposit creation
/// - derives recipient's bases
/// - samples ephemeral secrets lambda, omega, W_seed
/// - builds P_eph, Q_eph, W
/// - clamps and FE-encrypts P_eph/Q_eph and P_rec/Q_rec
/// - initialises two RDMPFState instances for T1 and T2
/// ====================================================
pub fn prepare_create_state(
    csrn: &[u8; 32],
    deposit_id: &[u8; 32],
    crypto_params: &CryptoParams,
) -> Result<CreateRDMPFState, String> {
    let params = &crypto_params.rdmpf;

    // =====================================
    // EPHEMERAL SECRETS - RAII SCOPE BEGINS
    // =====================================

    let lambda_eph = EphemeralSecret::generate();
    let omega_eph = EphemeralSecret::generate();
    let W_seed_secret = EphemeralSecret::generate();

    // STEP 1 -> Derive recipient's bases
    let (BaseX_recipient, BaseY_recipient) =
        derive_user_bases(csrn, params)
            .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 2 -> Compute ephemeral 
    //           public matrices
    //
    // (convert ephemeral secrets into 
    // scalars in [1, phi-1] using 
    // the RDMPF modulus)
    let lambda = scalar_from_seed(lambda_eph.as_bytes(), params);
    let omega  = scalar_from_seed(omega_eph.as_bytes(), params);

    // Compute P_eph = lambda_eph * BaseX_recipient
    let P_eph_full = scalar_mult(&lambda, &BaseX_recipient, &params.phi);

    // Compute Q_eph = omega_eph * BaseY_recipient
    let Q_eph_full = scalar_mult(&omega, &BaseY_recipient, &params.phi);

    // Enforce 16-bit entries 
    // as required by SgpFE
    let P_eph = clamp_matrix_entry_size(&P_eph_full, &params.p);
    let Q_eph = clamp_matrix_entry_size(&Q_eph_full, &params.p);


    // STEP 3 -> Generate 
    //           ephemeral W
    let W_seed: [u8; 32] = *W_seed_secret.as_bytes();
    let W = generate_W(&W_seed, params)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // STEP 4 -> FE setup 
    //           (no RDMPF yet)
    let (pp_ref, sk_master) = crypto_params
        .sgp_fe()
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;
    let pp = pp_ref.clone();

    // Use &pp for enc_matrix calls
    let hat_P_eph = ActiveFE::enc_matrix(&pp, &P_eph);
    let hat_Q_eph = ActiveFE::enc_matrix(&pp, &Q_eph);

    let P_rec_full = BaseX_recipient.clone();
    let Q_rec_full = BaseY_recipient.clone();

    let P_rec = clamp_matrix_entry_size(&P_rec_full, &params.p);
    let Q_rec = clamp_matrix_entry_size(&Q_rec_full, &params.p);

    let hat_P_rec = ActiveFE::enc_matrix(&pp, &P_rec);
    let hat_Q_rec = ActiveFE::enc_matrix(&pp, &Q_rec);

    let sk_eph_left = sk_master.clone();
    let sk_rec_right = sk_master.clone();

    let dim = params.dim;

    // Incremental RDMPF 
    // state for T1 and T2
    let rdmpf_state_t1 = rdmpf_state_init(dim);
    let rdmpf_state_t2 = rdmpf_state_init(dim);

    Ok(CreateRDMPFState {
        dim,
        W,
        rdmpf_state_t1,
        rdmpf_state_t2,
        pp,
        sk_eph_left,
        sk_rec_right,
        hat_P_eph,
        hat_Q_eph,
        hat_P_rec,
        hat_Q_rec,
        P_eph,
        Q_eph,
        W_seed,
        lambda_eph: lambda.clone(),
        omega_eph: omega.clone(),
        deposit_id: *deposit_id,
        ct_t1: None,
        ct_t2: None,
    })
}

/// Incremental RDMPF stepping 
/// for deposit creation
/// ==========================
pub fn step_create_rdmpf(
    state: &mut CreateRDMPFState,
    crypto_params: &CryptoParams,
    max_iters: u32,
) -> Result<bool, String> {
    let rdmpf = &crypto_params.rdmpf;

    // T1 = RDMPF(P_eph, W, Q_rec)
    if state.rdmpf_state_t1.j < state.dim {
        // Create ct if needed (for tests)
        // or use existing (for canister)
        if state.ct_t1.is_none() {
            let ct = crate::fe::SgpFE::create_session_ct(
                &state.pp,
                &state.hat_P_eph.mat,
                &state.hat_Q_rec.mat,
            );
            state.ct_t1 = Some(ct);
        }
        
        let ct_t1 = state.ct_t1.as_ref().unwrap();
        
        let done_t1 = rdmpf_step(
            &mut state.rdmpf_state_t1,
            &state.W,
            &rdmpf.p,
            &rdmpf.phi,
            &mut |j, ell, m, k| {
                crate::fe::SgpFE::eval_with_ct(
                    &state.pp,
                    &state.sk_eph_left,
                    ct_t1,
                    (j, ell, m, k),
                )
            },
            max_iters,
        );
        return Ok(done_t1 && state.rdmpf_state_t2.j >= state.dim);
    }

    // T2 = RDMPF(P_rec, W, Q_eph)
    if state.rdmpf_state_t2.j < state.dim {
        // Create ct if needed (for tests)
        // or use existing (for canister)
        if state.ct_t2.is_none() {
            let ct = crate::fe::SgpFE::create_session_ct(
                &state.pp,
                &state.hat_P_rec.mat,
                &state.hat_Q_eph.mat,
            );
            state.ct_t2 = Some(ct);
        }
        
        let ct_t2 = state.ct_t2.as_ref().unwrap();
        
        let done_t2 = rdmpf_step(
            &mut state.rdmpf_state_t2,
            &state.W,
            &rdmpf.p,
            &rdmpf.phi,
            &mut |j, ell, m, k| {
                crate::fe::SgpFE::eval_with_ct(
                    &state.pp,
                    &state.sk_rec_right,
                    ct_t2,
                    (j, ell, m, k),
                )
            },
            max_iters,
        );
        return Ok(done_t2);
    }
    Ok(true)
}

/// Finalize deposit creation once 
/// RDMPF is complete
/// - compose T1 and T2 into key_matrix
/// - derive K_enc, K_auth
/// - HMAC tag over context
/// - AEAD-encrypt payload
/// - AEAD-encrypt (P_eph, Q_eph) into eph_matrices_ct
/// ==================================================
pub fn finalize_create_after_rdmpf(
    state: &CreateRDMPFState,
    payload: &[u8],
    context: &[u8],
    crypto_params: &CryptoParams,
    csrn: &[u8; 32],
) -> Result<(TransferCapsule, EncryptedPayload, NoticeHint), String> {
    let params = &crypto_params.rdmpf;

    // Compose RDMPF outputs
    let T1 = &state.rdmpf_state_t1.output;
    let T2 = &state.rdmpf_state_t2.output;

    let key_matrix = composition(T1, T2, &params.p, &params.phi)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let key_AB = sha3_256(&encode_matrix(&key_matrix));

    // Derive transport keys 
    // using CSRN from Storage
    let nonce: [u8; 32] = *csrn;
    let (K_enc, K_auth) =
        HKDF::derive_transport_keys(&key_AB, &nonce, b"rdmpf-kem");

    // Derive auth_key from shared 
    // secret (NOT from recipient identity)
    let auth_key_raw = derive_auth_key_from_shared_secret(&key_AB, context);

    // Commit via SHA3-256 and hex-encode for verification
    let auth_key_hash = sha3_256(&auth_key_raw);
    let auth_key_hash_hex = hex::encode(&auth_key_hash);

    // Build complete payload with auth_key_hash_hex appended
    // Final format -> amount(8) || deposit_id(32) || i2_len(1) || i2_principal(1-29) || auth_key_hash_hex(64)
    let mut complete_payload = Vec::with_capacity(payload.len() + auth_key_hash_hex.len());
    complete_payload.extend_from_slice(payload);
    complete_payload.extend_from_slice(auth_key_hash_hex.as_bytes());

    // Encrypt payload
    let ciphertext = AEADCipher::encrypt(&K_enc, &complete_payload, context)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    // HMAC tag to bind 
    // capsule to context
    let tag = HMACSHA3::compute_tag(&K_auth, context);

    // Encode P_eph and Q_eph 
    // into a single byte blob
    let P_eph_bytes = crate::rdmpf::encode_matrix(&state.P_eph);
    let Q_eph_bytes = crate::rdmpf::encode_matrix(&state.Q_eph);

    let mut eph_plain = Vec::with_capacity(4 + P_eph_bytes.len() + Q_eph_bytes.len());

    let p_len: u32 = P_eph_bytes
        .len()
        .try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;
    eph_plain.extend_from_slice(&p_len.to_be_bytes());
    eph_plain.extend_from_slice(&P_eph_bytes);
    eph_plain.extend_from_slice(&Q_eph_bytes);

    // Derive symmetric key 
    // from SgpFE master secret
    let k_eph = {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ICPP:eph-matrices:v1");
        hasher.update(csrn);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    };

    // AEAD-encrypt (P_eph, Q_eph) 
    // binding to context
    let eph_matrices_ct = AEADCipher::encrypt(&k_eph, &eph_plain, context)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let capsule = TransferCapsule {
        eph_matrices_ct,
        W_seed: state.W_seed,
        nonce,
        tag,
    };

    let encrypted_payload = EncryptedPayload { ciphertext };

    // Derive notice hint using CSRN
    // Bob discovers via RDMPF decapsulation
    // rather than identity matching
    let notice_hint = derive_notice_hint_csrn(
        csrn,
        &state.deposit_id,
        params,
    );

    Ok((capsule, encrypted_payload, notice_hint))
}

/// Execute a bounded chunk 
/// of the RDMPF+FE computation
/// ===========================
pub fn step_verify_rdmpf(
    state: &mut VerifyRDMPFState,
    crypto_params: &CryptoParams,
    max_iters: u32,
) -> Result<bool, String> {
    if max_iters == 0 {
        return Ok(false);
    }

    let rdmpf = &crypto_params.rdmpf;

    // T1 = RDMPF(P_eph, W, Q_own)
    if state.rdmpf_state_t1.j < state.dim {
        // Create ct if needed (for tests)
        // or use existing (for canister)
        if state.ct_t1.is_none() {
            let ct = crate::fe::SgpFE::create_session_ct(
                &state.pp,
                &state.hat_P_eph.mat,
                &state.hat_Q_own.mat,
            );
            state.ct_t1 = Some(ct);
        }
        
        let ct_t1 = state.ct_t1.as_ref().unwrap();
        
        let done_t1 = rdmpf_step(
            &mut state.rdmpf_state_t1,
            &state.W,
            &rdmpf.p,
            &rdmpf.phi,
            &mut |j, ell, m, k| {
                crate::fe::SgpFE::eval_with_ct(
                    &state.pp,
                    &state.sk_eph_left,
                    ct_t1,
                    (j, ell, m, k),
                )
            },
            max_iters,
        );
        return Ok(done_t1 && state.rdmpf_state_t2.j >= state.dim);
    }

    // T2 = RDMPF(P_own, W, Q_eph)
    if state.rdmpf_state_t2.j < state.dim {
        // Create ct if needed (for tests)
        // or use existing (for canister)
        if state.ct_t2.is_none() {
            let ct = crate::fe::SgpFE::create_session_ct(
                &state.pp,
                &state.hat_P_own.mat,
                &state.hat_Q_eph.mat,
            );
            state.ct_t2 = Some(ct);
        }
        
        let ct_t2 = state.ct_t2.as_ref().unwrap();
        
        let done_t2 = rdmpf_step(
            &mut state.rdmpf_state_t2,
            &state.W,
            &rdmpf.p,
            &rdmpf.phi,
            &mut |j, ell, m, k| {
                crate::fe::SgpFE::eval_with_ct(
                    &state.pp,
                    &state.sk_own_right,
                    ct_t2,
                    (j, ell, m, k),
                )
            },
            max_iters,
        );
        return Ok(done_t2);
    }
    Ok(true)
}

/// Finalize verification once RDMPF is complete
/// - compose T1 and T2 into key_matrix
/// - derive K_enc, K_auth
/// - enforce capability
/// - verify capsule tag
/// - decrypt payload and extract deposit_id
/// ============================================
pub fn finalize_verify_after_rdmpf(
    state: &VerifyRDMPFState,
    _base_output: &VerifyOutput,
    crypto_params: &CryptoParams,
) -> Result<VerifyOutput, String> {
    let rdmpf = &crypto_params.rdmpf;

    // Expect both RDMPFState 
    // outputs to be fully populated
    let T1 = &state.rdmpf_state_t1.output;
    let T2 = &state.rdmpf_state_t2.output;

    let key_matrix = composition(T1, T2, &rdmpf.p, &rdmpf.phi)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    let mut key_AB = sha3_256(&encode_matrix(&key_matrix));

    // Derive transport keys
    let (mut K_enc, mut K_auth) =
        HKDF::derive_transport_keys(&key_AB, &state.capsule_nonce, b"rdmpf-kem");

    // Zeroize shared 
    // secret immediately
    key_AB.zeroize();

    // Capability semantics
    if !state.capability.is_empty() {
        if state.capability.len() != 32 {
            K_enc.zeroize();
            K_auth.zeroize();
            return Err(ERR_CRYPTO_FAILED.to_string());
        }

        let tag_bytes: &[u8; 32] = state.capability.as_slice()
            .try_into()
            .map_err(|_| {
                K_enc.zeroize();
                K_auth.zeroize();
                "Capability proof conversion failed".to_string()
            })?;

        if !HMACSHA3::verify_tag(&K_auth, &state.context, tag_bytes) {
            K_enc.zeroize();
            K_auth.zeroize();
            return Err(ERR_CRYPTO_FAILED.to_string());
        }
    }

    // Capsule HMAC tag
    if !HMACSHA3::verify_tag(&K_auth, &state.context, &state.capsule_tag) {
        K_enc.zeroize();
        K_auth.zeroize();
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    // Decrypt payload
    let plaintext_inner = AEADCipher::decrypt(
        &K_enc,
        &state.encrypted_inner,
        &state.context,
    )
    .map_err(|_e| {
        K_enc.zeroize();
        K_auth.zeroize();
        ERR_CRYPTO_FAILED.to_string()
    })?;

    // Zeroize keys 
    // after use
    K_enc.zeroize();
    K_auth.zeroize();

    // Extract deposit_id and 
    // i2_principal from inner 
    // payload
    let (deposit_id, i2_principal) = extract_i2_from_inner(&plaintext_inner)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    Ok(VerifyOutput {
        plaintext_inner,
        deposit_id,
        i2_principal,
    })
}

/// Construct a capability proof tag for a given context
///
/// This keeps capability semantics centralized instead of having
/// callers roll their own HMAC logic.
///
/// NOTE -> This does NOT attempt to manage or derive 'K_auth' itself
/// as it's purely a formatting helper for the HMAC-based proof
/// =================================================================
pub fn make_capability_proof(
    k_auth: &[u8; 32],
    context: &[u8],
) -> [u8; 32] {
    HMACSHA3::compute_tag(k_auth, context)
}

/// Verify a capability proof tag for a given context
///
/// This wraps the capability semantics used by
/// 'retrieve_transfer_with_capability' so callers
/// do not need to reimplement HMAC length checks or 
/// further tag verification
/// =================================================
pub fn verify_capability_proof(
    k_auth: &[u8; 32],
    context: &[u8],
    proof: &[u8],
) -> Result<(), String> {
    if proof.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    let tag_bytes: &[u8; 32] = proof
        .try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

    if !HMACSHA3::verify_tag(k_auth, context, tag_bytes) {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    Ok(())
}

/// High-level verification helper using the current FE backend
/// - runs the RDMPF+FE KEM via 'retrieve_transfer_with_capability'
/// - extracts 'deposit_id' from the first 32 bytes of the Inner
///
/// 'capability' semantics:
/// - if empty ('&[]'), no capability is enforced
/// - if non-empty, must be a 32-byte 'HMAC_{K_auth}(context)' tag
/// ==============================================================
pub fn verify_capsule_plainfe(
    capsule: &TransferCapsule,
    encrypted_payload: &EncryptedPayload,
    csrn: &[u8; 32],                        // -> CSRN seed for base derivation
    context: &[u8],
    capability: &[u8],
    params: &CryptoParams,
) -> Result<VerifyOutput, String> {
    // 1. Run the existing KEM + AEAD + HMAC verification path
    //    to recover the Inner plaintext, enforcing capability
    //    proofs when provided
    let plaintext_inner = retrieve_transfer_with_capability(
        capsule,
        encrypted_payload,
        csrn,
        context,
        capability,
        params,
    )?;

    // 2. Extract deposit_id and i2_principal from Inner payload
    //    Format -> deposit_id (32) || i2_len (1) || i2_principal (i2_len)
    let (deposit_id, i2_principal) = extract_i2_from_inner(&plaintext_inner)
        .map_err(|_e| ERR_CRYPTO_FAILED.to_string())?;

    Ok(VerifyOutput {
        plaintext_inner,
        deposit_id,
        i2_principal,
    })
}

/// Derive AEAD key from recipient 
/// bases (for I2 decryption)
/// ==============================
pub fn derive_aead_key_from_bases(
    base_x: &Matrix,
    base_y: &Matrix,
    params: &RDMPFParams,
) -> Result<[u8; 32], String> {
    // Serialize -> bases
    let mut base_bytes = Vec::new();
    base_bytes.extend_from_slice(b"ICPP:aead-key:v1");
    base_bytes.extend_from_slice(&params.version.to_be_bytes());
    
    // Serialize -> base_x
    for row in 0..params.dim {
        for col in 0..params.dim {
            base_bytes.extend_from_slice(&base_x[row][col].to_bytes_be());
        }
    }
    
    // Serialize -> base_y
    for row in 0..params.dim {
        for col in 0..params.dim {
            base_bytes.extend_from_slice(&base_y[row][col].to_bytes_be());
        }
    }
    
    // Hash to 
    // derive key
    let mut hasher = Sha3_256::new();
    hasher.update(&base_bytes);
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    Ok(key)
}

/// AEAD decrypt 
/// (ChaCha20-Poly1305)
/// ===================
pub fn aead_decrypt(
    key: &[u8; 32],
    context: &[u8],
    encrypted_payload: &EncryptedPayload,
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Nonce -> first 12 
    // bytes of SHA3(context)
    let mut hasher = Sha3_256::new();
    hasher.update(context);
    let nonce_hash = hasher.finalize();
    let nonce = Nonce::from_slice(&nonce_hash[..12]);
    
    // Decrypt (no AAD in 
    // current implementation)
    cipher
        .decrypt(nonce, encrypted_payload.ciphertext.as_ref())
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())
}