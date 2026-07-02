#![allow(non_snake_case)]

/// ===================================================
/// Crypto canister code
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.03
/// Date    -> 3 December 2025
/// Status  -> Public release ver:2 subver:0 release:03
///
/// Code developed by @Troesma
/// ===================================================

use ic_cdk_macros::{init, update, query};
use candid::{CandidType, Deserialize, Principal};

use crate::params::{CryptoParams, RDMPFParams};
use crate::crypto::sha3_256;
use crate::{transfer, params};
use crate::TransferCapsule;
use crate::verification;
use crate::codec;

use ic_cdk::api::{self, time};
use ic_cdk::management_canister::{
    CanisterIdRecord,
    stop_canister,
    delete_canister,
    raw_rand,
};

use crate::randomness;

use std::collections::HashMap;
use std::cell::{RefCell, Cell};
use std::rc::Rc;

use zeroize::Zeroize;

use crate::transfer::{
    VerifyRDMPFState,
    VerifyOutput,
    prepare_verify_state,
    step_verify_rdmpf,
    finalize_verify_after_rdmpf,
    CreateRDMPFState,
    prepare_create_state,
    step_create_rdmpf,
    finalize_create_after_rdmpf,
};

use crate::sgp::init_bsgs_cache_chunked;

const ERR_CRYPTO_FAILED: &str = "ERR.CRYPTO_FAILED";
const ERR_SESSION_INVALID: &str = "ERR.SESSION_INVALID";

#[derive(CandidType, Deserialize, Clone)]
pub struct CreateTransferArgs {
    /// 32-byte deposit id 
    /// (as raw bytes)
    /// ==================
    pub deposit_id: Vec<u8>,

    /// I2 canister principal
    /// (encrypted into inner 
    /// payload for forward privacy)
    /// ============================
    pub i2_principal: Principal,

    /// Transfer amount
    /// ===============
    pub amount: u64,

    /// CSRN from Storage (32 bytes)
    /// Used as nonce for HKDF 
    /// key derivation
    /// ===========================
    pub csrn: Vec<u8>,
}

/// Candid types 
/// matching .did file
/// ==================
#[derive(CandidType, Deserialize, Clone)]
pub struct Account {
    owner: Vec<u8>,
    subaccount: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct VerifyArgs {
    // Serialized TransferCapsule 
    // (capsule header)
    // --------------------------
    pub capsule: Vec<u8>,

    // Capability proof 
    // (HMAC response)
    // ----------------
    pub capability: Vec<u8>,

    // Recipient account 
    // -----------------
    pub recipient_account: Account,

    // Associated data 
    // used in AEAD/HMAC
    // -----------------
    pub context: Vec<u8>,

    // Encrypted Inner payload 
    // (AEAD  ciphertext as 
    // produced by 'create_transfer')
    // ------------------------------
    pub encrypted_inner: Vec<u8>,

    // CSRN seed for base derivation
    // (32-byte seed provided by Bob
    // obtained from I2.finalize)
    // -----------------------------
    pub csrn: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct VerifyOk {
    // 32-byte deposit id 
    // (as raw bytes)
    // ------------------
    pub deposit_id: Vec<u8>,

    // Nullifier (present 
    // for shielded deposits)
    // ----------------------
    pub nullifier: Option<Vec<u8>>,

    // SHA3-256 digest of the 
    // capsule (for transcript binding)
    // --------------------------------
    pub transcript_digest: Vec<u8>,

    // Public hint (8 bytes padded to 80)
    // Used for Noticeboard discovery
    // ----------------------------------
    pub hint: Vec<u8>,

    // I2 canister principal extracted from inner payload
    // Bob uses this to know which canister to contact
    // --------------------------------------------------
    pub i2_principal: Vec<u8>,
}

type SessionId = u64;

#[derive(CandidType, Deserialize, Clone, Copy)]
enum VerifyStage {
    RDMPFRunning,
    Done,
}

struct VerifySession {
    args: VerifyArgs,
    stage: VerifyStage,
    state: Option<(VerifyRDMPFState, VerifyOutput)>,
    result: Option<Result<VerifyOk, String>>,
}

#[derive(CandidType, Deserialize, Clone, Copy)]
enum CreateStage {
    RDMPFRunning,
    Done,
}

struct CreateSession {
    args: CreateTransferArgs,
    stage: CreateStage,
    state: Option<CreateRDMPFState>,
    payload: Vec<u8>,
    context: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Copy)]
enum DecryptStage {
    RDMPFRunning,
    Done,
}

struct DecryptSession {
    capsule: Vec<u8>,
    encrypted_inner: Vec<u8>,
    csrn: [u8; 32],
    context: Vec<u8>,
    stage: DecryptStage,
    state: Option<VerifyRDMPFState>,
    base_output: Option<VerifyOutput>,
}

thread_local! {
    // RDMPF + FE params
    // -----------------
    static PARAMS: RefCell<Option<Rc<CryptoParams>>> = RefCell::new(None);

    // Router principal
    // ----------------
    static ROUTER: RefCell<Option<Principal>> = RefCell::new(None);

    // Multi-message 
    // verify sessions
    // ---------------
    static SESSIONS: RefCell<HashMap<SessionId, VerifySession>> =
        RefCell::new(HashMap::new());

    // Multi-message 
    // create sessions
    // ---------------
    static CREATE_SESSIONS: RefCell<HashMap<SessionId, CreateSession>> =
        RefCell::new(HashMap::new());

    // Decrypt sessions
    // ----------------
    static DECRYPT_SESSIONS: RefCell<HashMap<SessionId, DecryptSession>> =
        RefCell::new(HashMap::new());

    static NEXT_SESSION_ID: Cell<SessionId> = Cell::new(1);
}

thread_local! {
    static BSGS_CACHE_CHUNKS: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
    static BSGS_CACHE_READY: Cell<bool> = Cell::new(false);
    static EXPECTED_CHUNK_COUNT: Cell<u32> = Cell::new(0);
}

/// Derive a 128-byte seed for SgpFE from IC 
/// randomness + context (this is only used 
/// ON THE CANISTER)
/// ========================================
async fn derive_sgp_fe_seed() -> [u8; 128] {
    // 1. Raw entropy from the IC 
    //    (management canister)
    // --------------------------
    let raw_entropy: Vec<u8> = raw_rand()
        .await
        .expect("RNG failed");

    // 2. Bind seed to this 
    //    canister and this init
    // -------------------------
    let canister_id = api::canister_self();
    let canister_bytes = canister_id.as_slice();
    let t = time().to_be_bytes();

    // 3. Domain-separated 
    //    base material
    // -------------------
    let mut base = Vec::new();
    base.extend_from_slice(b"ICPP:sgp-fe-master:v1");
    base.extend_from_slice(&raw_entropy);
    base.extend_from_slice(canister_bytes);
    base.extend_from_slice(&t);

    // 4. Expand to 128 bytes via 
    //    SHA3-256 in counter mode
    // ---------------------------
    let mut seed = [0u8; 128];
    for (ctr, chunk) in seed.chunks_mut(32).enumerate() {
        let mut buf = base.clone();
        buf.extend_from_slice(&(ctr as u32).to_be_bytes());
        let digest = sha3_256(&buf);
        chunk.copy_from_slice(&digest);
    }
    seed
}

/// Lazy one-shot initialisation of 
/// RDMPF + SgpFE + AUTH_MASTER
/// (MUST NOT be invoked from #[init] 
/// or from #[pre_upgrade])
/// =================================
async fn ensure_crypto_params_initialised() {
    // Fast path -> already initialised
    // --------------------------------
    let already_init = PARAMS.with(|cell| cell.borrow().is_some());
    if already_init {
        return;
    }

    // Seed the RNG used by 
    // rand::thread_rng() 
    // from raw_rand()
    // --------------------
    let rand_bytes: Vec<u8> = raw_rand()
        .await
        .expect("raw_rand failed during crypto::ensure_crypto_params_initialised");

    assert!(
        rand_bytes.len() >= 32,
        "raw_rand returned less than 32 bytes"
    );

    randomness::seed_rng_from_seed_bytes(&rand_bytes[..32]);

    // 1. Base RDMPF 
    //    production 
    //    parameters
    // -------------
    let rdmpf = RDMPFParams::production();

    // 2. FE bound for 
    //    P[i,l] * Q[m,k]
    // ------------------
    let bound = RDMPFParams::sgp_fe_default_bound();

    // 3. Seed from IC 
    //    randomness + 
    //    context
    // ---------------
    let seed = derive_sgp_fe_seed().await;

    // 4. Initialise SgpFE using 
    //    the seeded helper
    // -------------------------
    let (sgp_fe_pp, sgp_fe_sk) = rdmpf.init_sgp_fe_from_seed(bound, &seed);

    // 5. Assemble CryptoParams 
    //    and store in thread-local
    // ----------------------------
    let params = Rc::new(CryptoParams::with_sgp_fe(rdmpf, sgp_fe_pp, sgp_fe_sk));

    PARAMS.with(|cell| {
        *cell.borrow_mut() = Some(params.clone());
    });

    // 6. Sanity-check production params (host builds only)
    //    On Wasm this is deterministic and uses no RNG
    // ----------------------------------------------------
    #[cfg(not(target_arch = "wasm32"))]
    {
        PARAMS.with(|cell| {
            let binding = cell.borrow();
            let params_ref = binding
                .as_ref()
                .expect("PARAMS not initialized");
            verification::verify_production_params(&params_ref.rdmpf)
                .expect("FATAL: Parameter verification failed");
        });
    }
}

/// Verify parameters 
/// at initialization
/// =================
#[init]
async fn init() {
    // RUNTIME GUARD –> immediately traps if
    // we accidentally deployed a test build
    // -------------------------------------
    crate::assert_production_configuration();
}

/// Configure or update the ROUTER principal
/// First call (when ROUTER is None) is allowed from any caller
/// Subsequent calls are only allowed by the CURRENT ROUTER
/// ===========================================================
#[update]
fn set_router(router: Principal) {
    let me = api::msg_caller();
    ROUTER.with(|cell| {
        let mut current = cell.borrow_mut();
        match *current {
            None => {
                // First-time 
                // configuration
                *current = Some(router);
            }
            Some(existing) => {
                if me != existing {
                    ic_cdk::trap("UNAUTHORIZED: Only current router can update router principal");
                }
                *current = Some(router);
            }
        }
    });
}

/// Pre-warm BSGS cache incrementally
/// Returns -> (ok, finished, error)
/// =================================
#[update]
fn prewarm_bsgs(max_iters: u64) -> (bool, bool, String) {
    // Bound must match FE decrypt expectations
    // 2^12 is the standard bound for 12-bit DL
    // ----------------------------------------
    let bound: u64 = (1 << 12) + 1;
    let (done, _iters) = init_bsgs_cache_chunked(bound, max_iters);
    (true, done, String::new())
}

/// Initialize BSGS cache provisioning (called by  Factory)
/// Prepares to receive cache in chunks
/// =======================================================
#[update]
fn init_cache_start(chunk_count: u32) -> Result<(), String> {
    if chunk_count == 0 {
        return Err("CACHE.ZERO_CHUNKS".to_string());
    }
    
    BSGS_CACHE_CHUNKS.with(|cell| {
        cell.borrow_mut().clear();
    });
    
    EXPECTED_CHUNK_COUNT.set(chunk_count);
    BSGS_CACHE_READY.set(false);
    
    Ok(())
}

/// Add a cache chunk (
/// called by Factory)
/// ==================
#[update]
fn add_cache_chunk(chunk: Vec<u8>) -> Result<(), String> {
    if chunk.is_empty() {
        return Err("CACHE.EMPTY_CHUNK".to_string());
    }
    
    BSGS_CACHE_CHUNKS.with(|cell| {
        let mut chunks = cell.borrow_mut();
        let expected = EXPECTED_CHUNK_COUNT.get() as usize;
        
        if chunks.len() >= expected {
            return Err("CACHE.TOO_MANY_CHUNKS".to_string());
        }
        
        chunks.push(chunk);
        Ok(())
    })
}

/// Finalize cache provisioning called by Factory
/// (deserializes and activates the BSGS cache)
/// =============================================
#[update]
fn init_cache_finalize() -> Result<(), String> {
    let expected = EXPECTED_CHUNK_COUNT.get() as usize;
    
    BSGS_CACHE_CHUNKS.with(|cell| {
        let chunks = cell.borrow();
        
        if chunks.len() != expected {
            return Err(format!(
                "CACHE.INCOMPLETE: expected {} chunks, got {}",
                expected,
                chunks.len()
            ));
        }
        
        // Concatenate 
        // all chunks
        // -----------
        let mut full_cache = Vec::new();
        for chunk in chunks.iter() {
            full_cache.extend_from_slice(chunk);
        }
        
        // Deserialize and install cache
        // (sgp.rs provides deserialization function)
        // ------------------------------------------
        crate::sgp::install_bsgs_cache(&full_cache)
            .map_err(|e| format!("CACHE.DESERIALIZE_FAILED: {}", e))?;
        
        BSGS_CACHE_READY.set(true);
        Ok(())
    })
}

/// Internal helper -> start a streamed deposit creation
/// - enforces 32-byte deposit_id
/// - prepares CreateRDMPFState
/// - stores payload/context derived from deposit_id
/// ====================================================
async fn create_start_impl(args: CreateTransferArgs) -> Result<SessionId, String> {
    ensure_crypto_params_initialised().await;

    if args.deposit_id.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    let i2_bytes = args.i2_principal.as_slice();
    if i2_bytes.is_empty() || i2_bytes.len() > 29 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    if args.csrn.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    // Inner payload (without auth_key —> derived after RDMPF in finalize)
    // Format: amount(8) || deposit_id(32) || i2_len(1) || i2_principal(1-29)
    // auth_key(32) appended by finalize_create_after_rdmpf
    // ----------------------------------------------------------------------
    let mut payload: Vec<u8> = Vec::with_capacity(8 + 32 + 1 + i2_bytes.len());
    payload.extend_from_slice(&args.amount.to_be_bytes());
    payload.extend_from_slice(&args.deposit_id);
    payload.push(i2_bytes.len() as u8);
    payload.extend_from_slice(i2_bytes);

    let context: Vec<u8> = args.deposit_id.clone();

    let sid = NEXT_SESSION_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    });

    CREATE_SESSIONS.with(|cell| {
        cell.borrow_mut().insert(
            sid,
            CreateSession {
                args,
                stage: CreateStage::RDMPFRunning,
                state: None,
                payload,
                context,
            },
        );
    });

    Ok(sid)
}

async fn verify_start_impl(args: VerifyArgs) -> Result<SessionId, String> {
    ensure_crypto_params_initialised().await;

    let sid = NEXT_SESSION_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    });

    SESSIONS.with(|cell| {
        cell.borrow_mut().insert(
            sid,
            VerifySession {
                args,
                stage: VerifyStage::RDMPFRunning,
                state: None,
                result: None,
            },
        );
    });

    Ok(sid)
}

/// ========================
/// Public Candid-facing API
/// ========================

/// Start multi-message deposit creation
/// Returns (ok?, session_id, error_message)
/// ========================================
#[update]
async fn create_start(args: CreateTransferArgs) -> (bool, SessionId, String) {
    match create_start_impl(args).await {
        Ok(sid) => (true, sid, String::new()),
        Err(e) => (false, 0, e),
    }
}

/// Flat tuple
/// ==========
#[update]
async fn verify_start(args: VerifyArgs) -> (bool, SessionId, String) {
    match verify_start_impl(args).await {
        Ok(sid) => (true, sid, String::new()),
        Err(e)  => (false, 0, e),
    }
}

async fn verify_step_impl(session_id: SessionId, max_iters: u32) -> Result<bool, String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| "PARAMS not initialized".to_string())?;

    SESSIONS.with(|cell| -> Result<bool, String> {
        let mut map = cell.borrow_mut();
        let session = map
            .get_mut(&session_id)
            .ok_or_else(|| "VERIFY.SESSION_NOT_FOUND".to_string())?;

        match session.stage {
            VerifyStage::RDMPFRunning => {
                // FIRST CALL -> no FE/RDMPF state yet
                // -----------------------------------
                if session.state.is_none() {
                    let args = &session.args;

                    // Deserialize capsule
                    // -------------------
                    let capsule: TransferCapsule =
                        deserialize_capsule(&args.capsule)?;

                    // Encrypted payload
                    // -----------------
                    let encrypted_payload = transfer::EncryptedPayload {
                        ciphertext: args.encrypted_inner.clone(),
                    };

                    // Long-term secrets for tests
                    // (wallet-derived in production)
                    // ------------------------------
                    let args = &session.args;

                    // Extract CSRN as array
                    // ---------------------
                    if args.csrn.len() != 32 {
                        return Err("Invalid CSRN length".to_string());
                    }
                    let mut csrn_array = [0u8; 32];
                    csrn_array.copy_from_slice(&args.csrn[..32]);

                    // Prepare FE + RDMPF state 
                    // and base VerifyOutput
                    let (state, base_output) = prepare_verify_state(
                        &capsule,
                        &encrypted_payload,
                        &csrn_array,
                        &args.context,
                        &args.capability,
                        &*params,
                    )?;

                    session.state = Some((state, base_output));
                    return Ok(false);
                }

                // SECOND CALL -> create session ct_t1
                // -----------------------------------
                {
                    let (ref mut state, _) = session
                        .state
                        .as_mut()
                        .ok_or_else(|| "VERIFY.NO_STATE".to_string())?;

                    if state.ct_t1.is_none() {

                        let ct = crate::fe::SgpFE::create_session_ct(
                            &state.pp,
                            &state.hat_P_eph.mat,
                            &state.hat_Q_own.mat,
                        );
                        state.ct_t1 = Some(ct);
                        
                        return Ok(false);
                    }
                }

                // THIRD CALL -> create session ct_t2
                // ----------------------------------
                {
                    let (ref mut state, _) = session
                        .state
                        .as_mut()
                        .ok_or_else(|| "VERIFY.NO_STATE".to_string())?;

                    if state.ct_t2.is_none() {

                        let ct = crate::fe::SgpFE::create_session_ct(
                            &state.pp,
                            &state.hat_P_own.mat,
                            &state.hat_Q_eph.mat,
                        );
                        state.ct_t2 = Some(ct);

                        return Ok(false);
                    }
                }

                // SUBSEQUENT CALLS -> RDMPF chunking only
                // ---------------------------------------
                let (ref mut state, _) = session
                    .state
                    .as_mut()
                    .ok_or_else(|| "VERIFY.NO_STATE".to_string())?;

                let done_rdmpf = step_verify_rdmpf(state, &params, max_iters)?;

                if done_rdmpf {
                    session.stage = VerifyStage::Done;
                }

                Ok(done_rdmpf)
            }
            VerifyStage::Done => Ok(true),
        }
    })
}

/// Internal helper: advance RDMPF for deposit creation
/// - On first call: state is already prepared by 'create_start_impl'
/// - Calls 'step_create_rdmpf' with a bounded 'max_iters'
/// - When RDMPF is done, finalizes and stores (capsule, inner)
/// =================================================================
async fn create_step_impl(session_id: SessionId, max_iters: u32) -> Result<bool, String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| "PARAMS not initialized".to_string())?;

    CREATE_SESSIONS.with(|cell| -> Result<bool, String> {
        let mut map = cell.borrow_mut();
        let session = map
            .get_mut(&session_id)
            .ok_or_else(|| "CREATE.SESSION_NOT_FOUND".to_string())?;

        match session.stage {
            CreateStage::RDMPFRunning => {
                // FIRST CALL -> no FE/RDMPF state yet
                // -----------------------------------
                if session.state.is_none() {
                    let args = &session.args;

                    // Use CSRN 
                    // from Storage
                    // ------------
                    let csrn_array: [u8; 32] = args.csrn.clone().try_into()
                        .map_err(|_| "CREATE.INVALID_CSRN".to_string())?;
                    
                    let mut deposit_id_arr = [0u8; 32];
                    deposit_id_arr.copy_from_slice(&args.deposit_id);

                    let state = prepare_create_state(&csrn_array, &deposit_id_arr, &*params)
                        .map_err(|e| format!("CREATE.PREPARE_STATE_FAILED:{}", e))?;

                    session.state = Some(state);

                    return Ok(false);
                }

                // SECOND CALL -> create session ct_t1
                // -----------------------------------
                let state = session
                    .state
                    .as_mut()
                    .ok_or_else(|| "CREATE.NO_STATE".to_string())?;

                if state.ct_t1.is_none() {
                    
                    let ct = crate::fe::SgpFE::create_session_ct(
                        &state.pp,
                        &state.hat_P_eph.mat,
                        &state.hat_Q_rec.mat,
                    );
                    state.ct_t1 = Some(ct);

                    return Ok(false);
                }

                // THIRD CALL -> create session ct_t2
                // ----------------------------------
                if state.ct_t2.is_none() {
                    
                    let ct = crate::fe::SgpFE::create_session_ct(
                        &state.pp,
                        &state.hat_P_rec.mat,
                        &state.hat_Q_eph.mat,
                    );
                    state.ct_t2 = Some(ct);

                    return Ok(false);
                }

                // SUBSEQUENT CALLS -> RDMPF chunking
                // ----------------------------------
                let done_rdmpf = step_create_rdmpf(state, &params, max_iters)?;
                           
                if done_rdmpf {
                    session.stage = CreateStage::Done;
                }
                Ok(done_rdmpf)
            }
            CreateStage::Done => Ok(true),
        }
    })
}

/// ===============
/// Public flat API
/// ===============

/// Multi-message verification
/// Returns (ok?, finished?, error_message)
/// ---------------------------------------
#[update]
async fn verify_step(session_id: SessionId, max_iters: u32) -> (bool, bool, String) {
    match verify_step_impl(session_id, max_iters).await {
        Ok(done) => (true, done, String::new()),
        Err(e)   => (false, false, e),
    }
}

/// Multi-message deposit creation
/// Returns (ok?, finished?, error_message)
/// ---------------------------------------
#[update]
async fn create_step(session_id: SessionId, max_iters: u32) -> (bool, bool, String) {
    match create_step_impl(session_id, max_iters).await {
        Ok(done) => (true, done, String::new()),
        Err(e)   => (false, false, e),
    }
}

/// Internal helper -> fetch final verify result
/// and drop the session when we're done with it
/// --------------------------------------------
async fn verify_result_impl(session_id: SessionId) -> Result<VerifyOk, String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| "PARAMS not initialized".to_string())?;

    SESSIONS.with(|cell| {
        let mut map = cell.borrow_mut();

        // Always consume 
        // the session entry
        // -----------------
        let mut session = map
            .remove(&session_id)
            .ok_or_else(|| "VERIFY.SESSION_NOT_FOUND".to_string())?;

        // If some path already computed and 
        // stored a result just return it
        // ---------------------------------
        if let Some(res) = session.result.take() {
            return res;
        }

        // If RDMPF wasn't completed this is a 
        // caller misuse (don't keep the session)
        // --------------------------------------
        if !matches!(session.stage, VerifyStage::Done) {
            return Err("VERIFY.NO_RESULT".to_string());
        }

        // RDMPF is done and we haven't finalized 
        // yet -> do it once then drop everything
        // --------------------------------------
        let (state, base_output) = session
            .state
            .take()
            .ok_or_else(|| "VERIFY.NO_STATE".to_string())?;

        // This block is exactly what lived in 
        // 'verify_step_impl' after RDMPF finished
        // ---------------------------------------
        let capsule: TransferCapsule =
            deserialize_capsule(&session.args.capsule)?;

        let args = &session.args;

        // Extract CSRN 
        // as array
        // ------------
        if args.csrn.len() != 32 {
            return Err("Invalid CSRN length".to_string());
        }
        let mut csrn_array = [0u8; 32];
        csrn_array.copy_from_slice(&args.csrn[..32]);

        let final_output =
            finalize_verify_after_rdmpf(&state, &base_output, &params)?;

        let transcript_digest =
            sha3_256(&session.args.capsule).to_vec();

        let nullifier = Some(
            sha3_256(
                &[&capsule.tag[..], &final_output.deposit_id[..]].concat()
            ).to_vec(),
        );

        // Extract deposit_id 
        // from final_output
        // ------------------
        let mut deposit_id_arr = [0u8; 32];
        if final_output.deposit_id.len() != 32 {
            return Err("Invalid deposit_id length".to_string());
        }

        deposit_id_arr.copy_from_slice(&final_output.deposit_id[..32]);
        
        let notice_hint = params::derive_notice_hint_csrn(
            &csrn_array,
            &deposit_id_arr,
            &params.rdmpf,
        );

        let hint_bytes = codec::encode_notice_hint(&notice_hint);

        let ok = VerifyOk {
            deposit_id: final_output.deposit_id.clone(),
            nullifier,
            transcript_digest,
            hint: hint_bytes.to_vec(),
            i2_principal: final_output.i2_principal.clone(),
        };

        Ok(ok)
    })
}

#[update]
async fn verify_result(session_id: SessionId) -> (bool, VerifyOk, String) {
    let result = match verify_result_impl(session_id).await {
        Ok(okm) => (true, okm, String::new()),
        Err(e)  => (
            false,
            VerifyOk {
                deposit_id: Vec::new(),
                nullifier: None,
                transcript_digest: Vec::new(),
                hint: Vec::new(),
                i2_principal: Vec::new(),
            },
            e,
        ),
    };
    
    // Trigger self-destruct after returning result
    // (async fire-and-forget -> caller gets response first)
    // -----------------------------------------------------
    if result.0 {
        ic_cdk::futures::spawn_017_compat(async {
            self_destruct().await;
        });
    }
    result
}

/// Stateless Oracle for I2
/// =======================
async fn decrypt_start_impl(
    capsule: Vec<u8>,
    encrypted_inner: Vec<u8>,
    csrn: Vec<u8>,
    context: Vec<u8>,
) -> Result<SessionId, String> {
    ensure_crypto_params_initialised().await;

    if csrn.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    if context.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }

    let csrn_array: [u8; 32] = csrn.try_into()
        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

    let sid = NEXT_SESSION_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    });

    DECRYPT_SESSIONS.with(|cell| {
        cell.borrow_mut().insert(
            sid,
            DecryptSession {
                capsule,
                encrypted_inner,
                csrn: csrn_array,
                context,
                stage: DecryptStage::RDMPFRunning,
                state: None,
                base_output: None,
            },
        );
    });

    Ok(sid)
}

/// Advance RDMPF for decrypt operation
/// - On first call -> prepares VerifyRDMPFState
/// - Creates ct_t1, ct_t2 in separate calls (chunking)
/// - Drives RDMPF with bounded iterations
/// ===================================================
async fn decrypt_step_impl(session_id: SessionId, max_iters: u32) -> Result<bool, String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| ERR_CRYPTO_FAILED.to_string())?;

    DECRYPT_SESSIONS.with(|cell| -> Result<bool, String> {
        let mut map = cell.borrow_mut();
        let session = map
            .get_mut(&session_id)
            .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

        match session.stage {
            DecryptStage::RDMPFRunning => {
                // FIRST CALL -> prepare state 
                // (no FE/RDMPF state yet)
                // ---------------------------
                if session.state.is_none() {
                    let transfer_capsule = codec::decode_transfer_capsule(&session.capsule)
                        .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

                    let encrypted_payload = transfer::EncryptedPayload {
                        ciphertext: session.encrypted_inner.clone(),
                    };

                    let (state, base_output) = prepare_verify_state(
                        &transfer_capsule,
                        &encrypted_payload,
                        &session.csrn,
                        &session.context,
                        &[],
                        &params,
                    )
                    .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

                    session.state = Some(state);
                    session.base_output = Some(base_output);

                    return Ok(false);
                }

                // SECOND CALL -> create session ct_t1
                // -----------------------------------
                {
                    let state = session
                        .state
                        .as_mut()
                        .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

                    if state.ct_t1.is_none() {
                        let ct = crate::fe::SgpFE::create_session_ct(
                            &state.pp,
                            &state.hat_P_eph.mat,
                            &state.hat_Q_own.mat,
                        );
                        state.ct_t1 = Some(ct);

                        return Ok(false);
                    }
                }

                // THIRD CALL -> create session ct_t2
                // ----------------------------------
                {
                    let state = session
                        .state
                        .as_mut()
                        .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

                    if state.ct_t2.is_none() {
                        let ct = crate::fe::SgpFE::create_session_ct(
                            &state.pp,
                            &state.hat_P_own.mat,
                            &state.hat_Q_eph.mat,
                        );
                        state.ct_t2 = Some(ct);

                        return Ok(false);
                    }
                }

                // SUBSEQUENT CALLS -> RDMPF chunking
                // ----------------------------------
                let state = session
                    .state
                    .as_mut()
                    .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

                let done_rdmpf = step_verify_rdmpf(state, &params, max_iters)
                    .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

                if done_rdmpf {
                    session.stage = DecryptStage::Done;
                }

                Ok(done_rdmpf)
            }
            DecryptStage::Done => Ok(true),
        }
    })
}

/// Decrypt result structure 
/// returned to I2
/// ========================
#[derive(CandidType, Deserialize, Clone)]
pub struct DecryptResult {
    /// Decrypted inner plaintext
    /// =========================
    pub plaintext: Vec<u8>,
    /// Amount extracted 
    /// from plaintext
    /// ================
    pub amount: u64,
    /// Auth key extracted from plaintext 
    /// (for local verification by I2)
    /// =================================
    pub auth_key_hash_hex: String,
}

async fn decrypt_result_impl(session_id: SessionId) -> Result<DecryptResult, String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| ERR_CRYPTO_FAILED.to_string())?;

    DECRYPT_SESSIONS.with(|cell| {
        let mut map = cell.borrow_mut();
        let mut session = map
            .remove(&session_id)
            .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;
        
        // Zeroize CSRN 
        // immediately
        // ------------
        session.csrn.zeroize();

        if !matches!(session.stage, DecryptStage::Done) {
            return Err(ERR_SESSION_INVALID.to_string());
        }

        let state = session
            .state
            .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

        let base_output = session
            .base_output
            .ok_or_else(|| ERR_SESSION_INVALID.to_string())?;

        // Finalize verification 
        // to get decrypted payload
        // ------------------------
        let output = finalize_verify_after_rdmpf(&state, &base_output, &params)
            .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

        // Extract amount 
        // from first 8 bytes
        // ------------------
        if output.plaintext_inner.len() < 8 {
            return Err(ERR_CRYPTO_FAILED.to_string());
        }
        let amount = u64::from_be_bytes(
            output.plaintext_inner[0..8]
                .try_into()
                .map_err(|_| ERR_CRYPTO_FAILED.to_string())?
        );

        // Extract auth_key_hash_hex 
        // from last 64 bytes (hex string)
        let hex_len = 64;
        if output.plaintext_inner.len() < hex_len {
            return Err(ERR_CRYPTO_FAILED.to_string());
        }
        let hex_start = output.plaintext_inner.len() - hex_len;
        let auth_key_hash_hex = String::from_utf8(output.plaintext_inner[hex_start..].to_vec())
            .map_err(|_| ERR_CRYPTO_FAILED.to_string())?;

        // Plaintext excludes 
        // the hash suffix
        // ------------------
        let plaintext = output.plaintext_inner[..hex_start].to_vec();

        Ok(DecryptResult {
            plaintext,
            amount,
            auth_key_hash_hex,
        })
    })
}

/// Start decrypt session
/// Returns (ok?, session_id, error_message)
/// ========================================
#[update]
async fn decrypt_start(
    capsule: Vec<u8>,
    encrypted_inner: Vec<u8>,
    csrn: Vec<u8>,
    context: Vec<u8>,
) -> (bool, SessionId, String) {
    match decrypt_start_impl(capsule, encrypted_inner, csrn, context).await {
        Ok(sid) => (true, sid, String::new()),
        Err(e) => (false, 0, e),
    }
}

/// Drive decrypt RDMPF computation (chunked)
/// Returns (ok?, done?, error_message)
/// =========================================
#[update]
async fn decrypt_step(session_id: SessionId, max_iters: u32) -> (bool, bool, String) {
    match decrypt_step_impl(session_id, max_iters).await {
        Ok(done) => (true, done, String::new()),
        Err(e) => (false, false, e),
    }
}

/// Get decrypt result
/// Returns (ok?, DecryptResult, error_message)
/// ===========================================
#[update]
async fn decrypt_result(session_id: SessionId) -> (bool, Option<DecryptResult>, String) {
    match decrypt_result_impl(session_id).await {
        Ok(result) => (true, Some(result), String::new()),
        Err(e) => (false, None, e),
    }
}

/// Internal helper -> fetch the final 
/// (capsule, encrypted_inner) once
/// 'create_step' has concluded
/// ==================================
async fn create_result_impl(session_id: SessionId) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    ensure_crypto_params_initialised().await;

    let params = PARAMS
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| "PARAMS not initialized".to_string())?;

    CREATE_SESSIONS.with(|cell| -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let mut map = cell.borrow_mut();

        // Always consume 
        // the session entry
        // -----------------
        let mut session = map
            .remove(&session_id)
            .ok_or_else(|| "CREATE.SESSION_NOT_FOUND".to_string())?;

        // If RDMPF wasn't completed 
        // this is a caller misuse
        // -------------------------
        if !matches!(session.stage, CreateStage::Done) {
            return Err("CREATE.NO_RESULT".to_string());
        }

        // RDMPF is done and we haven't 
        // finalized yet -> do it once
        // ----------------------------
        let state = session
            .state
            .take()
            .ok_or_else(|| "CREATE.NO_STATE".to_string())?;

        let csrn_array: [u8; 32] = session.args.csrn.clone().try_into()
            .map_err(|_| "Invalid CSRN".to_string())?;
        
        let (capsule, encrypted_payload, notice_hint) = finalize_create_after_rdmpf(
            &state,
            &session.payload,
            &session.context,
            &params,
            &csrn_array,
        ).map_err(|e| format!("CREATE.FINALIZE_FAILED:{}", e))?;

        // Canonical capsule encoding
        // --------------------------
        let capsule_bytes = codec::encode_transfer_capsule(&capsule);
        let inner_bytes   = encrypted_payload.ciphertext;

        // Encode hint (account_tag || bucket_tag || checksum)
        // ---------------------------------------------------
        let hint_bytes = codec::encode_notice_hint(&notice_hint).to_vec();

        Ok((capsule_bytes, inner_bytes, hint_bytes))
    })
}

/// Get the final (capsule, encrypted_inner, hint) for a create session
/// Returns (ok?, Capsule, Inner, Hint, error_message)
/// ===================================================================
#[update]
async fn create_result(session_id: SessionId) -> (bool, Vec<u8>, Vec<u8>, Vec<u8>, String) {
    match create_result_impl(session_id).await {
        Ok((capsule, inner, hint)) => (true, capsule, inner, hint, String::new()),
        Err(e)                     => (false, Vec::new(), Vec::new(), Vec::new(), e),
    }
}

/// Encrypt CSRN for Alice (called by Storage during init_csrn)
/// Wraps crypto::encrypt_csrn library function as IC endpoint
/// ===========================================================
#[update]
fn encrypt_csrn_for_transit(
    deposit_id: Vec<u8>,
    alice_principal: Vec<u8>,
    nonce: Vec<u8>,
    csrn: Vec<u8>,
) -> Result<Vec<u8>, String> {

    if nonce.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    if csrn.len() != 32 {
        return Err(ERR_CRYPTO_FAILED.to_string());
    }
    
    let nonce_array: [u8; 32] = nonce.try_into()
        .map_err(|_| "Failed to convert nonce".to_string())?;
    let csrn_array: [u8; 32] = csrn.try_into()
        .map_err(|_| "Failed to convert CSRN".to_string())?;
    
    crate::crypto::encrypt_csrn(
        &deposit_id,
        &alice_principal,
        &nonce_array,
        &csrn_array,
    )
}

/// Self-destruct this Crypto canister
/// (called after verify_result completes 
/// and Bob receives result)
/// =====================================
#[update]
async fn self_destruct() {
    // 1. Clear all 
    //    sensitive state
    // ------------------
    PARAMS.with(|cell| {
        *cell.borrow_mut() = None;
    });
    
    SESSIONS.with(|cell| {
        cell.borrow_mut().clear();
    });
    
    CREATE_SESSIONS.with(|cell| {
        cell.borrow_mut().clear();
    });

    DECRYPT_SESSIONS.with(|cell| {
        cell.borrow_mut().clear();
    });
    
    BSGS_CACHE_CHUNKS.with(|cell| {
        cell.borrow_mut().clear();
    });
    
    BSGS_CACHE_READY.set(false);
    
    // 2. Stop and delete this canister 
    //    via IC management API
    // --------------------------------
    let self_id = ic_cdk::api::canister_self();
    
    let stop_arg = CanisterIdRecord {
        canister_id: self_id,
    };

    // Stop
    // ----
    let _ = stop_canister(&stop_arg).await;

    // Delete
    // ------
    let _ = delete_canister(&stop_arg).await;
}

/// Get parameters commitment
/// This does NOT depend on PARAMS or on any randomness
/// so it's SAFE to call even before the canister has
/// initialised its SgpFE state
/// ===================================================
#[query]
pub fn get_params_commitment() -> Vec<u8> {    
    let rdmpf = RDMPFParams::production();
    verification::compute_commitment(
        &rdmpf.p,
        rdmpf.dim,
        rdmpf.version,
        RDMPFParams::SGP_FE_ENTRY_BITS,
        RDMPFParams::SGP_FE_VALUE_BITS,
    )
    .to_vec()
}

/// Verify that the compiled-in production RDMPF 
/// parameters satisfy safety constraints
///
/// This can be called safely even before 
/// 'ensure_crypto_params_initialised()' has run
/// ============================================
pub fn verify_params() -> Result<(), String> {
    let rdmpf = RDMPFParams::production();
    verification::verify_production_params(&rdmpf)
        .map_err(|e| e.to_string())
}

/// Calling 'codec.rs' 
/// for deserialization
/// ===================
fn deserialize_capsule(bytes: &[u8]) -> Result<TransferCapsule, String> {
    codec::decode_transfer_capsule(bytes)
        .map_err(|_e| "Invalid encoding".to_string())
}