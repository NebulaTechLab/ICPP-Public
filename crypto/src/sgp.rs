#![allow(non_snake_case)]

/// ===================================================
/// FE execution code
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.03
/// Date    -> 3 December 2025
/// Status  -> Public release ver:2 subver:0 release:03
///
/// Code developed by @Troesma
/// ===================================================

use std::sync::RwLock;
use rustc_hash::FxHashMap;

use lazy_static::lazy_static;

use miracl_core::bls12381::big;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::dbig::DBIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp12::FP12;
use miracl_core::bls12381::pair;
use miracl_core::bls12381::rom;
use miracl_core::rand::RAND;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

pub type BigNum = BIG;
pub type DBigNum = DBIG;
pub type G1 = ECP;
pub type G2 = ECP2;
pub type GT = FP12;

pub const MB: usize = big::MODBYTES as usize;

pub type G1Vector = Vec<G1>;
pub type G2Vector = Vec<G2>;

// Size of serialized FP12 (GT) 
// element -> 12 * 48 bytes = 576
const GT_BYTES: usize = 12 * MB;

// Serialize into a mutable stack buffer
// to avoid heap allocation entirely
fn serialize_gt(point: &GT, buf: &mut [u8; GT_BYTES]) {
    let mut p = GT::new();
    p.copy(point);
    p.tobytes(buf);
}

#[derive(Debug)]
pub struct BigNumMatrix {
    pub data: Vec<BigNum>,
    pub n_rows: usize,
    pub n_cols: usize,
}

impl BigNumMatrix {
    pub fn new(n_rows: usize, n_cols: usize) -> Self {
        Self {
            data: vec![BigNum::new(); n_rows * n_cols],
            n_rows,
            n_cols,
        }
    }

    pub fn new_ints(a: &[i64], n_rows: usize, n_cols: usize) -> Self {
        let mut data: Vec<BigNum> = Vec::with_capacity(n_rows * n_cols);
        for i in 0..n_rows {
            for j in 0..n_cols {
                data.push(BigNum::new_int(a[i * n_cols + j].try_into().unwrap()));
            }
        }
        Self {
            data,
            n_rows,
            n_cols,
        }
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigNum {
        &self.data[i * self.n_cols + j]
    }

}

#[derive(Debug)]
pub struct BigNumMatrix2x2 {
    data: Vec<BigNum>,
}

impl BigNumMatrix2x2 {
    pub fn new() -> Self {
        Self {
            data: vec![BigNum::new(); 2 * 2],
        }
    }

    pub fn new_with_data(data: &[BigNum]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn new_random(modulus: &BigNum, rng: &mut impl RAND) -> Self {
        Self {
            data: uniform_sample_vec(2 * 2, modulus, rng),
        }
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigNum {
        &self.data[i * 2 + j]
    }

    pub fn determinant(&self) -> BigNum {
        let a: &BigNum = self.get_element(0, 0);
        let b: &BigNum = self.get_element(0, 1);
        let c: &BigNum = self.get_element(1, 0);
        let d: &BigNum = self.get_element(1, 1);
        let ad = BigNum::modmul(a, d, &CURVE_ORDER);
        let bc = BigNum::modmul(b, c, &CURVE_ORDER);
        let neg_bc = BigNum::modneg(&bc, &CURVE_ORDER);
        let mut det = ad;
        det.add(&neg_bc);
        det.rmod(&CURVE_ORDER);
        det
    }

    pub fn invmod(&self, modulus: &BigNum) -> Self {
        let mut det = self.determinant();
        if det.iszilch() {
            panic!("Matrix determinant is zero");
        }
        det.invmodp(modulus); 
        let det_inv = det;
        let e00 = BigNum::modmul(self.get_element(1, 1), &det_inv, modulus);
        let e01 = BigNum::modmul(&(BigNum::modneg(self.get_element(0, 1), modulus)), &det_inv, modulus);
        let e10 = BigNum::modmul(&(BigNum::modneg(self.get_element(1, 0), modulus)), &det_inv, modulus);
        let e11 = BigNum::modmul(self.get_element(0, 0), &det_inv, modulus);
        Self {
            data: vec![e00, e01, e10, e11],
        }
    }

    pub fn transpose(&mut self) {
        self.data.swap(1, 2); 
    }
}

#[derive(Clone)]
pub struct Sgp {
    n: usize,
}

#[derive(Clone)]
pub struct SgpSecKey {
    s: Vec<BigNum>, 
    t: Vec<BigNum>,
}

impl SgpSecKey {
    /// Serialize (s || t) as input key material (IKM)
    /// for higher-level KDFs (this only exposes a byte
    /// string but does not reveal the structure of the
    /// secret key to other modules)
    pub fn to_ikm(&self) -> Vec<u8> {
        let mut ikm = Vec::new();
        let mut buf = [0u8; MB];

        // Concatenate all 
        // s coefficients
        for s in &self.s {
            s.tobytes(&mut buf);
            ikm.extend_from_slice(&buf);
        }

        // Concatenate all 
        // t coefficients
        for t in &self.t {
            t.tobytes(&mut buf);
            ikm.extend_from_slice(&buf);
        }

        ikm
    }
}

#[derive(Clone)]
pub struct SgpPubKey {
    pub g1s: G1Vector,
    pub g2t: G2Vector,
}

#[derive(Debug, Clone)]
pub struct SgpCipher {
    g1MulGamma: G1,
    a: G1Vector,
    b: G2Vector,
}

#[derive(Debug)]
pub struct SgpDecKey {
    key: G2,
    f: BigNumMatrix,
}

lazy_static! {
    pub static ref CURVE_ORDER: BigNum = BigNum::new_ints(&rom::CURVE_ORDER);
    pub static ref GEN_PAIRING: GT = {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let mut p = pair::ate(&g2, &g1);
        p = pair::fexp(&p);
        p
    };
}

impl Sgp {
    pub fn new(n: usize) -> Sgp {
        Sgp {
            n
        }
    }

    pub fn generate_sec_key(&self, rng: &mut impl RAND) -> (SgpSecKey, SgpPubKey) {
        let msk = SgpSecKey {
            s: uniform_sample_vec(self.n, &(CURVE_ORDER), rng),
            t: uniform_sample_vec(self.n, &(CURVE_ORDER), rng),
        };
        let mut pk = SgpPubKey {
            g1s: vec![G1::generator(); self.n],
            g2t: vec![G2::generator(); self.n],
        };
        for i in 0..self.n {
            pk.g1s[i] = pk.g1s[i].mul(&(msk.s[i]));
            pk.g2t[i] = pk.g2t[i].mul(&(msk.t[i]));
        }
        (msk, pk)
    }

    pub fn encrypt(&self, x: &[BigInt], y: &[BigInt], pk: &SgpPubKey, rng: &mut impl RAND) -> SgpCipher {
        if x.len() != self.n || y.len() != self.n {
            panic!("Malformed input -> x.len ({}), y.len ({}), expected len ({})", x.len(), y.len(), self.n);
        }

        // Cache Generators
        let g1_gen = G1::generator();
        let g2_gen = G2::generator();

        // Matrix Setup
        let W = BigNumMatrix2x2::new_random(&CURVE_ORDER, rng);
        let mut W_inv = W.invmod(&CURVE_ORDER);
        W_inv.transpose();

        let gamma = uniform_sample(&CURVE_ORDER, rng);

        // Assign result 
        // of multiplication
        let mut g1MulGamma = G1::new();
        g1MulGamma.copy(&g1_gen);
        g1MulGamma = g1MulGamma.mul(&gamma);

        let mut a: G1Vector = Vec::with_capacity(self.n * 2);
        let mut b: G2Vector = Vec::with_capacity(self.n * 2);

        // BigInt -> BigNum
        let to_bignum = |val: &BigInt| -> BigNum {
            let (sign, bytes) = val.to_bytes_be(); 
            
            // Create a buffer of the exact size
            // expected by miracl_core (MB = 48)
            let mut buf = vec![0u8; MB];
            
            // Pad (Big Endian)
            if bytes.len() > MB {
                let start = bytes.len() - MB;
                buf.copy_from_slice(&bytes[start..]);
            } else {
                let start = MB - bytes.len();
                buf[start..].copy_from_slice(&bytes);
            }
            
            let mut bn = BigNum::frombytearray(&buf, 0);
            
            if let num_bigint::Sign::Minus = sign {
                let mut inverse = BigNum::new();
                inverse.copy(&CURVE_ORDER);
                inverse.sub(&bn); 
                inverse.norm();
                bn = inverse;
            }
            bn
        };

        for i in 0..self.n {
            let mut xi = to_bignum(&x[i]);
            let mut yi = to_bignum(&y[i]);

            xi.rmod(&CURVE_ORDER);
            yi.rmod(&CURVE_ORDER);

            // A Components
            let w00_x = BigNum::modmul(W_inv.get_element(0, 0), &xi, &CURVE_ORDER);
            let w10_x = BigNum::modmul(W_inv.get_element(1, 0), &xi, &CURVE_ORDER);
            let w01_gamma = BigNum::modmul(W_inv.get_element(0, 1), &gamma, &CURVE_ORDER);
            let w11_gamma = BigNum::modmul(W_inv.get_element(1, 1), &gamma, &CURVE_ORDER);

            // a0
            let mut a0 = G1::new(); 
            a0.copy(&g1_gen);
            a0 = a0.mul(&w00_x);
            
            let mut tmp_a = G1::new();
            tmp_a.copy(&pk.g1s[i]);
            tmp_a = tmp_a.mul(&w01_gamma);
            a0.add(&tmp_a);

            // a1
            let mut a1 = G1::new();
            a1.copy(&g1_gen);
            a1 = a1.mul(&w10_x);
            
            tmp_a.copy(&pk.g1s[i]);
            tmp_a = tmp_a.mul(&w11_gamma);
            a1.add(&tmp_a);

            a.push(a0);
            a.push(a1);

            // B Components
            let w00_y = BigNum::modmul(W.get_element(0, 0), &yi, &CURVE_ORDER);
            let w10_y = BigNum::modmul(W.get_element(1, 0), &yi, &CURVE_ORDER);
            let neg_w01 = BigNum::modneg(W.get_element(0, 1), &CURVE_ORDER);
            let neg_w11 = BigNum::modneg(W.get_element(1, 1), &CURVE_ORDER);

            // b0
            let mut b0 = G2::new();
            b0.copy(&g2_gen);
            b0 = b0.mul(&w00_y);
            
            let mut tmp_b = G2::new();
            tmp_b.copy(&pk.g2t[i]);
            tmp_b = tmp_b.mul(&neg_w01);
            b0.add(&tmp_b);

            // b1
            let mut b1 = G2::new();
            b1.copy(&g2_gen);
            b1 = b1.mul(&w10_y);

            tmp_b.copy(&pk.g2t[i]);
            tmp_b = tmp_b.mul(&neg_w11);
            b1.add(&tmp_b);

            b.push(b0);
            b.push(b1);
        }

        SgpCipher {
            g1MulGamma,
            a,
            b,
        }
    }

    pub fn derive_fe_key(&self, msk: &SgpSecKey, f: BigNumMatrix) -> SgpDecKey {
        let mut exp = BigNum::new();
        for i in 0..msk.s.len() {
            for j in 0..msk.t.len() {
                let fij = f.get_element(i, j);

                if fij.iszilch() {
                    continue;
                }

                let si_tj = BigNum::modmul(&(msk.s[i]), &(msk.t[j]), &CURVE_ORDER);
                let fij_si_tj = BigNum::modmul(&fij, &si_tj, &CURVE_ORDER);
                exp.add(&fij_si_tj);
                exp.rmod(&CURVE_ORDER);
            }
        }
        SgpDecKey {
            key: (G2::generator()).mul(&exp),
            f: f 
        }
    }

    pub fn decrypt(&self, ct: &SgpCipher, dk: &SgpDecKey, bound: &BigInt) -> Option<BigInt> {
        // Input Validation
        if ct.a.len() != dk.f.n_rows * 2 || ct.b.len() != dk.f.n_cols * 2 {
             panic!("Malformed input dims");
        }

        // Initial Pairing
        let mut miller_accum: GT = pair::ate(&dk.key, &ct.g1MulGamma);

        // Matrix Loop
        // (Miller loop aggregation)
        let mut pair0: GT;
        let mut pair1: GT;
        
        // Pre-allocate temp points to 
        // avoid allocation overhead in loop
        let mut tmp_a0 = G1::new();
        let mut tmp_a1 = G1::new();

        for i in 0..dk.f.n_rows {
            for j in 0..dk.f.n_cols {
                let f_ij = dk.f.get_element(i, j);
                
                // Optimization -> If f_ij is 0 (which is true for 4095 
                // out of 4096 entries) we can skip the pairing entirely)
                if f_ij.iszilch() {
                    continue;
                }

                // Move exponentiation to G1 
                // (scalar multiplication)                
                tmp_a0.copy(&ct.a[i * 2]);
                tmp_a0 = tmp_a0.mul(f_ij);

                tmp_a1.copy(&ct.a[i * 2 + 1]);
                tmp_a1 = tmp_a1.mul(f_ij);

                // Calculate Miller loops
                pair0 = pair::ate(&ct.b[j * 2], &tmp_a0);
                pair1 = pair::ate(&ct.b[j * 2 + 1], &tmp_a1);

                // Accumulate
                pair0.mul(&pair1); 
                miller_accum.mul(&pair0);
            }
        }

        // Final Exponentiation
        // (expensive hard part of 
        // pairing done only ONCE)
        let out = pair::fexp(&miller_accum);

        // -----------
        // BSGS SOLVER
        // -----------

        // Use cache
        let gen_g = &*GEN_PAIRING;

        if out.isunity() { 
            return Some(BigInt::from(0)); 
        }

        // Handle Bounds
        let max_practical: u64 = (1 << 12) + 1;
        let raw_bound = bound.to_u64().unwrap_or(u64::MAX);
        let effective_bound = if raw_bound > max_practical {
            max_practical
        } else {
            raw_bound
        };

        init_bsgs_cache(&gen_g, effective_bound);

        if let Some(x) = baby_step_giant_step(&out, effective_bound) {
            Some(x)
        } else {
            None
        }
    }
}

fn uniform_sample(modulus: &BigNum, rng: &mut impl RAND) -> BigNum {
    BigNum::randomnum(modulus, rng)
}

fn uniform_sample_vec(len: usize, modulus: &BigNum, rng: &mut impl RAND) -> Vec<BigNum> {
    let mut v: Vec<BigNum> = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(uniform_sample(modulus, rng));
    }
    v 
}

struct BsgsPrecomp {
    m: u64,
    // Key is Vec<u8> (bytes)
    // Value is index j
    table: FxHashMap<Vec<u8>, u64>, 
    g_neg_m: GT,
}

struct BsgsPrecompPartial {
    m: u64,
    table: FxHashMap<Vec<u8>, u64>,
    current_j: u64,
    baby: GT,
    g: GT,
}

lazy_static! {
    static ref BSGS_CACHE: RwLock<Option<BsgsPrecomp>> = RwLock::new(None);
    static ref BSGS_PARTIAL: RwLock<Option<BsgsPrecompPartial>> = RwLock::new(None);
}

/// Initialize or continue BSGS cache construction
/// (call repeatedly until complete is true)
pub fn init_bsgs_cache_chunked(bound_u64: u64, max_iters: u64) -> (bool, u64) {
    // Already complete?
    if BSGS_CACHE.read().unwrap().is_some() {
        return (true, 0);
    }

    let mut partial_lock = BSGS_PARTIAL.write().unwrap();

    // First call -> initialize 
    // partial state
    if partial_lock.is_none() {
        let m = ((bound_u64 as f64).sqrt().ceil() as u64) + 1;
        let table = FxHashMap::with_capacity_and_hasher(m as usize, Default::default());

        let g = GEN_PAIRING.clone();
        let mut baby = GT::new();
        baby.one();

        *partial_lock = Some(BsgsPrecompPartial {
            m,
            table,
            current_j: 0,
            baby,
            g,
        });
    }

    let partial = partial_lock.as_mut().unwrap();
    let mut buf = [0u8; GT_BYTES];
    let mut iters: u64 = 0;

    while partial.current_j < partial.m && iters < max_iters {
        let mut b_red = GT::new();
        b_red.copy(&partial.baby);
        b_red.reduce();

        serialize_gt(&b_red, &mut buf);
        partial.table.insert(buf.to_vec(), partial.current_j);

        partial.baby.mul(&partial.g);
        partial.current_j += 1;
        iters += 1;
    }

    // Check if complete
    if partial.current_j >= partial.m {
        // Compute g^(-m)
        let m_bn = BigNum::new_int(partial.m as isize);
        let mut g_m = partial.g.pow(&m_bn);
        g_m.inverse();

        // Move to 
        // final cache
        let final_cache = BsgsPrecomp {
            m: partial.m,
            table: std::mem::take(&mut partial.table),
            g_neg_m: g_m,
        };

        // Release partial lock 
        // before acquiring cache lock
        drop(partial_lock);

        *BSGS_CACHE.write().unwrap() = Some(final_cache);
        *BSGS_PARTIAL.write().unwrap() = None;

        return (true, iters);
    }

    (false, iters)
}

// Cache is built once by prewarm_bsgs() using GEN_PAIRING
// Reuse if cache exists with sufficient stride
fn init_bsgs_cache(g: &GT, bound_u64: u64) {
    {
        let guard = BSGS_CACHE.read().unwrap();
        if let Some(ref cache) = *guard {
            let required_m = ((bound_u64 as f64).sqrt().ceil() as u64) + 1;
            if cache.m >= required_m {
                return;
            }
        }
    }

    // Clear incomplete 
    // partial state if any
    *BSGS_PARTIAL.write().unwrap() = None;

    // Synchronous build (test fallback 
    // or first-call bootstrap)
    let m = ((bound_u64 as f64).sqrt().ceil() as u64) + 1;
    let mut table = FxHashMap::with_capacity_and_hasher(m as usize, Default::default());

    let mut baby = GT::new();
    baby.one();
    let mut buf = [0u8; GT_BYTES];

    for j in 0..m {
        let mut b_red = GT::new();
        b_red.copy(&baby);
        b_red.reduce();

        serialize_gt(&b_red, &mut buf);
        table.insert(buf.to_vec(), j);

        baby.mul(g);
    }

    let m_bn = BigNum::new_int(m as isize);
    let mut g_m = g.pow(&m_bn);
    g_m.inverse();

    let final_cache = BsgsPrecomp {
        m,
        table,
        g_neg_m: g_m,
    };

    *BSGS_CACHE.write().unwrap() = Some(final_cache);
}

fn baby_step_giant_step(h: &GT, bound: u64) -> Option<BigInt> {
    let cache_guard = BSGS_CACHE.read().unwrap();
    let cache = cache_guard.as_ref().expect("BSGS Cache not initialized");

    let m = cache.m;
    let max_i = (bound / m) + 1;

    let mut gamma = GT::new();
    gamma.copy(h);
    
    let mut gamma_neg = GT::new();
    gamma_neg.copy(h);
    gamma_neg.inverse();

    let mut key_buf = [0u8; GT_BYTES];

    for i in 0..=max_i {
        gamma.reduce(); 
        
        // Serialize POSITIVE 
        // to stack
        serialize_gt(&gamma, &mut key_buf);
        
        // Borrow a slice
        if let Some(&j) = cache.table.get(&key_buf[..]) {
            let x = i * m + j;
            if x <= bound { return Some(BigInt::from(x)); }
        }

        // Giant step
        gamma.mul(&cache.g_neg_m);
    }
    None
}

/// Serialize BSGS cache to bytes
/// (called by Factory)
/// Format:
/// 8 bytes: m (u64 LE)
/// 8 bytes: table_len (u64 LE)
/// table entries: (GT_BYTES key + 8 bytes value) × table_len
/// GT_BYTES: g_neg_m
pub fn serialize_bsgs_cache() -> Result<Vec<u8>, String> {
    let cache_guard = BSGS_CACHE.read().unwrap();
    let cache = cache_guard.as_ref()
        .ok_or_else(|| "BSGS cache not initialized".to_string())?;
    
    let table_len = cache.table.len() as u64;
    
    // Calculate 
    // total size
    let size = 8 + 8 + (table_len as usize * (GT_BYTES + 8)) + GT_BYTES;
    let mut buf = Vec::with_capacity(size);
    
    // Write m
    buf.extend_from_slice(&cache.m.to_le_bytes());
    
    // Write 
    // table_len
    buf.extend_from_slice(&table_len.to_le_bytes());
    
    // Write table 
    // entries
    for (key, value) in cache.table.iter() {
        if key.len() != GT_BYTES {
            return Err(format!("Invalid key length: {}", key.len()));
        }
        buf.extend_from_slice(key);
        buf.extend_from_slice(&value.to_le_bytes());
    }
    
    // Write g_neg_m
    let mut g_neg_m_bytes = [0u8; GT_BYTES];
    serialize_gt(&cache.g_neg_m, &mut g_neg_m_bytes);
    buf.extend_from_slice(&g_neg_m_bytes);
    
    Ok(buf)
}

/// Deserialize and install BSGS cache 
/// from bytes (called by Crypto canister)
pub fn install_bsgs_cache(data: &[u8]) -> Result<(), String> {
    if data.len() < 16 {
        return Err("Cache data too short".to_string());
    }
    
    let mut pos = 0;
    
    // Read m
    let m = u64::from_le_bytes(
        data[pos..pos + 8].try_into()
            .map_err(|_| "Failed to read m".to_string())?
    );
    pos += 8;
    
    // Read table_len
    let table_len = u64::from_le_bytes(
        data[pos..pos + 8].try_into()
            .map_err(|_| "Failed to read table_len".to_string())?
    );
    pos += 8;
    
    // Read table 
    // entries
    let mut table = FxHashMap::with_capacity_and_hasher(
        table_len as usize,
        Default::default()
    );
    
    for _ in 0..table_len {
        if pos + GT_BYTES + 8 > data.len() {
            return Err("Cache data truncated in table".to_string());
        }
        
        let key = data[pos..pos + GT_BYTES].to_vec();
        pos += GT_BYTES;
        
        let value = u64::from_le_bytes(
            data[pos..pos + 8].try_into()
                .map_err(|_| "Failed to read table value".to_string())?
        );
        pos += 8;
        
        table.insert(key, value);
    }
    
    // Read 
    // g_neg_m
    if pos + GT_BYTES > data.len() {
        return Err("Cache data truncated in g_neg_m".to_string());
    }
    
    let g_neg_m = FP12::frombytes(&data[pos..pos + GT_BYTES]);
    pos += GT_BYTES;
    
    if pos != data.len() {
        return Err(format!(
            "Cache data has extra bytes: expected {}, got {}",
            pos,
            data.len()
        ));
    }
    
    // Install 
    // cache
    let cache = BsgsPrecomp {
        m,
        table,
        g_neg_m,
    };
    
    *BSGS_CACHE.write().unwrap() = Some(cache);
    *BSGS_PARTIAL.write().unwrap() = None;
    
    Ok(())
}

/// Check if BSGS cache is 
/// initialized (query function)
pub fn is_bsgs_cache_ready() -> bool {
    BSGS_CACHE.read().unwrap().is_some()
}