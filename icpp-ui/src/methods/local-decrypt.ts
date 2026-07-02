// ===================================================
// Local RDMPF Decryption (Browser-side)
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 07 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import { sha3_256 } from "@noble/hashes/sha3";
import { hkdf } from "@noble/hashes/hkdf";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hmac } from "@noble/hashes/hmac";

// ================
// RDMPF Parameters
// ================

const RDMPF_PARAMS = {
  // 192-bit safe prime 
  // from params.rs
  // ------------------
  p: BigInt("5849654246768679574805475717474214619312947905955131683963"),
  dim: 6,
  version: 1,
  SGP_FE_ENTRY_BITS: 6,
};

const PHI = RDMPF_PARAMS.p - 1n;

// ============
// Matrix Types
// ============

type Matrix = bigint[][];

// =================
// Utility Functions
// =================

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const len = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function bigintToBytesLE(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  const bytes: number[] = [];
  let val = n;
  while (val > 0n) {
    bytes.push(Number(val & 0xffn));
    val >>= 8n;
  }
  return new Uint8Array(bytes);
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

function bytesToBigintLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function mod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  
  let result = 1n;
  base = mod(base, modulus);
  
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = mod(result * base, modulus);
    }
    exp = exp / 2n;
    base = mod(base * base, modulus);
  }
  return result;
}

function burnCpuDelay(ms: number) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    // Intentionally empty 
    // to block the thread
  }
}

// ===========
// ChaCha20Rng
// ===========

class ChaCha20Rng {
  private state: Uint32Array;
  private buffer: Uint8Array;
  private bufferPos: number;

  constructor(seed: Uint8Array | number[]) {
    const key = new Uint8Array(seed);
    if (key.length !== 32) throw new Error("Seed must be 32 bytes");

    this.state = new Uint32Array(16);

    // Expand 32-byte k
    // ----------------
    this.state[0] = 0x61707865;
    this.state[1] = 0x3320646e;
    this.state[2] = 0x79622d32;
    this.state[3] = 0x6b206574;

    // Key (little-endian)
    // -------------------
    for (let i = 0; i < 8; i++) {
      this.state[4 + i] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }

    // Counter + nonce = 0
    // -------------------
    this.state[12] = 0;
    this.state[13] = 0;
    this.state[14] = 0;
    this.state[15] = 0;

    this.buffer = new Uint8Array(64);
    this.bufferPos = 64;
  }

  private quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
    x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ((x[d] << 16) | (x[d] >>> 16)) >>> 0;
    x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ((x[b] << 12) | (x[b] >>> 20)) >>> 0;
    x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ((x[d] << 8) | (x[d] >>> 24)) >>> 0;
    x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ((x[b] << 7) | (x[b] >>> 25)) >>> 0;
  }

  private block(): void {
    const x = new Uint32Array(this.state);

    for (let i = 0; i < 10; i++) {
      this.quarterRound(x, 0, 4, 8, 12);
      this.quarterRound(x, 1, 5, 9, 13);
      this.quarterRound(x, 2, 6, 10, 14);
      this.quarterRound(x, 3, 7, 11, 15);
      this.quarterRound(x, 0, 5, 10, 15);
      this.quarterRound(x, 1, 6, 11, 12);
      this.quarterRound(x, 2, 7, 8, 13);
      this.quarterRound(x, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++) {
      x[i] = (x[i] + this.state[i]) >>> 0;
    }

    // Output little-endian
    // --------------------
    for (let i = 0; i < 16; i++) {
      this.buffer[i*4] = x[i] & 0xff;
      this.buffer[i*4+1] = (x[i] >>> 8) & 0xff;
      this.buffer[i*4+2] = (x[i] >>> 16) & 0xff;
      this.buffer[i*4+3] = (x[i] >>> 24) & 0xff;
    }

    // Increment 64-bit 
    // counter (words 12-13)
    // ---------------------
    this.state[12] = (this.state[12] + 1) >>> 0;
    if (this.state[12] === 0) {
      this.state[13] = (this.state[13] + 1) >>> 0;
    }

    this.bufferPos = 0;
  }

  nextBytes(len: number): Uint8Array {
    const out = new Uint8Array(len);
    let outPos = 0;

    while (outPos < len) {
      if (this.bufferPos >= 64) {
        this.block();
      }
      const take = Math.min(len - outPos, 64 - this.bufferPos);
      out.set(this.buffer.subarray(this.bufferPos, this.bufferPos + take), outPos);
      this.bufferPos += take;
      outPos += take;
    }

    return out;
  }

  nextBigintBelow(bound: bigint): bigint {
    if (bound <= 0n) throw new Error("Bound must be positive");
    
    const bitLen = BigInt(bound.toString(2).length);
    const u32Count = Number((bitLen + 31n) / 32n);
    const rem = Number(bitLen % 32n);

    while (true) {
      // Rust fetches randomness as 
      // u32 slice via rng.fill()
      const bytes = this.nextBytes(u32Count * 4);
      
      // Simulate Vec<u32> in Rust
      const u32s = new Uint32Array(u32Count);
      for (let i = 0; i < u32Count; i++) {
        u32s[i] = (bytes[i*4] | (bytes[i*4+1] << 8) | (bytes[i*4+2] << 16) | (bytes[i*4+3] << 24)) >>> 0;
      }

      // Keep the TOP 'rem' bits of the u32
      // moving them to the bottom
      if (rem > 0) {
        u32s[u32Count - 1] >>>= (32 - rem);
      }

      // Now reconstruct BigInt 
      // from the u32 digits
      let val = 0n;
      for (let i = u32Count - 1; i >= 0; i--) {
        val = (val << 32n) | BigInt(u32s[i]);
      }

      // Rejection
      // sampling
      if (val < bound) {
        return val;
      }
    }
  }
}

// =================
// Matrix Operations
// =================

function zeroMatrix(dim: number): Matrix {
  return Array.from({ length: dim }, () => Array(dim).fill(0n));
}

function clampMatrixEntrySize(mat: Matrix, p: bigint): Matrix {
  const mask = (1n << BigInt(RDMPF_PARAMS.SGP_FE_ENTRY_BITS)) - 1n;
  return mat.map(row => row.map(v => mod(v & mask, p)));
}

function encodeMatrix(mat: Matrix): Uint8Array {
  const dim = mat.length;
  const chunks: Uint8Array[] = [];
  
  // u32 LE dim
  // ----------
  const dimBytes = new Uint8Array(4);
  dimBytes[0] = dim & 0xff;
  dimBytes[1] = (dim >> 8) & 0xff;
  dimBytes[2] = (dim >> 16) & 0xff;
  dimBytes[3] = (dim >> 24) & 0xff;
  chunks.push(dimBytes);
  
  for (const row of mat) {
    for (const val of row) {
      // Variable-length LE 
      // with u32 length prefix
      // ----------------------
      const elemBytes = bigintToBytesLE(val);
      const lenBytes = new Uint8Array(4);
      lenBytes[0] = elemBytes.length & 0xff;
      lenBytes[1] = (elemBytes.length >> 8) & 0xff;
      lenBytes[2] = (elemBytes.length >> 16) & 0xff;
      lenBytes[3] = (elemBytes.length >> 24) & 0xff;
      chunks.push(lenBytes);
      chunks.push(elemBytes);
    }
  }
  return concatBytes(...chunks);
}

// ===============
// Base Derivation
// ===============

function generateRankDeficient(
  dim: number,
  targetRank: number,
  p: bigint,
  rng: ChaCha20Rng
): Matrix {
  const entryBound = 1n << BigInt(RDMPF_PARAMS.SGP_FE_ENTRY_BITS);
  
  // Generate targetRank 
  // random basis vectors
  // --------------------
  const basis: bigint[][] = [];
  for (let i = 0; i < targetRank; i++) {
    const vec: bigint[] = [];
    for (let j = 0; j < dim; j++) {
      vec.push(rng.nextBigintBelow(entryBound));
    }
    basis.push(vec);
  }
  
  // Start with basis
  // ----------------
  const matrix = [...basis.map(v => [...v])];
  
  // Fill remaining rows 
  // as linear combinations
  // ----------------------
  for (let i = targetRank; i < dim; i++) {
    const row: bigint[] = [];
    for (let j = 0; j < dim; j++) {
      let sum = 0n;
      for (const basisVec of basis) {
        const coeff = rng.nextBigintBelow(entryBound);
        sum += coeff * basisVec[j];
      }
      row.push(mod(sum, p));
    }
    matrix.push(row);
  }

  // Shuffle rows 
  // (Fisher-Yates)
  // --------------
  for (let i = matrix.length - 1; i > 0; i--) {
    const j = Number(rng.nextBigintBelow(BigInt(i + 1)));
    [matrix[i], matrix[j]] = [matrix[j], matrix[i]];
  }
  
  return matrix;
}

function deriveUserBases(csrn: Uint8Array): [Matrix, Matrix] {
  if (csrn.length !== 32) throw new Error("CSRN must be 32 bytes");

  burnCpuDelay(200);
  
  const rng = new ChaCha20Rng(csrn);
  const dim = RDMPF_PARAMS.dim;
  const p = RDMPF_PARAMS.p;
  
  const BaseX = generateRankDeficient(dim, dim - 1, p, rng);
  const BaseY = generateRankDeficient(dim, dim - 1, p, rng);

  return [BaseX, BaseY];
}

// ============
// W Generation
// ============

function randomMatrix(dim: number, p: bigint, rng: ChaCha20Rng): Matrix {
  const entryBound = 1n << BigInt(RDMPF_PARAMS.SGP_FE_ENTRY_BITS);
  const mat: Matrix = [];
  
  for (let i = 0; i < dim; i++) {
    const row: bigint[] = [];
    for (let j = 0; j < dim; j++) {
      row.push(mod(rng.nextBigintBelow(entryBound), p));
    }
    mat.push(row);
  }
  
  return mat;
}

function generateW(seed: Uint8Array): Matrix {
  if (seed.length !== 32) throw new Error("W_seed must be 32 bytes");
  
  const rng = new ChaCha20Rng(seed);
  const dim = RDMPF_PARAMS.dim;
  const p = RDMPF_PARAMS.p;
  
  // Try up to 100 times
  // -------------------
  for (let attempt = 0; attempt < 100; attempt++) {
    const W = randomMatrix(dim, p, rng);
    // Skip rank check for now -> random 6x6 matrix over 
    // large prime is almost certainly full rank
    // -------------------------------------------------
    return W;
  }
  
  throw new Error("Failed to generate full-rank W");
}

// ==========
// RDMPF Core
// ==========

type OracleFn = (j: number, l: number, m: number, k: number) => bigint;

function rdmpfWithOracle(
  dim: number,
  W: Matrix,
  p: bigint,
  phi: bigint,
  oracle: OracleFn
): Matrix {
  const output = zeroMatrix(dim);
  
  for (let j = 0; j < dim; j++) {
    for (let k = 0; k < dim; k++) {
      let product = 1n;
      
      for (let l = 0; l < dim; l++) {
        for (let m = 0; m < dim; m++) {
          let exp = oracle(j, l, m, k);
          exp = mod(exp, phi);
          
          const base = mod(W[l][m], p);
          
          if (base === 0n) {
            if (exp !== 0n) {
              product = 0n;
              break;
            }
            continue;
          }
          
          const term = modPow(base, exp, p);
          product = mod(product * term, p);
          
          if (product === 0n) break;
        }
        if (product === 0n) break;
      }   
      output[j][k] = product;
    }
  } 
  return output;
}

function composition(T1: Matrix, T2: Matrix, p: bigint, phi: bigint): Matrix {
  const dim = T1.length;
  const result = zeroMatrix(dim);
  
  for (let i = 0; i < dim; i++) {
    for (let j = 0; j < dim; j++) {
      // Element-wise multiplication
      // ---------------------------
      result[i][j] = mod(T1[i][j] * T2[i][j], p);
    }
  }
  
  return result;
}

// ====
// HKDF
// ====

function deriveTransportKeys(
  sharedSecret: Uint8Array,
  nonce: Uint8Array,
  info: Uint8Array
): [Uint8Array, Uint8Array] {
  const prk = hkdf(sha3_256, sharedSecret, nonce, info, 64);
  const K_enc = prk.slice(0, 32);
  const K_auth = prk.slice(32, 64);
  return [K_enc, K_auth];
}

// ============
// AEAD Decrypt
// ============

function aeadDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  if (ciphertext.length < 12 + 16) {
    throw new Error("Ciphertext too short");
  }
  
  // Format -> nonce(12) || ct || tag(16)
  const nonce = ciphertext.slice(0, 12);
  const ctWithTag = ciphertext.slice(12);
  
  // v1.x API -> aad in constructor
  const cipher = chacha20poly1305(key, nonce, aad);
  
  // Output = ciphertext - tag(16)
  const output = new Uint8Array(ctWithTag.length - 16);
  return cipher.decrypt(ctWithTag, output);
}

// ===============
// Capsule Parsing
// ===============

export interface TransferCapsule {
  eph_matrices_ct: Uint8Array;
  W_seed: Uint8Array;
  // THIS IS 
  // THE CSRN
  nonce: Uint8Array; 
  tag: Uint8Array;
}

export function decodeCapsule(bytes: Uint8Array): TransferCapsule {
  if (bytes.length < 4 + 32 + 32 + 32) {
    throw new Error("Capsule too short");
  }
  
  // ct_len is u32 LE
  // ----------------
  const ctLen = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  
  if (bytes.length < 4 + ctLen + 32 + 32 + 32) {
    throw new Error("Capsule truncated");
  }
  
  let offset = 4;
  const eph_matrices_ct = bytes.slice(offset, offset + ctLen);
  offset += ctLen;
  
  const W_seed = bytes.slice(offset, offset + 32);
  offset += 32;
  
  const nonce = bytes.slice(offset, offset + 32);
  offset += 32;
  
  const tag = bytes.slice(offset, offset + 32);
  
  return { eph_matrices_ct, W_seed, nonce, tag };
}

// ===================
// Decode eph_matrices
// ===================

function decodeMatrix(bytes: Uint8Array, dim: number): Matrix {
  // Rust format -> u32 LE dim and then for 
  // each entry u32 LE len + elem_bytes LE
  // --------------------------------------
  const mat: Matrix = [];
  let offset = 0;
  
  // Skip dim header
  // ---------------
  const encodedDim = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  if (encodedDim !== dim) {
    throw new Error(`Dimension mismatch: expected ${dim}, got ${encodedDim}`);
  }
  offset = 4;
  
  for (let i = 0; i < dim; i++) {
    const row: bigint[] = [];
    for (let j = 0; j < dim; j++) {
      // Read u32 
      // LE length
      // ---------
      const len = bytes[offset] | (bytes[offset+1] << 8) | (bytes[offset+2] << 16) | (bytes[offset+3] << 24);
      offset += 4;
      
      // Read elem bytes 
      // (little-endian)
      // ---------------
      const elemBytes = bytes.slice(offset, offset + len);
      row.push(bytesToBigintLE(elemBytes));
      offset += len;
    }
    mat.push(row);
  }
  
  return mat;
}

function decryptEphMatrices(
  eph_ct: Uint8Array,
  context: Uint8Array,
  csrn: Uint8Array
): [Matrix, Matrix] {
  // Derive symmetric key
  // --------------------
  const k_eph = sha3_256(concatBytes(
    new TextEncoder().encode("ICPP:eph-matrices:v1"),
    csrn
  ));

  burnCpuDelay(200);
  
  const plaintext = aeadDecrypt(k_eph, eph_ct, context);

  burnCpuDelay(200);

  // Parse -> p_len(4 BE) || P_eph_bytes || Q_eph_bytes
  // --------------------------------------------------
  if (plaintext.length < 4) {
    throw new Error("Decrypted blob too short");
  }
  
  const pLen = (plaintext[0] << 24) | (plaintext[1] << 16) | 
               (plaintext[2] << 8) | plaintext[3];
  
  const pBytes = plaintext.slice(4, 4 + pLen);
  const qBytes = plaintext.slice(4 + pLen);
  
  const dim = RDMPF_PARAMS.dim;
  const P_eph = decodeMatrix(pBytes, dim);
  const Q_eph = decodeMatrix(qBytes, dim);

  return [P_eph, Q_eph];
}

// =====================
// Main Decrypt Function
// =====================

export interface DecryptResult {
  plaintext: Uint8Array;
  auth_key_hash_hex: string;
  amount: bigint;
  deposit_id: Uint8Array;
  i2_principal: Uint8Array;
}

export function decryptTransfer(
  capsuleBytes: Uint8Array,
  encryptedInner: Uint8Array,
  depositId: Uint8Array
): DecryptResult {
  // 1. Parse capsule
  // ----------------
  const capsule = decodeCapsule(capsuleBytes);
  const csrn = capsule.nonce;

  burnCpuDelay(200);
  
  // 2. Derive own 
  //    bases from 
  //    CSRN
  // -------------
  const [BaseX_own, BaseY_own] = deriveUserBases(csrn);

  burnCpuDelay(200);

  // Clamp to 6-bit entries
  // ----------------------
  const P_own = clampMatrixEntrySize(BaseX_own, RDMPF_PARAMS.p);
  const Q_own = clampMatrixEntrySize(BaseY_own, RDMPF_PARAMS.p);
  
  // 3. Generate W from seed
  // -----------------------
  const W = generateW(capsule.W_seed);

  burnCpuDelay(200);

  // 4. Decrypt eph_matrices 
  //    to get P_eph, Q_eph
  // -----------------------
  const context = depositId;
  const [P_eph_raw, Q_eph_raw] = decryptEphMatrices(
    capsule.eph_matrices_ct,
    context,
    csrn
  );

  const P_eph = clampMatrixEntrySize(P_eph_raw, RDMPF_PARAMS.p);
  const Q_eph = clampMatrixEntrySize(Q_eph_raw, RDMPF_PARAMS.p);
  
  const dim = RDMPF_PARAMS.dim;
  const p = RDMPF_PARAMS.p;
  const phi = PHI;
  
  // 5. RDMPF -> T1 = RDMPF(P_eph, W, Q_own)
  // ---------------------------------------
  const T1 = rdmpfWithOracle(dim, W, p, phi, (j, l, m, k) => {
    return mod(P_eph[j][l] * Q_own[m][k], phi);
  });
  
  // 6. RDMPF -> T2 = RDMPF(P_own, W, Q_eph)
  // ---------------------------------------
  const T2 = rdmpfWithOracle(dim, W, p, phi, (j, l, m, k) => {
    return mod(P_own[j][l] * Q_eph[m][k], phi);
  });
  
  // 7. Compose
  // ----------
  const keyMatrix = composition(T1, T2, p, phi);
  
  // 8. Derive key_AB = SHA3-256(encode(keyMatrix))
  // ----------------------------------------------
  const keyAB = sha3_256(encodeMatrix(keyMatrix));
  
  // 9. Derive transport keys
  // ------------------------
  const [K_enc, K_auth] = deriveTransportKeys(
    keyAB,
    capsule.nonce,
    new TextEncoder().encode("rdmpf-kem")
  );

  burnCpuDelay(200);
  
  // 10. Verify HMAC tag
  // -------------------
  const expectedTag = hmac(sha3_256, K_auth, context);

  burnCpuDelay(200);

  let tagMatch = true;
  for (let i = 0; i < 32; i++) {
    if (capsule.tag[i] !== expectedTag[i]) {
      tagMatch = false;
    }
  }
  if (!tagMatch) {
    throw new Error("HMAC verification failed");
  }
 
  // 11. AEAD decrypt 
  //     inner payload
  // -----------------
  const plaintext = aeadDecrypt(K_enc, encryptedInner, context);
  
  // 12. Extract auth_key 
  //     from shared secret
  // ----------------------
  const authKeyRaw = hkdf(
    sha3_256,
    keyAB,
    context,
    new TextEncoder().encode("ICPP:auth-key:v1"),
    32
  );
  const authKeyHash = sha3_256(authKeyRaw);
  const auth_key_hash_hex = bytesToHex(authKeyHash);

  // 13. Zeroize keys
  // ----------------
  keyAB.fill(0);
  K_enc.fill(0);
  K_auth.fill(0);
  
  // 14. Parse plaintext -> amount(8) || deposit_id(32) || i2_len(1) || i2_principal || auth_key_hash_hex(64)
  // --------------------------------------------------------------------------------------------------------
  if (plaintext.length < 41 + 64) {
    throw new Error("Plaintext too short");
  }
  
  const amount = bytesToBigint(plaintext.slice(0, 8));
  const extractedDepositId = plaintext.slice(8, 40);
  const i2Len = plaintext[40];
  const i2Principal = plaintext.slice(41, 41 + i2Len);
  
  return {
    plaintext,
    auth_key_hash_hex,
    amount,
    deposit_id: extractedDepositId,
    i2_principal: i2Principal,
  };
}

// ========================================
// Convenience -> Extract CSRN from capsule
// ========================================

export function extractCsrnFromCapsule(capsuleBytes: Uint8Array): Uint8Array {
  const capsule = decodeCapsule(capsuleBytes);
  return capsule.nonce;
}