// ===================================================
// Setup, send and receive logic for UX frontend code
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 07 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import { Principal } from "@dfinity/principal";
import { Actor } from "@dfinity/agent";
import { 
  CMC_CANISTER_ID, 
  isDelegationStale, 
  getActorsForQuery,
  getIcpBalanceE8s, 
} from "./canisters";
import { generateNk, storeNk, loadNk } from "./nk";
import { sha3_256 } from "@noble/hashes/sha3";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { decryptTransfer } from "./local-decrypt";

// =======
// Helpers
// =======

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hexToBytes: invalid hex length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

function stringify(obj: unknown): string {
  return JSON.stringify(obj, (_, v) => typeof v === 'bigint' ? v.toString() : v);
}

export function sanitizeError(e: any): string {
  const msg = String(e?.message || e);
  
  if (msg.includes("out of cycles")) {
    return "No service – Try again later";
  }
  if (msg.includes("Reject code:") || msg.includes("replica returned a rejection")) {
    return "Unable now to handle your request";
  }
  if (msg.includes("HMAC verification failed")) {
    return "This transfer may not be for you";
  }
  const lower = msg.toLowerCase();
  if (
    lower.includes("failed to fetch") ||
    lower.includes("networkerror") ||
    lower.includes("load failed") ||
    lower.includes("the network connection was lost")
  ) {
    return "Bad connection – Try again later";
  }
  if (msg.includes("Insufficient funds") || msg.includes("InsufficientFunds")) {
    return "Insufficient funds available";
  }
  if (msg.includes("did not complete within")) {
    return "Timed out – Please try again";
  }
  if (msg.includes("No storage principals")) {
    return "Transfer data unavailable";
  }
  if (msg.includes("Package too short") || msg.includes("Package malformed")) {
    return "Invalid transfer data";
  }
  if (msg.includes("Session expired") || msg.includes("delegation")) {
    return "Session expired – Please re-login";
  }
  if (msg.includes("Router.deposit_prepare")) {
    return "Deposit failure – Please try again";
  }
  if (msg.includes("PIN")) {
    return "Invalid PIN – Please try again";
  }

  console.error("[UNCAUGHT ERROR]", {
    fullError: e,
    message: msg,
    stack: e?.stack,
    name: e?.name,
    code: e?.code,
    timestamp: new Date().toISOString()
  });

  console.error("[RAW ERROR]", {
    raw: e,
    message: e?.message,
    stack: e?.stack,
    name: e?.name,
    toString: String(e)
  });
  
  return "Unknown error – Try again later";
}

export async function getSessionIcpBalanceE8s(): Promise<bigint> {
  return await getIcpBalanceE8s();
}

export function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  timeoutMessage = "Timed out"
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(timeoutMessage)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); }
    );
  });
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

// ==========================
// Encrypted SENT IDs storage
// ==========================

const SENT_IDS_KEY = "icpp_sent_ids";
let cachedSentIdsKey: Uint8Array | null = null;

function getSentIdsKey(): Uint8Array {
  if (!cachedSentIdsKey) {
    throw new Error("Sent IDs key not initialized");
  }
  return cachedSentIdsKey;
}

export function initSentIdsKey(nk: Uint8Array): void {
  cachedSentIdsKey = sha3_256(
    concatBytes(nk, new TextEncoder().encode("ICPP:sent-ids:v1"))
  );
}

export function clearSentIdsKey(): void {
  cachedSentIdsKey = null;
}

function loadSentIdsFromStorage(): Set<string> {
  const key = getSentIdsKey();
  const stored = localStorage.getItem(SENT_IDS_KEY);
  if (!stored) return new Set();

  try {
    const blob = hexToBytes(stored);
    const nonce = blob.slice(0, 12);
    const ctWithTag = blob.slice(12);
    const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
    const plaintext = cipher.decrypt(ctWithTag, new Uint8Array(ctWithTag.length - 16));
    const nullIdx = plaintext.indexOf(0);
    const jsonBytes = nullIdx === -1 ? plaintext : plaintext.slice(0, nullIdx);
    const ids: string[] = JSON.parse(new TextDecoder().decode(jsonBytes));
    return new Set(ids);
  } catch {
    return new Set();
  }
}

function saveToStorage(ids: Set<string>): void {
  const key = getSentIdsKey();
  const json = new TextEncoder().encode(JSON.stringify([...ids]));
  // Fixed size
  // ~936 IDs capacity
  // -----------------
  const PADDED_SIZE = 65536;
  const plaintext = new Uint8Array(PADDED_SIZE);
  plaintext.set(json, 0);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
  const ctWithTag = cipher.encrypt(plaintext);
  const blob = new Uint8Array(12 + ctWithTag.length);
  blob.set(nonce, 0);
  blob.set(ctWithTag, 12);
  localStorage.setItem(SENT_IDS_KEY, bytesToHex(blob));
}

export function saveSentId(depositIdHex: string): void {
  const ids = loadSentIdsFromStorage();
  if (!ids.has(depositIdHex)) {
    ids.add(depositIdHex);
    saveToStorage(ids);
  }
}

export function removeSentId(depositIdHex: string): void {
  const ids = loadSentIdsFromStorage();
  ids.delete(depositIdHex);
  saveToStorage(ids);
}

export function getSentIds(): Set<string> {
  return loadSentIdsFromStorage();
}

// ================================
// Encrypted claim recovery storage
// ================================

const CLAIM_RECOVERY_KEY = "ICPP:claim_recovery";

interface ClaimRecoveryData {
  depositIdHex: string;
  jobId: string;
  i2Id: string;
  authKeyHashHex: string;
  bobPrincipal: string;
  timestamp: number;
}

function saveClaimRecovery(
  depositIdHex: string,
  jobId: bigint,
  i2Id: string,
  authKeyHashHex: string,
  bobPrincipal: string
): void {
  const key = getSentIdsKey();
  
  const data: ClaimRecoveryData = {
    depositIdHex,
    jobId: jobId.toString(),
    i2Id,
    authKeyHashHex,
    bobPrincipal,
    timestamp: Date.now()
  };
  
  const json = new TextEncoder().encode(JSON.stringify(data));
  
  // Pad to fixed size to hide content length
  // Recovery data is ~300 bytes so pad to 1024
  // ------------------------------------------
  const PADDED_SIZE = 1024;
  if (json.length > PADDED_SIZE) {
    throw new Error("Recovery data exceeds maximum size");
  }
  
  const plaintext = new Uint8Array(PADDED_SIZE);
  plaintext.set(json, 0);
  
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  
  const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
  const ctWithTag = cipher.encrypt(plaintext);
  
  const blob = new Uint8Array(12 + ctWithTag.length);
  blob.set(nonce, 0);
  blob.set(ctWithTag, 12);
  
  localStorage.setItem(CLAIM_RECOVERY_KEY, bytesToHex(blob));
}

function loadClaimRecovery(
  depositIdHex: string,
  bobPrincipal: string
): { jobId: bigint; i2Id: string; authKeyHashHex: string } | null {
  const stored = localStorage.getItem(CLAIM_RECOVERY_KEY);
  if (!stored) return null;
  
  try {
    const key = getSentIdsKey();
    const blob = hexToBytes(stored);
    
    if (blob.length < 12 + 16) {
      // Too short -> nonce(12) + tag(16) minimum
      // ----------------------------------------
      localStorage.removeItem(CLAIM_RECOVERY_KEY);
      return null;
    }
    
    const nonce = blob.slice(0, 12);
    const ctWithTag = blob.slice(12);
    
    const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
    const plaintext = cipher.decrypt(ctWithTag, new Uint8Array(ctWithTag.length - 16));
    
    // Find null terminator 
    // (padding starts after JSON)
    // ---------------------------
    const nullIdx = plaintext.indexOf(0);
    const jsonBytes = nullIdx === -1 ? plaintext : plaintext.slice(0, nullIdx);
    const data: ClaimRecoveryData = JSON.parse(new TextDecoder().decode(jsonBytes));
    
    // Validate recovery data matches current claim context
    // - Same deposit being claimed
    // - Same recipient principal (guard against II identity change)
    // -------------------------------------------------------------
    if (data.depositIdHex !== depositIdHex) {
      // Different deposit
      // -> recovery not applicable
      // --------------------------
      return null;
    }
    
    if (data.bobPrincipal !== bobPrincipal) {
      // Principal changed (different II login)
      // -> discard stale recovery
      localStorage.removeItem(CLAIM_RECOVERY_KEY);
      return null;
    }
    
    // Discard if older than 2 hours 
    //  -> job likely expired on-chain
    // -------------------------------
    const maxAgeMs = 2 * 60 * 60 * 1000;
    if (Date.now() - data.timestamp > maxAgeMs) {
      localStorage.removeItem(CLAIM_RECOVERY_KEY);
      return null;
    }
    
    return {
      jobId: BigInt(data.jobId),
      i2Id: data.i2Id,
      authKeyHashHex: data.authKeyHashHex
    };
  } catch {
    // Decryption failed (wrong NK, corrupted data)
    // -> clear and proceed with fresh claim
    // --------------------------------------------
    localStorage.removeItem(CLAIM_RECOVERY_KEY);
    return null;
  }
}

function clearClaimRecovery(): void {
  localStorage.removeItem(CLAIM_RECOVERY_KEY);
}

// ===================
// Send recovery state
// ===================

const SEND_RECOVERY_KEY = "ICPP:send_recovery";

interface SendRecoveryData {
  deposit_id_hex: string;
  router_account_owner: string;
  router_account_sub: string | null;
  treasury_account_owner: string;
  treasury_account_sub: string | null;
  spawn_fee_estimate: string;
  amount_e8s: string;
  bob_principal: string;
  stage: "allocated" | "funded" | "prepared" | "sealed";
  i1_id?: string;
  i2_id?: string;
  timestamp: number;
}

function saveSendRecovery(data: SendRecoveryData): void {
  const key = getSentIdsKey();
  const json = new TextEncoder().encode(JSON.stringify(data));
  const PADDED_SIZE = 2048;
  const plaintext = new Uint8Array(PADDED_SIZE);
  plaintext.set(json, 0);
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
  const ctWithTag = cipher.encrypt(plaintext);
  const blob = new Uint8Array(12 + ctWithTag.length);
  blob.set(nonce, 0);
  blob.set(ctWithTag, 12);
  localStorage.setItem(SEND_RECOVERY_KEY, bytesToHex(blob));
}

function loadSendRecovery(bobPrincipal: string): SendRecoveryData | null {
  const stored = localStorage.getItem(SEND_RECOVERY_KEY);
  if (!stored) return null;
  
  try {
    const key = getSentIdsKey();
    const blob = hexToBytes(stored);
    if (blob.length < 28) return null;
    
    const nonce = blob.slice(0, 12);
    const ctWithTag = blob.slice(12);
    const cipher = chacha20poly1305(key, nonce, new Uint8Array(0));
    const plaintext = cipher.decrypt(ctWithTag, new Uint8Array(ctWithTag.length - 16));
    const nullIdx = plaintext.indexOf(0);
    const jsonBytes = nullIdx === -1 ? plaintext : plaintext.slice(0, nullIdx);
    const data: SendRecoveryData = JSON.parse(new TextDecoder().decode(jsonBytes));
    
    // Must match 
    // current recipient
    // -----------------
    if (data.bob_principal !== bobPrincipal) {
      clearSendRecovery();
      return null;
    }
    
    // Discard if older 
    // than 1 hour
    // ----------------
    if (Date.now() - data.timestamp > 60 * 60 * 1000) {
      clearSendRecovery();
      return null;
    }
    
    return data;
  } catch {
    clearSendRecovery();
    return null;
  }
}

function clearSendRecovery(): void {
  localStorage.removeItem(SEND_RECOVERY_KEY);
}

// =======================
// CSRN transit decryption
// =======================

const te = new TextEncoder();
const TRANSIT_DOMAIN = te.encode("ICPP:transit:v1");

function deriveCsrnTransitKey(
  depositId: Uint8Array,
  alicePrincipal: Uint8Array,
  nonce32: Uint8Array
): Uint8Array {
  if (nonce32.length !== 32) {
    throw new Error(`Invalid CSRN nonce length: ${nonce32.length}`);
  }

  const h = sha3_256.create();
  h.update(TRANSIT_DOMAIN);
  h.update(depositId);
  h.update(alicePrincipal);
  h.update(nonce32);

  return h.digest();
}

function decryptCsrn(
  depositId: Uint8Array,
  alicePrincipal: Uint8Array,
  nonce32: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  if (ciphertext.length !== 48) {
    throw new Error(`Invalid CSRN ciphertext length: ${ciphertext.length}`);
  }

  const key = deriveCsrnTransitKey(depositId, alicePrincipal, nonce32);
  const nonce12 = nonce32.subarray(0, 12);

  const aead = chacha20poly1305(key, nonce12, depositId);
  const output = new Uint8Array(32);
  const plaintext = aead.decrypt(ciphertext, output);

  if (plaintext.length !== 32) {
    throw new Error(`Invalid CSRN plaintext length: ${plaintext.length}`);
  }

  return plaintext;
}

// Pre-warm
// ========

// ----------------------------------------------------------------------------
// - Local prewarm (startup-safe): primes JS/WebCrypto hot paths (no actors/II)
// - Canister prewarm: calls crypto.prewarm_bsgs once actors exist -> never
//   initializes actors (no II popup)
// ----------------------------------------------------------------------------

let cryptoPrewarmed = false;
let prewarmInFlight: Promise<void> | null = null;

let cryptoLocalPrewarmed = false;

async function prewarmCryptoLocal(): Promise<void> {
  if (cryptoLocalPrewarmed) return;
  cryptoLocalPrewarmed = true;

  // Prime WebCrypto 
  // first-call penalty
  // ------------------
  try {
    const subtle: SubtleCrypto | undefined = (globalThis as any).crypto?.subtle;
    if (subtle) await subtle.digest("SHA-256", new Uint8Array(32));
  } catch {}

}

// Reset prewarm state on session 
// expiry (a new delegation can re-prewarm)
// ----------------------------------------
if (typeof window !== "undefined") {
  window.addEventListener("icpp:session_expired", () => {
    cryptoPrewarmed = false;
    prewarmInFlight = null;
    cryptoLocalPrewarmed = false;
  });
}

// Canister prewarm worker
// -----------------------
async function prewarmCrypto(): Promise<void> {
  if (cryptoPrewarmed) return;
  if (prewarmInFlight) return prewarmInFlight;

  const actors = getActorsForQuery();
  if (!actors) return;

  const { crypto } = actors;

  prewarmInFlight = (async () => {
    const timeoutMs = 120_000;
    const start = Date.now();
    let calls = 0;

    while (Date.now() - start < timeoutMs) {
      const res = await (crypto as any).prewarm_bsgs(BigInt(1000));
      calls += 1;

      if (!Array.isArray(res) || res.length < 2) {
        throw new Error("Pre-warming error");
      }

      const ok = Boolean(res[0]);
      const done = Boolean(res[1]);

      if (!ok) {
        throw new Error("Pre-warming failed");
      }

      if (done) {
        cryptoPrewarmed = true;
        return;
      }

      await new Promise((r) => setTimeout(r, 75));
    }

    throw new Error(`Pre-warming timeout (calls=${calls})`);
  })();

  try {
    await prewarmInFlight;
  } finally {
    prewarmInFlight = null;
  }
}

// Startup triggers
// ----------------
if (typeof window !== "undefined") {
  void prewarmCryptoLocal();

  const deadline = Date.now() + 30_000;

  const tick = () => {
    if (cryptoPrewarmed) return;

    if (getActorsForQuery()) {
      void prewarmCrypto().catch(() => {});
      return;
    }

    if (Date.now() >= deadline) return;
    setTimeout(tick, 250);
  };

  setTimeout(tick, 0);
}

// Operational status 
// for adaptive delay
// ==================
export interface OperationalStatus {
  cycles_balance: bigint;
  spawns_available: number;
  recommended_delay_ms: number;
}

export async function getOperationalStatus(): Promise<OperationalStatus> {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }

  const result = await (actors.router as any).get_operational_status();

  return {
    cycles_balance: BigInt(result.cycles_balance),
    spawns_available: Number(result.spawns_available),
    recommended_delay_ms: Number(result.recommended_delay_ms),
  };
}

// Router config
// =============
export interface RouterConfig {
  deposit_fee_bps: number;
  egress_fee_bps: number;
  reclaim_fee_bps: number;
  ttl_secs: number;
}

let cachedConfig: RouterConfig | null = null;
let configFetchTime: number = 0;
const CONFIG_CACHE_MS = 60_000;

export async function getRouterConfig(): Promise<RouterConfig> {
  const now = Date.now();

  if (cachedConfig && now - configFetchTime < CONFIG_CACHE_MS) {
    return cachedConfig;
  }

  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }

  const result = await actors.router.get_config();

  cachedConfig = {
    deposit_fee_bps: Number(result.config.deposit_fee_bps),
    egress_fee_bps: Number(result.config.egress_fee_bps),
    reclaim_fee_bps: Number(result.config.reclaim_fee_bps),
    ttl_secs: Number(result.config.ttl_secs),
  };

  configFetchTime = now;
  return cachedConfig;
}

export function clearConfigCache(): void {
  cachedConfig = null;
  configFetchTime = 0;
}

// Fee Calculation
// ===============
export interface FeeBreakdown {
  depositFee: bigint;
  spawnFee: bigint;
  ledgerFee: bigint;
  numLedgerTransfers: number;
  totalLedgerFees: bigint;
  totalApproval: bigint;
}

// CMC Rate query
// ==============
async function getCMCRate(): Promise<bigint> {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }
  
  const CMC = Actor.createActor(
    ({ IDL }: any) => IDL.Service({
      get_icp_xdr_conversion_rate: IDL.Func(
        [],
        [IDL.Record({
          data: IDL.Record({
            timestamp_seconds: IDL.Nat64,
            xdr_permyriad_per_icp: IDL.Nat64
          })
        })],
        ['query']
      )
    }),
    { agent: actors.agent, canisterId: Principal.fromText(CMC_CANISTER_ID) }
  );
  
  const result = await (CMC as any).get_icp_xdr_conversion_rate();
  const rate = BigInt(result.data.xdr_permyriad_per_icp);
  
  if (rate === 0n) {
    throw new Error("CMC offline or rate unavailable");
  }
  
  return rate;
}

export async function calculateFees(amountE8s: bigint): Promise<FeeBreakdown> {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }
  
  const { router } = actors;
  const config = await getRouterConfig();
  const spawnCycles = await router.get_spawn_cycles();
  
  const ceilDiv = (a: bigint, b: bigint) => (a + (b - 1n)) / b;
  
  // Calculate spawn fee 
  // using real-time CMC rate
  // ------------------------
  const cmcRate = await getCMCRate();
  const spawnFee = cmcRate > 0n 
    ? ceilDiv(spawnCycles, cmcRate) 
    : (() => { throw new Error("CMC offline or rate unavailable"); })();
  
  // Round up 
  // to whole ICP
  // ------------
  const E8S_PER_ICP = 100_000_000n;
  const ceilAmount = ceilDiv(amountE8s, E8S_PER_ICP) * E8S_PER_ICP;
  const roundingTopUp = ceilAmount - amountE8s;
  
  const depositFee = (ceilAmount * BigInt(config.deposit_fee_bps)) / 10_000n;
  const ledgerFee = 10_000n;
  
  // Transfer accounting
  // -------------------
  // 1. Alice -> Router deposit subaccount
  // 2. Alice -> Treasury (platform fee)
  // 3. Router deposit -> CMC (cycles conversion)
  // 4. Router deposit -> Mixer (d1)
  // 5. Router deposit -> Mixer (d2)
  // 6. Router deposit -> Mixer (d3)
  // 7. Mixer -> Bob
  // 8. Buffer
  // -------------------------------------------
  const numLedgerTransfers = 10;
  
  const totalLedgerFees = BigInt(numLedgerTransfers) * ledgerFee;
  const totalApproval = ceilAmount + roundingTopUp + depositFee + spawnFee + totalLedgerFees;
  
  return {
    depositFee,
    spawnFee,
    ledgerFee,
    numLedgerTransfers,
    totalLedgerFees,
    totalApproval,
  };
}

// NK + setup
// ==========
export async function setupICPP(pin: string) {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }
  const { principal } = actors;

  // Reuse existing NK if 
  // already provisioned
  // --------------------
  const nkStorageKey = `ICPP:nk:${principal.toText()}`;
  const hasNk = localStorage.getItem(nkStorageKey) !== null;

  const nk = hasNk ? await loadNk(principal, pin) : generateNk();

  if (!hasNk) {
    await storeNk(principal, pin, nk);
  }

  initSentIdsKey(nk);

  return { principal };
}

// =========
// SEND FLOW
// =========

export interface SendParams {
  amountE8s: bigint;
  bobPrincipal: Principal;
  // ICRC-1 optional subaccount 
  // encoding (None=[], Some=[32-byte])
  // ----------------------------------
  subaccount: [] | [Uint8Array];
}

function assertOptSubaccount32(opt: [] | [Uint8Array]): void {
  if (opt.length === 0) return;
  if (opt.length !== 1) throw new Error("Invalid opt subaccount encoding");
  const sa = opt[0];
  if (!(sa instanceof Uint8Array)) throw new Error("Subaccount must be Uint8Array");
  if (sa.length !== 32) throw new Error("Subaccount must be 32 bytes");
}

export interface SendResult {
  depositIdHex: string;
  i2IdText: string;
}

export async function sendShielded(params: SendParams): Promise<SendResult> {
  const actors = getActorsForQuery();
  
  if (!actors) {
    throw new Error("Session not initialized");
  }

  await prewarmCrypto();
  
  const { router, crypto, ledger, i1, principal: alice } = actors;
  const amount = params.amountE8s;
  const bobPrincipal = params.bobPrincipal;

  // Validate optional 
  // subaccount encoding early
  // -------------------------
  assertOptSubaccount32(params.subaccount);

  // Hard limit of 
  // 2000 ICP max
  // -------------
  const MAX_SEND_E8S = 2000n * 100_000_000n;
  if (amount > MAX_SEND_E8S) {
    throw new Error("Only up to 2000 ICP can be sent");
  }

  // Check for in-progress 
  // deposit to resume
  // ---------------------
  const recovery = loadSendRecovery(bobPrincipal.toText());
  
  let deposit_id: Uint8Array;
  let depositIdHex: string;
  let routerAccount: { owner: Principal; subaccount: [] | [Uint8Array] };
  let treasuryAccount: { owner: Principal; subaccount: [] | [Uint8Array] };
  let spawnFeeEstimate: bigint;
  let stage: "allocated" | "funded" | "prepared" | "sealed";
  let i1Id: Principal | null = null;
  let i2Id: Principal | null = null;

  if (recovery && BigInt(recovery.amount_e8s) === amount) {
    // Resume existing deposit
    // -----------------------
    deposit_id = hexToBytes(recovery.deposit_id_hex);
    depositIdHex = recovery.deposit_id_hex;
    routerAccount = {
      owner: Principal.fromText(recovery.router_account_owner),
      subaccount: recovery.router_account_sub ? [hexToBytes(recovery.router_account_sub)] : []
    };
    treasuryAccount = {
      owner: Principal.fromText(recovery.treasury_account_owner),
      subaccount: recovery.treasury_account_sub ? [hexToBytes(recovery.treasury_account_sub)] : []
    };
    spawnFeeEstimate = BigInt(recovery.spawn_fee_estimate);
    stage = recovery.stage;
    if (recovery.i1_id) i1Id = Principal.fromText(recovery.i1_id);
    if (recovery.i2_id) i2Id = Principal.fromText(recovery.i2_id);
  } else {
    // Fresh deposit
    // -------------
    clearSendRecovery();
    
    const allocRes = await router.deposit_alloc({
      recipient_hint_pref: 1_000_000,
    });

    if ("err" in allocRes) {
      throw new Error(`Router.deposit_alloc failed: ${allocRes.err}`);
    }

    const allocOk = allocRes.ok as {
      deposit_id: Uint8Array;
      router_account: { owner: Principal; subaccount: [] | [Uint8Array] };
      treasury_account: { owner: Principal; subaccount: [] | [Uint8Array] };
      spawn_fee_estimate: bigint;
      memo: [] | [Uint8Array] | null;
    };

    deposit_id = allocOk.deposit_id;
    depositIdHex = bytesToHex(deposit_id);
    routerAccount = allocOk.router_account;
    treasuryAccount = allocOk.treasury_account;
    spawnFeeEstimate = allocOk.spawn_fee_estimate;
    stage = "allocated";

    // Persist immediately 
    // after allocation
    // -------------------
    saveSendRecovery({
      deposit_id_hex: depositIdHex,
      router_account_owner: routerAccount.owner.toText(),
      router_account_sub: routerAccount.subaccount[0] ? bytesToHex(routerAccount.subaccount[0] as Uint8Array) : null,
      treasury_account_owner: treasuryAccount.owner.toText(),
      treasury_account_sub: treasuryAccount.subaccount[0] ? bytesToHex(treasuryAccount.subaccount[0] as Uint8Array) : null,
      spawn_fee_estimate: spawnFeeEstimate.toString(),
      amount_e8s: amount.toString(),
      bob_principal: bobPrincipal.toText(),
      stage: "allocated",
      timestamp: Date.now(),
    });
  }

  // Calculate fees using 
  // server spawn_fee_estimate
  // -------------------------
  if (stage === "allocated") {
    const config = await getRouterConfig();
    const depositFee = (amount * BigInt(config.deposit_fee_bps)) / 10_000n;
    const ledgerFee = 10_000n;
    const routerDeposit = amount + spawnFeeEstimate + (5n * ledgerFee);

    // Check Router state to 
    // prevent double-spend
    // ---------------------
    let skipTransfers = false;
    try {
      const statusRes = await router.status(deposit_id);
      if ("ok" in statusRes) {
        const routerState = statusRes.ok.state;
        if (!("Allocated" in routerState)) {
          skipTransfers = true;
          stage = "funded";
        }
      }
    } catch {
      // Proceed with 
      // transfers
    }

    if (!skipTransfers) {
      if (depositFee > 0n) {
        const feeTransferResult = await ledger.icrc1_transfer({
          from_subaccount: params.subaccount,
          to: treasuryAccount,
          amount: depositFee,
          fee: [],
          memo: [],
          created_at_time: [],
        } as any);

        if ("Err" in feeTransferResult) {
          throw new Error(`Protocol fee transfer failed: ${stringify(feeTransferResult.Err)}`);
        }
      }

      const memo = [new Uint8Array(Array.from(deposit_id).slice(0, 8))];
      
      const transferResult = await ledger.icrc1_transfer({
        from_subaccount: params.subaccount,
        to: routerAccount,
        amount: routerDeposit,
        fee: [],
        memo,
        created_at_time: [],
      } as any);

      if ("Err" in transferResult) {
        throw new Error(`Router deposit transfer failed: ${stringify(transferResult.Err)}`);
      }
    }

    stage = "funded";
    saveSendRecovery({
      deposit_id_hex: depositIdHex,
      router_account_owner: routerAccount.owner.toText(),
      router_account_sub: routerAccount.subaccount[0] ? bytesToHex(routerAccount.subaccount[0] as Uint8Array) : null,
      treasury_account_owner: treasuryAccount.owner.toText(),
      treasury_account_sub: treasuryAccount.subaccount[0] ? bytesToHex(treasuryAccount.subaccount[0] as Uint8Array) : null,
      spawn_fee_estimate: spawnFeeEstimate.toString(),
      amount_e8s: amount.toString(),
      bob_principal: bobPrincipal.toText(),
      stage: "funded",
      timestamp: Date.now(),
    });

    await new Promise(r => setTimeout(r, 5000));
  }

  // Retry loop ONLY (invisible lock)
  // We try up to 5 times for the 
  // lock to clear
  // --------------------------------
  if (stage === "funded") {
    const MAX_PREPARE_RETRIES = 5;
    
    for (let attempt = 0; attempt < MAX_PREPARE_RETRIES; attempt++) {
      const prepRes = await router.deposit_prepare(deposit_id, spawnFeeEstimate);

      if ("ok" in prepRes) {
        i1Id = prepRes.ok.i1_id;
        i2Id = prepRes.ok.i2_id;
        break;
      }

      const err = prepRes.err;

    // Lock returns 
    // ERR_TEMP_UNAVAILABLE
    // --------------------
      if (err.includes("TEMPORARILY_UNAVAILABLE")) {
        await new Promise(r => setTimeout(r, 1000));
        continue;
      }

      throw new Error(`Router.deposit_prepare failed: ${err}`);
    }

    if (!i1Id || !i2Id) {
      throw new Error(`Router.deposit_prepare timed out - Please try again`);
    }

    stage = "prepared";
    saveSendRecovery({
      deposit_id_hex: depositIdHex,
      router_account_owner: routerAccount.owner.toText(),
      router_account_sub: routerAccount.subaccount[0] ? bytesToHex(routerAccount.subaccount[0] as Uint8Array) : null,
      treasury_account_owner: treasuryAccount.owner.toText(),
      treasury_account_sub: treasuryAccount.subaccount[0] ? bytesToHex(treasuryAccount.subaccount[0] as Uint8Array) : null,
      spawn_fee_estimate: spawnFeeEstimate.toString(),
      amount_e8s: amount.toString(),
      bob_principal: bobPrincipal.toText(),
      stage: "prepared",
      i1_id: i1Id.toText(),
      i2_id: i2Id.toText(),
      timestamp: Date.now(),
    });
  }

  // Get operational status 
  // for adaptive delay
  // ----------------------
  if (stage === "prepared") {
    const opStatus = await getOperationalStatus();
    if (opStatus.recommended_delay_ms > 0) {
      await new Promise((r) => setTimeout(r, opStatus.recommended_delay_ms));
    }

    const MAX_SEAL_RETRIES = 5;

    for (let attempt = 0; attempt < MAX_SEAL_RETRIES; attempt++) {
      const sealRes = await router.seal_push(deposit_id);

      if ("ok" in sealRes) {
        stage = "sealed";
        break;
      }

      const err = sealRes.err;

      if (err.includes("TRANSFER_FAILED") || err.includes("TEMPORARILY_UNAVAILABLE")) {
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      throw new Error(`Router.seal_push failed: ${err}`);
    }

    if (stage !== "sealed") {
      throw new Error(`Router.seal_push timed out. Please try again.`);
    }

    saveSendRecovery({
      deposit_id_hex: depositIdHex,
      router_account_owner: routerAccount.owner.toText(),
      router_account_sub: routerAccount.subaccount[0] ? bytesToHex(routerAccount.subaccount[0] as Uint8Array) : null,
      treasury_account_owner: treasuryAccount.owner.toText(),
      treasury_account_sub: treasuryAccount.subaccount[0] ? bytesToHex(treasuryAccount.subaccount[0] as Uint8Array) : null,
      spawn_fee_estimate: spawnFeeEstimate.toString(),
      amount_e8s: amount.toString(),
      bob_principal: bobPrincipal.toText(),
      stage: "sealed",
      i1_id: i1Id!.toText(),
      i2_id: i2Id!.toText(),
      timestamp: Date.now(),
    });
  }

  // Ask I1 to initialise CSRN 
  // and encrypt it for transit
  // --------------------------
  const i1Actor = i1(i1Id!);

  const csrnRes = await i1Actor.prepare_deposit(deposit_id);

  if ("err" in csrnRes) {
    throw new Error(`I1.prepare_deposit failed: ${csrnRes.err}`);
  }

  const { nonce, ciphertext } = csrnRes.ok as {
    nonce: Uint8Array;
    ciphertext: Uint8Array;
  };

  // Decrypt CSRN 
  // client-side
  // ------------
  const depositIdBytes = deposit_id instanceof Uint8Array ? deposit_id : Uint8Array.from(deposit_id);
  const aliceBytes = alice.toUint8Array();
  const nonceBytes = nonce instanceof Uint8Array ? nonce : Uint8Array.from(nonce);
  const ciphertextBytes = ciphertext instanceof Uint8Array ? ciphertext : Uint8Array.from(ciphertext);

  const csrnBytes = decryptCsrn(
    depositIdBytes,
    aliceBytes,
    nonceBytes,
    ciphertextBytes
  );

  // Drive Crypto.create_* session
  // -----------------------------
  const createStartOut = await crypto.create_start({
    deposit_id,
    i2_principal: i2Id!,
    amount,
    csrn: csrnBytes,
  } as any);

  {
    const [okFlag, sessionId, errMsg] = createStartOut as [
      boolean,
      bigint,
      string
    ];

    if (!okFlag) {
      throw new Error(`Crypto.create_start failed: ${errMsg}`);
    }

    const maxIters = 100n;

    while (true) {
      const [ok, finished, stepErr] = (await crypto.create_step(
        sessionId,
        Number(maxIters)
      )) as [boolean, boolean, string];

      if (!ok) {
        throw new Error(`Crypto.create_step failed: ${stepErr}`);
      }

      if (finished) break;
    }

    const [resOk, capsule, inner, hint, resErr] = (await crypto.create_result(sessionId)) as [
      boolean,
      Uint8Array,
      Uint8Array,
      Uint8Array,
      string
    ];

    if (!resOk) {
      throw new Error(`Crypto.create_result failed: ${resErr}`);
    }

    // Ask I1 to 
    // store + announce
    // ----------------
    const sealedPackage = {
      hint,
      capsule,
      inner,
    };

    const storeRes = await i1Actor.store_and_announce({
      package: sealedPackage,
      deposit_id,
      client_ctx: [] as [] | [null],
    } as any);

    if ("err" in storeRes) {
      throw new Error(`I1.store_and_announce failed: ${storeRes.err}`);
    }
  }

  // Success -> clear 
  // recovery state
  // ----------------
  clearSendRecovery();
  saveSentId(depositIdHex);

  return {
    depositIdHex,
    i2IdText: i2Id!.toText(),
  };
}

// ============
// RECEIVE FLOW
// ============

export interface AnnouncementView {
  idx: bigint;
  hintHex: string;
  depositIdHex: string;
  storagePrincipals: Principal[];
  tsNs: bigint;
}

export async function listAnnouncements(
  startIdx: bigint = 0n,
  limit: bigint = 50n
): Promise<AnnouncementView[]> {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }

  const { noticeboard } = actors;

  let sentIds: Set<string> = new Set();
  try {
    sentIds = getSentIds();
  } catch {
    sentIds = new Set();
  }

  const anns: any[] = await (noticeboard as any).get_announcements(startIdx, limit);

  return (anns as any[])
    .filter((a) => !sentIds.has(bytesToHex(new Uint8Array(a.deposit_id))))
    .map((a) => {
      const dep = new Uint8Array(a.deposit_id);
      const hint = new Uint8Array(a.hint);

      return {
        idx: BigInt(a.idx),
        tsNs: BigInt(a.ts),
        depositIdHex: bytesToHex(dep),
        hintHex: bytesToHex(hint),
        storagePrincipals: a.storage as Principal[],
      };
    });
}

// ====================================
// CLAIM DEPOSIT -> LOCAL RDMPF DECRYPT
// ====================================

export async function claimDeposit(
  depositIdHex: string,
  pin: string,
  storagePrincipals: Principal[]
): Promise<void> {
  const actors = getActorsForQuery();
  
  if (!actors) {
    throw new Error("Session not initialized");
  }
  const { principal: bob, router, i2, agent } = actors;
  const bobPrincipalText = bob.toText();

  // Force fresh 
  // agent state
  // -----------
  try {
    if ((agent as any).fetchRootKey) {
      await (agent as any).fetchRootKey();
    }
  } catch {
    // Ignore
  }

  // Verify PIN (proves 
  // device ownership)
  // ------------------
  await loadNk(bob, pin);

  // Decode deposit_id 
  // from hex
  // -----------------
  const deposit_id = hexToBytes(depositIdHex);

  // Discover I2 
  // via Router
  // -----------
  const infoOpt = await router.get_deposit_info(deposit_id);

  let info: any | null = null;
  if (Array.isArray(infoOpt)) {
    info = infoOpt.length > 0 ? infoOpt[0] : null;
  } else {
    info = infoOpt;
  }

  if (!info) {
    throw new Error("Router.get_deposit_info returned null for this deposit");
  }
  
  const i2Id: Principal = info.i2 as Principal;
  const i2IdText = i2Id.toText();

  // Fetch package from 
  // Storage canister(s)
  // -------------------
  if (storagePrincipals.length === 0) {
    throw new Error("No storage principals provided");
  }

  let packageBlob: Uint8Array | null = null;
  for (const storagePrincipal of storagePrincipals) {
    try {
      const storageActor = Actor.createActor(
        ({ IDL }: any) =>
          IDL.Service({
            get_package: IDL.Func(
              [],
              [IDL.Variant({ ok: IDL.Vec(IDL.Nat8), err: IDL.Text })],
              ["query"]
            ),
          }),
        { agent, canisterId: storagePrincipal }
      );
      const result = await (storageActor as any).get_package();
      if ("ok" in result) {
        packageBlob = new Uint8Array(result.ok);
        break;
      }
    } catch (e) {
      // Continue to next 
      // storage canister
    }
  }

  if (!packageBlob) {
    throw new Error("Unable now to handle your request");
  }

  // Parse package -> hint(80) || cap_len(4 BE) || capsule || encrypted_inner
  // ------------------------------------------------------------------------
  const hintLen = 80;
  const lenFieldLen = 4;

  if (packageBlob.length < hintLen + lenFieldLen) {
    throw new Error("Package too short");
  }

  const capLen =
    (packageBlob[hintLen] << 24) |
    (packageBlob[hintLen + 1] << 16) |
    (packageBlob[hintLen + 2] << 8) |
    packageBlob[hintLen + 3];

  const capStart = hintLen + lenFieldLen;
  const innerStart = capStart + capLen;

  if (packageBlob.length < innerStart) {
    throw new Error("Package malformed");
  }

  const capsule = packageBlob.slice(capStart, innerStart);
  const encrypted_inner = packageBlob.slice(innerStart);

  // LOCAL RDMPF DECRYPT
  //  - Extracts CSRN from capsule.nonce
  //  - Derives bases from CSRN
  //  - Runs double RDMPF (T1, T2) locally
  //  - Composes, derives key, decrypts
  //  - Returns auth_key_hash_hex
  // -------------------------------------
  let decryptResult;
  try {
    decryptResult = decryptTransfer(
      new Uint8Array(capsule),
      new Uint8Array(encrypted_inner),
      new Uint8Array(deposit_id)
    );
  } catch (e) {
    throw e;
  }

  const authKeyHashHex = decryptResult.auth_key_hash_hex;

  // Create I2 actor
  // ---------------
  const i2Actor = i2(i2Id);

  // Check for recoverable job 
  // from previous expired session
  // -----------------------------
  let currentJobId: bigint;
  const recovery = loadClaimRecovery(depositIdHex, bobPrincipalText);
  
  if (recovery && recovery.i2Id === i2IdText && recovery.authKeyHashHex === authKeyHashHex) {
    // Valid recovery found: resume existing job
    // -----------------------------------------
    currentJobId = recovery.jobId;
  } else {
    // No valid recovery
    // -> start fresh job
    // ------------------
    const startRes = await i2Actor.finalize_start({
      deposit_id,
      auth_key_hash_hex: authKeyHashHex,
      recipient: {
        owner: bob,
        subaccount: [],
      },
    });

    if ("err" in startRes) {
      throw new Error(`I2.finalize_start failed: ${startRes.err}`);
    }
    
    currentJobId = startRes.ok;
  }

  // Persist job state (encrypted) 
  // for recovery after session expiry
  // ---------------------------------
  saveClaimRecovery(
    depositIdHex,
    currentJobId,
    i2IdText,
    authKeyHashHex,
    bobPrincipalText
  );

  // ==============================
  // Network-aware finalize polling
  // ==============================

  // 540 * 5s = 2700s (45 minutes)
  // 5 sec between polls
  // 15 min reset threshold
  // -----------------------------
  const maxAttempts = 540;
  const delayMs = 5000;  
  const resetThreshold = 180;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Check delegation validity EVERY iteration
    // (prevents wasted retries with expired auth)
    // -------------------------------------------
    if (isDelegationStale()) {
      // Recovery data already persisted (encrypted)
      // so user can resume after re-authenticating
      // ------------------------------------------
      throw new Error("Session expired — please re-login and retry claim");
    }

    // After 15 min stuck 
    // attempt reset and restart
    // -------------------------
    if (attempt === resetThreshold) {
      try {
        const resetRes = await i2Actor.reset_job({
          deposit_id,
          auth_key_hash_hex: authKeyHashHex,
        });
        if ("ok" in resetRes) {
          const restartRes = await i2Actor.finalize_start({
            deposit_id,
            auth_key_hash_hex: authKeyHashHex,
            recipient: { owner: bob, subaccount: [] },
          });
          if ("ok" in restartRes) {
            currentJobId = restartRes.ok;
            // Update recovery 
            // data with new job ID
            // --------------------
            saveClaimRecovery(
              depositIdHex,
              currentJobId,
              i2IdText,
              authKeyHashHex,
              bobPrincipalText
            );
          }
        }
      } catch (e) {
        // Reset failed continue 
        // so polling original job
      }
    }

    let statusRes: any;
    try {
      statusRes = await i2Actor.finalize_status(currentJobId);
    } catch (e: any) {
      const msg = String(e?.message || e);
      
      // Distinguish auth failures from network failures
      // (auth failures are unrecoverable without re-login)
      // --------------------------------------------------
      if (
        msg.includes("Invalid delegation") ||
        msg.includes("delegation has expired") ||
        msg.includes("Invalid signature") ||
        msg.includes("Sender delegation has expired")
      ) {
        // Recovery data 
        // already persisted
        // -----------------
        throw new Error("Session expired — please re-login and retry claim");
      }
      
      // Network or transient 
      // replica errors -> retry
      // -----------------------
      await new Promise((r) => setTimeout(r, delayMs));
      continue;
    }

    if ("err" in statusRes) {
      // Permanent canister error
      // -> clean up recovery
      // ------------------------
      clearClaimRecovery();
      throw new Error(`I2.finalize_status failed: ${statusRes.err}`);
    }

    const status = statusRes.ok;

    if ("done" in status) {
      // Success -> clean 
      // up recovery data
      // ----------------
      clearClaimRecovery();
      removeSentId(depositIdHex);
      return;
    }

    if ("error" in status) {
      // Permanent failure
      // -> clean up recovery data
      // -------------------------
      clearClaimRecovery();
      throw new Error(`I2.finalize failed: ${status.error}`);
    }

    // Still pending/processing 
    // -> wait and retry
    // ------------------------
    await new Promise((r) => setTimeout(r, delayMs));
  }

  // Timeout -> keep recovery 
  // data so user can retry
  // ------------------------
  throw new Error(
    "I2.finalize did not complete within 45 minutes — please retry claim"
  );
}

// ============
// WITHDRAW ICP
// ============

export async function withdrawIcp(
  destinationPrincipal: Principal,
  amountE8s: bigint,
  pin: string,
  destinationSubaccount?: Uint8Array
): Promise<bigint> {
  const actors = getActorsForQuery();
  if (!actors) {
    throw new Error("Session not initialized");
  }

  const { ledger, principal } = actors;

  // Verify PIN
  // ----------
  await loadNk(principal, pin);

  // Execute ICRC-1 transfer
  // -----------------------
  const result = await (ledger as any).icrc1_transfer({
    to: {
      owner: destinationPrincipal,
      subaccount: destinationSubaccount ? [destinationSubaccount] : [],
    },
    amount: amountE8s,
    fee: [10_000n],
    memo: [],
    from_subaccount: [],
    created_at_time: [],
  });

  if ("Err" in result) {
    const err = result.Err;
    if ("InsufficientFunds" in err) {
      throw new Error("Insufficient funds available");
    }
    if ("BadFee" in err) {
      throw new Error("Invalid fee");
    }
    if ("TemporarilyUnavailable" in err) {
      throw new Error("Ledger temporarily unavailable");
    }
    throw new Error(`Transfer failed: ${JSON.stringify(err)}`);
  }

  return result.Ok;
}