// ===================================================
// Agents and typed actors
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 07 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import { HttpAgent, Actor } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { Principal } from "@dfinity/principal";
import { ENV } from "./env";

// Import IDL factories from 
// generated declarations
// -------------------------
import {
  idlFactory as routerIdl,
  _SERVICE as RouterService,
} from "../../../src/declarations/router/router.did.js";

import {
  idlFactory as cryptoIdl,
  _SERVICE as CryptoService,
} from "../../../src/declarations/crypto/crypto.did.js";

import {
  idlFactory as noticeboardIdl,
  _SERVICE as NoticeboardService,
} from "../../../src/declarations/noticeboard/noticeboard.did.js";

import {
  idlFactory as registryIdl,
  _SERVICE as RegistryService,
} from "../../../src/declarations/registry/registry.did.js";

import {
  idlFactory as ledgerIdl,
  _SERVICE as LedgerService,
} from "../../../src/declarations/ledger/ledger.did.js";

import {
  idlFactory as i1Idl,
  _SERVICE as I1Service,
} from "../../../src/declarations/i1/i1.did.js";

import {
  idlFactory as i2Idl,
  _SERVICE as I2Service,
} from "../../../src/declarations/i2/i2.did.js";

import {
  idlFactory as storageIdl,
  _SERVICE as StorageService,
} from "../../../src/declarations/storage/storage.did.js";


export interface ICPPActors {
  agent: HttpAgent;
  authClient: AuthClient | null;
  principal: Principal;
  router: RouterService;
  crypto: CryptoService;
  noticeboard: NoticeboardService;
  registry: RegistryService;
  ledger: LedgerService;
  i1: (canisterId: Principal) => I1Service;
  i2: (canisterId: Principal) => I2Service;
  storage: (canisterId: Principal) => StorageService;
}

let cachedActors: ICPPActors | null = null;

export function clearActorCache(): void {
  cachedActors = null;
}

// =================
// Identity handling
// =================

// - Delegation TTL requested from Internet Identity -> 60 minutes
// - Before starting any user operation ensure > 30 minutes remain or else refresh
// - Idle timeout (UI inactivity) 20 min but not killing in-flight ops

// Delegation and
// session policy
// --------------
const DELEGATION_MAX_TTL_NS = 4n * 60n * 60n * 1_000_000_000n;   // -> 4 hours
const DELEGATION_MIN_REMAIN_NS = 60n * 60n * 1_000_000_000n;     // -> 1 hour
const IDLE_TIMEOUT_MS = 20 * 60 * 1000;                          // -> 20 minutes
const DELEGATION_REFRESH_GRACE_NS = 5n * 60n * 1_000_000_000n;   // -> 5 minutes

// In-flight 
// operation counter
// -----------------
let opsInFlight = 0;

// Any actor/identity refresh and operation-start 
// is serialized so they cannot interleave
// ----------------------------------------------
let authGate: Promise<void> = Promise.resolve();
async function withAuthGate<T>(fn: () => Promise<T>): Promise<T> {
  const prev = authGate;
  let release!: () => void;
  authGate = new Promise<void>((r) => (release = r));
  await prev;
  try {
    return await fn();
  } finally {
    release();
  }
}
function getDelegationExpiryNs(authClient: AuthClient): bigint | null {
  const identity: any = authClient.getIdentity() as any;
  const delegation = identity?.getDelegation?.();
  const exp = delegation?.delegations?.[0]?.delegation?.expiration;
  if (!exp) return null;
  return BigInt(exp);
}

async function loginWithII(authClient: AuthClient): Promise<void> {
  const derivationOrigin =
    (ENV as any).DERIVATION_ORIGIN && String((ENV as any).DERIVATION_ORIGIN).length > 0
      ? String((ENV as any).DERIVATION_ORIGIN)
      : undefined;

  const identityProvider = (ENV as any).II_URL
    ? String((ENV as any).II_URL)
    : "https://id.ai/?feature_flag_guided_upgrade=true";

  await new Promise<void>((resolve, reject) => {
    authClient.login({
      identityProvider,
      derivationOrigin,
      maxTimeToLive: DELEGATION_MAX_TTL_NS,
      onSuccess: () => resolve(),
      onError: (err) => reject(err),
    });
  });
}

// Refresh delegation if remaining time 
// is below DELEGATION_MIN_REMAIN_NS
// ------------------------------------
async function ensureDelegationBudget(authClient: AuthClient): Promise<boolean> {
  const expNs = getDelegationExpiryNs(authClient);
  if (!expNs) return false;

  const nowNs = BigInt(Date.now()) * 1_000_000n;
  const remainingNs = expNs > nowNs ? expNs - nowNs : 0n;

  if (remainingNs < (DELEGATION_MIN_REMAIN_NS + DELEGATION_REFRESH_GRACE_NS)) {
    await loginWithII(authClient);
    return true;
  }
  return false;
}

export function getSessionRemainingMs(): number | null {
  const ac = cachedActors?.authClient;
  if (!ac) return null;

  const expNs = getDelegationExpiryNs(ac);
  if (!expNs) return null;

  const nowNs = BigInt(Date.now()) * 1_000_000n;
  const remainingNs = expNs > nowNs ? expNs - nowNs : 0n;
  return Number(remainingNs / 1_000_000n);
}

// Checks if delegation has sufficient runway for a long operation
// Requires at least 15 minutes above max operation time (~45 min)
// ---------------------------------------------------------------
export function hasSufficientDelegation(): boolean {
  const remainingMs = getSessionRemainingMs();
  if (remainingMs === null) return false;
  return remainingMs >= 60 * 60 * 1000;
}

// Returns true if delegation 
// is expired or critically low
// ----------------------------
export function isDelegationStale(): boolean {
  const remainingMs = getSessionRemainingMs();
  if (remainingMs === null) return true;
  return remainingMs < 2 * 60 * 1000;
}

// Called by UI before long-running operations (send/claim)
// Disables idle expiry and refreshes delegation if needed
// --------------------------------------------------------
export async function beginUserOperation(): Promise<void> {
  await withAuthGate(async () => {
    // Ensure actors/identity are ready BEFORE 
    // marking the operation as in-flight
    // ---------------------------------------
    const actors = await initICPPActorsUnlocked();

    // Verify delegation 
    // has sufficient runway
    // ---------------------
    if (!hasSufficientDelegation()) {
      throw new Error("State invalid – please refresh");
    }

    // Mark in-flight only 
    // after actors are stable
    // -----------------------
    opsInFlight += 1;

    try {
      // Disable idle expiry while 
      // the operation is in-flight
      // --------------------------
      const ac: any = actors.authClient as any;
      ac?.idleManager?.disable?.();
      ac?.idleManager?.reset?.();
    } catch (e) {
      opsInFlight = Math.max(0, opsInFlight - 1);
      throw e;
    }
  });
}

// Must be called in a finally{} 
// after beginUserOperation()
// -----------------------------
export function endUserOperation(): void {
  opsInFlight = Math.max(0, opsInFlight - 1);

  if (opsInFlight === 0) {
    const ac: any = cachedActors?.authClient as any;
    ac?.idleManager?.enable?.();
    ac?.idleManager?.reset?.();
  }
}

// Logout actions
// --------------
export async function logoutICPP(): Promise<void> {
  await withAuthGate(async () => {
    if (opsInFlight > 0) {
      throw new Error("Operation in flight");
    }

    // We logout the existing authClient if present
    // (otherwise we create one to clear any 
    // persisted session)
    // --------------------------------------------
    const ac = cachedActors?.authClient ?? (await AuthClient.create());

    // Clear actor cache first to ensure 
    // no stale agent/identity is reused
    // ---------------------------------
    clearActorCache();

    await (ac as any).logout?.();
  });

  // Tell UI to reset state
  // ----------------------
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("icpp:session_expired"));
  }
}

async function getIdentity(): Promise<{
  identity: any;
  principal: Principal;
  authClient: AuthClient | null;
}> {
  const authClient = await AuthClient.create({
    idleOptions: {
      idleTimeout: IDLE_TIMEOUT_MS,
      // We control the idle callback
      // (do NOT expire when in-flight)
      // ------------------------------
      disableDefaultIdleCallback: true,
      onIdle: () => {
        // If an operation is 
        // in-flight keep it alive
        // -----------------------
        if (opsInFlight > 0) {
          try {
            (authClient as any)?.idleManager?.reset?.();
          } catch {
            // Ignore
            // this
          }
          return;
        }

        clearActorCache();

        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("icpp:session_expired"));
        }
      },
    },
  });

  if (!(await authClient.isAuthenticated())) {
    await loginWithII(authClient);
  }

  const identity = authClient.getIdentity();
  const principal = identity.getPrincipal();
  const principalText = principal.toText();

  return { identity, principal, authClient };
}

// ===================
// Main initialization
// ===================

// CMC (Cycles Minting Canister) 
// for real-time ICP -> cycles rate
// --------------------------------
export const CMC_CANISTER_ID = "rkp4c-7iaaa-aaaaa-aaaca-cai";

export interface CMCRate {
  timestamp_seconds: bigint;
  xdr_permyriad_per_icp: bigint;
}

// Here initICPPActorsUnlocked() contains the actual init logic
// -> called under withAuthGate() to prevent interleaving 
// ------------------------------------------------------------
async function initICPPActorsUnlocked(): Promise<ICPPActors> {
  // Fast path -> return cached actors (no 
  // refresh while an operation is in-flight)
  // ----------------------------------------
  if (cachedActors) {
    // Careful -> Never refresh delegation or rebuild 
    // actors while a long-running operation is in-flight
    // --------------------------------------------------
    if (opsInFlight === 0 && cachedActors.authClient) {
      const refreshed = await ensureDelegationBudget(cachedActors.authClient);
      if (refreshed) {
        // Rebuild so the agent 
        // uses the new delegation
        // -----------------------
        const identity = cachedActors.authClient.getIdentity();
        const principal = identity.getPrincipal();
        const authClient = cachedActors.authClient;

        // Clear old actors 
        // before rebuilding
        // -----------------
        clearActorCache();

        return await buildActors(identity, principal, authClient);
      }
    }
    return cachedActors;
  }

  const { identity, principal, authClient } = await getIdentity();
  return await buildActors(identity, principal, authClient);
}

async function buildActors(identity: any, principal: Principal, authClient: AuthClient | null): Promise<ICPPActors> {
  const agent = new HttpAgent({
    host: ENV.HOST,
    identity,
  });

  // Fetch root key 
  // only on local 
  // network
  // --------------
  if (ENV.NETWORK === "local") {
    try {
      await agent.fetchRootKey();
    } catch (_) {
      // Silent -> UI 
      // already warns user
    }
  }

  // Create static actors
  // --------------------
  const router = Actor.createActor<RouterService>(routerIdl, {
    agent,
    canisterId: ENV.CANISTER_IDS.router,
  });

  const crypto = Actor.createActor<CryptoService>(cryptoIdl, {
    agent,
    canisterId: ENV.CANISTER_IDS.crypto,
  });

  const noticeboard = Actor.createActor<NoticeboardService>(noticeboardIdl, {
    agent,
    canisterId: ENV.CANISTER_IDS.noticeboard,
  });

  const registry = Actor.createActor<RegistryService>(registryIdl, {
    agent,
    canisterId: ENV.CANISTER_IDS.registry,
  });

  const ledger = Actor.createActor<LedgerService>(ledgerIdl, {
    agent,
    canisterId: ENV.CANISTER_IDS.ledger,
  });

  // Dynamic actor factories 
  // for ephemeral canisters
  // -----------------------
  const i1 = (canisterId: Principal) =>
    Actor.createActor<I1Service>(i1Idl, {
      agent,
      canisterId,
    });

  const i2 = (canisterId: Principal) =>
    Actor.createActor<I2Service>(i2Idl, {
      agent,
      canisterId,
    });

  const storage = (canisterId: Principal) =>
    Actor.createActor<StorageService>(storageIdl, {
      agent,
      canisterId,
    });

  cachedActors = {
    agent,
    authClient,
    principal,
    router,
    crypto,
    noticeboard,
    registry,
    ledger,
    i1,
    i2,
    storage,
  };

  return cachedActors;
}

export async function initICPPActors(): Promise<ICPPActors> {
  return await withAuthGate(initICPPActorsUnlocked);
}

export function getActorsForQuery(): ICPPActors | null {
  return cachedActors;
}

// ICRC-1 account shape
// --------------------
type IcrcAccount = {
  owner: Principal;
  subaccount: [] | [Uint8Array];
};

export async function getSessionPrincipalText(): Promise<string> {
  const actors = await initICPPActors();
  return actors.principal.toText();
}

export async function getIcpBalanceE8s(
  owner?: Principal,
  subaccount?: Uint8Array
): Promise<bigint> {
  const actors = getActorsForQuery();
  if (!actors) throw new Error("Session not initialized");

  const acct: IcrcAccount = {
    owner: owner ?? actors.principal,
    subaccount: subaccount ? [subaccount] : [],
  };

  const ledgerAny: any = actors.ledger as any;

  // Prefer ICRC-1
  // -------------
  if (typeof ledgerAny.icrc1_balance_of === "function") {
    const bal = await ledgerAny.icrc1_balance_of(acct);
    return BigInt(bal);
  }

  throw new Error("Not an ICRC-1 format");
}

export function formatIcpFromE8s(e8s: bigint): string {
  const E8S = 100_000_000n;
  const whole = e8s / E8S;
  const frac = e8s % E8S;
  return `${whole.toString()}.${frac.toString().padStart(8, "0")}`;
}

// =======================
// Tab visibility handling
// =======================

// When tab resumes from suspension
// delegation may have expired while
// JS was paused
// ---------------------------------

let lastVisibilityTime = Date.now();

function handleVisibilityChange(): void {
  if (document.visibilityState === "visible") {
    const now = Date.now();
    const suspended = now - lastVisibilityTime;
    
    // If tab was hidden for more than 
    // 60 seconds check delegation validity
    // ------------------------------------
    if (suspended > 60_000) {
      if (isDelegationStale()) {
        // Only clear cache if 
        // no operations in flight
        // -----------------------
        if (opsInFlight === 0) {
          clearActorCache();
          
          if (typeof window !== "undefined") {
            window.dispatchEvent(new CustomEvent("icpp:session_expired"));
          }
        } else {
          // Continue
        }
      }
    }
    lastVisibilityTime = now;
  } else {
    lastVisibilityTime = Date.now();
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", handleVisibilityChange);
}

// ==================
// Session validation
// ==================

export type SessionInvalidReason = 
  | "no_actors" 
  | "no_delegation" 
  | "delegation_stale";

export type SessionValidReason = 
  | "ok" 
  | "delegation_expiring";

export type SessionStatus = 
  | { valid: false; principal: null; remainingMs: null; reason: SessionInvalidReason }
  | { valid: true; principal: Principal; remainingMs: number; reason: SessionValidReason };

export function validateSession(): SessionStatus {
  if (!cachedActors) {
    return { valid: false, principal: null, remainingMs: null, reason: "no_actors" };
  }
  
  const remainingMs = getSessionRemainingMs();
  
  if (remainingMs === null || remainingMs < 2 * 60 * 1000) {
    return { valid: false, principal: null, remainingMs: null, reason: "delegation_stale" };
  }
  
  const reason: SessionValidReason = remainingMs < 10 * 60 * 1000 ? "delegation_expiring" : "ok";
  
  return { valid: true, principal: cachedActors.principal, remainingMs, reason };
}