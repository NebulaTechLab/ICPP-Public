// ===================================================
// NK for UX frontend code
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 07 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import { Principal } from "@dfinity/principal";

// =======
// Helpers
// =======

function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const c of chunks) len += c.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i) & 0xff;
  }
  return out;
}

const STORAGE_KEY_PREFIX = "ICPP:nk:";

function storageKey(principal: Principal): string {
  return `${STORAGE_KEY_PREFIX}${principal?.toText() ?? "unknown"}`;
}

// =============
// Public NK API
// =============

// Generate a fresh 32-byte 
// NK (network key) for the user
// -----------------------------
export function generateNk(): Uint8Array {
  const nk = new Uint8Array(32);
  crypto.getRandomValues(nk);
  return nk;
}

export interface EncryptedNkRecord {
  version: number;
  saltB64: string;
  ivB64: string;
  ciphertextB64: string;
  iterations: number;
}

// Derive an AES-GCM key from 
// (principal || pin) via PBKDF2(SHA-256)
// --------------------------------------
async function deriveKey(
  principal: Principal,
  pin: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const pinBytes = utf8(pin);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    // Bind to principal so same PIN on different principals
    // does not reuse the same key material
    // -----------------------------------------------------
    concatBytes(principal.toUint8Array(), pinBytes),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Encrypt and persist NK in localStorage gated by (principal, PIN)
// - AES-GCM(256) with random salt(16B) + iv(12B)
// - PBKDF2(SHA-256, iterations=200_000) to derive the AES key
// ----------------------------------------------------------------
export async function storeNk(
  principal: Principal,
  pin: string,
  nk: Uint8Array,
): Promise<void> {
  if (nk.length !== 32) {
    throw new Error(`NK must be 32 bytes, got ${nk.length}`);
  }

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(iv);

  const iterations = 200_000;
  const key = await deriveKey(principal, pin, salt, iterations);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      nk,
    ),
  );

  const rec: EncryptedNkRecord = {
    version: 1,
    saltB64: toB64(salt),
    ivB64: toB64(iv),
    ciphertextB64: toB64(ciphertext),
    iterations,
  };

  localStorage.setItem(storageKey(principal), JSON.stringify(rec));
}

// Load and decrypt NK from localStorage using 
// (principal, PIN)
//
// - No NK stored for this principal
// - The record is malformed
// - PIN is wrong (AES-GCM decryption fails)
// - Or the decrypted NK is not 32 bytes
// -------------------------------------------
export async function loadNk(
  principal: Principal,
  pin: string,
): Promise<Uint8Array> {
  const raw = localStorage.getItem(storageKey(principal));
  if (!raw) {
    throw new Error("ICPP not set up on this device");
  }

  let rec: EncryptedNkRecord;
  try {
    rec = JSON.parse(raw) as EncryptedNkRecord;
  } catch {
    throw new Error("Corrupted NK record (JSON parse failed)");
  }

  if (
    typeof rec.version !== "number" ||
    typeof rec.saltB64 !== "string" ||
    typeof rec.ivB64 !== "string" ||
    typeof rec.ciphertextB64 !== "string" ||
    typeof rec.iterations !== "number"
  ) {
    throw new Error("Corrupted NK record (invalid structure)");
  }

  const salt = fromB64(rec.saltB64);
  const iv = fromB64(rec.ivB64);
  const ciphertext = fromB64(rec.ciphertextB64);

  const key = await deriveKey(principal, pin, salt, rec.iterations);

  let pt: Uint8Array;
  try {
    pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext,
      ),
    );
  } catch {
    // Wrong PIN or 
    // tampered ciphertext
    // -------------------
    throw new Error("Invalid PIN or corrupted NK ciphertext");
  }

  if (pt.length !== 32) {
    throw new Error(`Invalid NK length, expected 32 bytes, got ${pt.length}`);
  }

  return pt;
}