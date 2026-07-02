// ===================================================
// Crypto canister interface
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 03 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";

module {
  public type Account = {
    owner : Blob;
    subaccount : Blob;
  };

  // CreateArgs
  public type CreateArgs = {
    deposit_id : Blob;
    i2_principal : Principal;
    amount : Nat64;
    csrn : Blob;
  };

  public type VerifyArgs = {
    capsule : Blob;
    capability : Blob;
    recipient_account : Account;
    context : Blob;
    encrypted_inner : Blob;
    csrn : Blob;
  };

  public type VerifyOk = {
    deposit_id : Blob;
    nullifier : ?Blob;
    transcript_digest : Blob;
    hint : Blob;
    i2_principal : Blob;
  };

  // DecryptResult
  // (returned by decrypt_result)
  public type DecryptResult = {
    plaintext : Blob;
    amount : Nat64;
    auth_key_hash_hex : Text;
  };

  public type SessionId = Nat64;

  public type CryptoActor = actor {
    set_router : (Principal) -> async ();

    // CREATE API
    create_start : (CreateArgs) -> async (Bool, SessionId, Text);
    create_step : (SessionId, Nat32) -> async (Bool, Bool, Text);
    create_result : (SessionId) -> async (Bool, Blob, Blob, Blob, Text);

    // VERIFY API
    verify_start : (VerifyArgs) -> async (Bool, SessionId, Text);
    verify_step : (SessionId, Nat32) -> async (Bool, Bool, Text);
    verify_result : (SessionId) -> async (Bool, VerifyOk, Text);

    // DECRYPT API
    decrypt_start : (Blob, Blob, Blob, Blob) -> async (Bool, SessionId, Text);
    decrypt_step : (SessionId, Nat32) -> async (Bool, Bool, Text);
    decrypt_result : (SessionId) -> async (Bool, ?DecryptResult, Text);

    // PARAMS
    get_params_commitment : () -> async Blob;
    prewarm_bsgs : (Nat32) -> async (Bool, Bool);
  };

  public func mkCrypto(p : Principal) : CryptoActor =
    actor (Principal.toText(p));
}