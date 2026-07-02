// ===================================================
// I1 (send-side) Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 3 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Array "mo:base/Array";
import HashMap "mo:base/HashMap";

import Blake2s "../shared/hash/BLAKE2s";

persistent actor I1 {

  private func u32be(n : Nat32) : Blob {
    let b0 = Nat8.fromNat(Nat32.toNat(n / 16777216));
    let b1 = Nat8.fromNat(Nat32.toNat((n / 65536) % 256));
    let b2 = Nat8.fromNat(Nat32.toNat((n / 256) % 256));
    let b3 = Nat8.fromNat(Nat32.toNat(n % 256));
    Blob.fromArray([b0, b1, b2, b3])
  };

  private func u64be(n : Nat64) : Blob {
    let b0 = Nat8.fromNat(Nat64.toNat(n / 72057594037927936));
    let b1 = Nat8.fromNat(Nat64.toNat((n / 281474976710656) % 256));
    let b2 = Nat8.fromNat(Nat64.toNat((n / 1099511627776) % 256));
    let b3 = Nat8.fromNat(Nat64.toNat((n / 4294967296) % 256));
    let b4 = Nat8.fromNat(Nat64.toNat((n / 16777216) % 256));
    let b5 = Nat8.fromNat(Nat64.toNat((n / 65536) % 256));
    let b6 = Nat8.fromNat(Nat64.toNat((n / 256) % 256));
    let b7 = Nat8.fromNat(Nat64.toNat(n % 256));
    Blob.fromArray([b0, b1, b2, b3, b4, b5, b6, b7])
  };

  // Common types
  // ============
  public type Account   = { owner : Principal; subaccount : ?Blob };
  public type Amount    = Nat;
  public type DepositId = Blob;

  public type ClientCtx = {
    proto_ver : Nat32;
    param_hash : Blob;
    ctx_commit : Blob;
    hints_mask : Nat32;
    expiry     : Nat64;
  };

  // Rate limiting
  // =============
  private type Rate = { window_start : Nat64; count : Nat32 };

  // Sealed package
  // types
  // ==============
  public type SealedPackage = {
    hint : Blob;
    capsule : Blob;
    inner : Blob;
  };

  // Witness (best-effort)
  // =====================
  private func mkWitness(p : Principal) : actor {
    log_ingress : ({
      deposit_id : DepositId;
      ts : Nat64;
      bucket : Nat32;
      client_ctx_digest : Blob
    }) -> async { #ok : (); #err : Text };
    log_destruct_intent : ({
      canister_id : Principal;
      ts : Nat64;
    }) -> async { #ok : (); #err : Text };
    is_destroyed : (Principal) -> async Bool;
  } = actor(Principal.toText(p));

  // Digest client 
  // context
  // =============
  private func digestClientCtx(ctx : ClientCtx) : Blob {
    // ICPP:ctx
    // --------
    let domain : [Nat8] = [105,99,112,112,58,99,116,120];
    
    let proto_bytes = Blob.toArray(u32be(ctx.proto_ver));
    let param_hash_bytes = Blob.toArray(ctx.param_hash);
    let ctx_commit_bytes = Blob.toArray(ctx.ctx_commit);
    let hints_bytes = Blob.toArray(u32be(ctx.hints_mask));
    let expiry_bytes = Blob.toArray(u64be(ctx.expiry));
    
    let msg = Array.append<Nat8>(proto_bytes, param_hash_bytes);
    let msg2 = Array.append<Nat8>(msg, ctx_commit_bytes);
    let msg3 = Array.append<Nat8>(msg2, hints_bytes);
    let msg4 = Array.append<Nat8>(msg3, expiry_bytes);
    
    Blob.fromArray(Blake2s.keyedHash(domain, msg4, 32))
  };

  // Errors
  // ======
  let ERR_PAUSED = "ERR.PAUSED";
  let ERR_RATE_LIMIT = "ERR.RATE_LIMIT";
  let ERR_BAD_ARG = "ERR.BAD_ARG";
  let ERR_WITNESS = "ERR.WITNESS";
  let ERR_UNAUTHORIZED = "ERR.UNAUTHORIZED";
  let ERR_STORAGE_FAILED = "ERR.STORAGE_FAILED";

  var paused : Bool = false;
  var admins : [Principal] = [];
  var witness : ?Principal = null;
  var witness_failures : Nat64 = 0;
  var storage_ids : [Principal] = [];
  var noticeboard_id : Principal = Principal.fromText("aaaaa-aa");
  var factory_id : Principal = Principal.fromText("aaaaa-aa");
  var initialized : Bool = false;

  // Ephemeral rate window
  // =====================
  transient var calls  = HashMap.HashMap<Principal, Rate>(64, Principal.equal, Principal.hash);

  private func now() : Nat64 = Nat64.fromIntWrap(Time.now());
  private func isAdmin(p:Principal) : Bool { for (a in admins.vals()) { if (a == p) return true }; false };
  private func requireNotPaused() : ?Text { if (paused) ?ERR_PAUSED else null };

  private func rate(caller : Principal) : ?Text {
    let t = now();
    switch (calls.get(caller)) {
      case null { calls.put(caller, { window_start = t; count = 1 }); null };
      case (?r) {
        if (t - r.window_start > 10_000_000_000) { calls.put(caller, { window_start = t; count = 1 }); null }
        else if (r.count >= 50) ?ERR_RATE_LIMIT
        else { calls.put(caller, { r with count = r.count + 1 }); null }
      }
    }
  };

  // Discovery
  // =========
  public query func supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICPP-i1-v1"; url = "https://example.com/specs/ICPP-i1-v1" }
    ]
  };

  public query func get_services()
    : async { witness : ?Principal; storage : [Principal]; noticeboard : Principal } {
    { witness; storage = storage_ids; noticeboard = noticeboard_id }
  };

  // Initialization
  // ==============
  public shared({ caller }) func init(args : {
    storage : [Principal];
    noticeboard : Principal;
    witness : Principal;
    ttl : Nat64;
    factory : Principal;
  }) : async { #ok : (); #err : Text } {
    if (initialized) return #err("ERR.ALREADY_INITIALIZED");
    if (caller != args.factory) return #err(ERR_UNAUTHORIZED);
    
    storage_ids := args.storage;
    noticeboard_id := args.noticeboard;
    witness := ?args.witness;
    factory_id := args.factory;
    initialized := true;
    
    #ok(())
  };

  // Administrator
  // =============
  public shared({ caller }) func set_admins(a:[Principal]) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) }
    else { admins := a; #ok(()) }
  };

  public shared({ caller }) func pause()  : async { #ok : (); #err : Text } { 
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) } 
    else { paused := true;  #ok(()) } 
  };

  public shared({ caller }) func unpause(): async { #ok : (); #err : Text } { 
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) } 
    else { paused := false; #ok(()) } 
  };

  public shared({ caller }) func set_services(s : { witness : ?Principal }) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) }
    else { witness := s.witness; #ok(()) }
  };

  // CSRN preparation 
  // (Alice requests encrypted CSRN)
  // ===============================
  public shared({ caller }) func prepare_deposit(
    deposit_id : DepositId
  ) : async { #ok : { nonce : Blob; ciphertext : Blob }; #err : Text } {
    
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };
    
    if (not initialized) return #err(ERR_STORAGE_FAILED);
    if (storage_ids.size() == 0) return #err(ERR_STORAGE_FAILED);
    
    // Request CSRN from first Storage canister
    // (all Storage canisters are identical 
    // so use first one)
    let storage_id = storage_ids[0];
    let storage_actor = actor(Principal.toText(storage_id)) : actor {
      init_csrn : (Blob, Principal) -> async { #ok : { nonce : Blob; ciphertext : Blob }; #err : Text };
    };
    
    try {
      let csrn_result = await storage_actor.init_csrn(deposit_id, caller);
      switch (csrn_result) {
        case (#err _e) { #err(ERR_STORAGE_FAILED) };
        case (#ok data) { #ok(data) };
      };
    } catch (_) {
      #err(ERR_STORAGE_FAILED)
    }
  };

  // Store and announce
  // ==================
  public shared({ caller }) func store_and_announce(args : {
    package : SealedPackage;
    deposit_id : DepositId;
    client_ctx : ?ClientCtx;
  }) : async { #ok : (); #err : Text } {

    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    if (not initialized) return #err(ERR_STORAGE_FAILED);
    if (args.package.hint.size() == 0 or args.package.capsule.size() == 0) { 
      return #err(ERR_BAD_ARG) 
    };

    // Add a 4-byte big-endian capsule length after the 80-byte hint
    // package_blob = hint(80) || u32_be(cap_len) || capsule || inner
    // ==============================================================
    let cap_len_nat : Nat = args.package.capsule.size();
    if (cap_len_nat > 0xFFFF_FFFF) {
      return #err(ERR_BAD_ARG);
    };
    let cap_len : Nat32 = Nat32.fromNat(cap_len_nat);

    let cap_len_be : Blob = u32be(cap_len);

    let package_blob = Blob.fromArray(
      Array.append<Nat8>(
        Array.append<Nat8>(
          Array.append<Nat8>(
            Blob.toArray(args.package.hint),
            Blob.toArray(cap_len_be),
          ),
          Blob.toArray(args.package.capsule),
        ),
        Blob.toArray(args.package.inner),
      )
    );

    // Store at all C_i
    // ================
    for (storage_id in storage_ids.vals()) {
      let storage_actor = actor(Principal.toText(storage_id)) : actor {
        store : (Blob) -> async { #ok : (); #err : Text };
      };
      
      let store_result = await storage_actor.store(package_blob);
      switch (store_result) {
        case (#err _e) { return #err(ERR_STORAGE_FAILED) };
        case (#ok _) {};
      };
    };

    // Announce to 
    // noticeboard
    // ===========
    let noticeboard_actor = actor(Principal.toText(noticeboard_id)) : actor {
      announce : ({ hint : Blob; deposit_id : DepositId; storage : [Principal]; ts : Nat64 }) 
        -> async { #ok : (); #err : Text };
    };
    
    let announce_result = await noticeboard_actor.announce({
      hint = args.package.hint;
      deposit_id = args.deposit_id;
      storage = storage_ids;
      ts = now();
    });
    
    switch (announce_result) {
      case (#err _e) { return #err(ERR_STORAGE_FAILED) };
      case (#ok _) {};
    };

    // Compute client context digest
    let cc_digest : Blob = switch (args.client_ctx) {
      case null Blob.fromArray([]);
      case (?cc) {
        if (cc.param_hash.size() == 0 or cc.ctx_commit.size() == 0) { 
          return #err(ERR_BAD_ARG) 
        };
        digestClientCtx(cc)
      }
    };

    // Log to witness 
    // and self-destruct
    // =================
    switch (witness) {
      case null { 
        ignore async { await self_destruct(); };
        #ok(()) 
      };
      case (?w) {
        let W = mkWitness(w);
        try {
          let log_result = await W.log_ingress({
            deposit_id = args.deposit_id;
            ts = now();
            bucket = 0;
            client_ctx_digest = cc_digest;
          });
          
          let destruct_result = await W.log_destruct_intent({
            canister_id = Principal.fromActor(I1);
            ts = now();
          });
          
          switch (destruct_result) {
            case (#ok _) {
              ignore async { await self_destruct(); };
            };
            case (#err _) {
              witness_failures += 1;
              ignore async { await self_destruct(); };
            };
          };
          
          switch (log_result) {
            case (#ok _) { #ok(()) };
            case (#err _e) { #err(ERR_WITNESS) };
          }
        } catch (_) {
          witness_failures += 1;
          ignore async { await self_destruct(); };
          #err(ERR_WITNESS)
        }
      }
    }
  };

  // Destruct
  // ========
  private func self_destruct() : async () {
    storage_ids := [];
    
    let IC : actor {
      update_settings : ({ canister_id : Principal; settings : { controllers : ?[Principal] } }) -> async ();
    } = actor("aaaaa-aa");
    let self_id = Principal.fromActor(I1);
    
    try {
      await IC.update_settings({
        canister_id = self_id;
        settings = { controllers = ?[self_id, factory_id] };
      });
    } catch (_) { return };
    
    let F = actor(Principal.toText(factory_id)) : actor {
      cleanup_child : (Principal) -> async ();
    };
    
    ignore F.cleanup_child(self_id);
  };

  public query func get_witness_stats() : async { failures : Nat64 } {
    { failures = witness_failures }
  };

  public query func ping() : async Text { "i1:ok" };
}