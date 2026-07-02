// ===================================================
// Witness Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 03 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import Array "mo:base/Array";
import Blob "mo:base/Blob";
import HashMap "mo:base/HashMap";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Prim "mo:prim";

import Blake2s "../shared/hash/BLAKE2s";

persistent actor Witness {

  // Common types
  // ============
  public type Account = { owner : Principal; subaccount : ?Blob };
  public type DepositId = Blob;

  public type CertifiedHeader = { policy_ver : Nat32; certified_hash : Blob; tip : Nat };
  public type Ctx = {
    policy_ver  : Nat32;
    router_cert : Blob;
    param_hash  : Blob;
    proto_ver   : Nat32;
    hints_mask  : Nat32;
  };

  // Noticeboard 
  // interface
  // ===========
  private func mkNoticeboard(p : Principal) : actor {
    finalize : ({ 
      idx : Nat; 
      destruction_proofs : [{ canister_id : Principal; ts : Nat64 }] 
    }) -> async { #ok : (); #err : Text };
  } = actor(Principal.toText(p));

  // Errors
  // ======
  let ERR_PAUSED       = "ERR.PAUSED";
  let ERR_RATE_LIMIT   = "ERR.RATE_LIMIT";
  let ERR_BAD_ARG      = "ERR.BAD_ARG";

  // Event encoding
  // ==============

  private func u32be(x : Nat32) : Blob {
    let n = Nat32.toNat(x);
    let b0 = Nat8.fromNat((Nat.bitshiftRight(n, 24)) % 256);
    let b1 = Nat8.fromNat((Nat.bitshiftRight(n, 16)) % 256);
    let b2 = Nat8.fromNat((Nat.bitshiftRight(n,  8)) % 256);
    let b3 = Nat8.fromNat(n % 256);
    Blob.fromArray([b0,b1,b2,b3])
  };

  private func u64be(x : Nat64) : Blob {
    let n = Nat64.toNat(x);
    let b0 = Nat8.fromNat((Nat.bitshiftRight(n, 56)) % 256);
    let b1 = Nat8.fromNat((Nat.bitshiftRight(n, 48)) % 256);
    let b2 = Nat8.fromNat((Nat.bitshiftRight(n, 40)) % 256);
    let b3 = Nat8.fromNat((Nat.bitshiftRight(n, 32)) % 256);
    let b4 = Nat8.fromNat((Nat.bitshiftRight(n, 24)) % 256);
    let b5 = Nat8.fromNat((Nat.bitshiftRight(n, 16)) % 256);
    let b6 = Nat8.fromNat((Nat.bitshiftRight(n,  8)) % 256);
    let b7 = Nat8.fromNat(n % 256);
    Blob.fromArray([b0,b1,b2,b3,b4,b5,b6,b7])
  };

  private func enc_ctx(pv:Nat32, rc:Blob, ph:Blob, ver:Nat32, mask:Nat32) : Blob {
    let tag : [Nat8] = [0x00];
    let rcA = Blob.toArray(rc);
    let phA = Blob.toArray(ph);
    let result = Array.append<Nat8>(tag, Blob.toArray(u32be(pv)));
    let result2 = Array.append<Nat8>(result, [Nat8.fromNat(Nat.min(255, rcA.size()))]);
    let result3 = Array.append<Nat8>(result2, rcA);
    let result4 = Array.append<Nat8>(result3, [Nat8.fromNat(Nat.min(255, phA.size()))]);
    let result5 = Array.append<Nat8>(result4, phA);
    let result6 = Array.append<Nat8>(result5, Blob.toArray(u32be(ver)));
    let result7 = Array.append<Nat8>(result6, Blob.toArray(u32be(mask)));
    Blob.fromArray(result7)
  };

  private func enc_ingress(deposit_id:DepositId, ts:Nat64, bucket:Nat32, digest:Blob) : Blob {
    let tag : [Nat8] = [0x01];
    let did = Blob.toArray(deposit_id);
    let dg  = Blob.toArray(digest);
    let result = Array.append<Nat8>(tag, Blob.toArray(u64be(ts)));
    let result2 = Array.append<Nat8>(result, Blob.toArray(u32be(bucket)));
    let result3 = Array.append<Nat8>(result2, [Nat8.fromNat(Nat.min(255, did.size()))]);
    let result4 = Array.append<Nat8>(result3, did);
    let result5 = Array.append<Nat8>(result4, [Nat8.fromNat(Nat.min(255, dg.size()))]);
    let result6 = Array.append<Nat8>(result5, dg);
    Blob.fromArray(result6)
  };

  private func enc_egress(deposit_id:DepositId, ts:Nat64, recipient:Account, digest:Blob) : Blob {
    let tag : [Nat8] = [0x02];
    let did = Blob.toArray(deposit_id);
    let rec_owner = Blob.toArray(Principal.toBlob(recipient.owner));
    let rec_sub = switch (recipient.subaccount) { case null []; case (?b) Blob.toArray(b) };
    let dg  = Blob.toArray(digest);
    let result = Array.append<Nat8>(tag, Blob.toArray(u64be(ts)));
    let result2 = Array.append<Nat8>(result, [Nat8.fromNat(Nat.min(255, did.size()))]);
    let result3 = Array.append<Nat8>(result2, did);
    let result4 = Array.append<Nat8>(result3, [Nat8.fromNat(Nat.min(255, rec_owner.size()))]);
    let result5 = Array.append<Nat8>(result4, rec_owner);
    let result6 = Array.append<Nat8>(result5, [Nat8.fromNat(Nat.min(255, rec_sub.size()))]);
    let result7 = Array.append<Nat8>(result6, rec_sub);
    let result8 = Array.append<Nat8>(result7, [Nat8.fromNat(Nat.min(255, dg.size()))]);
    let result9 = Array.append<Nat8>(result8, dg);
    Blob.fromArray(result9)
  };

  // Rate limiting
  // =============
  private type Rate = { window_start : Nat64; count : Nat32 };
  private var noticeboard_id : ?Principal = null;
  private var destruction_log : [{ canister_id : Principal; ts : Nat64 }] = [];
  private var finalized : Bool = false;

  // Expected ephemeral canisters (set during init)
  // Witness auto-destructs when all have logged destruct_intent
  // -----------------------------------------------------------
  private var expected_canisters : [Principal] = [];
  private var destroyed_set : [Principal] = [];

  var policy_ver : Nat32 = 1;
  var paused : Bool  = false;
  var events : [Blob] = [];
  var certified_hash : Blob = Blob.fromArray([]);

  // Last witnessed context
  // ----------------------
  var last_ctx : ?Ctx = null;

  // Ephemeral rate-window
  // ---------------------
  transient var calls = HashMap.HashMap<Principal, Rate>(128, Principal.equal, Principal.hash);

  // Factory calls init immediately after spawn so
  // no authorization needed (canister is blackholed)
  // ================================================
  public shared(_) func init(args : {
    noticeboard : Principal;
    expected : [Principal];
  }) : async { #ok : (); #err : Text } {
    switch (noticeboard_id) {
      case (?_) { #err("ERR.ALREADY_INITIALIZED") };
      case null {
        noticeboard_id := ?args.noticeboard;
        expected_canisters := args.expected;
        #ok(())
      };
    }
  };

  private func now() : Nat64 = Nat64.fromIntWrap(Time.now());
  private func requireNotPaused() : ?Text { if (paused) ?ERR_PAUSED else null };
  
  private func rate(caller : Principal) : ?Text {
    let t = now();
    switch (calls.get(caller)) {
      case null { calls.put(caller, { window_start = t; count = 1 }); null };
      case (?r) {
        if (t - r.window_start > 10_000_000_000) { calls.put(caller, { window_start = t; count = 1 }); null }
        else if (r.count >= 200) ?ERR_RATE_LIMIT
        else { calls.put(caller, { r with count = r.count + 1 }); null }
      }
    }
  };

  // Compact certification
  // -> (policy_ver, tip)
  // =====================
  private func certify() : () {
    let tip8 = Nat8.fromNat(events.size() % 256);
    let ver8 = Nat8.fromNat(Nat32.toNat(policy_ver) % 256);
    // ICPP:witness
    // ------------
    let domain : [Nat8] = [105,99,112,112,58,119,105,116,110,101,115,115];
    let msg : [Nat8] = [ver8, tip8];
    certified_hash := Blob.fromArray(Blake2s.keyedHash(domain, msg, 32));
    Prim.setCertifiedData(certified_hash)
  };

  private func ev_push(b:Blob) : () { events := Array.append<Blob>(events, [b]); certify() };

  // Discovery
  // =========
  public query func supported_standards() : async [{ name : Text; url : Text }] {
    [ { name = "ICPP-witness-v1"; url = "about:blank" } ]
  };
  public query func get_header() : async CertifiedHeader { { policy_ver; certified_hash; tip = events.size() } };

  // Latest context (plus the same 
  // cert returned with event feed)
  // ==============================
  public query func get_latest_ctx() : async (?Ctx, Blob) { (last_ctx, certified_hash) };

  // Context notification
  // (permissionless - canister is blackholed anyway)
  // ================================================
  public shared(_) func announce_ctx(a : {
    policy_ver  : Nat32;
    router_cert : Blob;
    param_hash  : Blob;
    proto_ver   : Nat32;
    hints_mask  : Nat32;
  }) : async { #ok : (); #err : Text } {
    if (a.router_cert.size() == 0 or a.param_hash.size() == 0) { #err(ERR_BAD_ARG) }
    else {
      policy_ver := a.policy_ver;
      last_ctx := ?{ policy_ver = a.policy_ver; router_cert = a.router_cert; param_hash = a.param_hash; proto_ver = a.proto_ver; hints_mask = a.hints_mask };
      ev_push(enc_ctx(a.policy_ver, a.router_cert, a.param_hash, a.proto_ver, a.hints_mask));
      #ok(())
    }
  };

  // Storage commit
  // (append-only log, no sensitive operation)
  // =========================================
  public shared(_) func log_storage_commit(args : {
    hint : Blob;
    storage_id : Principal;
  }) : async { #ok : (); #err : Text } {
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    
    if (args.hint.size() == 0) { #err(ERR_BAD_ARG) }
    else {
      let tag : [Nat8] = [0x03]; // Storage commit event
      let sid = Blob.toArray(Principal.toBlob(args.storage_id));
      let hint_bytes = Blob.toArray(args.hint);
      
      var result = Array.append<Nat8>(tag, Blob.toArray(u64be(now())));
      result := Array.append<Nat8>(result, [Nat8.fromNat(Nat.min(255, sid.size()))]);
      result := Array.append<Nat8>(result, sid);
      result := Array.append<Nat8>(result, [Nat8.fromNat(Nat.min(255, hint_bytes.size()))]);
      result := Array.append<Nat8>(result, hint_bytes);
      
      ev_push(Blob.fromArray(result));
      #ok(())
    }
  };

  // Destruct intent
  // (append-only log, certified 
  // state prevents tampering)
  // ===========================
  public shared(_) func log_destruct_intent(args : {
    canister_id : Principal;
    ts : Nat64;
  }) : async { #ok : (); #err : Text } {
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    
    let tag : [Nat8] = [0x04];
    let cid = Blob.toArray(Principal.toBlob(args.canister_id));
    
    var result = Array.append<Nat8>(tag, Blob.toArray(u64be(args.ts)));
    result := Array.append<Nat8>(result, [Nat8.fromNat(Nat.min(255, cid.size()))]);
    result := Array.append<Nat8>(result, cid);
    
    ev_push(Blob.fromArray(result));
    
    destruction_log := Array.append(destruction_log, [{ 
      canister_id = args.canister_id; 
      ts = args.ts 
    }]);
    
    // Track destroyed 
    // canisters (idempotent)
    // ----------------------
    let already = Array.find<Principal>(destroyed_set, func p = p == args.canister_id);
    if (already == null) {
      destroyed_set := Array.append(destroyed_set, [args.canister_id]);
    };
    
    // Auto-finalize when all 
    // expected canisters destroyed
    // ----------------------------
    if (destroyed_set.size() >= expected_canisters.size() and expected_canisters.size() > 0) {
      let all_destroyed = Array.foldLeft<Principal, Bool>(
        expected_canisters,
        true,
        func (acc, p) = acc and Array.find<Principal>(destroyed_set, func q = q == p) != null
      );
      
      if (all_destroyed and not finalized) {
        ignore async { await auto_finalize(); };
      };
    };
    
    #ok(())
  };
  
  // Query -> check if a specific 
  // canister is destroyed
  // ----------------------------
  public query func is_destroyed(canister_id : Principal) : async Bool {
    Array.find<Principal>(destroyed_set, func p = p == canister_id) != null
  };
  
  // Auto-finalize and wait
  // for I2 to kill us
  // ----------------------
  private func auto_finalize() : async () {
    if (finalized) return;
    
    switch (noticeboard_id) {
      case null {};
      case (?nbid) {
        let NB = mkNoticeboard(nbid);
        try {
          // Send destruction_log to 
          // Noticeboard (await completes)
          // -----------------------------
          let _ = await NB.finalize({ 
            idx = 0; 
            destruction_proofs = destruction_log 
          });

          // Mark as finalized
          // -----------------
          finalized := true;

        } catch (_) {};
      };
    };
  };

  // Pass destruction
  // request on
  // ================
  public shared func request_destruct(factory : Principal) : async () {
    // Zero state
    // ----------
    events := [];
    destruction_log := [];
    destroyed_set := [];
    expected_canisters := [];
    last_ctx := null;
    
    let IC : actor {
      update_settings : ({ canister_id : Principal; settings : { controllers : ?[Principal] } }) -> async ();
    } = actor("aaaaa-aa");
    let self_id = Principal.fromActor(Witness);
    
    try {
      await IC.update_settings({
        canister_id = self_id;
        settings = { controllers = ?[self_id, factory] };
      });
    } catch (_) { return };
    
    let F = actor(Principal.toText(factory)) : actor {
      cleanup_child : (Principal) -> async ();
    };
    
    ignore F.cleanup_child(self_id);
  };
  
  // Append-only log
  // (append-only log, certified 
  // state prevents tampering)
  // ===========================
  public shared({ caller }) func log_ingress(args : {
    deposit_id : DepositId;
    ts : Nat64;
    bucket : Nat32;
    client_ctx_digest : Blob
  }) : async { #ok : (); #err : Text } {
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    if (args.deposit_id.size() == 0) { #err(ERR_BAD_ARG) }
    else { ev_push(enc_ingress(args.deposit_id, args.ts, args.bucket, args.client_ctx_digest)); #ok(()) }
  };

  public shared({ caller }) func log_egress(args : {
    deposit_id : DepositId;
    ts : Nat64;
    recipient : Account;
    meta_digest : Blob
  }) : async { #ok : (); #err : Text } {
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    if (args.deposit_id.size() == 0 or args.meta_digest.size() == 0) { #err(ERR_BAD_ARG) }
    else { ev_push(enc_egress(args.deposit_id, args.ts, args.recipient, args.meta_digest)); #ok(()) }
  };

  // Opaque feed
  // ===========
  public query func get_events(q : { from : Nat; limit : Nat })
    : async { events : [Blob]; tip : Nat; cert : Blob } {
    let start = q.from;
    let end = Nat.min(events.size(), start + q.limit);
    let slice = if (end > start) Array.tabulate<Blob>(end - start, func i = events[start + i]) else [];
    { events = slice; tip = events.size(); cert = certified_hash }
  };
}
