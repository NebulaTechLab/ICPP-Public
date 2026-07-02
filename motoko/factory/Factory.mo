// ===================================================
// Factory Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 03 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// Phase 2: Destruction guarantees + spawn rollback
// ===================================================

import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Prim "mo:prim";

import Cycles "mo:base/ExperimentalCycles";
import Blake2s "../shared/hash/BLAKE2s";

persistent actor Factory {

  // Canister management
  // ===================
  type CanisterSettings = {
    controllers : ?[Principal];
    compute_allocation : ?Nat;
    memory_allocation : ?Nat;
    freezing_threshold : ?Nat;
    reserved_cycles_limit : ?Nat;
  };

  let IC : actor {
    create_canister : ({ settings : ?CanisterSettings }) -> async { canister_id : Principal };
    install_code : ({ mode : { #install; #reinstall; #upgrade };
                      canister_id : Principal; 
                      wasm_module : Blob; 
                      arg : Blob }) -> async ();
    update_settings : ({ canister_id : Principal; settings : CanisterSettings }) -> async ();
    stop_canister : ({ canister_id : Principal }) -> async ();
    delete_canister : ({ canister_id : Principal }) -> async ();
  } = actor ("aaaaa-aa");

  // Common types
  // ============
  public type CodeHashes = { 
    i1 : Blob; 
    i2 : Blob; 
    storage : Blob; 
    witness : Blob
  };
  
  public type CertifiedHeader = { 
    policy_ver : Nat32; 
    certified_hash : Blob; 
    tip : Nat 
  };
  
  public type Spawned = {
    i1 : Principal; 
    i2 : Principal; 
    storage : [Principal];
    witness : Principal;
    spawn_proof : Blob; 
    tip : Nat;
  };

  // Errors
  // ======
  let ERR_UNAUTHORIZED = "ERR.UNAUTHORIZED";
  let ERR_ALREADY_INITIALIZED = "ERR.ALREADY_INITIALIZED";
  let ERR_GENERIC = "ERR.GENERIC";
  let ERR_PAUSED = "ERR.PAUSED";
  let ERR_BAD_WASM = "ERR.BAD_WASM";
  let ERR_MISSING_WASM = "ERR.MISSING_WASM";
  let ERR_SPAWN_FAILED = "ERR.SPAWN_FAILED";
  let ERR_INSUFFICIENT_CYCLES = "ERR.INSUFFICIENT_CYCLES";
  let ERR_CYCLES_ACCEPT = "ERR.CYCLES_ACCEPT";

  // State
  // =====
  var policy_ver : Nat32 = 1;
  var paused : Bool = false;
  var admins : [Principal] = [];
  var admin_initialized : Bool = false;
  var wasm_i1 : ?Blob = null;
  var wasm_i2 : ?Blob = null;
  var wasm_witness : ?Blob = null;
  var wasm_storage : ?Blob = null;

  var code_hashes : CodeHashes = { 
    i1 = Blob.fromArray([]); 
    i2 = Blob.fromArray([]); 
    storage = Blob.fromArray([]);
    witness = Blob.fromArray([]);
  };

  var events : [Blob] = [];
  var certified_hash : Blob = Blob.fromArray([]);

  private var router_principal : ?Principal = null;  // -> Security: only Router can spawn
  private var total_cycles_consumed : Nat = 0;       // -> Accounting: track costs

  // Fallback policy 
  // ===============
  private var fallback_max_spawns : Nat = 1;         // -> Allow N emergency spawns from Factory balance
  private var fallback_spawns_used : Nat = 0;        // -> How many have been used since last reset/upgrade
  private var fallback_reserve_floor : Nat = 0;      // -> Minimum cycles to retain on Factory
  
  // BSGS cache (computed once and 
  // provisioned to each Crypto instance)
  private var bsgs_cache : ?Blob = null;

  // Initialize Administrator 
  // ========================
  public shared({ caller }) func initialize_admins(initial_admins : [Principal]) : async { #ok : (); #err : Text } {
    if (admin_initialized) return #err(ERR_ALREADY_INITIALIZED);
    if (initial_admins.size() == 0) return #err(ERR_GENERIC);
    
    // Security -> caller must be 
    // in the admin list being set
    // ---------------------------
    let is_in_list = Array.find<Principal>(initial_admins, func p = p == caller);
    switch (is_in_list) {
      case null return #err(ERR_UNAUTHORIZED);
      case (?_) {};
    };
    
    admins := initial_admins;
    admin_initialized := true;
    ev(0xA0);
    #ok(())
  };

  // Helpers
  // =======
  private func _now() : Nat64 = Nat64.fromIntWrap(Time.now());
  
  private func isAdmin(p : Principal) : Bool { 
    for (a in admins.vals()) { 
      if (a == p) return true 
    }; 
    false 
  };
  
  private func ev(tag : Nat8) : () { 
    events := Array.append<Blob>(events, [ Blob.fromArray([tag]) ]); 
    certify() 
  };

  // Compact certification 
  // (policy_ver, tip mod 256)
  // =========================
  private func certify() : () {
    let tip8 = Nat8.fromNat(events.size() % 256);
    let ver8 = Nat8.fromNat(Nat32.toNat(policy_ver) % 256);
    // ICPP:factory
    // ------------
    let domain : [Nat8] = [105,99,112,112,58,102,97,99,116,111,114,121];
    let msg : [Nat8] = [ver8, tip8];
    certified_hash := Blob.fromArray(Blake2s.keyedHash(domain, msg, 32));
    Prim.setCertifiedData(certified_hash)
  };

  // Calculate cycles
  // Base -> 100B canister creation + 2T WASM installation 
  // per canister (6 canisters total + 50% safety margin)
  // =====================================================
  private func calculate_min_cycles() : Nat {
    let per_canister = 100_000_000_000 + 2_000_000_000_000;
    let base_total = per_canister * 6;
    (base_total * 3) / 2
  };

  // Hash WASM module
  // ================
  private func hash_blob(b : Blob) : Blob {
    // ICPP:wasm
    // ---------
    let domain : [Nat8] = [105,99,112,112,58,119,97,115,109];
    Blob.fromArray(Blake2s.keyedHash(domain, Blob.toArray(b), 32))
  };

  // Blackhole controller (set to 
  // canister itself -> immutable)
  // =============================
  private func blackholeController(id : Principal) : async () {
    await IC.update_settings({
      canister_id = id;
      settings = {
        controllers = ?[id];
        compute_allocation = null;
        memory_allocation = null;
        freezing_threshold = null;
        reserved_cycles_limit = null;
      };
    });
  };

  // Rollback: delete all created canisters
  // Factory retains control until blackhole
  // =======================================
  private func rollback(canisters : [Principal]) : async () {
    for (cid in canisters.vals()) {
      try {
        await IC.stop_canister({ canister_id = cid });
        await IC.delete_canister({ canister_id = cid });
      } catch (_) {
        // Best effort - canister may already be stopped/deleted
      };
    };
  };

  // Executioner function called by children
  // SAME LOGIC AS ROLLBACK but public method
  // (can be called by children)
  // ========================================
  public shared({ caller }) func cleanup_child(child_id : Principal) : async () {
    // Security Check -> Only the child itself can ask to be killed
    // (prevents external parties from deleting legit children)
    // ------------------------------------------------------------
    if (caller != child_id) return;

    let IC : actor {
      stop_canister : ({ canister_id : Principal }) -> async ();
      delete_canister : ({ canister_id : Principal }) -> async ();
    } = actor("aaaaa-aa");

    // Kill Sequence
    // -> If we are not the controller this traps/fails safely
    // -> If we are the controller we execute and get the cycle refund
    // ---------------------------------------------------------------
    ignore async {
      try {
        await IC.stop_canister({ canister_id = child_id });
        await IC.delete_canister({ canister_id = child_id });
      } catch (_) {
        // Child didn't add us or child 
        // is already deleted -> ignore
      };
    };
  };

  // Discovery
  // =========
  public query func supported_standards() : async [{ name : Text; url : Text }] {
    [{ name = "ICPP-factory-v1"; url = "https://example.com/specs/ICPP-factory-v1" }]
  };
  
  public query func get_header() : async CertifiedHeader {
    { policy_ver; certified_hash; tip = events.size() }
  };
  
  public query func get_code_hashes() : async CodeHashes { 
    code_hashes 
  };

  // Administration
  // ==============
  public shared({ caller }) func set_admins(a : [Principal]) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    admins := a; 
    ev(0xA0); 
    #ok(())
  };

  public shared({ caller }) func pause() : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    paused := true; 
    ev(0xA1); 
    #ok(())
  };

  public shared({ caller }) func unpause() : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    paused := false; 
    ev(0xA2); 
    #ok(())
  };

  public shared({ caller }) func set_router(r : Principal) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    router_principal := ?r;
    ev(0xA3);
    #ok(())
  };

  public shared({ caller }) func set_fallback_policy(max_spawns : Nat, reserve_floor : Nat, reset_used : Bool)
    : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    fallback_max_spawns := max_spawns;
    fallback_reserve_floor := reserve_floor;
    if (reset_used) { fallback_spawns_used := 0 };
    ev(0xD0);
    #ok(())
  };

  public query func get_fallback_policy() : async {
    max_spawns : Nat;
    spawns_used : Nat;
    reserve_floor : Nat;
  } {
    {
      max_spawns = fallback_max_spawns;
      spawns_used = fallback_spawns_used;
      reserve_floor = fallback_reserve_floor;
    }
  };

  private func requireNotPaused() : ?Text { 
    if (paused) ?ERR_PAUSED else null 
  };

  // WASM management
  // ===============
  public shared({ caller }) func set_wasm_i1(w : Blob) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (w.size() == 0) return #err(ERR_BAD_WASM);
    wasm_i1 := ?w; 
    code_hashes := { code_hashes with i1 = hash_blob(w) };
    ev(0xB1); 
    #ok(())
  };

  public shared({ caller }) func set_wasm_i2(w : Blob) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (w.size() == 0) return #err(ERR_BAD_WASM);
    wasm_i2 := ?w; 
    code_hashes := { code_hashes with i2 = hash_blob(w) };
    ev(0xB2); 
    #ok(())
  };

  public shared({ caller }) func set_wasm_witness(w : Blob) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (w.size() == 0) return #err(ERR_BAD_WASM);
    wasm_witness := ?w; 
    code_hashes := { code_hashes with witness = hash_blob(w) };
    ev(0xB3); 
    #ok(())
  };

  public shared({ caller }) func set_wasm_storage(w : Blob) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (w.size() == 0) return #err(ERR_BAD_WASM);
    wasm_storage := ?w; 
    code_hashes := { code_hashes with storage = hash_blob(w) };
    ev(0xB4); 
    #ok(())
  };

  // Chunked WASM upload
  // ===================
  private var wasm_i1_chunks : [Blob] = [];
  private var wasm_i2_chunks : [Blob] = [];
  private var wasm_storage_chunks : [Blob] = [];
  private var wasm_witness_chunks : [Blob] = [];

  public shared({ caller }) func upload_wasm_chunk_i1(chunk : Blob, is_last : Bool) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    wasm_i1_chunks := Array.append(wasm_i1_chunks, [chunk]);
    if (is_last) {
      var combined : [Nat8] = [];
      for (c in wasm_i1_chunks.vals()) {
        combined := Array.append(combined, Blob.toArray(c));
      };
      let final_blob = Blob.fromArray(combined);
      wasm_i1 := ?final_blob;
      code_hashes := { code_hashes with i1 = hash_blob(final_blob) };
      wasm_i1_chunks := [];
      ev(0xB1);
    };
    #ok(())
  };

  public shared({ caller }) func upload_wasm_chunk_i2(chunk : Blob, is_last : Bool) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    wasm_i2_chunks := Array.append(wasm_i2_chunks, [chunk]);
    if (is_last) {
      var combined : [Nat8] = [];
      for (c in wasm_i2_chunks.vals()) {
        combined := Array.append(combined, Blob.toArray(c));
      };
      let final_blob = Blob.fromArray(combined);
      wasm_i2 := ?final_blob;
      code_hashes := { code_hashes with i2 = hash_blob(final_blob) };
      wasm_i2_chunks := [];
      ev(0xB2);
    };
    #ok(())
  };

  public shared({ caller }) func upload_wasm_chunk_storage(chunk : Blob, is_last : Bool) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    wasm_storage_chunks := Array.append(wasm_storage_chunks, [chunk]);
    if (is_last) {
      var combined : [Nat8] = [];
      for (c in wasm_storage_chunks.vals()) {
        combined := Array.append(combined, Blob.toArray(c));
      };
      let final_blob = Blob.fromArray(combined);
      wasm_storage := ?final_blob;
      code_hashes := { code_hashes with storage = hash_blob(final_blob) };
      wasm_storage_chunks := [];
      ev(0xB4);
    };
    #ok(())
  };

  public shared({ caller }) func upload_wasm_chunk_witness(chunk : Blob, is_last : Bool) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    wasm_witness_chunks := Array.append(wasm_witness_chunks, [chunk]);
    if (is_last) {
      var combined : [Nat8] = [];
      for (c in wasm_witness_chunks.vals()) {
        combined := Array.append(combined, Blob.toArray(c));
      };
      let final_blob = Blob.fromArray(combined);
      wasm_witness := ?final_blob;
      code_hashes := { code_hashes with witness = hash_blob(final_blob) };
      wasm_witness_chunks := [];
      ev(0xB3);
    };
    #ok(())
  };

  // BSGS cache initialization 
  // (one-time computation called by admin)
  // ======================================
  public shared({ caller }) func init_bsgs_cache() : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    
    // Check if already computed
    switch (bsgs_cache) {
      case (?_) return #err(ERR_ALREADY_INITIALIZED);
      case null {};
    };
    
    // Call Rust crypto lib to serialize BSGS cache
    // This requires the crypto WASM to have been uploaded
    // and temporarily deployed for cache generation
    // 
    // For now, admin must provide pre-computed cache
    // via separate set_bsgs_cache method (see below)
    
    #err(ERR_GENERIC);
  };
  
  // Admin helper -> directly set pre-computed BSGS cache
  // (cache must be serialized by sgp.rs::serialize_bsgs_cache)
  // ==========================================================
  public shared({ caller }) func set_bsgs_cache(cache : Blob) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (cache.size() == 0) return #err(ERR_GENERIC);
    
    bsgs_cache := ?cache;
    ev(0xC1);
    #ok(())
  };

  // Spawn volatile infrastructure 
  // with rollback on failure
  // =============================
  public shared({ caller }) func spawn_triplet(ttl : Nat64, noticeboard : Principal, router : Principal, crypto : Principal) : async { #ok : Spawned; #err : Text } {
 
    // Authorization
    // -------------
    switch (router_principal) {
      case null return #err(ERR_UNAUTHORIZED # ":NO_ROUTER_SET");
      case (?expected_router) {
        if (caller != expected_router) {
          return #err(ERR_UNAUTHORIZED # ":ONLY_ROUTER_CAN_SPAWN");
        };
      };
    };

    switch (requireNotPaused()) { 
      case (?e) return #err(e); 
      case null {} 
    };

    let n : Nat = 2;

    let wi1 = switch (wasm_i1) { 
      case null return #err(ERR_MISSING_WASM # ":I1"); 
      case (?b) b 
    };

    let wi2 = switch (wasm_i2) { 
      case null return #err(ERR_MISSING_WASM # ":I2"); 
      case (?b) b 
    };

    let wst = switch (wasm_storage) { 
      case null return #err(ERR_MISSING_WASM # ":STORAGE"); 
      case (?b) b 
    };

    let www = switch (wasm_witness) { 
      case null return #err(ERR_MISSING_WASM # ":WITNESS"); 
      case (?b) b 
    };

    // Accept and distribute 
    // cycles from Router
    // ---------------------
    let cycles_received = Cycles.available();

    let cycles_per_canister : Nat = if (cycles_received > 0) {
      // Mainnet mode -> Router 
      // sending cycles via CMC
      // ----------------------
      if (cycles_received < 5_500_000_000_000) {
        return #err(ERR_INSUFFICIENT_CYCLES);
      };
      let cycles_accepted = Cycles.accept<system>(cycles_received);
      if (cycles_accepted < cycles_received) {
        return #err(ERR_CYCLES_ACCEPT);
      };

      (2 * cycles_accepted) / 11

    } else {
      
      // Fallback mode -> use Factory's own balance (no cycles were attached)
      // This should never trigger in the intended production path.
      // --------------------------------------------------------------------
      if (fallback_max_spawns == 0 or fallback_spawns_used >= fallback_max_spawns) {
        return #err(ERR_INSUFFICIENT_CYCLES # ":FALLBACK_CAP");
      };

      let bal = Cycles.balance();
      if (bal <= fallback_reserve_floor) {
        return #err(ERR_INSUFFICIENT_CYCLES # ":FALLBACK_RESERVE");
      };

      let spendable : Nat = bal - fallback_reserve_floor;

      // Require spendable >= 5.5T
      // -------------------------
      if (spendable < 5_500_000_000_000) {
        return #err(ERR_INSUFFICIENT_CYCLES # ":FALLBACK_LOW");
      };

      fallback_spawns_used += 1;
      ev(0xD1);

      (2 * spendable) / 11

    };

    // Track cycles 
    // about to be 
    // spent
    // ------------
    let cycles_to_spend = cycles_per_canister * 5;

    // Track all created 
    // canisters for rollback
    // ======================
    var created : [Principal] = [];

    // PHASE 1 -> Create all 
    // canisters (NO blackhole yet)
    // ============================
    let cw : Principal = try {
      let result = await (with cycles = cycles_per_canister) IC.create_canister({ settings = null });
      created := Array.append(created, [result.canister_id]);
      result.canister_id
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    let c1 : Principal = try {
      let result = await (with cycles = cycles_per_canister) IC.create_canister({ settings = null });
      created := Array.append(created, [result.canister_id]);
      result.canister_id
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    let c2 : Principal = try {
      let result = await (with cycles = cycles_per_canister) IC.create_canister({ settings = null });
      created := Array.append(created, [result.canister_id]);
      result.canister_id
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    var storage_canisters : [Principal] = [];
    var i = 0;
    while (i < n) {
      let cs : Principal = try {
        let result = await (with cycles = cycles_per_canister) IC.create_canister({ settings = null });
        created := Array.append(created, [result.canister_id]);
        result.canister_id
      } catch (_) {
        await rollback(created);
        return #err(ERR_SPAWN_FAILED);
      };
      storage_canisters := Array.append(storage_canisters, [cs]);
      i += 1;
    };

    // PHASE 2 -> Install code
    // on all canisters
    // =======================
    try {
      await IC.install_code({ 
        mode = #install; 
        canister_id = cw; 
        wasm_module = www; 
        arg = Blob.fromArray([]) 
      });
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    try {
      await IC.install_code({ 
        mode = #install; 
        canister_id = c1; 
        wasm_module = wi1; 
        arg = Blob.fromArray([]) 
      });
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    try {
      await IC.install_code({ 
        mode = #install; 
        canister_id = c2; 
        wasm_module = wi2; 
        arg = Blob.fromArray([]) 
      });
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    i := 0;
    for (cs in storage_canisters.vals()) {
      try {
        await IC.install_code({ 
          mode = #install; 
          canister_id = cs; 
          wasm_module = wst; 
          arg = Blob.fromArray([]) 
        });
      } catch (_) {
        await rollback(created);
        return #err(ERR_SPAWN_FAILED);
      };
      i += 1;
    };

    // PHASE 3 -> Initialize 
    // all canisters
    // =====================
    i := 0;
    for (cs in storage_canisters.vals()) {
      let storage_init = actor(Principal.toText(cs)) : actor {
        init : (Principal, Nat64, Principal, Principal, Principal) -> async { #ok : (); #err : Text };
      };
      try {
        let result = await storage_init.init(cw, ttl, c1, c2, crypto);
        switch (result) {
          case (#err _e) {
            await rollback(created);
            return #err(ERR_SPAWN_FAILED);
          };
          case (#ok _) {};
        };
      } catch (_) {
        await rollback(created);
        return #err(ERR_SPAWN_FAILED);
      };
      i += 1;
    };

    // I1 init
    // -------
    let i1_init = actor(Principal.toText(c1)) : actor {
      init : ({ 
        storage : [Principal]; 
        noticeboard : Principal; 
        witness : Principal; 
        ttl : Nat64;
        factory : Principal
      }) -> async { #ok : (); #err : Text };
    };
    try {
      let result = await i1_init.init({
        storage = storage_canisters;
        noticeboard;
        witness = cw;
        ttl;
        factory = Principal.fromActor(Factory);
      });
      switch (result) {
        case (#err _e) {
          await rollback(created);
          return #err(ERR_SPAWN_FAILED);
        };
        case (#ok _) {};
      };
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    // I2 init
    // -------
    let i2_init = actor(Principal.toText(c2)) : actor {
      init : ({ 
        router : Principal;
        storage : [Principal];
        crypto : Principal;
        witness : Principal;
        noticeboard : Principal;
        factory : Principal;
      }) -> async { #ok : (); #err : Text };
    };
    try {
      let result = await i2_init.init({
        router;
        storage = storage_canisters;
        crypto;
        witness = cw;
        noticeboard;
        factory = Principal.fromActor(Factory);
      });
      switch (result) {
        case (#err _e) {
          await rollback(created);
          return #err(ERR_SPAWN_FAILED);
        };
        case (#ok _) {};
      };
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    // Witness init (last - needs to know all expected canisters)
    let expected_canisters = Array.append(
      [c1, c2],
      storage_canisters
    );
    
    let witness_init = actor(Principal.toText(cw)) : actor {
      init : ({ noticeboard : Principal; expected : [Principal] }) -> async { #ok : (); #err : Text };
    };
    try {
      let result = await witness_init.init({
        noticeboard;
        expected = expected_canisters;
      });
      switch (result) {
        case (#err _e) {
          await rollback(created);
          return #err(ERR_SPAWN_FAILED);
        };
        case (#ok _) {};
      };
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    // PHASE 4 -> All succeeded
    // NOW blackhole everything
    // ========================
    try {
      await blackholeController(cw);
    } catch (_) {
      await rollback(created);
      return #err(ERR_SPAWN_FAILED);
    };

    try {
      await blackholeController(c1);
    } catch (_) {
      // Witness already blackholed - partial state
      // Attempt cleanup of remaining controllable canisters
      // ---------------------------------------------------
      await rollback(Array.append([c1, c2], storage_canisters));
      return #err(ERR_SPAWN_FAILED);
    };

    try {
      await blackholeController(c2);
    } catch (_) {
      await rollback(Array.append([c2], storage_canisters));
      return #err(ERR_SPAWN_FAILED);
    };

    for (cs in storage_canisters.vals()) {
      try {
        await blackholeController(cs);
      } catch (_) {
        // At this point Witness/I1/I2 are blackholed
        // Storage failure leaves partial blackhole state
        // This is an unrecoverable edge case -> log event and fail
        // --------------------------------------------------------
        ev(0xE0);
        return #err(ERR_SPAWN_FAILED);
      };
    };

    // PHASE 5 -> Generate spawn proof
    // ===============================
    let tipNat = events.size();
    let payload_base : [Nat8] = [
      Nat8.fromNat(Nat32.toNat(policy_ver) % 256),
      Nat8.fromNat(tipNat % 256)
    ];

    // ICPP:spawn
    // ----------
    let domain : [Nat8] = [105,99,112,112,58,115,112,97,119,110];
    var payload = Array.append<Nat8>(payload_base, Blob.toArray(code_hashes.i1));
    payload := Array.append<Nat8>(payload, Blob.toArray(code_hashes.i2));
    payload := Array.append<Nat8>(payload, Blob.toArray(code_hashes.storage));
    payload := Array.append<Nat8>(payload, Blob.toArray(code_hashes.witness));
    payload := Array.append<Nat8>(payload, Blob.toArray(Principal.toBlob(c1)));
    payload := Array.append<Nat8>(payload, Blob.toArray(Principal.toBlob(c2)));
    
    for (cs in storage_canisters.vals()) {
      payload := Array.append<Nat8>(payload, Blob.toArray(Principal.toBlob(cs)));
    };
    
    payload := Array.append<Nat8>(payload, Blob.toArray(Principal.toBlob(cw)));
    
    let proof = Blob.fromArray(Blake2s.keyedHash(domain, payload, 32));

    total_cycles_consumed += cycles_to_spend;
    ev(0xC0);

    #ok({
      i1 = c1; 
      i2 = c2; 
      storage = storage_canisters;
      witness = cw;
      spawn_proof = proof; 
      tip = tipNat
    })
  };

  // Events
  // ======
  public query func get_events(args : { from : Nat; limit : Nat }) : async { 
    events : [Blob]; 
    tip : Nat; 
    cert : Blob 
  } {
    let start = args.from; 
    let end = Nat.min(events.size(), start + args.limit);
    let slice = if (end > start) {
      Array.tabulate<Blob>(end - start, func i = events[start + i])
    } else { 
      [] 
    };
    { events = slice; tip = events.size(); cert = certified_hash }
  };

  public query func get_wasm_witness_size() : async Nat {
    switch (wasm_witness) {
      case null 0;
      case (?w) w.size();
    }
  };

  public query func get_cycle_metrics() : async {
    factory_balance : Nat;
    total_consumed : Nat;
    min_required_per_spawn : Nat;
  } {
    {
      factory_balance = Cycles.balance();
      total_consumed = total_cycles_consumed;
      min_required_per_spawn = calculate_min_cycles();
    }
  };

}