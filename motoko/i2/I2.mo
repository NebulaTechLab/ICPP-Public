// ===================================================
// I2 (receive-side) Canister
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
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat16 "mo:base/Nat16";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Array "mo:base/Array";
import HashMap "mo:base/HashMap";

import Blake2s "../shared/hash/BLAKE2s";
import Crypto "../crypto/Crypto";

persistent actor I2 {

  // Common types
  // ============
  public type Account = { owner : Principal; subaccount : ?Blob };
  public type Amount = Nat;
  public type DepositId = Blob;

  // Job status for async polling
  // ============================
  public type JobStatus = {
    #pending;
    #processing;
    #done : { tx_id : Nat; fees_charged : Amount; csrn : Blob };
    #error : Text;
  };

  type Job = {
    var status : JobStatus;
    deposit_id : DepositId;
    auth_key_hash_hex : Text;
    recipient : Account;
    created_at : Nat64;
  };

  // Rate limiting
  // =============
  type Rate = { window_start : Nat64; count : Nat32 };

  // Constant-time array comparison
  // (Used for BLAKE2s hash verification in quorum)
  // ==============================================
  private func arrayEqCt(a : [Nat8], b : [Nat8]) : Bool {
    if (a.size() != b.size()) return false;
    var diff : Nat8 = 0;
    var i = 0;
    while (i < a.size()) {
      diff := diff | (a[i] ^ b[i]);
      i += 1;
    };
    diff == 0
  };

  // Constant-time Text comparison
  // (converts to UTF-8 bytes and uses arrayEqCt)
  // =============================================
  private func textEqCt(a : Text, b : Text) : Bool {
    let bytesA = Blob.toArray(Text.encodeUtf8(a));
    let bytesB = Blob.toArray(Text.encodeUtf8(b));
    arrayEqCt(bytesA, bytesB)
  };

  // DYNAMIC Router binding 
  // via stored principal
  // ======================
  func routerActor(router : Principal) : actor {
    get_config : () -> async { 
      config : {
        policy_ver : Nat32;
        hash_alg : Text;
        deposit_fee_bps : Nat16;
        egress_fee_bps : Nat16;
        reclaim_fee_bps : Nat16;
        spawn_cycles_target : Nat;
        fee_split : { treasury_bps : Nat16; cycles_bps : Nat16; witness_bps : Nat16 };
        size_buckets : [Nat32];
        ttl_secs : Nat64;
        code_hashes : { i1 : Blob; i2 : Blob; witness : Blob };
        factory : Principal;        
        noticeboard : Principal; 
        crypto : Principal; 
        fee_accounts : { treasury : Account; witness : Account; buffer : Account };
        rate : { window_secs : Nat64; max_calls_per_principal : Nat32 };
        cmc : Principal;
        treasury_fee_subs : [Blob];
        treasury_remainder_sub : Blob;
      }; 
      certified_hash : Blob 
    };
    finalize : (DepositId, Blob, Blob, Account, Amount)
          -> async { #ok : { tx_id : Nat; fees_charged : Amount }; #err : Text }
  } = actor(Principal.toText(router));

  // Crypto Verifier 
  // ===============
  public type VerifyOk = Crypto.VerifyOk;
  public type VerifyArgs = Crypto.VerifyArgs;
  public type CryptoActor = Crypto.CryptoActor;

  // Dynamic binding to the 
  // Rust crypto canister
  // ======================
  func mkCrypto(p : Principal) : CryptoActor {
    actor(Principal.toText(p));
  };

  // Witness (best-effort)
  // =====================
  func mkWitness(p : Principal) : actor {
    log_egress : ({
      deposit_id : DepositId; ts : Nat64; recipient : Account; meta_digest : Blob
    }) -> async { #ok : (); #err : Text };
    log_destruct_intent : ({
      canister_id : Principal;
      ts : Nat64;
    }) -> async { #ok : (); #err : Text };
    is_destroyed : (Principal) -> async Bool;
  } = actor(Principal.toText(p));

  func digestVerifyOk(v : VerifyOk) : Blob {
    // ICPP:vok
    // --------
    let key : [Nat8] = [105,99,112,112,58,118,111,107];

    let did_bytes  : [Nat8] = Blob.toArray(v.deposit_id);
    let td_bytes   : [Nat8] = Blob.toArray(v.transcript_digest);
    let hint_bytes : [Nat8] = Blob.toArray(v.hint);
    let null_bytes : [Nat8] = switch (v.nullifier) {
      case null [];
      case (?n) Blob.toArray(n);
    };

    let msg  = Array.append<Nat8>(did_bytes, td_bytes);
    let msg2 = Array.append<Nat8>(msg, null_bytes);
    let msg3 = Array.append<Nat8>(msg2, hint_bytes);

    Blob.fromArray(Blake2s.keyedHash(key, msg3, 32))
  };

  // Noticeboard (best-effort)
  // =========================
  func mkNoticeboard(p : Principal) : actor {
    consume : ({ deposit_id : DepositId }) -> async { #ok : (); #err : Text };
  } = actor(Principal.toText(p));

  // Errors
  // ======
  let ERR_PAUSED = "ERR.PAUSED";
  let ERR_RATE_LIMIT = "ERR.RATE_LIMIT";
  let ERR_BAD_ARG = "ERR.BAD_ARG";
  let ERR_UNAUTHORIZED = "ERR.UNAUTHORIZED";
  let ERR_ROUTERSVC = "ERR.ROUTERSVC";
  let ERR_JOB_NOT_FOUND = "ERR.JOB_NOT_FOUND";
  let ERR_RETRIEVAL_FAILED = "ERR.RETRIEVAL_FAILED";
  let ERR_CRYPTO_FAILED = "ERR.CRYPTO_FAILED";
  let ERR_AUTH_FAILED = "ERR.AUTH_FAILED";

  var paused  : Bool = false;
  var admins  : [Principal] = [];
  var router  : Principal = Principal.fromText("aaaaa-aa");
  var crypto  : Principal = Principal.fromText("aaaaa-aa");
  var witness : ?Principal = null;
  var noticeboard : ?Principal = null;
  var factory : Principal = Principal.fromText("aaaaa-aa");
  var witness_failures : Nat64 = 0;
  var storage_ids : [Principal] = [];
  var initialized : Bool = false;
  var cached_package : ?Blob = null;

  // Job tracking
  // ============
  var next_job_id : Nat64 = 0;

  // job_id -> Job
  // -------------
  transient var jobs = HashMap.HashMap<Nat64, Job>(
    16,
    func(a : Nat64, b : Nat64) : Bool { a == b },
    func(n : Nat64) : Nat32 { Nat32.fromNat(Nat64.toNat(n) % 4294967296) }
  );

  // deposit_id -> job_id 
  // (idempotent finalize_start)
  // ---------------------------
  transient var jobs_by_deposit = HashMap.HashMap<DepositId, Nat64>(
    16,
    Blob.equal,
    Blob.hash
  );

  // Deposits that this I2 
  // has successfully finalized
  // --------------------------
  transient var finalized_deposits = HashMap.HashMap<DepositId, Bool>(
    16,
    Blob.equal,
    Blob.hash
  );

  // Self-destruct scheduling
  // (TTL after a successful finalize)
  // Units -> nanoseconds (2.5 min)
  // ---------------------------------
  let DESTRUCT_TTL_NS : Nat64 = 150_000_000_000;

  // Maximum canister lifetime
  // (1 hour from first job)
  // -------------------------
  let MAX_LIFETIME_NS : Nat64 = 3_600_000_000_000;
  transient var created_at_first_job : ?Nat64 = null;

  // When to destroy this canister
  // (null == no destruction scheduled yet)
  // --------------------------------------
  transient var destroy_at : ?Nat64 = null;

  // Ephemeral rate window
  // ---------------------
  transient var calls = HashMap.HashMap<Principal, Rate>(
    64,
    Principal.equal,
    Principal.hash
  );

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

  // Initialize
  // ==========
  public shared({ caller }) func init(args : {
    router : Principal;
    storage : [Principal];
    crypto : Principal;
    witness : Principal;
    noticeboard : Principal;
    factory : Principal;
  }) : async { #ok : (); #err : Text } {
    if (initialized) return #err("ERR.ALREADY_INITIALIZED");
    if (caller != args.factory) return #err(ERR_UNAUTHORIZED);
    
    router := args.router;
    storage_ids := args.storage;
    crypto := args.crypto;
    witness := ?args.witness;
    noticeboard := ?args.noticeboard;
    initialized := true;
    factory := args.factory;
    #ok(())
  };

  // Discovery
  // =========
  public query func supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICPP-i2-v1"; url = "https://example.com/specs/ICPP-i2-v1" }
    ]
  };

  // Administrator
  // =============
  public shared({ caller }) func set_admins(a:[Principal]) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) }
    else { admins := a; #ok(()) }
  };

  public shared({ caller }) func pause()  : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) } else { paused := true;  #ok(()) }
  };

  public shared({ caller }) func unpause(): async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) } else { paused := false; #ok(()) }
  };

  public shared({ caller }) func set_services(s : { router : Principal; crypto : Principal; witness : ?Principal })
    : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) { #err(ERR_UNAUTHORIZED) }
    else { router := s.router; crypto := s.crypto; witness := s.witness; #ok(()) }
  };

  // =====================
  // ASYNC POLLING PATTERN
  // =====================

  // Start finalize job (returns immediately)
  // ========================================
  public shared({ caller }) func finalize_start(args : {
    deposit_id : DepositId;
    auth_key_hash_hex : Text;
    recipient : Account;
  }) : async { #ok : Nat64; #err : Text } {

    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    if (not initialized) return #err("ERR.NOT_INITIALIZED");
    if (args.deposit_id.size() == 0) return #err(ERR_BAD_ARG);

    // Check for 
    // existing job
    // ------------
    switch (jobs_by_deposit.get(args.deposit_id)) {
      case (?existing_id) {
        // Job exists -> check if  
        // it's in a retryable state
        // -------------------------
        switch (jobs.get(existing_id)) {
          case (?existing_job) {
            switch (existing_job.status) {
              // Terminal success
              // -> return existing
              // ------------------
              case (#done _) { return #ok(existing_id) };
              
              // Still running 
              // -> return existing
              // ------------------
              case (#pending) { return #ok(existing_id) };
              case (#processing) { return #ok(existing_id) };
              
              // Failed -> allow retry 
              // by falling through
              // ---------------------
              case (#error _) {
                jobs.delete(existing_id);
                jobs_by_deposit.delete(args.deposit_id);
              };
            };
          };
          // Orphaned mapping
          // -> clean up
          // ----------------
          case null {
            jobs_by_deposit.delete(args.deposit_id);
          };
        };
      };
      case null {};
    };

    let job_id = next_job_id;
    next_job_id += 1;

    let job : Job = {
      var status = #pending;
      deposit_id = args.deposit_id;
      auth_key_hash_hex = args.auth_key_hash_hex;
      recipient = args.recipient;
      created_at = now();
    };

    jobs.put(job_id, job);
    jobs_by_deposit.put(args.deposit_id, job_id);

    // Set lifetime clock on 
    // first job creation
    // --------------------
    switch (created_at_first_job) {
      case null { created_at_first_job := ?now() };
      case _ {};
    };

    // Kick off async 
    // processing
    // --------------
    ignore async {
      await process_job(job_id);
      jobs_by_deposit.delete(args.deposit_id);
    };

    #ok(job_id)
  };

  // Poll job status
  // ===============
  public query func finalize_status(job_id : Nat64) : async { #ok : JobStatus; #err : Text } {
    switch (jobs.get(job_id)) {
      case null { #err(ERR_JOB_NOT_FOUND) };
      case (?job) { #ok(job.status) };
    }
  };

  // Reset stuck job 
  // (allows retry)
  // ===============
  public shared({ caller }) func reset_job(args : {
    deposit_id : DepositId;
    auth_key_hash_hex : Text;
  }) : async { #ok : (); #err : Text } {

    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    if (not initialized) return #err("ERR.NOT_INITIALIZED");
    if (args.deposit_id.size() == 0) return #err(ERR_BAD_ARG);

    switch (jobs_by_deposit.get(args.deposit_id)) {
      case null { return #err(ERR_JOB_NOT_FOUND) };
      case (?job_id) {
        switch (jobs.get(job_id)) {
          case null {
            jobs_by_deposit.delete(args.deposit_id);
            return #err(ERR_JOB_NOT_FOUND);
          };
          case (?job) {
            // Verify caller 
            // knows auth_key_hash
            // -------------------
            if (not textEqCt(args.auth_key_hash_hex, job.auth_key_hash_hex)) {
              return #err(ERR_UNAUTHORIZED);
            };

            switch (job.status) {
              case (#done _) { return #err("ERR.ALREADY_FINALIZED") };
              case (#error _) {
                jobs.delete(job_id);
                jobs_by_deposit.delete(args.deposit_id);
                return #ok(());
              };

              // 15 min
              // ------
              case (#pending) {
                let age_ns = now() - job.created_at;
                if (age_ns < 900_000_000_000) { return #err("ERR.JOB_STILL_ACTIVE") };
                jobs.delete(job_id);
                jobs_by_deposit.delete(args.deposit_id);
                return #ok(());
              };

              // 15 min
              // ------
              case (#processing) {
                let age_ns = now() - job.created_at;
                if (age_ns < 900_000_000_000) { return #err("ERR.JOB_STILL_ACTIVE") };
                jobs.delete(job_id);
                jobs_by_deposit.delete(args.deposit_id);
                return #ok(());
              };
            };
          };
        };
      };
    };
  };

  // Internal job processor
  // ======================
  private func process_job(job_id : Nat64) : async () {
    switch (jobs.get(job_id)) {
      case null {};
      case (?job) {
        job.status := #processing;

        // Fetch CSRN from Storage
        // (before retrieving package)
        // ---------------------------
        if (storage_ids.size() == 0) {
          job.status := #error(ERR_RETRIEVAL_FAILED);
          return;
        };
        
        let storage_actor_csrn = actor(Principal.toText(storage_ids[0])) : actor {
          fetch_csrn : () -> async { #ok : Blob; #err : Text };
        };
        
        let csrn_blob = switch (await storage_actor_csrn.fetch_csrn()) {
          case (#err _e) { 
            job.status := #error(ERR_RETRIEVAL_FAILED);
            return;
          };
          case (#ok csrn) { csrn };
        };

        // Check cache first
        // and then retrieve
        // -----------------
        let package_blob : Blob = switch (cached_package) {
          case (?pkg) { pkg };
          case null {
            // Retrieve from ALL storage 
            // canisters and verify quorum
            // ---------------------------
            var responses : [(Principal, Blob)] = [];
            
            for (storage_id in storage_ids.vals()) {
              let storage_actor = actor(Principal.toText(storage_id)) : actor {
                retrieve : () -> async { #ok : Blob; #err : Text };
              };
              
              try {
                let retrieve_result = await storage_actor.retrieve();
                switch (retrieve_result) {
                  case (#ok b) {
                    responses := Array.append(responses, [(storage_id, b)]);
                  };
                  case (#err _) {};
                };
              } catch (_) {};
            };

            if (responses.size() == 0) {
              job.status := #error(ERR_RETRIEVAL_FAILED);
              return;
            };

            // Verify quorum consistency 
            // via BLAKE2s hash comparison
            // ---------------------------
            let quorum_domain : [Nat8] = [73,67,80,80,58,113,117,111,114,117,109];
            let reference_blob = responses[0].1;
            let reference_hash = Blake2s.keyedHash(quorum_domain, Blob.toArray(reference_blob), 32);
            
            var quorum_valid = true;
            var idx = 1;
            
            while (idx < responses.size()) {
              let current_hash = Blake2s.keyedHash(quorum_domain, Blob.toArray(responses[idx].1), 32);
              if (not arrayEqCt(reference_hash, current_hash)) {
                quorum_valid := false;
              };
              idx += 1;
            };
            
            if (not quorum_valid) {
              job.status := #error(ERR_RETRIEVAL_FAILED);
              return;
            };
            
            // Cache it
            cached_package := ?reference_blob;
            reference_blob
          };
        };

        // Decode package -> hint(80) || u32_be(cap_len) || capsule || inner
        // -----------------------------------------------------------------
        let pkg_arr = Blob.toArray(package_blob);
        let hint_len : Nat = 80;
        let len_field_len : Nat = 4;

        if (pkg_arr.size() < hint_len + len_field_len) {
          job.status := #error(ERR_RETRIEVAL_FAILED);
          return;
        };

        let b0 = Nat8.toNat(pkg_arr[hint_len]);
        let b1 = Nat8.toNat(pkg_arr[hint_len + 1]);
        let b2 = Nat8.toNat(pkg_arr[hint_len + 2]);
        let b3 = Nat8.toNat(pkg_arr[hint_len + 3]);

        let cap_len : Nat = (((b0 * 256) + b1) * 256 + b2) * 256 + b3;

        let cap_start : Nat = hint_len + len_field_len;
        let inner_offset : Nat = cap_start + cap_len;

        if (pkg_arr.size() < inner_offset) {
          job.status := #error(ERR_RETRIEVAL_FAILED);
          return;
        };

        // Extract capsule
        // ---------------
        let capsule_arr = Array.tabulate<Nat8>(cap_len, func (i : Nat) : Nat8 {
          pkg_arr[cap_start + i]
        });
        let capsule_blob : Blob = Blob.fromArray(capsule_arr);

        // Extract encrypted_inner
        // -----------------------
        let inner_len : Nat = pkg_arr.size() - inner_offset;
        let inner_arr = Array.tabulate<Nat8>(inner_len, func (i : Nat) : Nat8 {
          pkg_arr[inner_offset + i]
        });
        let encrypted_inner : Blob = Blob.fromArray(inner_arr);

        // Call Crypto decrypt API
        // (stateless oracle)
        // -----------------------
        let C = mkCrypto(crypto);

        // Start decrypt session
        // ---------------------
        let (start_ok, session_id, _) = await C.decrypt_start(
          capsule_blob,
          encrypted_inner,
          csrn_blob,
          job.deposit_id
        );

        if (not start_ok) {
          job.status := #error(ERR_CRYPTO_FAILED);
          return;
        };

        // Drive decrypt 
	      // to completion
        // -------------
        var decrypt_done = false;
        while (not decrypt_done) {
          let (step_ok, done, _) = await C.decrypt_step(session_id, 100);
          if (not step_ok) {
            job.status := #error(ERR_CRYPTO_FAILED);
            return;
          };
          decrypt_done := done;
        };

        // Get decrypt result
        // ------------------
        let (result_ok, maybe_result, _) = await C.decrypt_result(session_id);

        if (not result_ok) {
          job.status := #error(ERR_CRYPTO_FAILED);
          return;
        };

        let decrypt_result = switch (maybe_result) {
          case null { 
            job.status := #error(ERR_CRYPTO_FAILED);
            return;
          };
          case (?r) { r };
        };

        // Compare caller-provided 
        // hash with embedded hash
        // (proves caller successfully 
        // decrypted)
        // ---------------------------
        let embedded_auth_key_hash_hex = decrypt_result.auth_key_hash_hex;

        if (not textEqCt(job.auth_key_hash_hex, embedded_auth_key_hash_hex)) {
          job.status := #error(ERR_AUTH_FAILED);
          return;
        };

        let amount : Nat = Nat64.toNat(decrypt_result.amount);

        // Build minimal VerifyOk 
        // for witness digest
        // ----------------------
        let meta : VerifyOk = {
          deposit_id = job.deposit_id;
          nullifier = null;
          transcript_digest = Blob.fromArray([]);
          hint = Blob.fromArray([]);
          i2_principal = Blob.fromArray([]);
        };

        // Call Router to 
        // finalize payment
        // ----------------
        let router_actor = routerActor(router);
        let r = await router_actor.finalize(
          job.deposit_id,
          Blob.fromArray([]),
          Text.encodeUtf8(job.auth_key_hash_hex),
          job.recipient,
          amount
        );

        switch (r) {
          // Router reports 
          // an error
          case (#err e) {
            // If Router says REPLAY and we successfully 
            // finalized this deposit treat it as 
            // idempotent success
            if (e == "ERR.REPLAY") {
              switch (finalized_deposits.get(job.deposit_id)) {
                case (?true) {
                  // Best-effort -> mark 
                  // consumed on Noticeboard
                  switch (noticeboard) {
                    case null {};
                    case (?nb) {
                      let NB = mkNoticeboard(nb);
                      ignore async {
                        try {
                          let _ = await NB.consume({ deposit_id = job.deposit_id });
                        } catch (_) {};
                      };
                    };
                  };

                  job.status := #done({
                    tx_id = 0;
                    fees_charged = 0;
                    csrn = csrn_blob;
                  });
                  destroy_at := ?(now() + DESTRUCT_TTL_NS);
                };
                case _ {
                  job.status := #error(ERR_ROUTERSVC);
                };
              };
            } else {
              job.status := #error(ERR_ROUTERSVC);
            };
          };

          // Router finalize 
          // succeeded
          case (#ok res) {
            // Remember success 
            // for this deposit
            finalized_deposits.put(job.deposit_id, true);

            // Clear cache
            // -----------
            cached_package := null;

            // Best-effort -> mark 
            // consumed on Noticeboard
            switch (noticeboard) {
              case null {};
              case (?nb) {
                let NB = mkNoticeboard(nb);
                ignore async {
                  try {
                    let _ = await NB.consume({ deposit_id = job.deposit_id });
                  } catch (_) {};
                };
              };
            };

            let md = digestVerifyOk(meta);

            // Log to witness -> schedule 
            // destruction after TTL
            switch (witness) {
              case null {
                job.status := #done({
                  tx_id = res.tx_id;
                  fees_charged = res.fees_charged;
                  csrn = csrn_blob;
                });
                destroy_at := ?(now() + DESTRUCT_TTL_NS);
              };
              case (?w) {
                let W = mkWitness(w);
                try {
                  ignore await W.log_egress({
                    deposit_id = job.deposit_id;
                    ts = now();
                    recipient = job.recipient;
                    meta_digest = md;
                  });

                  ignore await W.log_destruct_intent({
                    canister_id = Principal.fromActor(I2);
                    ts = now();
                  });

                  job.status := #done({
                    tx_id = res.tx_id;
                    fees_charged = res.fees_charged;
                    csrn = csrn_blob;
                  });
                  destroy_at := ?(now() + DESTRUCT_TTL_NS);
                } catch (_) {
                  witness_failures += 1;

                  // Even if witness logging 
                  // fails payment is finalized
                  job.status := #done({
                    tx_id = res.tx_id;
                    fees_charged = res.fees_charged;
                    csrn = csrn_blob;
                  });
                  destroy_at := ?(now() + DESTRUCT_TTL_NS);
                }
              }
            }
          }
        }
      }
    }
  };

  // Periodic GC for 
  // timed self-destruct
  // ===================
  system func heartbeat() : async () {
    let t = now();
    
    // Check explicit 
    // destruction schedule
    // --------------------
    switch (destroy_at) {
      case (?d) { if (t >= d) { await self_destruct(); return } };
      case null {};
    };
    
    // Check maximum lifetime
    // ----------------------
    switch (created_at_first_job) {
      case (?start) {
        if (t >= start + MAX_LIFETIME_NS) {
          await self_destruct();
        };
      };
      case null {};
    };
  };

  // Destruct 
  // ========
  private func self_destruct() : async () {
    // Request Storage 
    // destruction
    // ---------------
    for (sid in storage_ids.vals()) {
      let S = actor(Principal.toText(sid)) : actor {
        request_destruct : (Principal) -> async ();
      };
      try {
        await S.request_destruct(factory);
      } catch (_) {};
    };
    
    // Request Witness 
    // destruction
    // ---------------
    switch (witness) {
      case (?wid) {
        let W = actor(Principal.toText(wid)) : actor {
          request_destruct : (Principal) -> async ();
        };
        try {
          await W.request_destruct(factory);
        } catch (_) {};
      };
      case null {};
    };
    
    // Destroy self
    // ------------
    storage_ids := [];
    
    let IC : actor {
      update_settings : ({ canister_id : Principal; settings : { controllers : ?[Principal] } }) -> async ();
    } = actor("aaaaa-aa");
    let self_id = Principal.fromActor(I2);
    
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

  public query func ping() : async Text { "i2:ok" };
}