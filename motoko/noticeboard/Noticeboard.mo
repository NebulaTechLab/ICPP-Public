// ===================================================
// Noticeboard Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 11 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import Time "mo:base/Time";
import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat64 "mo:base/Nat64";
import Principal "mo:base/Principal";

persistent actor Noticeboard {

  // TYPES
  // =====
  public type Announcement = {
    hint : Blob;
    deposit_id : Blob;
    storage : [Principal];
    ts : Nat64;
    idx : Nat;
    consumed : Bool;
  };

  public type FinalizeRecord = {
    idx : Nat;
    destruction_proofs : [{ canister_id : Principal; ts : Nat64 }];
    finalized_at : Nat64;
  };

  // STATE
  // =====
  private var announcements : [Announcement] = [];
  private var next_idx : Nat = 0;
  private var finalizations : [FinalizeRecord] = [];

  // +++
  // DPS
  // +++

  // Immutable 
  // defaults
  // ---------
  private let POOL_SIZE : Nat = 256;
  private let CHURN_MIN_NS : Nat64 = 300_000_000_000;
  private let CHURN_MAX_NS : Nat64 = 900_000_000_000;
  private let REMOVAL_MIN_PCT : Nat = 5;
  private let REMOVAL_MAX_PCT : Nat = 20;

  // Runtime state
  // -------------
  private var cfg_pool_size : Nat = POOL_SIZE;
  private var cfg_churn_min : Nat64 = CHURN_MIN_NS;
  private var cfg_churn_max : Nat64 = CHURN_MAX_NS;

  private var rng_state : Nat64 = 0;
  private var next_churn_ts : Nat64 = 0;
  private var dummy_ids : [Blob] = [];
  private var pool_initialized : Bool = false;

  // SAFE ARITHMETIC
  // ===============
  private func safeSub(a : Nat, b : Nat) : Nat {
    if (a >= b) { a - b } else { 0 }
  };

  private func safeSub64(a : Nat64, b : Nat64) : Nat64 {
    if (a >= b) { a - b } else { 0 }
  };
  
  // PRNG
  // ====
  private func rand() : Nat64 {
    var x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state := x;
    x
  };

  private func rand_bytes(len : Nat) : [Nat8] {
    Array.tabulate<Nat8>(len, func(i) : Nat8 {
      if (i % 8 == 0) { rng_state := rand() };
      let shift = 8 * (i % 8);
      Nat8.fromNat(Nat64.toNat((rng_state >> Nat64.fromNat(shift)) & 0xFF))
    })
  };

  private func nat64_to_bytes(n : Nat64) : [Nat8] {
    [
      Nat8.fromNat(Nat64.toNat((n >> 56) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 48) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 40) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 32) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 24) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 16) & 0xFF)),
      Nat8.fromNat(Nat64.toNat((n >> 8) & 0xFF)),
      Nat8.fromNat(Nat64.toNat(n & 0xFF))
    ]
  };

  // DPS INTERNALS
  // =============
  private func schedule_next_churn() {
    let range = safeSub64(cfg_churn_max, cfg_churn_min);
    let delay = cfg_churn_min + (rand() % range);
    next_churn_ts := Nat64.fromIntWrap(Time.now()) + delay;
  };

  private func rand_removal_pct() : Nat {
    let range = safeSub(REMOVAL_MAX_PCT, REMOVAL_MIN_PCT) + 1;
    REMOVAL_MIN_PCT + (Nat64.toNat(rand()) % range)
  };

  private func is_dummy(dep : Blob) : Bool {
    for (d in dummy_ids.vals()) {
      if (Blob.equal(d, dep)) return true;
    };
    false
  };

  private func make_dummy(now : Nat64) : Announcement {
    let id_bytes = Array.flatten<Nat8>([
      nat64_to_bytes(rand()),
      nat64_to_bytes(rand()),
      nat64_to_bytes(rand()),
      nat64_to_bytes(rand())
    ]);
    let dep_id = Blob.fromArray(id_bytes);
    let hint = Blob.fromArray(rand_bytes(80));

    dummy_ids := Array.append(dummy_ids, [dep_id]);

    let ann : Announcement = {
      hint;
      deposit_id = dep_id;
      storage = [];
      ts = now;
      idx = next_idx;
      consumed = false;
    };
    next_idx += 1;
    ann
  };

  private func ensure_initialized() {
    if (pool_initialized) return;

    let now = Nat64.fromIntWrap(Time.now());
    // Seed PRNG
    // ---------
    rng_state := now ^ 0x5DEECE66D;

    // Generate
    // --------
    var i = 0;
    while (i < cfg_pool_size) {
      let ann = make_dummy(now);
      announcements := Array.append(announcements, [ann]);
      i += 1;
    };

    schedule_next_churn();
    pool_initialized := true;
  };

  private func do_churn() {
    if (not pool_initialized) return;

    let now = Nat64.fromIntWrap(Time.now());
    let remove_pct = rand_removal_pct();
    let remove_count = (dummy_ids.size() * remove_pct) / 100;

    // Removals
    // --------
    var removed = 0;
    while (removed < remove_count and dummy_ids.size() > 0) {
      let idx = Nat64.toNat(rand()) % dummy_ids.size();
      let target_id = dummy_ids[idx];

      dummy_ids := Array.filter<Blob>(dummy_ids, func(d) = not Blob.equal(d, target_id));
      announcements := Array.filter<Announcement>(announcements, func(a) = not Blob.equal(a.deposit_id, target_id));

      removed += 1;
    };

    // Count RA
    // --------
    let real_count = Array.filter<Announcement>(
      announcements,
      func(a) = not a.consumed and not is_dummy(a.deposit_id)
    ).size();

    // Replenish
    // ---------
    let current_dummy_count = dummy_ids.size();
    let total_active = real_count + current_dummy_count;
    let needed = safeSub(cfg_pool_size, total_active);

    var j = 0;
    while (j < needed) {
      let ann = make_dummy(now);
      announcements := Array.append(announcements, [ann]);
      j += 1;
    };

    schedule_next_churn();
  };

  // HEARTBEAT
  // =========
  system func heartbeat() : async () {
    ensure_initialized();

    let now = Nat64.fromIntWrap(Time.now());
    if (now >= next_churn_ts) {
      do_churn();
    };
  };

  // PUBLIC INTERFACE
  // ================
  public shared(_) func announce(args : {
    hint : Blob;
    deposit_id : Blob;
    storage : [Principal];
    ts : Nat64;
  }) : async { #ok : (); #err : Text } {
    ensure_initialized();

    let ann : Announcement = {
      hint = args.hint;
      deposit_id = args.deposit_id;
      storage = args.storage;
      ts = args.ts;
      idx = next_idx;
      consumed = false;
    };
    announcements := Array.append(announcements, [ann]);
    next_idx += 1;
    #ok(())
  };

  public shared(_) func finalize(args : {
    idx : Nat;
    destruction_proofs : [{ canister_id : Principal; ts : Nat64 }];
  }) : async { #ok : (); #err : Text } {
    let rec : FinalizeRecord = {
      idx = args.idx;
      destruction_proofs = args.destruction_proofs;
      finalized_at = Nat64.fromIntWrap(Time.now());
    };
    finalizations := Array.append(finalizations, [rec]);
    #ok(())
  };

  // Mark an announcement as consumed by its deposit_id
  // Idempotent -> calling it again for the same deposit_id is #ok
  // -------------------------------------------------------------
  public shared(_) func consume(args : { deposit_id : Blob }) : async { #ok : (); #err : Text } {
    announcements := Array.map<Announcement, Announcement>(
      announcements,
      func (a : Announcement) : Announcement {
        if (not a.consumed and Blob.equal(a.deposit_id, args.deposit_id)) {
          {
            hint = a.hint;
            deposit_id = a.deposit_id;
            storage = a.storage;
            ts = a.ts;
            idx = a.idx;
            consumed = true;
          }
        } else {
          a
        }
      }
    );
    // Keep this idempotent 
    // (#ok even if nothing was updated)
    // ---------------------------------
    #ok(())
  };

  // Paginated retrieval 
  // of all announcements
  // --------------------
  public query func get_announcements(from : Nat, limit : Nat) : async [Announcement] {
    let pending = Array.filter<Announcement>(
      announcements,
      func (a : Announcement) : Bool { 
        not a.consumed and a.storage.size() > 0 
      }
    );

    let start = Nat.min(from, pending.size());
    let end = Nat.min(start + limit, pending.size());
    let count = safeSub(end, start);

    if (count > 0) {
      Array.tabulate<Announcement>(count, func i = pending[start + i])
    } else { [] }
  };

  public query func get_finalization(idx : Nat) : async ?FinalizeRecord {
    Array.find<FinalizeRecord>(finalizations, func r = r.idx == idx)
  };

  // Find by exact 
  // hint match (80 bytes)
  // ---------------------
  public query func find_by_hint(hint : Blob) : async [Announcement] {
    Array.filter<Announcement>(announcements, func a = a.hint == hint and a.storage.size() > 0)
  }; 

  // Bucket-filtered query for efficient discovery
  // Bucket = SHA3("ICPP:bucket:v1" || recipient_principal)[0]
  // ---------------------------------------------------------
  public query func find_by_bucket(bucket : Nat8, from : Nat, limit : Nat) : async [Announcement] {
    let filtered = Array.filter<Announcement>(
      announcements,
      func (a : Announcement) : Bool {
        if (a.consumed) { return false };
        if (a.storage.size() == 0) { return false };
        let hint_arr = Blob.toArray(a.hint);
        hint_arr.size() > 0 and hint_arr[0] == bucket
      }
    );

    let start = Nat.min(from, filtered.size());
    let end = Nat.min(start + limit, filtered.size());
    let count = safeSub(end, start);

    if (count > 0) {
      Array.tabulate<Announcement>(count, func i = filtered[start + i])
    } else { [] }
  };

  public query func ping() : async Text { "noticeboard:ok" };

  // PRUNING
  // =======
  public func prune() : async Nat {
    let before = announcements.size();

    let consumed_dummy_ids = Array.filter<Blob>(dummy_ids, func(d) {
      for (a in announcements.vals()) {
        if (Blob.equal(a.deposit_id, d) and a.consumed) return true;
      };
      false
    });

    for (cd in consumed_dummy_ids.vals()) {
      dummy_ids := Array.filter<Blob>(dummy_ids, func(d) = not Blob.equal(d, cd));
    };

    // Remove all 
    // consumed
    // ----------
    announcements := Array.filter<Announcement>(
      announcements,
      func(a : Announcement) : Bool { not a.consumed }
    );

    safeSub(before, announcements.size())
  };

  // DIAGNOSTICS 
  // (read-only)
  // ===========
  public query func get_pool_stats() : async {
    total : Nat;
    dummies : Nat;
    real : Nat;
    consumed : Nat;
    initialized : Bool;
  } {
    let consumed_count = Array.filter<Announcement>(announcements, func(a) = a.consumed).size();
    let dummy_count = dummy_ids.size();
    let total = announcements.size();
    let real_count = safeSub(safeSub(total, consumed_count), dummy_count);

    {
      total;
      dummies = dummy_count;
      real = real_count;
      consumed = consumed_count;
      initialized = pool_initialized;
    }
  }; 
}
