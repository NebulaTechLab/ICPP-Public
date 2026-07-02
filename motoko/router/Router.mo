// ===================================================
// Router Canister
// Privacy ICP (ICPP)
//
// Version -> 2.1.00
// Date    -> 03 January 2026
// Status  -> Public release ver:2 subver:1 release:00
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
import Prim "mo:prim"; 

import Cycles "mo:base/ExperimentalCycles";
import Blake2s "../shared/hash/BLAKE2s";

persistent actor Router {

  // Factory interface
  // =================
  func mkFactory(p : Principal) : actor {
    spawn_triplet : (Nat64, Principal, Principal, Principal) -> async { 
      #ok : { 
        i1 : Principal; 
        i2 : Principal; 
        storage : [Principal];
        witness : Principal;
        spawn_proof : Blob; 
        tip : Nat 
      }; 
      #err : Text 
    };
  } = actor(Principal.toText(p));
 
  public type NotifyError = {
    #Refunded : { block_index : ?Nat64; reason : Text };
    #InvalidTransaction : Text;
    #Other : { error_message : Text; error_code : Nat64 };
    #Processing;
    #TransactionTooOld : Nat64;
  };

  // CMC interface for ICP
  // to cycles conversion
  // =====================
  func mkCMC(p : Principal) : actor {
    notify_top_up : ({ canister_id : Principal; block_index : Nat64 }) -> async { #Ok : Nat; #Err : NotifyError };
  } = actor(Principal.toText(p));

  // Ledger setup
  // ============
  public type Account = { owner : Principal; subaccount : ?Blob };

  public type TransferError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #TemporarilyUnavailable;
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #GenericError : { error_code : Nat; message : Text };
  };

  public type TransferResult = { #Ok : Nat; #Err : TransferError };

  let Ledger : actor {
    icrc1_transfer : ({ from_subaccount : ?Blob; to : Account; amount : Nat; fee : ?Nat; memo : ?Blob; created_at_time : ?Nat64 }) -> async TransferResult;
    icrc1_fee : () -> async Nat;
    icrc1_balance_of : (Account) -> async Nat;
  } = actor("ryjl3-tyaaa-aaaaa-aaaba-cai");

  public type Amount = Nat;
  public type DepositId = Blob;

  public type Config = {
    policy_ver : Nat32;
    hash_alg : Text;
    deposit_fee_bps : Nat16;
    spawn_cycles_target : Nat;
    crypto_cycles_per_tx : Nat;
    noticeboard_cycles_per_tx : Nat;
    registry_cycles_per_tx : Nat;
    size_buckets : [Nat32];
    ttl_secs : Nat64;
    code_hashes : { i1 : Blob; i2 : Blob; witness : Blob };
    factory : Principal;
    noticeboard : Principal;
    registry : Principal;
    crypto : Principal;
    fee_accounts : { treasury : Account; buffer : Account };
    rate : { window_secs : Nat64; max_calls_per_principal : Nat32 };
    cmc : Principal;
    treasury_fee_subs : [Blob];
    treasury_remainder_sub : Blob;
  };

  type Timestamp = Nat64;
  type DepositState = { #Allocated; #Created; #Sealed; #Finalized; #Reclaimed };

  public type State = DepositState;
  public type Notice = { deposit_id : DepositId; hint : Blob; bucket : Nat32; ts : Nat64 };

  public type Event = {
    #DepositCreated : { id : DepositId; payer : Account; amount : Amount; bucket : Nat32; ts : Nat64 };
    #Sealed : { id : DepositId; ts : Nat64 };
    #Finalized : { id : DepositId; recipient : Account; fee_user : Amount; ts : Nat64 };
    #Reclaimed : { id : DepositId; fee_user : Amount; ts : Nat64 };
    #ConfigChanged : { ver : Nat32; ts : Nat64 };
    #Paused : { ts : Nat64 };
    #Unpaused : { ts : Nat64 }
  };

  type Deposit = {
    payer : Account;
    recipient_hint_pref : Nat32;
    amount : Amount;
    user_fee : Amount;
    spawn_fee : Amount;
    bucket : Nat32;
    created_at : Nat64;
    i1 : Principal;
    i2 : Principal;
    witness : Principal;
    storage : [Principal];
    expires_at : Timestamp;
    state : DepositState;
  };

  // Errors
  // ======
  let ERR_INVALID_CTX = "ERR.INVALID_CTX";
  let ERR_EXPIRED = "ERR.EXPIRED";
  let ERR_REPLAY = "ERR.REPLAY";
  let ERR_CMC_FAIL = "ERR.CMC_FAIL";
  let ERR_NOT_FOUND = "ERR.NOT_FOUND";
  let ERR_UNAUTHORIZED = "ERR.UNAUTHORIZED";
  let ERR_RATE_LIMIT = "ERR.RATE_LIMIT";
  let ERR_INSUFFICIENT_FUNDS = "ERR.INSUFFICIENT_FUNDS";
  let ERR_INSUFFICIENT_CYCLES = "ERR.INSUFFICIENT_CYCLES";
  let ERR_BAD_FEE = "ERR.BAD_FEE";
  let ERR_TEMP_UNAVAILABLE = "ERR.TEMPORARILY_UNAVAILABLE";
  let ERR_PAUSED = "ERR.PAUSED";
  let ERR_NOT_EXPIRED = "ERR.NOT_EXPIRED";
  let ERR_ALREADY_INITIALIZED = "ERR.ALREADY_INITIALIZED";
  let ERR_LEDGER_GENERIC = "ERR.LEDGER_GENERIC";

  // Rate limiting
  // =============
  private type Rate = { window_start : Nat64; count : Nat32 };

  // ======================
  // Cycle budget breakdown
  // ======================
  // Factory        7.0T
  // Router         1.2T
  // Noticeboard    0.3T
  // Registry       0.2T
  // Crypto         1.2T
  // Website        0.1T
  // ----------------------
  // Total         10.0T
  // ======================

  var cfg : Config = {
    policy_ver = 1;
    hash_alg = "blake2s-256";
    deposit_fee_bps = 50;
    spawn_cycles_target = 7_000_000_000_000;
    crypto_cycles_per_tx = 1_200_000_000_000;
    noticeboard_cycles_per_tx = 300_000_000_000;
    registry_cycles_per_tx = 200_000_000_000;
    size_buckets = [1024 : Nat32, 2048, 4096, 8192];
    ttl_secs = 259_200;
    code_hashes = { i1 = Blob.fromArray([]); i2 = Blob.fromArray([]); witness = Blob.fromArray([]) };
    factory = Principal.fromText("aaaaa-aa");
    noticeboard = Principal.fromText("aaaaa-aa");
    crypto = Principal.fromText("aaaaa-aa");
    registry = Principal.fromText("aaaaa-aa");
    fee_accounts = {
        treasury = { owner = Principal.fromText("aaaaa-aa"); subaccount = null };
        buffer   = { owner = Principal.fromText("aaaaa-aa"); subaccount = null };
    };
    rate = { window_secs = 10_000_000_000; max_calls_per_principal = 20 };
    cmc = Principal.fromText("aaaaa-aa");
    treasury_fee_subs = [];
    treasury_remainder_sub = Blob.fromArray([]);
  };

  // Internal parameters
  // CAPITALIZED
  // ===================
  let ROUTER_CYCLES_PER_TX : Nat = 1_200_000_000_000;
  let WEBSITE_CYCLES_PER_TX : Nat = 100_000_000_000;
  let WEBSITE_CANISTER : Principal = Principal.fromText("tuaah-oaaaa-aaaai-atxdq-cai");

  // Pool recycling constants
  // ========================
  let RECYCLE_INTERVAL : Nat = 3;
  let ROUTER_CYCLES_TARGET : Nat = 20_000_000_000_000;
  var seal_count : Nat = 0;
  var pool_claims : Nat = 0;

  // Pool sweep threshold (1 ICP)
  // ============================
  let POOL_SWEEP_THRESHOLD : Nat = 100_000_000;

  // CMC rate cache
  // ==============
  var cached_cmc_rate : Nat = 0;
  var cmc_rate_ts : Nat64 = 0;
  let CMC_RATE_TTL : Nat64 = 30_000_000_000;

  // ============================================
  // Privacy denomination constants
  // --------------------------------------------
  // Tiered structure for cascading decomposition
  // with zero leakage by construction
  //
  // Any amount 1-2000 ICP decomposes exactly
  // into LARGE + HUNDREDS + TENS + UNITS
  // with no non-denomination remainders
  // ============================================

  // Conversion constant
  // -------------------
  let E8S_PER_ICP : Nat = 100_000_000;

  // Tier 1
  // Large anchors (consume bulk)
  // ----------------------------
  let DENOM_LARGE : [Nat] = [
    150_000_000_000,  // 1500 ICP
    100_000_000_000   // 1000 ICP
  ];

  // Tier 2
  // Hundreds (100-900)
  // ------------------
  let DENOM_HUNDREDS : [Nat] = [
    90_000_000_000,   // 900 ICP
    80_000_000_000,   // 800 ICP
    70_000_000_000,   // 700 ICP
    60_000_000_000,   // 600 ICP
    50_000_000_000,   // 500 ICP
    40_000_000_000,   // 400 ICP
    30_000_000_000,   // 300 ICP
    20_000_000_000,   // 200 ICP
    10_000_000_000    // 100 ICP
  ];

  // Tier 3
  // Tens (10-90)
  // ------------
  let DENOM_TENS : [Nat] = [
    9_000_000_000,    // 90 ICP
    8_000_000_000,    // 80 ICP
    7_000_000_000,    // 70 ICP
    6_000_000_000,    // 60 ICP
    5_000_000_000,    // 50 ICP
    4_000_000_000,    // 40 ICP
    3_000_000_000,    // 30 ICP
    2_000_000_000,    // 20 ICP
    1_000_000_000     // 10 ICP
  ];

  // Tier 4
  // Units (1-9)
  // -----------
  let DENOM_UNITS : [Nat] = [
    900_000_000,      // 9 ICP
    800_000_000,      // 8 ICP
    700_000_000,      // 7 ICP
    600_000_000,      // 6 ICP
    500_000_000,      // 5 ICP
    400_000_000,      // 4 ICP
    300_000_000,      // 3 ICP
    200_000_000,      // 2 ICP
    100_000_000       // 1 ICP
  ];

  // Maximum transfers 
  // per seal
  // -----------------
  let MAX_POOL_TRANSFERS : Nat = 5;

  // 2 ICP minimum for 
  // denomination splitting
  // ----------------------
  let MIN_DENOMINATION_THRESHOLD : Nat = 200_000_000;

  // Secret for cryptographic 
  // deposit_id transformation
  // =========================
  var router_secret : ?Blob = null;

  private func ensure_secret() : async () {
    if (router_secret != null or initializing_secret) return;
    initializing_secret := true;
    try {
      let IC : actor { raw_rand : () -> async Blob } = actor("aaaaa-aa");
      let r = await IC.raw_rand();
      if (r.size() == 32) {
        switch (router_secret) {
          case null { router_secret := ?r };
          case (?_) {};
        };
      };
    } catch (_) {};
    initializing_secret := false;
  };

  // Derive withdrawal_id from 
  // deposit_id using HMAC
  // =========================
  private func deriveWithdrawalId(deposit_id : DepositId) : Blob {
    let secret = switch (router_secret) {
      case null { Prim.trap("Router secret not initialized") };
      case (?s) s;
    };
    // icpp:withdrawal
    // ---------------
    let domain : [Nat8] = [105, 99, 112, 112, 58, 119, 105, 116, 104, 100, 114, 97, 119, 97, 108];
    let key = Array.append<Nat8>(domain, Blob.toArray(secret));
    Blob.fromArray(Blake2s.keyedHash(key, Blob.toArray(deposit_id), 32))
  };

  // Shared liquidity 
  // pool subaccount
  // ================
  private func getMixerSub() : Blob {
    // mixer
    // -----
    let domain : [Nat8] = [109, 105, 120, 101, 114]; 
    let seed = Blob.toArray(Principal.toBlob(Principal.fromActor(Router))); 
    Blob.fromArray(Blake2s.keyedHash(domain, seed, 32))
  };

  // Fee buffer subaccount
  // (absorbs dust from pool snapping)
  // =================================
  private func getFeeBufferSub() : Blob {
    // icpp:feebuf
    // -----------
    let domain : [Nat8] = [105, 99, 112, 112, 58, 102, 101, 101, 98, 117, 102];
    let seed = Blob.toArray(Principal.toBlob(Principal.fromActor(Router)));
    Blob.fromArray(Blake2s.keyedHash(domain, seed, 32))
  };

  // State
  // =====
  var initializing_secret = false;
  var admins : [Principal] = [];
  var events : [Blob] = [];
  var paused : Bool = false;
  var next_seq : Nat = 0;
  var admin_initialized : Bool = false;
  var certified_hash : Blob = Blob.fromArray([]);
  transient var deposits = HashMap.HashMap<DepositId, Deposit>(128, Blob.equal, Blob.hash);
  transient var calls = HashMap.HashMap<Principal, Rate>(64, Principal.equal, Principal.hash);
  transient var locks = HashMap.HashMap<DepositId, ()>(16, Blob.equal, Blob.hash);

  // Subtract 10 seconds 
  // to handle clock skew
  // ====================
  private func now() : Nat64 {
    let timeNow = Nat64.fromIntWrap(Time.now());
    if (timeNow > 10_000_000_000) { timeNow - 10_000_000_000 } else { timeNow }
  };

  // Calculate total Bob commitments
  // ================================
  private func totalBobCommitments() : Nat { pool_claims };

  // Sweep excess 
  // pool to treasury
  // ================
  private func sweepPoolExcess() : async () {
    let mixer_sub = getMixerSub();
    let mixer_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?mixer_sub };
    let pool_balance = await balance_of(mixer_acct);
    let commitments = totalBobCommitments();
    let threshold = commitments + POOL_SWEEP_THRESHOLD;
    
    if (pool_balance <= threshold) return;
    
    let excess : Nat = pool_balance - threshold;
    let fee = await ledger_fee();
    
    if (excess <= fee) return;
    
    let sweep_amt : Nat = excess - fee;
    let treasury_acct : Account = { 
      owner = cfg.fee_accounts.treasury.owner; 
      subaccount = ?cfg.treasury_remainder_sub 
    };
    ignore await Ledger.icrc1_transfer({
      from_subaccount = ?mixer_sub;
      to = treasury_acct;
      amount = sweep_amt;
      fee = ?fee;
      memo = null;
      created_at_time = ?now();
    });
  };

  // Initialize 
  // Administrator 
  // =============
  public shared({ caller }) func initialize_admins(initial_admins : [Principal]) : async { #ok : (); #err : Text } {
    if (admin_initialized) return #err(ERR_ALREADY_INITIALIZED);
    if (initial_admins.size() == 0) return #err(ERR_NOT_FOUND);
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

  private func isAdmin(p : Principal) : Bool { for (a in admins.vals()) { if (a == p) return true }; false };

  // ID and subaccount 
  // derivation
  // =================
  private func depositId(payer : Account) : DepositId {
    next_seq += 1;
    let ctx = certified_hash;
    let domain : [Nat8] = [105, 99, 112, 112, 58, 105, 100];
    let msg1 = Array.append<Nat8>(Blob.toArray(ctx), Blob.toArray(Principal.toBlob(payer.owner)));
    let msg2 = Array.append<Nat8>(msg1, [Nat8.fromNat(next_seq % 256)]);
    Blob.fromArray(Blake2s.keyedHash(domain, msg2, 32))
  };

  private func deriveSub(id : DepositId, stage : Text) : Blob {
    let base : [Nat8] = [105, 99, 112, 112, 58, 115, 117, 98, 58];
    let stage_bytes = Blob.toArray(Text.encodeUtf8(stage));
    let domain = Array.append<Nat8>(base, stage_bytes);
    let msg = Array.append<Nat8>([Nat8.fromNat(Nat32.toNat(cfg.policy_ver))], Blob.toArray(id));
    Blob.fromArray(Blake2s.keyedHash(domain, msg, 32))
  };

  // Router internal secret
  // (not essential to be
  // cryptographically protected)
  // ============================
  private func deriveEntropy(id : DepositId) : [Nat8] {
    let secret = switch (router_secret) {
      case null { Prim.trap("Router secret not initialized") };
      case (?s) s;
    };
    let domain : [Nat8] = [105, 99, 112, 112, 58, 101, 110, 116, 114, 111, 112, 121];
    let key = Array.append<Nat8>(domain, Blob.toArray(secret));
    let hash = Blake2s.keyedHash(key, Blob.toArray(id), 32);
    [hash[0], hash[1], hash[2], hash[3]]
  };

  // Certification
  // =============
  private func ev(tag : Nat8) : () { 
    let s = events.size();
    if (s >= 2000) {
       let new_len = Nat.sub(s, 1);
       events := Array.tabulate<Blob>(new_len, func i = events[i+1]);
    };
    events := Array.append<Blob>(events, [ Blob.fromArray([tag]) ]); 
    certify() 
  };

  private func certify() : () {
    let tip = Nat8.fromNat(events.size() % 256);
    let ver = Nat8.fromNat(Nat32.toNat(cfg.policy_ver) % 256);
    // icpp:cfg
    // --------
    let domain : [Nat8] = [105, 99, 112, 112, 58, 99, 102, 103];
    certified_hash := Blob.fromArray(Blake2s.keyedHash(domain, [ver, tip], 32)); 
    Prim.setCertifiedData(certified_hash)
  };

  certify();

  // Rate limiting/pause
  // ===================
  private func requireNotPaused() : ?Text { if (paused) ?ERR_PAUSED else null };
  
  private func rate(caller : Principal) : ?Text {
    let t = now();
    switch (calls.get(caller)) {
      case null { calls.put(caller, { window_start = t; count = 1 }); null };
      case (?r) {
        if (t - r.window_start > cfg.rate.window_secs) { calls.put(caller, { window_start = t; count = 1 }); null }
        else if (r.count >= cfg.rate.max_calls_per_principal) ?ERR_RATE_LIMIT
        else { calls.put(caller, { r with count = r.count + 1 }); null }
      }
    }
  };

  // Administration
  // ==============
  public shared({ caller }) func set_admins(ns : [Principal]) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    admins := ns; ev(0x05); #ok(())
  };

  public shared({ caller }) func set_config(nc : Config) : async { #ok : (); #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    if (nc.deposit_fee_bps > 10_000) return #err(ERR_BAD_FEE);
    cfg := nc; ev(0x05); #ok(())
  };

  public shared({ caller }) func pause() : async { #ok : (); #err : Text } { 
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED); 
    paused := true; ev(0x06); #ok(()) 
  };

  public shared({ caller }) func unpause() : async { #ok : (); #err : Text } { 
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED); 
    paused := false; ev(0x07); #ok(()) 
  };

  // Admin emergency sweep
  // =====================
  public shared({ caller }) func admin_sweep(sub : Blob, to : Account, amount : Amount) : async { #ok : Nat; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    let fee = await ledger_fee();
    let res = await Ledger.icrc1_transfer({
      from_subaccount = ?sub;
      to;
      amount;
      fee = ?fee;
      memo = null;
      created_at_time = ?now();
    });
    switch (res) {
      case (#Ok idx) { #ok(idx) };
      case (#Err _) { #err(ERR_TEMP_UNAVAILABLE) };
    }
  };

  // Internal helpers 
  // (ledger)
  // ================
  private func ledger_fee() : async Amount { await Ledger.icrc1_fee() };

  private func balance_of(acct : Account) : async Amount {
    await Ledger.icrc1_balance_of(acct)
  };

  // Send 'amt' from the deposit subaccount to 
  // 'to' (paying ledger fee from sub/buffer)
  // =========================================
  private func pay_from_sub(from_sub : Blob, to : Account, amt : Amount) : async { #ok : Nat; #err : Text } {
    if (amt == 0) return #ok(0);
    let fee = await ledger_fee();
    let need = amt + fee;
    if (not (await ensureTopUpIfNeeded(from_sub, need))) return #err(ERR_INSUFFICIENT_FUNDS);
    let res = await Ledger.icrc1_transfer({
      from_subaccount = ?from_sub; to; amount = amt; fee = ?fee; memo = null; created_at_time = ?now()
    });
    switch (res) { 
      case (#Ok tx_id) #ok(tx_id); 
      case (#Err _e) #err(ERR_LEDGER_GENERIC)
    }
  };

  // Ensure from_sub has at least 'need' 
  // ICP (if short pull from buffer)
  // ===================================
  private func ensureTopUpIfNeeded(from_sub : Blob, need : Amount) : async Bool {
    let acct_from : Account = { owner = Principal.fromActor(Router); subaccount = ?from_sub };
    let bal = await balance_of(acct_from);
    if (bal >= need) return true;
    let deficit : Nat = need - bal;
    let fee = await ledger_fee();

    // We must send 'deficit' from buffer to from_sub 
    // and pay fee for that transfer from buffer
    // If buffer has insufficient funds -> fail
    // ----------------------------------------------
    let fee_buf_sub = getFeeBufferSub();
    let fee_buf_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?fee_buf_sub };
    let fee_buf_bal = await balance_of(fee_buf_acct);
    if (fee_buf_bal < deficit + fee) return false;
    
    let res = await Ledger.icrc1_transfer({
      from_subaccount = ?fee_buf_sub;
      to = acct_from; amount = deficit; fee = ?fee; memo = null; created_at_time = ?now();
    });
    switch (res) { case (#Ok _) true; case (#Err _) false }
  };

  // Convert ICP to 
  // cycles via CMC
  // ==============
  private func convertToCycles(from_sub : Blob, amount_e8s : Amount) : async { #Ok : Nat; #Err : Text } {
    if (amount_e8s == 0) return #Err("convertToCycles: amount_e8s=0");
    
    let fee = await ledger_fee();
    let p_bytes = Blob.toArray(Principal.toBlob(Principal.fromActor(Router)));
    let len = p_bytes.size();
    let cmc_subaccount_bytes = Array.tabulate<Nat8>(32, func(i : Nat) : Nat8 {
      if (i == 0) { Nat8.fromNat(len) }
      else if (i <= len) { p_bytes[i - 1] }
      else { 0 }
    });

    let cmc_subaccount = Blob.fromArray(cmc_subaccount_bytes);
    let cmc_account : Account = { owner = cfg.cmc; subaccount = ?cmc_subaccount };
    let top_up_memo = Blob.fromArray([0x54, 0x50, 0x55, 0x50, 0x00, 0x00, 0x00, 0x00]);
    let transfer_res = await Ledger.icrc1_transfer({
      from_subaccount = ?from_sub;
      to = cmc_account;
      amount = amount_e8s;
      fee = ?fee;
      memo = ?top_up_memo;
      created_at_time = ?now();
    });

    let block_index : Nat = switch (transfer_res) {
      case (#Ok idx) idx;
      case (#Err e) return #Err(switch (e) {
        case (#BadFee _) ERR_BAD_FEE;
        case (#BadBurn _) ERR_BAD_FEE;
        case (#InsufficientFunds _) ERR_INSUFFICIENT_FUNDS;
        case (#TemporarilyUnavailable) ERR_TEMP_UNAVAILABLE;
        case (#TooOld) ERR_EXPIRED;
        case (#CreatedInFuture _) ERR_INVALID_CTX;
        case (#Duplicate _) ERR_REPLAY;
        case (#GenericError _) ERR_LEDGER_GENERIC;
      });
    };

    let CMC = mkCMC(cfg.cmc);
    let notify_res = await CMC.notify_top_up({
      canister_id = Principal.fromActor(Router);
      block_index = Nat64.fromNat(block_index);
    });
    
    switch (notify_res) {
      case (#Ok cycles) #Ok(cycles);
      case (#Err e) #Err(switch (e) {
        case (#Refunded _) ERR_CMC_FAIL;
        case (#InvalidTransaction _) ERR_INVALID_CTX;
        case (#Other _) ERR_CMC_FAIL;
        case (#Processing) ERR_TEMP_UNAVAILABLE;
        case (#TransactionTooOld _) ERR_EXPIRED;
      });
    }
  };

  // Get cycles per ICP 
  // in e8s from CMC
  // ==================
  private func get_cmc_rate() : async Nat {
    let t = now();
    if (cached_cmc_rate > 0 and t > cmc_rate_ts and (t - cmc_rate_ts) < CMC_RATE_TTL) {
      return cached_cmc_rate;
    };
    let CMC : actor {
      get_icp_xdr_conversion_rate : () -> async { data : { xdr_permyriad_per_icp : Nat64 } };
    } = actor(Principal.toText(cfg.cmc));
    try {
      let rate_result = await CMC.get_icp_xdr_conversion_rate();
      let fresh = Nat64.toNat(rate_result.data.xdr_permyriad_per_icp);
      if (fresh > 0) {
        cached_cmc_rate := fresh;
        cmc_rate_ts := t;
      };
      fresh
    } catch (_) { 0 }
  };

  // Sweep remainder 
  // to treasury
  // ===============
  private func sweepLeftoverToTreasury(deposit_id : DepositId, from_sub : Blob) : async () {
    let fee = await ledger_fee();
    let acct_from : Account = { owner = Principal.fromActor(Router); subaccount = ?from_sub };
    let bal = await balance_of(acct_from);
    if (bal <= fee) return ();
    let amt : Nat = bal - fee;
    let target_sub = selectTreasurySubForDeposit(deposit_id);
    
    let treasury_target : Account = { 
      owner = cfg.fee_accounts.treasury.owner; 
      subaccount = ?target_sub 
    };
    
    ignore await Ledger.icrc1_transfer({
      from_subaccount = acct_from.subaccount;
      to = treasury_target;
      amount = amt;
      fee = ?fee;
      memo = null;
      created_at_time = ?now();
    })
  };

  // Select treasury 
  // subaccount
  // ===============
  private func selectTreasurySubForDeposit(deposit_id : DepositId) : Blob {
    let n = cfg.treasury_fee_subs.size();
    if (n == 0) return cfg.treasury_remainder_sub;
    let id_bytes = Blob.toArray(deposit_id);
    let idx = if (id_bytes.size() > 0) { Nat8.toNat(id_bytes[0]) % n } else { 0 };
    cfg.treasury_fee_subs[idx]
  };

  // Get deposit 
  // fee for client
  // ==============
  public query func get_deposit_fee_bps() : async Nat16 { cfg.deposit_fee_bps };

  // Get spawn 
  // cycles target
  // =============
  public query func get_spawn_cycles() : async Nat {
    let base = cfg.spawn_cycles_target + cfg.crypto_cycles_per_tx 
               + cfg.noticeboard_cycles_per_tx + cfg.registry_cycles_per_tx 
               + ROUTER_CYCLES_PER_TX + WEBSITE_CYCLES_PER_TX;
    (base * 11) / 10
  };

  // Get treasury info
  // =================
  public query func get_treasury_info() : async {
    treasury_owner : Principal;
    fee_subs : [Blob];
    remainder_sub : Blob;
  } {
    {
      treasury_owner = cfg.fee_accounts.treasury.owner;
      fee_subs = cfg.treasury_fee_subs;
      remainder_sub = cfg.treasury_remainder_sub;
    }
  };

  // Get operational status
  // ======================
  public query func get_operational_status() : async { cycles_balance : Nat; spawns_available : Nat; recommended_delay_ms : Nat } {
    let balance = Cycles.balance();
    let min_per_spawn : Nat = 7_000_000_000_000;
    let spawns = if (min_per_spawn > 0) { balance / min_per_spawn } else { 0 };
    let delay : Nat = if (balance > 150_000_000_000_000) { 5_000 }
                else if (balance > 100_000_000_000_000) { 10_000 }
                else if (balance > 50_000_000_000_000) { 15_000 }
                else if (balance > 20_000_000_000_000) { 30_000 }
                else { 60_000 };
    { cycles_balance = balance; spawns_available = spawns; recommended_delay_ms = delay }
  };

  // Allocate deposit
  // ================
  public shared({ caller }) func deposit_alloc(args : { recipient_hint_pref : Nat32 }) : async {
    #ok : { deposit_id : DepositId; router_account : Account; treasury_account : Account; spawn_fee_estimate : Amount; memo : ?Blob }; 
    #err : Text 
  } {
    await ensure_secret();
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };
    
    let payer : Account = { owner = caller; subaccount = null };
    let id = depositId(payer);
    let created = now();
    let expires = created + (cfg.ttl_secs * 1_000_000_000);
    let deposit_sub = deriveSub(id, "deposit");
    let router_account : Account = { owner = Principal.fromActor(Router); subaccount = ?deposit_sub };
    let treasury_sub = selectTreasurySubForDeposit(id);
    let treasury_account : Account = { owner = cfg.fee_accounts.treasury.owner; subaccount = ?treasury_sub };
    
    let bucket : Nat32 = switch (Array.find<Nat32>(cfg.size_buckets, func b = (Nat32.toNat(b) >= Nat32.toNat(args.recipient_hint_pref)))) { 
      case (?b) b; case null cfg.size_buckets[0] 
    };
    
    let idb = Blob.toArray(id); 
    let memo = ?Blob.fromArray(Array.tabulate<Nat8>(Nat.min(8, idb.size()), func i = idb[i]));
    let cycles_per_e8s = await get_cmc_rate();
    if (cycles_per_e8s == 0) return #err(ERR_CMC_FAIL);
    let ledger_fee_val = 10_000;

    let total_cycles = cfg.spawn_cycles_target + cfg.crypto_cycles_per_tx 
                       + cfg.noticeboard_cycles_per_tx + cfg.registry_cycles_per_tx 
                       + ROUTER_CYCLES_PER_TX + WEBSITE_CYCLES_PER_TX;
    
    let buffered_cycles = (total_cycles * 11) / 10;
    let spawn_fee_estimate : Nat = if (cycles_per_e8s > 0) {
      (buffered_cycles + (cycles_per_e8s - 1)) / cycles_per_e8s + (ledger_fee_val * 2)
    } else { 0 };
    
    deposits.put(id, {
      payer; recipient_hint_pref = args.recipient_hint_pref; amount = 0; user_fee = 0; spawn_fee = 0; bucket;
      created_at = created; expires_at = expires; state = #Allocated;
      i1 = Principal.fromText("aaaaa-aa"); i2 = Principal.fromText("aaaaa-aa");
      witness = Principal.fromText("aaaaa-aa"); storage = [];
    });
    
    #ok({ deposit_id = id; router_account; treasury_account; spawn_fee_estimate; memo })
  };

  // Prepare Alice deposit
  // ---------------------
  public shared({ caller }) func deposit_prepare(deposit_id : DepositId, spawn_fee_e8s : Nat) : async {
    #ok : { i1_id : Principal; i2_id : Principal; storage_ids : [Principal]; actual_spawn_fee : Amount };
    #err : Text
  } {
    await ensure_secret();
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    switch (deposits.get(deposit_id)) {
      case null { #err(ERR_NOT_FOUND) };
      case (?d) {
        if (d.state != #Allocated) return #err(ERR_REPLAY);
        if (caller != d.payer.owner) return #err(ERR_UNAUTHORIZED);
        if (locks.get(deposit_id) != null) return #err(ERR_TEMP_UNAVAILABLE);
        locks.put(deposit_id, ());
        
        func unlock(msg : Text) : { #ok : { i1_id : Principal; i2_id : Principal; storage_ids : [Principal]; actual_spawn_fee : Amount }; #err : Text } {
           ignore locks.remove(deposit_id); #err(msg)
        };
        let deposit_sub = deriveSub(deposit_id, "deposit");
        let deposit_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?deposit_sub };
        let balance = await balance_of(deposit_acct);
        let fee = await ledger_fee();
        let safety_margin = fee * 5;
        let min_required = spawn_fee_e8s + safety_margin;
        
        if (balance < min_required) return unlock(ERR_INSUFFICIENT_FUNDS);
        
        let cycles_per_e8s = await get_cmc_rate();
        if (cycles_per_e8s == 0) return unlock(ERR_CMC_FAIL);

        // Derive shared entropy to calculate 
        // the algorithmic burn/subsidy split
        // ----------------------------------
        let r = deriveEntropy(deposit_id);
        let to_pool_pct = calculateToPoolPct(r[0], r[1]);
        
        let topups_needed = cfg.crypto_cycles_per_tx + cfg.noticeboard_cycles_per_tx 
                            + cfg.registry_cycles_per_tx + WEBSITE_CYCLES_PER_TX;
        let total_cycles_needed = cfg.spawn_cycles_target + topups_needed;

        // Calculate the burn portion (total infrastructure less subsidy)
        // -> converted to cycles immediately to stabilize the 
        //    Router balance
        // -> ROUTER_CYCLES_PER_TX are PROTECTED
        // --------------------------------------------------------------
        let burn_pct : Nat = if (100 > to_pool_pct) { 100 - to_pool_pct } else { 0 };
        let burn_cycles = ((total_cycles_needed * burn_pct) / 100) + ROUTER_CYCLES_PER_TX;
        
        func ceilDiv(a : Nat, b : Nat) : Nat { if (b == 0) return 0; (a + (b - 1)) / b };

        // Calculate how much ICP Router needs to absorb
        // (Router absorbs ROUTER_CYCLES worth of ICP 
        // to replenish itself)
        // ---------------------------------------------
        let burn_e8s = ceilDiv(burn_cycles, cycles_per_e8s);
        
        // Convert router_absorb from deposit to cycles
        // The rest (Q) stays as ICP for T-component in seal_push
        // ------------------------------------------------------
        let available : Nat = if (balance > safety_margin) { balance - safety_margin } else { 0 };
        let convert_amt : Nat = Nat.min(burn_e8s, available);
        
        if (convert_amt == 0) return unlock(ERR_INSUFFICIENT_FUNDS);
        let cycles_res = await convertToCycles(deposit_sub, convert_amt);
        switch (cycles_res) {
          case (#Err _e) return unlock(ERR_CMC_FAIL);
          case (#Ok _) {};
        };

        // Pre-check cycles balance to avoid trap
        // ---------------------------------------
        let required_cycles = cfg.spawn_cycles_target + cfg.crypto_cycles_per_tx 
                              + cfg.noticeboard_cycles_per_tx + cfg.registry_cycles_per_tx 
                              + ROUTER_CYCLES_PER_TX + WEBSITE_CYCLES_PER_TX;
        if (Cycles.balance() < required_cycles) return unlock(ERR_INSUFFICIENT_CYCLES);
        
        // Infrastructure spending (enforced funding)
        // -> if the Router balance is insufficient here 
        // the call will trap
        // ---------------------------------------------
        let Factory = mkFactory(cfg.factory);
        let spawn_result = await (with cycles = cfg.spawn_cycles_target) Factory.spawn_triplet(
            cfg.ttl_secs, cfg.noticeboard, Principal.fromActor(Router), cfg.crypto
        );
        
        let spawned = switch (spawn_result) {
          case (#err e) return unlock("ERR.OTHER:" # e);
          case (#ok s) s;
        };

        // Top-ups (consolidated actor 
        // and enforced funding)
        // ----------------------------
        let IC : actor { deposit_cycles : ({ canister_id : Principal }) -> async () } = actor("aaaaa-aa");

        if (cfg.crypto_cycles_per_tx > 0) {
          try {
            await (with cycles = cfg.crypto_cycles_per_tx) IC.deposit_cycles({ canister_id = cfg.crypto });
          } catch (_) {};
        };

        if (cfg.noticeboard_cycles_per_tx > 0) {
          try {
            await (with cycles = cfg.noticeboard_cycles_per_tx) IC.deposit_cycles({ canister_id = cfg.noticeboard });
          } catch (_) {};
        };

        if (cfg.registry_cycles_per_tx > 0) {
          try {
            await (with cycles = cfg.registry_cycles_per_tx) IC.deposit_cycles({ canister_id = cfg.registry });
          } catch (_) {};
        };

        if (WEBSITE_CYCLES_PER_TX > 0) {
          try {
            await (with cycles = WEBSITE_CYCLES_PER_TX) IC.deposit_cycles({ canister_id = WEBSITE_CANISTER });
          } catch (_) {};
        };
        
        // Update state
        // ------------
        deposits.put(deposit_id, { d with 
          spawn_fee = convert_amt + fee; 
          state = #Created;
          i1 = spawned.i1; 
          i2 = spawned.i2; 
          witness = spawned.witness; 
          storage = spawned.storage 
        });

        ignore locks.remove(deposit_id);
        ev(0x01);
        
        #ok({ 
          i1_id = spawned.i1; 
          i2_id = spawned.i2; 
          storage_ids = spawned.storage; 
          actual_spawn_fee = convert_amt 
        })
      }
    }
  };

  // T-component 
  // calculation
  // ===========
  private func calculateToPoolPct(r0 : Nat8, r1 : Nat8) : Nat {
    let t2 = 5 + (Nat8.toNat(r0) % 16);
    let t3 = 5 + (Nat8.toNat(r1) % 16);
    let t23 = t2 + t3;
    if (t23 <= 25) { t23 } else { 
      let scaled = 125 + (5 * t23); 
      assert(10 != 0);
      scaled / 10 
    }
  };

  // =========================================
  // Cascading Randomized Decomposition
  // =========================================
  // Decomposes pool_in_e8s into 1-5 transfers
  // using tiered denomination selection
  // (every transfer is a denomination)
  // =========================================
  private func decomposeCascading(pool_in_e8s : Nat, entropy : [Nat8]) : [Nat] {
    // Edge case
    // -> zero amount
    // --------------
    if (pool_in_e8s == 0) { return [] };

    // Below threshold 
    // -> single transfer
    // ------------------
    if (pool_in_e8s < MIN_DENOMINATION_THRESHOLD) {
        return [pool_in_e8s];
    };

    var result : [Nat] = [];
    var remaining_e8s : Nat = pool_in_e8s;

    // Pick 1 -> random from 
    // all denoms ≤ floor(remaining/2)
    // -------------------------------
    if (remaining_e8s >= 2 * E8S_PER_ICP and result.size() < MAX_POOL_TRANSFERS) {
      let half_e8s = remaining_e8s / 2;

      // Build valid set 
      // from all tiers
      // ---------------
      var valid : [Nat] = [];
      
      for (d in DENOM_LARGE.vals()) { 
        if (d <= half_e8s) { 
          valid := Array.append(valid, [d]);
        };
      };

      for (d in DENOM_HUNDREDS.vals()) { 
        if (d <= half_e8s) {
          valid := Array.append(valid, [d]);
        };
      };

      for (d in DENOM_TENS.vals()) { 
        if (d <= half_e8s) {
          valid := Array.append(valid, [d]);
        };
      };

      for (d in DENOM_UNITS.vals()) { 
        if (d <= half_e8s) {
          valid := Array.append(valid, [d]);
        };
      };

      if (valid.size() > 0) {
        let idx = Nat8.toNat(entropy[0]) % valid.size();
        let picked = valid[idx];

        result := Array.append(result, [picked]);
        remaining_e8s -= picked;
      };
    };

    // Picks 2-5 -> greedy 
    // descending through all tiers
    // ----------------------------
    for (denom in DENOM_LARGE.vals()) {
      while (remaining_e8s >= denom and result.size() < MAX_POOL_TRANSFERS) {
        result := Array.append(result, [denom]);
        remaining_e8s -= denom;
      };
    };

    for (denom in DENOM_HUNDREDS.vals()) {
      while (remaining_e8s >= denom and result.size() < MAX_POOL_TRANSFERS) {
        result := Array.append(result, [denom]);
        remaining_e8s -= denom;
      };
    };

    for (denom in DENOM_TENS.vals()) {
      while (remaining_e8s >= denom and result.size() < MAX_POOL_TRANSFERS) {
        result := Array.append(result, [denom]);
        remaining_e8s -= denom;
      };
    };
    
    for (denom in DENOM_UNITS.vals()) {
      while (remaining_e8s >= denom and result.size() < MAX_POOL_TRANSFERS) {
        result := Array.append(result, [denom]);
        remaining_e8s -= denom;
      };
    };

    // Handle sub-ICP dust (add 
    // to last transfer if exists)
    // ---------------------------
    if (remaining_e8s > 0 and result.size() > 0) {
      let len = result.size();
      result := Array.tabulate<Nat>(len, func(i : Nat) : Nat {
        if (i + 1 == len) { result[i] + remaining_e8s } else { result[i] }
      });
    } else if (remaining_e8s > 0) {
      // Dust is the 
      // only component
      // --------------
      result := [remaining_e8s];
    };

    result
  };

  // Pool recycling
  // ==============
  private func maybeRecycleToRouter(rate_val : Nat) : async () {
    let router_balance = Cycles.balance();
    if (router_balance >= ROUTER_CYCLES_TARGET) return;

    let mixer_sub = getMixerSub();
    let mixer_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?mixer_sub };
    let pool_balance = await balance_of(mixer_acct);
    let wedge : Nat = if (pool_balance > pool_claims) { pool_balance - pool_claims } else { 0 };
    if (wedge == 0) return;
    
    let wedge_cycles : Nat = if (rate_val > 0) { (wedge * rate_val) } else { 0 };
    if (wedge_cycles == 0) return;
    
    let shortfall : Nat = if (ROUTER_CYCLES_TARGET > router_balance) { ROUTER_CYCLES_TARGET - router_balance } else { 0 };
    let recycle_cycles = Nat.min(wedge_cycles, shortfall);
    if (recycle_cycles == 0) return;
    
    let recycle_e8s : Nat = if (rate_val > 0) { (recycle_cycles + (rate_val - 1)) / rate_val } else { 0 };
    if (recycle_e8s == 0) return;
    
    let safe_recycle_e8s = Nat.min(recycle_e8s, wedge);
    if (safe_recycle_e8s == 0) return;

    ignore await convertToCycles(mixer_sub, safe_recycle_e8s);
  };

  // Seal deposit
  // ============
  public shared({ caller }) func seal_push(id : DepositId) : async { #ok : (); #err : Text } {
    // Initial guards
    // --------------
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    // Concurrency lock
    // ----------------
    if (locks.get(id) != null) return #err(ERR_TEMP_UNAVAILABLE);
    locks.put(id, ());

    // Ensure the lock is 
    // ALWAYS released on return
    // -------------------------
    func unlockWith<T>(res : T) : T {
      ignore locks.remove(id);
      res
    };

    // State Validation
    // ----------------
    let d = switch (deposits.get(id)) {
      case null { return unlockWith(#err(ERR_NOT_FOUND)) };
      case (?d) d;
    };

    if (d.state != #Created) return unlockWith(#err(ERR_REPLAY));
    if (caller != d.payer.owner) return unlockWith(#err(ERR_UNAUTHORIZED));

    // Execution
    // ---------
    try {
      let deposit_sub = deriveSub(id, "deposit");
      let mixer_sub = getMixerSub();
      let deposit_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?deposit_sub };
      let mixer_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?mixer_sub };
      
      let bal = await balance_of(deposit_acct);
      let fee = await ledger_fee();
      let total_fees = fee * 10;
      
      // Reconstruct original balance
      // ----------------------------
      let original_bal = bal + d.spawn_fee;
      if (original_bal <= total_fees) return unlockWith(#err(ERR_INSUFFICIENT_FUNDS));

      // bal = X + Q (where Q = Z - router_absorb 
      // with remaining after deposit_prepare)
      // -----------------------------------------
      let cycles_per_e8s = await get_cmc_rate();
      let total_cycles = cfg.spawn_cycles_target + cfg.crypto_cycles_per_tx + cfg.noticeboard_cycles_per_tx 
                         + cfg.registry_cycles_per_tx + ROUTER_CYCLES_PER_TX + WEBSITE_CYCLES_PER_TX;
      let zz_e8s : Nat = if (cycles_per_e8s > 0) { (total_cycles * 11) / (cycles_per_e8s * 10) } else { 0 };

      let x_e8s : Nat = if (original_bal > zz_e8s + total_fees) { original_bal - zz_e8s - total_fees } else { 0 };
      let q_e8s : Nat = if (original_bal > x_e8s + total_fees) { original_bal - x_e8s - total_fees } else { 0 };

      // Use the shared 
      // internal entropy
      // ----------------
      let r = deriveEntropy(id);

      // T-component applies to Q
      // ------------------------
      let to_pool_pct = calculateToPoolPct(r[0], r[1]);
      let to_pool_e8s : Nat = (q_e8s * to_pool_pct) / 100;
      let to_cycles_e8s : Nat = if (q_e8s > to_pool_e8s) { q_e8s - to_pool_e8s } else { 0 };

      // Bob's claim (whole ICP
      // and centered rounding)
      // ----------------------
      let x_e8s_whole : Nat = ((x_e8s + 50_000_000) / 100_000_000) * 100_000_000;

      // Manage dust
      // -----------
      let (x_dust, borrow) : (Nat, Nat) = 
        if (x_e8s >= x_e8s_whole) { (x_e8s - x_e8s_whole, 0) } 
        else { (0, x_e8s_whole - x_e8s) };

      // Pool receives 
      // Bob's claim
      // -------------
      let pool_in_e8s : Nat = x_e8s_whole;

      // Fee buffer allocation:
      // - x_dust: fractional remainder from rounding down
      // - subsidy_residue: leftover after covering borrow
      // - 2*fee: withdrawal pre-funding (withdrawal fee + top-up transfer fee)
      // ----------------------------------------------------------------------
      let subsidy_residue : Nat = if (to_pool_e8s >= borrow) { to_pool_e8s - borrow } else { 0 };
      let fee_buffer_amount : Nat = x_dust + subsidy_residue + (2 * fee);

      // Bob's claim
      // -----------
      pool_claims += x_e8s_whole;

      // Send dust + subsidy + withdrawal pre-funding to fee buffer
      // (always executes -> fee_buffer_amount >= 2*fee)
      // ----------------------------------------------------------
      let fee_buf_sub = getFeeBufferSub();
      let fee_buf_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?fee_buf_sub };
      ignore await Ledger.icrc1_transfer({
        from_subaccount = ?deposit_sub;
        to = fee_buf_acct;
        amount = fee_buffer_amount;
        fee = ?fee;
        memo = null;
        created_at_time = ?now()
      });

      // Denomination-based split for privacy
      // using cascading decomposition
      // ------------------------------------
      if (pool_in_e8s < MIN_DENOMINATION_THRESHOLD) {
        // Legacy path for tiny amounts (< 2 ICP)
        // Single transfer, no splitting needed
        // -------------------------------------
        if (pool_in_e8s > 0) {
          let res = await Ledger.icrc1_transfer({ 
            from_subaccount = ?deposit_sub; 
            to = mixer_acct; 
            amount = pool_in_e8s; 
            fee = ?fee; 
            memo = null; 
            created_at_time = ?now() 
          });
          switch (res) {
            case (#Err(_)) return unlockWith(#err(ERR_TEMP_UNAVAILABLE));
            case (#Ok(_)) {};
          };
        };
      } else {
        // Cascading decomposition (>= 2 ICP)
        // Returns 1-5 transfer amounts, all denominations
        // -----------------------------------------------
        let transfers = decomposeCascading(pool_in_e8s, r);

        // Execute transfers sequentially
        // ------------------------------
        for (amt in transfers.vals()) {
          if (amt > 0) {
            let res = await Ledger.icrc1_transfer({ 
              from_subaccount = ?deposit_sub; 
              to = mixer_acct; 
              amount = amt; 
              fee = ?fee; 
              memo = null; 
              created_at_time = ?now() 
            });
            switch (res) {
              case (#Err(_)) return unlockWith(#err(ERR_TEMP_UNAVAILABLE));
              case (#Ok(_)) {};
            };
          };
        };
      };

      // to_cycles conversion here is now just for 
      // remaining dust as prepare took the bulk
      // -----------------------------------------
      if (to_cycles_e8s > d.spawn_fee + fee) {
        let convert_amt : Nat = to_cycles_e8s - d.spawn_fee - fee;
        if (convert_amt > 0) { ignore await convertToCycles(deposit_sub, convert_amt) };
      };

      // State update
      // ------------
      deposits.put(id, { d with state = #Sealed });
      ev(0x02);
      seal_count += 1;

      // Maintenance
      // -----------
      if (seal_count % RECYCLE_INTERVAL == 0 and cycles_per_e8s > 0) { 
        await maybeRecycleToRouter(cycles_per_e8s) 
      };

      try { await sweepLeftoverToTreasury(id, deposit_sub) } catch (_) {};
      try { await sweepPoolExcess() } catch (_) {};

      // Recycle 80% of fee buffer 
      // excess into pool if > 1 ICP
      // ---------------------------
      if (seal_count % RECYCLE_INTERVAL == 0) {
        let fee_buf_sub = getFeeBufferSub();
        let fee_buf_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?fee_buf_sub };
        let fee_buf_bal = await balance_of(fee_buf_acct);
        let reserve : Nat = 10_000_000;
        if (fee_buf_bal > reserve + fee) {
          let available : Nat = fee_buf_bal - reserve;
          let sweep_amt : Nat = (available * 80) / 100;
          if (sweep_amt >= 100_000_000) {
            ignore await Ledger.icrc1_transfer({
              from_subaccount = ?fee_buf_sub;
              to = mixer_acct;
              amount = (sweep_amt / 100_000_000) * 100_000_000;
              fee = ?fee;
              memo = null;
              created_at_time = ?now()
            });
          };
        };
      };
      
      return unlockWith(#ok(()));
    
    } catch (err) {
      return unlockWith(#err("ERR.PANIC:" # Prim.errorMessage(err)));
    };
  };

  // Finalize
  // ========
  public shared({ caller }) func finalize(id : DepositId, _capsule : Blob, _capability_or_proof : Blob, recipient : Account, amount : Amount)
    : async { #ok : { tx_id : Nat; fees_charged : Amount }; #err : Text } {
    
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };

    // Prevent double-spend 
    // and reclaim-race
    // --------------------
    if (locks.get(id) != null) return #err(ERR_TEMP_UNAVAILABLE);

    // Check state
    // -----------
    switch (deposits.get(id)) {
      case null { #err(ERR_NOT_FOUND) };
      case (?d) {
        if (caller != d.i2) return #err(ERR_UNAUTHORIZED);
        if (d.state != #Sealed) return #err(ERR_REPLAY);
        if (now() > d.expires_at) return #err(ERR_EXPIRED);
    
        // Acquire lock
        // ------------
        locks.put(id, ());

        // Execute
        // -------
        let fee = await ledger_fee();
        let mixer_sub = getMixerSub();
        let fee_buf_sub = getFeeBufferSub();
        let mixer_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?mixer_sub };
        
        // Pre-load fee into mixer from fee_buffer
        // (seal pre-funded 2*fee for this)
        // ---------------------------------------
        let fee_preload = await Ledger.icrc1_transfer({
          from_subaccount = ?fee_buf_sub;
          to = mixer_acct;
          amount = fee;
          fee = ?fee;
          memo = null;
          created_at_time = ?now()
        });
        
        switch (fee_preload) {
          case (#Err _) {
            ignore locks.remove(id);
            return #err(ERR_INSUFFICIENT_FUNDS);
          };
          case (#Ok _) {};
        };

        // Verify mixer has sufficient funds
        // (covers rounding shortfall edge cases)
        // --------------------------------------
        let mixer_bal = await balance_of(mixer_acct);
        let required = amount + fee;
        if (mixer_bal < required) {
          let shortfall : Nat = if (required > mixer_bal) { required - mixer_bal } else { 0 };
          let topup_res = await Ledger.icrc1_transfer({
            from_subaccount = ?fee_buf_sub;
            to = mixer_acct;
            amount = shortfall;
            fee = ?fee;
            memo = null;
            created_at_time = ?now()
          });
          switch (topup_res) {
            case (#Err _) {
              ignore locks.remove(id);
              return #err(ERR_INSUFFICIENT_FUNDS);
            };
            case (#Ok _) {};
          };
        };

        // Pay Bob
        // -------
        let bob_payment = try {
          await pay_from_sub(mixer_sub, recipient, amount);
        } catch (_) {
          ignore locks.remove(id);
          return #err("ERR.PAYMENT_FAILED");
        };

        // Normal release
        // --------------
        ignore locks.remove(id);

        // Update state
        // ------------
        let tx_id = switch (bob_payment) { 
          case (#err e) { return #err(e) }; 
          case (#ok tid) tid 
        };

        pool_claims := if (pool_claims > amount) { pool_claims - amount } else { 0 };
        deposits.delete(id); 
        ev(0x03);

        #ok({ tx_id; fees_charged = 0 })
      }
    }
  };

  // Reclaim
  // =======
  public shared({ caller }) func reclaim(id : DepositId) : async { #ok : { tx_id : Nat; fees_charged : Amount }; #err : Text } {
    switch (requireNotPaused()) { case (?e) return #err(e); case null {} };
    switch (rate(caller)) { case (?e) return #err(e); case null {} };
    switch (deposits.get(id)) {
      case null { #err(ERR_NOT_FOUND) };
      case (?d) {
        if (d.state != #Created) return #err(ERR_REPLAY);
        if (now() <= d.expires_at) return #err(ERR_NOT_EXPIRED);
        if (caller != d.payer.owner) return #err(ERR_UNAUTHORIZED);

        switch (locks.get(id)) {
           case (?_) return #err(ERR_TEMP_UNAVAILABLE);
           case null { locks.put(id, ()); };
        };

        func unlock(msg : Text) : { #ok : { tx_id : Nat; fees_charged : Amount }; #err : Text } {
           ignore locks.remove(id);
           #err(msg)
        };

        try {
          let fee = await ledger_fee();
          let from_sub = deriveSub(id, "deposit");
          let acct_from : Account = { owner = Principal.fromActor(Router); subaccount = ?from_sub };
          let bal = await balance_of(acct_from);
          
          if (bal <= fee) return unlock(ERR_INSUFFICIENT_FUNDS);
          let refund_amount : Nat = bal - fee;

          let res = await Ledger.icrc1_transfer({
            from_subaccount = ?from_sub; to = d.payer; amount = refund_amount; fee = ?fee; memo = null; created_at_time = ?now()
          });

          switch (res) {
            case (#Ok tx) {
              deposits.delete(id); 
              ignore locks.remove(id);
              try { await sweepLeftoverToTreasury(id, from_sub) } catch(_) {};
              ev(0x04);
              #ok({ tx_id = tx; fees_charged = 0 })
            };
            case (#Err e) {
              let msg : Text = switch (e) {
                case (#BadFee _) ERR_BAD_FEE; 
                case (#BadBurn _) ERR_BAD_FEE;
                case (#InsufficientFunds _) ERR_INSUFFICIENT_FUNDS;
                case (#TemporarilyUnavailable) ERR_TEMP_UNAVAILABLE; 
                case (#TooOld) ERR_REPLAY;
                case (#CreatedInFuture _) ERR_INVALID_CTX; 
                case (#Duplicate _) ERR_REPLAY;
                case (#GenericError _) ERR_LEDGER_GENERIC
              };
              unlock(msg)
            }
          }
        } catch (_) { unlock(ERR_TEMP_UNAVAILABLE) };
      }
    }
  };

  // Query deposit info
  // ==================
  public query func get_deposit_info(id : DepositId) : async ?{ 
    i1 : Principal; 
    i2 : Principal; 
    witness : Principal; 
    storage : [Principal];
  } {
    switch (deposits.get(id)) {
      case null null;
      case (?d) { ?{ i1 = d.i1; i2 = d.i2; witness = d.witness; storage = d.storage } }
    }
  };

  // Discovery
  // =========  
  public query func supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "icrc-1"; url = "https://github.com/dfinity/ICRC-1" },
      { name = "icrc-2"; url = "https://github.com/dfinity/ICRC-2" },
      { name = "ICPP-shield-v1"; url = "https://example.com/specs/ICPP-shield-v1" }
    ]
  };

  public query func get_config() : async { config : Config; certified_hash : Blob } { { config = cfg; certified_hash } };

  // Status/events
  // =============
  public query func status(id : DepositId) : async { #ok : { state : State; expires_at : Nat64 }; #err : Text } {
    switch (deposits.get(id)) { case null { #err(ERR_NOT_FOUND) }; case (?d) { #ok({ state = d.state; expires_at = d.expires_at }) } }
  };

  public query func get_notice(id : DepositId) : async ?Notice {
    switch (deposits.get(id)) { 
      case (?d) { let notice_hint = deriveWithdrawalId(id); ?{ deposit_id = id; hint = notice_hint; bucket = d.bucket; ts = d.created_at } }; 
      case null null 
    }
  };

  public query func get_events(args : { from : Nat; limit : Nat }) : async { events : [Blob]; tip : Nat; cert : Blob } {
    let start = args.from; let end = Nat.min(events.size(), start + args.limit);
    let slice = if (end > start) Array.tabulate<Blob>(end - start, func i = events[start + i]) else [];
    { events = slice; tip = events.size(); cert = certified_hash }
  };

  // Balance queries
  // ===============
  public shared({ caller }) func buffer_balance() : async { #ok : Amount; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    switch (rate(caller)) { case (?e) return #err(e); case null {} };
    #ok(await balance_of(cfg.fee_accounts.buffer))
  };

  public shared({ caller }) func mixer_balance() : async { #ok : Amount; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    switch (rate(caller)) { case (?e) return #err(e); case null {} };
    let mixer_sub = getMixerSub();
    let mixer_acct : Account = { owner = Principal.fromActor(Router); subaccount = ?mixer_sub };
    #ok(await balance_of(mixer_acct))
  };

  // Pre-upgrade 
  // validation
  // ===========
  public query func can_upgrade() : async { #ok : (); #err : Text } {
    if (Nat16.toNat(cfg.deposit_fee_bps) > 10_000) return #err("bad.deposit_fee_bps");
    let sb = cfg.size_buckets;
    if (sb.size() == 0) return #err("bad.size_buckets.empty");
    var i : Nat = 0;
    label chk while (i < sb.size()) {
      if (sb[i] == 0) return #err("bad.size_buckets.zero");
      if (i + 1 < sb.size() and not (sb[i] < sb[i+1])) return #err("bad.size_buckets.nonstrict");
      i += 1;
    };
    if (cfg.ttl_secs == 0) return #err("bad.ttl.zero");
    if (cfg.fee_accounts.treasury.owner == Principal.fromText("aaaaa-aa")) return #err("bad.treasury.principal");
    if (cfg.fee_accounts.buffer.owner == Principal.fromText("aaaaa-aa")) return #err("bad.buffer.principal");
    if (cfg.cmc == Principal.fromText("aaaaa-aa")) return #err("bad.cmc.principal");
    if (cfg.treasury_fee_subs.size() == 0) return #err("bad.treasury_fee_subs.empty");
    #ok(())
  };

  public shared query({ caller }) func get_pool_claims() : async { #ok : Nat; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    #ok(pool_claims)
  };

  // Admin -> monitor
  // protocol economics
  // ==================
  public shared query({ caller }) func get_economics_status() : async { #ok : { router_cycles : Nat; router_target : Nat; pool_claims : Nat; seal_count : Nat; recycle_interval : Nat }; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    #ok({ router_cycles = Cycles.balance(); router_target = ROUTER_CYCLES_TARGET; pool_claims; seal_count; recycle_interval = RECYCLE_INTERVAL })
  };

  // Admin -> force 
  // pool sweep
  // ==============
  public shared({ caller }) func admin_sweep_pool() : async { #ok; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    await sweepPoolExcess();
    #ok
  };

  // Admin -> clear 
  // stale lock
  // ==============
  public shared({ caller }) func admin_clear_lock(key : Blob) : async { #ok; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    ignore locks.remove(key);
    #ok
  };

  // Admin -> get 
  // mixer sub
  // ============
  public shared query({ caller }) func admin_get_mixer_sub() : async { #ok : Blob; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    #ok(getMixerSub())
  };

  // Admin -> clear stale
  // pool claims and deposit
  // =======================
  public shared({ caller }) func admin_clear_deposit(id : DepositId) : async { #ok; #err : Text } {
    if (not isAdmin(caller)) return #err(ERR_UNAUTHORIZED);
    switch (deposits.get(id)) {
      case null { #err(ERR_NOT_FOUND) };
      case (?d) {
        // Must be expired
        // ---------------
        if (now() <= d.expires_at) return #err("ERR.NOT_EXPIRED");
        
        // Must be stuck 
        // (Sealed -> can't finalize 
        // or reclaim normally)
        // -------------------------
        if (d.state != #Sealed) return #err("ERR.NOT_STUCK");
        
        let amount = d.amount;
        pool_claims := if (pool_claims > amount) { pool_claims - amount } else { 0 };
        deposits.delete(id);
        #ok
      };
    };
  };

}
