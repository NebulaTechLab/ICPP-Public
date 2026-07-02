// ===================================================
// Ledger Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 03 November 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import HashMap "mo:base/HashMap";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Hash "mo:base/Hash";
import Array "mo:base/Array";
import Time "mo:base/Time";

persistent actor Ledger {

  // Types
  // =====
  public type Subaccount = Blob;
  public type Account = { owner : Principal; subaccount : ?Subaccount };
  public type TransferArg = {
    from_subaccount : ?Subaccount;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type TransferFromArg = {
    from : Account;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
    spender_subaccount : ?Subaccount;
  };

  public type ApproveArg = {
    from_subaccount : ?Subaccount;
    spender : Account;
    amount : Nat;
    expected_allowance : ?Nat;
    expires_at : ?Nat64;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type AllowanceArgs = {
    account : Account;
    spender : Account;
  };

  public type Allowance = {
    allowance : Nat;
    expires_at : ?Nat64;
  };

  public type TxIndex = Nat;
  
  public type TransferError = {
    #BadFee : { expected_fee : Nat };
    #InsufficientFunds : { balance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { message : Text; error_code : Nat }
  };
  
  public type Result<T> = { #Ok : T; #Err : TransferError };

  // ICRC-3 types
  // ------------
  public type Value = {
    #Nat : Nat;
    #Int : Int;
    #Blob : Blob;
    #Text : Text;
  };

  public type Block = {
    #Map : [(Text, Value)];
  };

  public type GetBlocksArgs = {
    start : Nat;
    length : Nat;
  };

  public type GetBlocksResult = {
    log_length : Nat;
    blocks : [Block];
    archived_blocks : [{
      start : Nat;
      length : Nat;
      callback : shared query (GetBlocksArgs) -> async GetBlocksResult;
    }];
  };

  // Stable snapshots
  // ================
  var next_tx : Nat = 0;
  var balances : [(Account, Nat)] = [];
  var allowances : [((Account, Account), (Nat, ?Nat64))] = [];
  var blocks : [Block] = [];
  var total_supply : Nat = 0;

  // Hashing & equality
  // ==================
  func subOrEmpty(sa : ?Subaccount) : Blob {
    switch (sa) { case (?b) b; case null Blob.fromArray([]) }
  };

  func accountHash(a : Account) : Hash.Hash {
    let h1 = Principal.hash(a.owner);
    let h2 = Blob.hash(subOrEmpty(a.subaccount));
    h1 ^ (h2 << 1)
  };
  func accountEq(a : Account, b : Account) : Bool {
    a.owner == b.owner and a.subaccount == b.subaccount
  };

  func pairHash(p : (Account,Account)) : Hash.Hash {
    accountHash(p.0) ^ (accountHash(p.1) << 1)
  };
  func pairEq(x : (Account,Account), y : (Account,Account)) : Bool {
    accountEq(x.0,y.0) and accountEq(x.1,y.1)
  };

  // In-memory maps 
  // ==============
  transient var bal = HashMap.HashMap<Account, Nat>(32, accountEq, accountHash);
  transient var allow = HashMap.HashMap<(Account, Account), (Nat, ?Nat64)>(32, pairEq, pairHash);

  system func postupgrade() {
    for ((k,v) in balances.vals()) { bal.put(k,v) };
    for ((k,v) in allowances.vals()) { allow.put(k,v) };
  };
  system func preupgrade() {
    balances := Iter.toArray(bal.entries());
    allowances := Iter.toArray(allow.entries());
  };

  // Balance helpers
  // ===============
  func getBal(a : Account) : Nat { switch (bal.get(a)) { case (?n) n; case null 0 } };
  func add(a : Account, n : Nat) { bal.put(a, getBal(a) + n); total_supply += n };
  func sub(a : Account, n : Nat) : Bool {
    let cur = getBal(a);
    if (cur < n) return false;
    bal.put(a, cur - n);
    total_supply -= n;
    true
  };

  // Block creation
  // ==============
  func makeBlock(kind : Text, from : Account, to : Account, amount : Nat, fee : Nat, memo : ?Blob, ts : Nat64) : Block {
    var fields : [(Text, Value)] = [
      ("btype", #Text(kind)),
      ("from", #Blob(Principal.toBlob(from.owner))),
      ("to", #Blob(Principal.toBlob(to.owner))),
      ("amt", #Nat(amount)),
      ("fee", #Nat(fee)),
      ("ts", #Nat(Nat64.toNat(ts)))
    ];
    switch (memo) {
      case (?m) { fields := Array.append(fields, [("memo", #Blob(m))]) };
      case null {};
    };
    #Map(fields)
  };

  // Supported standards
  // ===================
  public query func icrc1_supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICRC-1"; url = "https://github.com/dfinity/ICRC-1" },
      { name = "ICRC-2"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2" },
      { name = "ICRC-3"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" }
    ]
  };

  // ICRC-1
  // ======
  public query func icrc1_name() : async Text { "Mock ICP" };
  public query func icrc1_symbol() : async Text { "mICP" };
  public query func icrc1_decimals() : async Nat8 { 8 };
  public query func icrc1_fee() : async Nat { 10000 };
  public query func icrc1_total_supply() : async Nat { total_supply };
  var minting_account : ?Account = null;
  public query func icrc1_minting_account() : async ?Account { 
    minting_account
  };
  public query func icrc1_balance_of(a : Account) : async Nat { getBal(a) };
  public query func icrc1_metadata() : async [(Text, Value)] {
    [
      ("icrc1:name", #Text("Mock ICP")),
      ("icrc1:symbol", #Text("mICP")),
      ("icrc1:decimals", #Nat(8)),
      ("icrc1:fee", #Nat(10000))
    ]
  };
  
  public shared ({ caller }) func icrc1_transfer(arg : TransferArg) : async { #Ok : TxIndex; #Err : TransferError } {
    let fee = switch (arg.fee) { case (?f) f; case null 10000 };
    let from_acct = { owner = caller; subaccount = arg.from_subaccount };
    let ts = Nat64.fromIntWrap(Time.now());
    
    if (not sub(from_acct, arg.amount + fee)) {
      return #Err(#InsufficientFunds({ balance = getBal(from_acct) }))
    };
    
    add(arg.to, arg.amount);
    blocks := Array.append(blocks, [makeBlock("xfer", from_acct, arg.to, arg.amount, fee, arg.memo, ts)]);
    let tx = next_tx; next_tx += 1;
    #Ok(tx)
  };

  // ICRC-2
  // ======
  public shared ({ caller }) func icrc2_approve(arg : ApproveArg) : async { #Ok : TxIndex; #Err : ApproveError } {
    let owner = { owner = caller; subaccount = arg.from_subaccount };
    allow.put((owner, arg.spender), (arg.amount, arg.expires_at));
    let tx = next_tx; next_tx += 1;
    #Ok(tx)
  };

  public query func icrc2_allowance(args : AllowanceArgs) : async Allowance {
    let key = (args.account, args.spender);
    switch (allow.get(key)) {
      case (?(amt, exp)) { { allowance = amt; expires_at = exp } };
      case null { { allowance = 0; expires_at = null } };
    }
  };

  public shared ({ caller }) func icrc2_transfer_from(arg : TransferFromArg) : async Result<TxIndex> {
    let spender = { owner = caller; subaccount = arg.spender_subaccount };
    let key = (arg.from, spender);
    let (allowAmt, expires) = switch (allow.get(key)) { case (?(a,e)) (a,e); case null (0,null) };
    let fee = switch (arg.fee) { case (?f) f; case null 10000 };
    let need = arg.amount + fee;
    let ts = Nat64.fromIntWrap(Time.now());
    
    // Check expiry
    // ============
    switch (expires) {
      case (?exp) { if (ts > exp) return #Err(#GenericError({ message = "Allowance expired"; error_code = 1 })) };
      case null {};
    };
    
    if (allowAmt < need) return #Err(#InsufficientFunds({ balance = allowAmt }));
    if (getBal(arg.from) < need) return #Err(#InsufficientFunds({ balance = getBal(arg.from) }));

    ignore sub(arg.from, need);
    add(arg.to, arg.amount);
    allow.put(key, (allowAmt - need, expires));
    blocks := Array.append(blocks, [makeBlock("xfer_from", arg.from, arg.to, arg.amount, fee, arg.memo, ts)]);
    let tx = next_tx; next_tx += 1;
    #Ok(tx)
  };

  // ICRC-3
  // ======
  public query func icrc3_get_blocks(args : GetBlocksArgs) : async GetBlocksResult {
    let start = args.start;
    let end = Nat.min(blocks.size(), start + args.length);
    let slice = if (end > start) {
      Array.tabulate<Block>(end - start, func i = blocks[start + i])
    } else { [] };
    {
      log_length = blocks.size();
      blocks = slice;
      archived_blocks = [];
    }
  };

  public query func icrc3_get_archives() : async [{
    canister_id : Principal;
    start : Nat;
    end : Nat;
  }] { [] };

  public query func icrc3_get_tip_certificate() : async ?{
    certificate : Blob;
    hash_tree : Blob;
  } { null };

  public query func icrc3_supported_block_types() : async [{
    block_type : Text;
    url : Text;
  }] {
    [
      { block_type = "xfer"; url = "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md" },
      { block_type = "xfer_from"; url = "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md" }
    ]
  };

  // ICP Faucet 
  // ==========
  public func mint(to : Account, amount : Nat) : async () { add(to, amount) };
}