// ===================================================
// Registry Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.01
// Date    -> 25 November 2025
// Status  -> Public release ver:2 subver:0 release:01
//
// Code developed by @Troesma
// ===================================================

import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Time "mo:base/Time";
import Array "mo:base/Array";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";

persistent actor Registry {

  public type Account = {
    owner : Blob;         // -> Principal bytes
    subaccount : Blob;    // -> 32-byte subaccount or empty
  };

  public type EncodedBases = {
    // SgpFE-encoded 
    // user bases
    hatP : Blob;
    hatQ : Blob;
  };

  public type Profile = {
    owner : Principal;
    account : Account;
    alias : ?Text;
    bases : EncodedBases;
    created_at : Nat64;
    last_update : Nat64;
  };

  // Linear store 
  // (stable across upgrades)
  var profiles : [Profile] = [];

  func findIndexByOwner(owner : Principal) : ?Nat {
    var i : Nat = 0;
    for (p in profiles.vals()) {
      if (p.owner == owner) {
        return ?i;
      };
      i += 1;
    };
    null
  };

  // Register or update the caller's 
  // FE profile
  // - caller principal becomes 'owner'
  // - if a profile already exists it 
  //   is overwritten
  public shared ({ caller }) func register(
    alias : ?Text,
    account : Account,
    bases : EncodedBases,
  ) : async () {
    let now : Nat64 = Nat64.fromIntWrap(Time.now());

    switch (findIndexByOwner(caller)) {
      // Update existing entry
      case (?idx) {
        let existing = profiles[idx];
        let updated : Profile = {
          owner = caller;
          account;
          alias;
          bases;
          created_at  = existing.created_at;
          last_update = now;
        };

        let len = profiles.size();
        profiles := Array.tabulate<Profile>(
          len,
          func (i : Nat) : Profile {
            if (i == idx) updated else profiles[i]
          },
        );
      };
      // Insert 
      // new entry
      case null {
        let profile : Profile = {
          owner = caller;
          account;
          alias;
          bases;
          created_at = now;
          last_update = now;
        };
        profiles := Array.append(profiles, [profile]);
      };
    };
  };

  // Lookup full profile 
  // by principal
  public query func getByOwner(owner : Principal) : async ?Profile {
    switch (findIndexByOwner(owner)) {
      case (?idx) ?profiles[idx];
      case null   null;
    }
  };

  // Convenience –> just 
  // the encoded bases
  public query func getBases(owner : Principal) : async ?EncodedBases {
    switch (findIndexByOwner(owner)) {
      case (?idx) ?profiles[idx].bases;
      case null   null;
    }
  };

  // Expose account to show 
  // Bob's ledger account
  public query func getAccount(owner : Principal) : async ?Account {
    switch (findIndexByOwner(owner)) {
      case (?idx) ?profiles[idx].account;
      case null   null;
    }
  };
};