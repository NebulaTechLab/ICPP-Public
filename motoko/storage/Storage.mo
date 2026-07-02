// ===================================================
// Storage Canister
// Privacy ICP (ICPP)
//
// Version -> 2.0.03
// Date    -> 3 December 2025
// Status  -> Public release ver:2 subver:0 release:03
//
// Code developed by @Troesma
// ===================================================

import Time "mo:base/Time";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";
import Random "mo:base/Random";

persistent actor Storage {

  // Errors
  // ======
  let ERR_ALREADY_STORED = "ERR.ALREADY_STORED";
  let ERR_NOT_FOUND = "ERR.NOT_FOUND";
  let ERR_UNAUTHORIZED = "ERR.UNAUTHORIZED";
  let ERR_CRYPTO = "ERR.CRYPTO";
  let ERR_WITNESS = "ERR.WITNESS";
  let ERR_CSRN_UNAVAILABLE = "ERR.CSRN_UNAVAILABLE";
  let ERR_STORAGE_FAILED = "ERR.STORAGE_FAILED";

  // Witness interface
  // =================
  private func mkWitness(p : Principal) : actor {
    log_storage_commit : ({ hint : Blob; storage_id : Principal }) -> async { #ok : (); #err : Text };
    log_destruct_intent : ({ canister_id : Principal; ts : Nat64 }) -> async { #ok : (); #err : Text };
    is_destroyed : (Principal) -> async Bool;
  } = actor(Principal.toText(p));

  // Crypto interface
  // ================
  private func mkCrypto(p : Principal) : actor {
    encrypt_csrn_for_transit : (Blob, Blob, Blob, Blob) -> async { #Ok : Blob; #Err : Text };
  } = actor(Principal.toText(p));

  private var witness_id : ?Principal = null;
  private var authorized_storer : ?Principal = null;
  private var authorized_retriever : ?Principal = null;
  private var stored : ?Blob = null;
  private var served : Bool = false;
  private var ttl_deadline : Nat64 = 0;
  private var hint_stored : ?Blob = null;
  
  // CSRN state (generated once served to 
  // Alice via I1 and then to Bob via I2)
  private var csrn : ?Blob = null;
  private var csrn_nonce : ?Blob = null;
  private var csrn_ciphertext : ?Blob = null;
  private var csrn_served_to_i2 : Bool = false;
  
  // Crypto canister 
  // reference
  private var crypto_id : ?Principal = null;

  private func now() : Nat64 = Nat64.fromIntWrap(Time.now());

  public shared(_) func init(w : Principal, ttl : Nat64, i1 : Principal, i2 : Principal, crypto : Principal) : async { #ok : (); #err : Text } {
    switch (witness_id) {
      case (?_) { #err("ERR.ALREADY_INITIALIZED") };
      case null {
        witness_id := ?w;
        authorized_storer := ?i1;
        authorized_retriever := ?i2;
        crypto_id := ?crypto;
        ttl_deadline := now() + (ttl * 1_000_000_000);
        #ok(())
      };
    }
  };

  // Generate and encrypt CSRN for Alice (called by I1)
  // Returns (nonce, ciphertext) for Alice to decrypt client-side
  // ============================================================
  public shared({ caller }) func init_csrn(
    deposit_id : Blob, 
    alice_principal : Principal
  ) : async { #ok : { nonce : Blob; ciphertext : Blob }; #err : Text } {
    
    // Authorization -> only I1
    // ------------------------
    switch (authorized_storer) {
      case null return #err(ERR_STORAGE_FAILED);
      case (?auth) {
        if (caller != auth) return #err(ERR_UNAUTHORIZED);
      };
    };
    
    // Check if 
    // already 
    // generated
    // ---------
    switch (csrn) {
      case (?_) return #err(ERR_CSRN_UNAVAILABLE);
      case null {};
    };
    
    // Generate 32-byte CSRN 
    // using IC randomness
    // ---------------------
    let random_blob = await Random.blob();
    let random_bytes = Blob.toArray(random_blob);
    
    if (random_bytes.size() < 32) {
      return #err(ERR_STORAGE_FAILED);
    };
    
    let csrn_bytes = Array.tabulate<Nat8>(32, func(i) = random_bytes[i]);
    let csrn_blob = Blob.fromArray(csrn_bytes);
    
    // Generate 
    // 32-byte 
    // nonce
    // --------
    let nonce_blob = await Random.blob();
    let nonce_bytes = Blob.toArray(nonce_blob);
    
    if (nonce_bytes.size() < 32) {
      return #err(ERR_STORAGE_FAILED);
    };
    
    let nonce_array = Array.tabulate<Nat8>(32, func(i) = nonce_bytes[i]);
    let nonce = Blob.fromArray(nonce_array);
    
    // Encrypt CSRN via 
    // Crypto canister
    // ----------------
    switch (crypto_id) {
      case null { 
        #err(ERR_STORAGE_FAILED); 
      };
      case (?cid) {
        let C = mkCrypto(cid);
        let alice_blob = Principal.toBlob(alice_principal);
        
        try {
          let encrypt_result = await C.encrypt_csrn_for_transit(
            deposit_id,
            alice_blob,
            nonce,
            csrn_blob
          );
          
          switch (encrypt_result) {
            case (#Err _e) {
              return #err(ERR_CRYPTO);
            };
            case (#Ok ct) {
              // Store state
              // -----------
              csrn := ?csrn_blob;
              csrn_nonce := ?nonce;
              csrn_ciphertext := ?ct;
              
              #ok({ nonce; ciphertext = ct })
            };
          };
        } catch (_) {
          #err(ERR_CRYPTO)
        };
      };
    };
  };

  public shared({ caller }) func store(data : Blob) : async { #ok : (); #err : Text } {
    if (now() > ttl_deadline) return #err("ERR.EXPIRED");
    
    switch (authorized_storer) {
      case null return #err("ERR.NOT_INITIALIZED");
      case (?auth) {
        if (caller != auth) return #err(ERR_UNAUTHORIZED);
      };
    };
    
    switch (stored) {
      case (?_) { #err(ERR_ALREADY_STORED) };
      case null {
        stored := ?data;
        
        // Extract hint (first 80 bytes)
        // ------------------------------
        let hint = if (data.size() >= 80) {
          let arr = Blob.toArray(data);
          Blob.fromArray(Array.tabulate<Nat8>(80, func(i) = arr[i]))
        } else {
          Blob.fromArray([])
        };
        hint_stored := ?hint;
        
        // Report commit 
        // to witness
        // -------------
        switch (witness_id) {
          case null { #err("ERR.NO_WITNESS") };
          case (?wid) {
            let W = mkWitness(wid);
            try {
              let _ = await W.log_storage_commit({ 
                hint; 
                storage_id = Principal.fromActor(Storage) 
              });
              #ok(())
            } catch (_) {
              #err(ERR_WITNESS)
            }
          };
        }
      };
    }
  };

  // Retrieve package (called by I2)
  // Verifies I1 destroyed via Witness before serving
  // ================================================
  public shared({ caller }) func retrieve() : async { #ok : Blob; #err : Text } {
    if (now() > ttl_deadline) return #err(ERR_STORAGE_FAILED);
    if (served) return #err(ERR_STORAGE_FAILED);
    
    switch (authorized_retriever) {
      case null return #err(ERR_STORAGE_FAILED);
      case (?auth) {
        if (caller != auth) return #err(ERR_UNAUTHORIZED);
      };
    };
    
    // Verify I1 
    // destruction
    // -----------
    switch (witness_id, authorized_storer) {
      case (?wid, ?i1) {
        let W = mkWitness(wid);
        try {
          let i1_destroyed = await W.is_destroyed(i1);
          if (not i1_destroyed) return #err(ERR_STORAGE_FAILED);
        } catch (_) { return #err(ERR_WITNESS); };
      };
      case _ {};
    };
    
    switch (stored) {
      case null { #err(ERR_NOT_FOUND) };
      case (?data) {
        // Mark as 
        // served
        // -------
        served := true;
        
        // I2 will call request_destruct(factory) 
        // immediately after this
        // --------------------------------------
        #ok(data)
      };
    }
  };

  // Fetch plaintext CSRN (called by I2 for Bob)
  // Only authorized retriever (I2) can fetch
  // ===========================================
  public shared({ caller }) func fetch_csrn() : async { #ok : Blob; #err : Text } {
    if (now() > ttl_deadline) return #err(ERR_STORAGE_FAILED);
    
    // Authorization -> only 
    // I2 can fetch CSRN
    // ---------------------
    switch (authorized_retriever) {
      case null return #err(ERR_STORAGE_FAILED);
      case (?auth) {
        if (caller != auth) return #err(ERR_UNAUTHORIZED);
      };
    };
    
    // Check if already 
    // served to I2
    // ----------------
    if (csrn_served_to_i2) {
      return #err(ERR_CSRN_UNAVAILABLE);
    };
    
    // Return plaintext CSRN
    // ---------------------
    switch (csrn) {
      case null { #err(ERR_CSRN_UNAVAILABLE) };
      case (?csrn_blob) {
        csrn_served_to_i2 := true;
        #ok(csrn_blob)
      };
    }
  };

  // Pass destruction
  // request on
  // ================
  public shared func request_destruct(factory : Principal) : async () {
    // Log intent 
    // to Witness
    // ----------
    switch (witness_id) {
      case null {};
      case (?wid) {
        let W = mkWitness(wid);
        try {
          let _ = await W.log_destruct_intent({ 
            canister_id = Principal.fromActor(Storage); 
            ts = now() 
          });
        } catch (_) {};
      };
    };

    // Now zero 
    // sensitive data
    // --------------
    stored := null;
    hint_stored := null;
    csrn := null;
    csrn_nonce := null;
    csrn_ciphertext := null;
    csrn_served_to_i2 := false;
    
    let IC : actor {
      update_settings : ({ canister_id : Principal; settings : { controllers : ?[Principal] } }) -> async ();
    } = actor("aaaaa-aa");
    let self_id = Principal.fromActor(Storage);
    
    // Add Factory 
    // as controller
    // -------------
    try {
      await IC.update_settings({
        canister_id = self_id;
        settings = { controllers = ?[self_id, factory] };
      });
    } catch (_) { return };
    
    // Call the 
    // executioner
    // -----------
    let F = actor(Principal.toText(factory)) : actor {
      cleanup_child : (Principal) -> async ();
    };
    
    // Fire and forget
    // --------------- 
    ignore F.cleanup_child(self_id);
  };

  // Public read-only access to stored package
  // The package is encrypted -> authorization is defense-in-depth
  // (Bob needs this to discover I2 principal from encrypted inner)
  // --------------------------------------------------------------
  public query func get_package() : async { #ok : Blob; #err : Text } {
    if (now() > ttl_deadline) return #err("ERR.EXPIRED");
    
    switch (stored) {
      case null { #err(ERR_NOT_FOUND) };
      case (?data) { #ok(data) };
    }
  };

  public query func get_ttl_info() : async { deadline : Nat64; current : Nat64; expired : Bool } {
    let current = now();
    { 
      deadline = ttl_deadline; 
      current; 
      expired = current > ttl_deadline 
    }
  };

  public query func ping() : async Text { "storage:ok" };
  
}