// ===================================================
// Unkeyed BLAKE2s Implementation
// Privacy ICP (ICPP)
//
// Version -> 2.0.01
// Date    -> 25 November 2025
// Status  -> Public release ver:2 subver:0 release:01
//
// Code developed by @Troesma
// ===================================================

import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Array "mo:base/Array";
import Blob "mo:base/Blob";

module Blake2s {

  // Initialization vector
  // =====================
  let IV : [Nat32] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
  ];

  // Round constants
  // ===============
  let SIGMA : [[Nat8]] = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,4,7,15,14,1,13,3,9,8,5,11,0],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]
  ];

  // 32-bit rotate right
  // ===================
  func rotr32(x : Nat32, n : Nat32) : Nat32 {
    (x >> n) | (x << (32 : Nat32 - n))
  };

  // Little-endian load
  // ==================
  func toU32LE(b : [Nat8], i : Nat) : Nat32 {
    Nat32.fromNat(Nat8.toNat(b[i])) |
    (Nat32.fromNat(Nat8.toNat(b[i+1])) << 8) |
    (Nat32.fromNat(Nat8.toNat(b[i+2])) << 16) |
    (Nat32.fromNat(Nat8.toNat(b[i+3])) << 24)
  };

  // Core compression (unkeyed, 32-byte 
  // output, no salt/personalisation)
  // ==========================================
  private func compressAll(msg : [Nat8]) : [Nat8] {
    // State
    let hInit : [Nat32] = Array.tabulate<Nat32>(8, func(i) { IV[i] });
    var h : [var Nat32] = Array.thaw(hInit);

    // Parameter block: digest=32, key=0, fanout=1, depth=1
    h[0] ^= 0x01010020;

    // Message counters
    // ----------------
    var t0 : Nat32 = 0;
    var t1 : Nat32 = 0;
    func inc(bytes : Nat) {
      let add = Nat32.fromNat(bytes);
      let sum = t0 +% add;
      if (sum < t0) { t1 := t1 +% 1 };
      t0 := sum;
    };

    // Mixing function G
    // -----------------
    func G(v : [var Nat32], a : Nat, b : Nat, c : Nat, d : Nat, x : Nat32, y : Nat32) {
      v[a] := v[a] +% v[b] +% x; v[d] := rotr32(v[d] ^ v[a], 16);
      v[c] := v[c] +% v[d];      v[b] := rotr32(v[b] ^ v[c], 12);
      v[a] := v[a] +% v[b] +% y; v[d] := rotr32(v[d] ^ v[a], 8);
      v[c] := v[c] +% v[d];      v[b] := rotr32(v[b] ^ v[c], 7);
    };

    // Single block 
    // compression
    // ------------
    func compress(block : [Nat8], last : Bool) {
      var v : [var Nat32] = Array.init<Nat32>(16, 0);
      let m : [Nat32] = Array.tabulate<Nat32>(16, func(j) { toU32LE(block, j*4) });

      var j : Nat = 0;
      while (j < 8) {
        v[j] := h[j];
        v[j + 8] := IV[j];
        j += 1;
      };

      v[12] ^= t0;
      v[13] ^= t1;
      if (last) { v[14] ^= 0xFFFFFFFF };

      // 10 rounds
      // ---------
      var r : Nat = 0;
      while (r < 10) {
        let s = SIGMA[r];
        G(v, 0, 4, 8, 12, m[Nat8.toNat(s[0])],  m[Nat8.toNat(s[1])]);
        G(v, 1, 5, 9, 13, m[Nat8.toNat(s[2])],  m[Nat8.toNat(s[3])]);
        G(v, 2, 6,10, 14, m[Nat8.toNat(s[4])],  m[Nat8.toNat(s[5])]);
        G(v, 3, 7,11, 15, m[Nat8.toNat(s[6])],  m[Nat8.toNat(s[7])]);
        G(v, 0, 5,10, 15, m[Nat8.toNat(s[8])],  m[Nat8.toNat(s[9])]);
        G(v, 1, 6,11, 12, m[Nat8.toNat(s[10])], m[Nat8.toNat(s[11])]);
        G(v, 2, 7, 8, 13, m[Nat8.toNat(s[12])], m[Nat8.toNat(s[13])]);
        G(v, 3, 4, 9, 14, m[Nat8.toNat(s[14])], m[Nat8.toNat(s[15])]);
        r += 1;
      };

      j := 0;
      while (j < 8) {
        h[j] ^= v[j] ^ v[j+8];
        j += 1;
      };
    };

    // Process full blocks
    // ===================
    var off : Nat = 0;
    while (off + 64 <= msg.size()) {
      inc(64);
      let block = Array.tabulate<Nat8>(64, func(k) { msg[off + k] });
      compress(block, false);
      off += 64;
    };

    // Padding and 
    // final block
    // ===========
    let tailLen : Nat = if (off <= msg.size()) { msg.size() - off } else { 0 };
    let tail = Array.tabulate<Nat8>(tailLen, func(i) { msg[off + i] });
    let lastBlock = Array.tabulate<Nat8>(64, func(i) {
      if (i < tailLen) tail[i] else 0
    });
    inc(tailLen);
    compress(lastBlock, true);

    // Output (little-endian)
    // ======================
    let out = Array.init<Nat8>(32, 0);
    var i : Nat = 0;
    while (i < 8) {
      let w = h[i];
      out[4*i]     := Nat8.fromNat(Nat32.toNat(w         & 0xFF));
      out[4*i + 1] := Nat8.fromNat(Nat32.toNat((w >> 8)  & 0xFF));
      out[4*i + 2] := Nat8.fromNat(Nat32.toNat((w >> 16) & 0xFF));
      out[4*i + 3] := Nat8.fromNat(Nat32.toNat((w >> 24) & 0xFF));
      i += 1;
    };
    Array.freeze(out)
  };

  // Array concatenation
  // ===================
  private func cat(a : [Nat8], b : [Nat8]) : [Nat8] {
    Array.tabulate<Nat8>(a.size() + b.size(), func(i) {
      if (i < a.size()) a[i] else b[i - a.size()]
    })
  };

  // Public API
  // ==========
  public func digest(msg : [Nat8]) : [Nat8] {
    compressAll(msg)
  };

  public func digestBlob(b : Blob) : Blob {
    Blob.fromArray(digest(Blob.toArray(b)))
  };

  public func digestDomain(domain : [Nat8], msg : [Nat8]) : Blob {
    Blob.fromArray(compressAll(cat(domain, msg)))
  };

  // Simple domain-separated 
  // hash (prepend domain)
  // =======================
  public func keyedHash(domain : [Nat8], msg : [Nat8], _outlen : Nat32) : [Nat8] {
    compressAll(cat(domain, msg))
  };

  public func blake2s_keyed(domain : [Nat8], msg : [Nat8]) : Blob {
    Blob.fromArray(keyedHash(domain, msg, 32))
  };
}