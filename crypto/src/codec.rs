#![allow(non_snake_case)]

/// ===================================================
/// Canonical binary encodings for core crypto types
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// These functions define the on-wire formats for
/// - TransferCapsule
/// - EncryptedPayload
/// - NoticeHint
/// All serialization/deserialization of these types 
/// (by canisters, tests, or off-chain tools) goes through
/// this module so the formats are defined in one place
/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++

use crate::transfer::{TransferCapsule, EncryptedPayload};
use crate::params::NoticeHint;

/// Encode a TransferCapsule into bytes
/// Format -> ct_len(4 LE) | eph_matrices_ct | W_seed(32) | nonce(32) | tag(32)
pub fn encode_transfer_capsule(capsule: &TransferCapsule) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + capsule.eph_matrices_ct.len() + 32 + 32 + 32,
    );

    // eph_matrices_ct 
    // length (u32 LE)
    out.extend_from_slice(&(capsule.eph_matrices_ct.len() as u32).to_le_bytes());
    
    // eph_matrices_ct 
    // bytes
    out.extend_from_slice(&capsule.eph_matrices_ct);
    
    // fixed-size 
    // fields
    out.extend_from_slice(&capsule.W_seed);
    out.extend_from_slice(&capsule.nonce);
    out.extend_from_slice(&capsule.tag);

    out
}

/// Decode a TransferCapsule from bytes 
/// using the canonical format
/// (see above for layout)
pub fn decode_transfer_capsule(bytes: &[u8]) -> Result<TransferCapsule, String> {
    // Minimum size: 4 (ct_len) + 32 + 32 + 32
    if bytes.len() < 4 + 32 + 32 + 32 {
        return Err("Capsule too short".to_string());
    }

    let mut offset = 0;

    // Ciphertext length 
    // (u32 LE)
    let ct_len = u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid length header".to_string())?,
    ) as usize;
    offset += 4;

    if bytes.len() < 4 + ct_len + 32 + 32 + 32 {
        return Err("Capsule truncated".to_string());
    }

    let eph_matrices_ct = bytes[offset..offset + ct_len].to_vec();
    offset += ct_len;

    let W_seed: [u8; 32] = bytes[offset..offset + 32]
        .try_into()
        .map_err(|_| "Invalid W seed field".to_string())?;
    offset += 32;

    let nonce: [u8; 32] = bytes[offset..offset + 32]
        .try_into()
        .map_err(|_| "Invalid nonce field".to_string())?;
    offset += 32;

    let tag: [u8; 32] = bytes[offset..offset + 32]
        .try_into()
        .map_err(|_| "Invalid tag field".to_string())?;

    Ok(TransferCapsule {
        eph_matrices_ct,
        W_seed,
        nonce,
        tag,
    })
}

/// Encode an EncryptedPayload into bytes
/// If we later add framing (lengths, associated data
/// versioning) it all changes in one place
pub fn encode_encrypted_payload(payload: &EncryptedPayload) -> Vec<u8> {
    payload.ciphertext.clone()
}

/// Decode an EncryptedPayload from bytes
pub fn decode_encrypted_payload(bytes: &[u8]) -> Result<EncryptedPayload, String> {
    Ok(EncryptedPayload {
        ciphertext: bytes.to_vec(),
    })
}

/// Encode a NoticeHint as a fixed-length 
/// 80-byte array
/// Format -> account_tag(32) | bucket_tag(32) | checksum(16)
pub fn encode_notice_hint(hint: &NoticeHint) -> [u8; 80] {
    let mut out = [0u8; 80];

    out[0..32].copy_from_slice(&hint.account_tag);
    out[32..64].copy_from_slice(&hint.bucket_tag);
    out[64..80].copy_from_slice(&hint.checksum);

    out
}

/// Decode a NoticeHint from bytes
/// (requires exactly 80 bytes with the encoding 
/// as described above)
pub fn decode_notice_hint(bytes: &[u8]) -> Result<NoticeHint, String> {
    if bytes.len() != 80 {
        return Err("Invalid hint encoding ".to_string());
    }

    let mut account_tag = [0u8; 32];
    account_tag.copy_from_slice(&bytes[0..32]);

    let mut bucket_tag = [0u8; 32];
    bucket_tag.copy_from_slice(&bytes[32..64]);

    let mut checksum = [0u8; 16];
    checksum.copy_from_slice(&bytes[64..80]);

    Ok(NoticeHint {
        account_tag,
        bucket_tag,
        checksum,
    })
}