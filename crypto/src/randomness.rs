#![allow(non_snake_case)]

/// ===================================================
/// Custom provider that pulls randomness from ICP
/// raw_rand()
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

use std::cell::RefCell;
use std::convert::TryInto;

use getrandom::Error;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Thread-local CSPRNG seeded once 
// from IC randomness (via canister [init])
thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
}

/// Seed the thread-local RNG from a 32-byte 
/// seed derived from raw_rand()
pub fn seed_rng_from_seed_bytes(seed: &[u8]) {
    let seed_arr: [u8; 32] = seed
        .try_into()
        .expect("seed_rng_from_seed_bytes expects a 32-byte seed");

    RNG.with(|cell| {
        *cell.borrow_mut() = Some(ChaCha20Rng::from_seed(seed_arr));
    });
}

/// Custom getrandom backend -> fills 'buf' 
/// from the thread-local ChaCha20Rng
fn ic_getrandom(buf: &mut [u8]) -> Result<(), Error> {
    RNG.with(|cell| {
        let mut opt = cell.borrow_mut();
        if let Some(rng) = opt.as_mut() {
            rng.fill_bytes(buf);
            Ok(())
        } else {
            Err(Error::UNSUPPORTED)
        }
    })
}

// Register our custom 
// getrandom implementation
getrandom::register_custom_getrandom!(ic_getrandom);