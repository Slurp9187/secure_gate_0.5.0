// tests/rng_tests.rs
//! Public RNG API tests (requires "rand" feature)

#![cfg(feature = "rand")]

use secure_gate::{fixed_alias_rng, SecureRandomExt};

#[test]
fn random_bytes_generates_different_values() {
    fixed_alias_rng!(TestKey32, 32);
    fixed_alias_rng!(TestKey16, 16);

    let key1 = TestKey32::new();
    let key2 = TestKey32::new();
    assert_ne!(key1.expose_secret(), key2.expose_secret());

    let nonce1 = TestKey16::new();
    let nonce2 = TestKey16::new();
    assert_ne!(nonce1.expose_secret(), nonce2.expose_secret());
}
