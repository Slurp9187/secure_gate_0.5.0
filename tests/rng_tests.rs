// tests/rng_tests.rs
//! Tests for RNG features (requires "rand" feature)

#![cfg(feature = "rand")]

use secure_gate::{random_alias, SecureRandomExt};

#[test]
fn random_bytes_generates_different_values() {
    random_alias!(TestKey32, 32);
    random_alias!(TestKey16, 16);

    // Generate two keys — they must be different (probability of collision: 2^256 or 2^128)
    let key1 = TestKey32::new();
    let key2 = TestKey32::new();

    assert_ne!(key1.expose_secret(), key2.expose_secret());
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);

    // Also test a different size
    let nonce1 = TestKey16::new();
    let nonce2 = TestKey16::new();

    assert_ne!(nonce1.expose_secret(), nonce2.expose_secret());
    assert_eq!(nonce1.len(), 16);

    // Bonus: sanity-check that it's not all zeros (extremely unlikely, but catches broken RNG)
    assert_ne!(*key1.expose_secret(), [0u8; 32]);
    assert_ne!(*nonce1.expose_secret(), [0u8; 16]);
}

#[test]
fn deprecated_random_still_works() {
    random_alias!(OldKey32, 32);

    #[allow(deprecated)]
    let key = OldKey32::random(); // Tests the soft deprecation shim
    assert_eq!(key.len(), 32);
}
