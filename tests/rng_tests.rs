// tests/rng_tests.rs
//! Public RNG API tests (requires "rand" feature)

#![cfg(feature = "rand")]

use secure_gate::{fixed_alias_rng, rng::FixedRng};

#[test]
fn random_generates_different_values() {
    fixed_alias_rng!(TestKey32, 32);
    fixed_alias_rng!(TestKey16, 16);

    // Correct API: use .rng() — this is the only way to generate random secrets
    let key1 = TestKey32::rng();
    let key2 = TestKey32::rng();
    assert_ne!(key1.expose_secret(), key2.expose_secret());
    assert_eq!(key1.len(), 32);

    let nonce1 = TestKey16::rng();
    let nonce2 = TestKey16::rng();
    assert_ne!(nonce1.expose_secret(), nonce2.expose_secret());
    assert_eq!(nonce1.len(), 16);

    // Bonus: sanity check — not all zeros (extremely unlikely with real RNG)
    assert_ne!(*key1.expose_secret(), [0u8; 32]);
    assert_ne!(*nonce1.expose_secret(), [0u8; 16]);
}

#[test]
fn fixed_rng_generic_works() {
    // Test the raw type directly — should work identically
    let a = FixedRng::<32>::rng();
    let b = FixedRng::<32>::rng();
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(a.len(), 32);
}
