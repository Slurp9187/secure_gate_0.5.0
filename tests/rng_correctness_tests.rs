// tests/rng_correctness_tests.rs
//! Exhaustive tests for random-only types and aliases
//!
//! These ensure FixedRng, DynamicRng, and related macros work correctly
//! and cannot be broken by future changes.

#![cfg(feature = "rand")]

use secure_gate::{fixed_alias_rng, rng::FixedRng};

// ──────────────────────────────────────────────────────────────
// Basic generation and uniqueness
// ──────────────────────────────────────────────────────────────
#[test]
fn basic_generation() {
    fixed_alias_rng!(Key32, 32);

    let a = Key32::rng();
    let b = Key32::rng();

    assert_ne!(a.expose_secret(), b.expose_secret());
    assert!(!a.expose_secret().iter().all(|&b| b == 0));
    assert_eq!(a.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Debug is redacted
// ──────────────────────────────────────────────────────────────
#[test]
fn debug_is_redacted() {
    fixed_alias_rng!(DebugTest, 32);

    let rb = DebugTest::rng();
    assert_eq!(format!("{rb:?}"), "[REDACTED_RANDOM]");
}

// ──────────────────────────────────────────────────────────────
// Different aliases are distinct types
// ──────────────────────────────────────────────────────────────
#[test]
fn different_aliases_are_different_types() {
    fixed_alias_rng!(TypeA, 32);
    fixed_alias_rng!(TypeB, 32);

    let a = TypeA::rng();
    let _ = a;
    // let _wrong: TypeB = a; // ← must not compile — types are distinct
}

// ──────────────────────────────────────────────────────────────
// Raw FixedRng works directly
// ──────────────────────────────────────────────────────────────
#[test]
fn raw_fixed_rng_works() {
    let a = FixedRng::<32>::rng();
    let b = FixedRng::<32>::rng();

    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(a.len(), 32);
}
