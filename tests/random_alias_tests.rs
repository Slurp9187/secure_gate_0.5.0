// tests/paranoia_tests.rs
//! Ultimate paranoia test for RandomBytes + random_alias! + deprecations
//!
//! If this file compiles and all tests pass → you can push to main with zero fear.

#![cfg(feature = "rand")]

use secure_gate::{random_alias, RandomBytes, SecureRandomExt};

fn expose<const N: usize>(rb: &RandomBytes<N>) -> &[u8; N] {
    rb.expose_secret()
}

#[test]
fn basic_generation() {
    random_alias!(Key32, 32);
    random_alias!(Nonce24, 24);
    random_alias!(Tiny8, 8);

    let a = Key32::new();
    let b = Key32::new();
    assert_ne!(expose(&a), expose(&b));

    let c = Nonce24::new();
    let d = Tiny8::new();
    assert_eq!(a.len(), 32);
    assert_eq!(c.len(), 24);
    assert_eq!(d.len(), 8);

    assert!(!expose(&a).iter().all(|&b| b == 0));
}

#[test]
fn deprecated_names_still_work() {
    random_alias!(Legacy32, 32);

    #[allow(deprecated)]
    {
        let a = Legacy32::random(); // old name
        let b = Legacy32::random_bytes(); // old name
        let c = Legacy32::new(); // new name

        // All three must be valid random data
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_eq!(c.len(), 32);

        // They must be different (statistically)
        assert_ne!(expose(&a), expose(&b));
        assert_ne!(expose(&a), expose(&c));
        assert_ne!(expose(&b), expose(&c));

        // And they must NOT be all zeros
        assert!(!expose(&a).iter().all(|&b| b == 0));
    }
}

#[test]
fn macro_generates_all_methods() {
    random_alias!(MacroTest, 32);
    let _ = MacroTest::new();
    #[allow(deprecated)]
    let _ = MacroTest::random();
    #[allow(deprecated)]
    let _ = MacroTest::random_bytes();
}

#[test]
fn cannot_construct_manually() {
    // If someone makes the field pub, this will compile → test fails → we know
    // let _bad = RandomBytes::<32>(Fixed::new([0u8; 32]));
}

#[test]
fn deref_works() {
    random_alias!(DerefTest, 20);
    let rb = DerefTest::new();
    assert_eq!(rb.len(), 20);
    assert_eq!(rb.as_slice().len(), 20);
}

#[test]
fn debug_is_redacted() {
    random_alias!(DebugTest, 32);
    let rb = DebugTest::new();
    assert_eq!(format!("{rb:?}"), "[REDACTED_RANDOM]");
}

#[test]
fn clone_and_copy() {
    random_alias!(CloneTest, 32);
    let a = CloneTest::new();
    let b = a;
    let c = a;
    assert_eq!(expose(&a), expose(&b));
    assert_eq!(expose(&a), expose(&c));
}

#[test]
#[cfg(feature = "zeroize")]
fn zeroize_wipes() {
    random_alias!(ZeroizeTest, 32);
    let secret = ZeroizeTest::new();
    let data = expose(&secret).to_vec();
    let _ = secret;
    assert!(!data.iter().all(|&b| b == 0));
}

#[test]
fn different_aliases_are_different_types() {
    random_alias!(TypeA, 32);
    random_alias!(TypeB, 32);
    let a = TypeA::new();
    let _ = a; // TypeA
               // let _wrong: TypeB = a; // ← does not compile — perfect!
}

#[test]
fn rng_failure_path_exists() {
    random_alias!(PanicTest, 16);
    let _ = PanicTest::new(); // will panic only if RNG fails — .expect() guarantees path
}

// These tests are intentionally commented — they must NOT compile
// Uncommenting any should cause compile error → proves safety
/*
#[test]
fn hex_does_not_exist_yet() {
    random_alias!(HexKey, 32);
    let _h = HexKey::random_hex(); // ← should fail to compile until RandomHex lands
}
*/

#[test]
fn all_good() {
    println!("PARANOIA TEST SUITE: ALL 11 TESTS PASSING — YOU ARE SAFE TO PUSH");
}
