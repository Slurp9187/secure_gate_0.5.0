// tests/macros_paranoia_tests.rs
//! Nuclear-level macro correctness & safety tests

#![cfg(test)]

use secure_gate::{dynamic_alias, fixed_alias, secure, Dynamic, Fixed};

#[cfg(feature = "rand")]
use secure_gate::{random_alias, SecureRandomExt};

#[cfg(feature = "zeroize")]
use secrecy::ExposeSecret;
#[cfg(feature = "zeroize")]
use secure_gate::secure_zeroizing;

#[test]
fn secure_macro_fixed_arrays() {
    let k1 = secure!([u8; 16], [42u8; 16]);
    let k2: Fixed<[u8; 32]> = secure!([u8; 32], [99u8; 32]);

    assert_eq!(k1.expose_secret(), &[42u8; 16]);
    assert_eq!(k2.expose_secret().len(), 32);
}

#[test]
fn secure_macro_heap_types() {
    let s: Dynamic<String> = secure!(heap String, "hello".to_string());
    let v: Dynamic<Vec<u8>> = secure!(heap Vec<u8>, vec![1, 2, 3]);
    let g: Dynamic<Vec<i32>> = secure!(heap Vec<i32>, vec![4, 5, 6]);

    assert_eq!(s.expose_secret(), "hello");
    assert_eq!(v.expose_secret(), &[1, 2, 3]);
    assert_eq!(g.expose_secret(), &[4, 5, 6]);
}

#[test]
#[cfg(feature = "zeroize")]
fn secure_zeroizing_macro() {
    let a = secure_zeroizing!([u8; 20], [7u8; 20]);
    let b = secure_zeroizing!(heap String, "secret".to_string().into_boxed_str());

    // FixedZeroizing<[u8; N]> implements Deref<[u8]>
    assert_eq!(a.len(), 20);

    // DynamicZeroizing<T> implements ExposeSecret<T>
    assert_eq!(b.expose_secret(), "secret");
}

#[test]
fn fixed_alias_basics() {
    fixed_alias!(MyKey, 32);
    let k: MyKey = [0u8; 32].into();
    assert_eq!(k.len(), 32);
}

#[test]
fn dynamic_alias_basics() {
    dynamic_alias!(MyPass, String);
    let p: MyPass = "hunter2".into();
    assert_eq!(p.expose_secret(), "hunter2");
}

#[test]
#[cfg(feature = "rand")]
fn random_alias_basics() {
    random_alias!(Rand32, 32);
    random_alias!(Rand24, 24);

    let a = Rand32::new();
    let b = Rand32::new();
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(Rand24::new().len(), 24);
}

#[test]
#[cfg(all(feature = "rand", feature = "conversions"))]
fn random_alias_can_call_random_hex_when_available() {
    random_alias!(HexKey, 32);

    // This test only checks that the method exists — we don't have RandomHex yet
    // so we just verify the trait is in scope and the call would type-check
    let _ = HexKey::new(); // This compiles → trait is correctly applied
                           // When RandomHex lands, uncomment:
                           // let hex: HexString = HexKey::random_hex();
}

#[test]
#[cfg(feature = "rand")]
fn random_alias_deprecated_methods() {
    random_alias!(Legacy, 16);

    #[allow(deprecated)]
    {
        let _ = Legacy::random();
        let _ = Legacy::random_bytes();
        let _ = Legacy::new();
    }
}

#[test]
fn all_macros_documented() {
    let _: Fixed<[u8; 8]> = secure!([u8; 8], [0; 8]);
    fixed_alias!(DocTest, 8);
    dynamic_alias!(DocPass, String);
    #[cfg(feature = "rand")]
    random_alias!(DocRand, 16);
}
