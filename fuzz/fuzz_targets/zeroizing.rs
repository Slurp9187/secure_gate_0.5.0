#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, DynamicZeroizing, Fixed, FixedZeroizing};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ---------- FixedZeroizing<[u8; N]> ----------
    // FixedZeroizing = Zeroizing<T> → use .as_ref() or direct indexing
    for &n in &[16usize, 32, 64, 128, 256, 512, 1024] {
        if data.len() < n {
            continue;
        }
        let mut arr = [0u8; 1024];
        arr[..n].copy_from_slice(&data[..n]);
        let secret = FixedZeroizing::new(arr);
        let _ = &secret[..n]; // ← safe, public, works
        let _ = secret.as_ref(); // ← also public
        drop(secret); // zeroized
    }

    // ---------- DynamicZeroizing<Vec<u8>> ----------
    // DynamicZeroizing = SecretBox<T> → must use .expose_secret()
    // But trait not in scope → so we bring it in from the dependency
    use secrecy::ExposeSecret; // ← allowed in fuzz target, not part of your public API
    let vec_secret = DynamicZeroizing::<Vec<u8>>::new(Box::new(data.to_vec()));
    let _ = vec_secret.expose_secret().len();
    drop(vec_secret);

    // ---------- DynamicZeroizing<String> ----------
    let s = String::from_utf8_lossy(data).to_string();
    let str_secret = DynamicZeroizing::<String>::new(Box::new(s));
    let _ = str_secret.expose_secret().len();
    drop(str_secret);

    // ---------- Non-zeroizing ----------
    let _ = Fixed::<[u8; 32]>::new([0u8; 32]);
    let _ = Dynamic::<Vec<u8>>::new(Box::new(data.to_vec()));
});
