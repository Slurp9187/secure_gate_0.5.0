// fuzz/fuzz_targets/expose.rs
// Fuzz target: stress test expose_secret() / expose_secret_mut() borrowing rules
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    let fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // 1. Growable Vec<u8> — mutation + shrink
    let mut vec_dyn = dyn_vec.clone();
    vec_dyn.reverse();
    vec_dyn.truncate(data.len().min(64));
    vec_dyn.extend_from_slice(b"fuzz");
    vec_dyn.shrink_to_fit();

    // 2. Fixed-size array — mutable access
    let mut fixed_key = fixed_32;
    fixed_key.expose_secret_mut()[0] = 0xFF;

    // 3. String mutation
    let mut dyn_str_mut = dyn_str.clone();
    dyn_str_mut.push('!');

    // 4. Immutable borrow from fixed
    let _nonce_arr = fixed_key.expose_secret();
    let fixed_nonce = Fixed::new([0u8; 32]);
    let _ = fixed_nonce.len();

    // 5. Clone + into_inner (only when zeroize enabled)
    let cloneable = Dynamic::<Vec<u8>>::new(vec![1u8, 2, 3]);
    let _ = cloneable.clone();
    let _default = Dynamic::<String>::new(String::new());

    #[cfg(feature = "zeroize")]
    let _inner: Box<Vec<u8>> = cloneable.into_inner();

    // 6. finish_mut helpers — eliminate slack capacity
    {
        let mut v = Dynamic::<Vec<u8>>::new(vec![0u8; 1000]);
        v.truncate(10);
        let _ = v.finish_mut();
    }
    {
        let mut s = Dynamic::<String>::new("long string with excess capacity".to_string());
        s.push_str("!!!");
        let _ = s.finish_mut();
    }

    // 7. Borrowing stress — immutable
    {
        let view_imm1 = vec_dyn.expose_secret();
        let _ = view_imm1.len();

        if !data.is_empty() && data[0] % 2 == 0 {
            let view_imm2 = vec_dyn.expose_secret();
            let _ = view_imm2.as_slice()[0];
            let nested_ref: &[u8] = &**view_imm2;
            let _ = nested_ref.len();
        }
    }

    // 8. Borrowing stress — mutable
    {
        let view_mut = fixed_key.expose_secret_mut();
        view_mut[1] = 0x42;

        let str_imm = dyn_str_mut.expose_secret();
        let _ = str_imm.as_str();

        let str_mut = dyn_str_mut.expose_secret_mut();
        str_mut.push('?');
        let nested_mut: &mut String = &mut *str_mut;
        nested_mut.push('@');
    }

    // 9. Scoped drop stress — ensure drop doesn't panic during borrow
    {
        let temp_dyn = Dynamic::<Vec<u8>>::new(vec![0u8; 10]);
        let temp_view = temp_dyn.expose_secret();
        let _ = temp_view.len();
        drop(temp_dyn); // Must not panic
    }
});
