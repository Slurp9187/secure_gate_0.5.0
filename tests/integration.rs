use secure_gate_0_5_0::{fixed_secret, secure};
use secure_gate_0_5_0::{Dynamic, Fixed};

// tests/integration.rs
#[test]
fn it_works() {
    let key = Fixed::new([0u8; 32]);

    // Option 1 — turbofish (recommended)
    let pw = Dynamic::<String>::new("hunter2".to_string());

    // Option 2 — type ascription (also works)
    // let pw: Dynamic<String> = Dynamicnas::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert_eq!(pw.len(), 7);
    assert_eq!(&*pw, "hunter2");

    println!("{key:?}"); // Fixed<[REDACTED]>
    println!("{pw:?}"); // Dynamic<[REDACTED]>
}

#[test]
fn macros_work() {
    fixed_secret!(TestKey, 16); // alias only — no From in macro
    let key = TestKey::new([0u8; 16]);
    assert_eq!(key.len(), 16);

    let iv = secure!([u8; 12], [1u8; 12]);
    assert_eq!(iv.len(), 12);
}

#[test]
fn expose_views() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert_eq!(pw.as_str(), "hunter2");

    pw.push('!');
    key[0] = 1;

    assert_eq!(&*pw, "hunter2!");
    assert_eq!(key[0], 1);

    let s: &str = &pw;
    assert_eq!(s, "hunter2!");
}

#[test]
fn expose_slice() {
    let slice = Dynamic::<[u8]>::new_boxed(Box::new([1u8; 16]));
    let view = slice.view();
    assert_eq!(view.as_slice(), &[1u8; 16]);
}
