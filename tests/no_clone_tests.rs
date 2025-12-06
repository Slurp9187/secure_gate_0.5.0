// tests/no_clone_tests.rs
#[cfg(test)]
mod tests {
    use secure_gate::{DynamicNoClone, Fixed, FixedNoClone};

    #[test]
    fn fixed_no_clone_cannot_be_cloned() {
        let _key = FixedNoClone::new([0u8; 32]);
        // let _ = key.clone(); // ← compile error if uncommented
    }

    #[test]
    fn fixed_no_clone_has_full_api_parity() {
        let mut key = FixedNoClone::new([42u8; 32]);
        assert_eq!(key.expose_secret()[0], 42);
        key.expose_secret_mut()[0] = 99;
        assert_eq!(key[0], 99);
        let raw: [u8; 32] = key.into_inner();
        assert_eq!(raw[0], 99);
    }

    #[test]
    fn from_fixed_to_no_clone_works() {
        let fixed = Fixed::new([1u8; 32]);
        let no_clone = fixed.no_clone(); // ← now compiles!
        assert_eq!(no_clone.expose_secret()[0], 1);
        // no_clone.clone(); // ← hard error
    }

    #[test]
    fn dynamic_no_clone_string() {
        let mut pw: DynamicNoClone<String> = DynamicNoClone::new(Box::new("secret".into()));
        pw.push_str("123");
        assert_eq!(&*pw, "secret123");
        let s = pw.finish_mut();
        assert_eq!(s, "secret123");
    }
}
