// src/macros.rs
//! Ergonomic macros for creating secure secret aliases.

/// Creates a type alias for a fixed-size secret.
///
/// # Example
///
/// ```
/// use secure_gate::fixed_alias;
///
/// fixed_alias!(Aes256Key, 32);
///
/// let key: Aes256Key = [0u8; 32].into();
/// assert_eq!(key.len(), 32);
/// ```
#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        /// Fixed-size secret of exactly `$size` bytes.
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}

/// Creates a type alias for a heap-allocated secure secret.
///
/// # Example
///
/// ```
/// use secure_gate::dynamic_alias;
///
/// dynamic_alias!(Password, String);
///
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $ty:ty) => {
        pub type $name = $crate::Dynamic<$ty>;
    };
}

/// Creates a type alias for a **random-only** fixed-size secret.
///
/// Requires the `rand` feature.
///
/// # Example
///
/// ```
/// use secure_gate::fixed_alias_rng;
///
/// #[cfg(feature = "rand")]
/// fixed_alias_rng!(Aes256Key, 32);
///
/// #[cfg(feature = "rand")]
/// let key = Aes256Key::rng();
/// ```
#[macro_export]
macro_rules! fixed_alias_rng {
    ($name:ident, $size:literal) => {
        #[cfg(feature = "rand")]
        pub type $name = $crate::rng::FixedRng<$size>;
    };
}

/// Creates a type alias for a **random-only** dynamic-length secret.
///
/// Requires the `rand` feature.
///
/// # Example
///
/// ```
/// use secure_gate::dynamic_alias_rng;
///
/// #[cfg(feature = "rand")]
/// dynamic_alias_rng!(Salt);
///
/// #[cfg(feature = "rand")]
/// let salt = Salt::rng(32);
/// ```
#[macro_export]
macro_rules! dynamic_alias_rng {
    ($name:ident) => {
        #[cfg(feature = "rand")]
        pub type $name = $crate::rng::DynamicRng;
    };
}
