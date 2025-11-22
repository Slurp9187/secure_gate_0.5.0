// src/macros.rs
// Ergonomic constructor macro + type aliases only

/// Create a secret from an expression or literal.
#[macro_export]
macro_rules! secure {
    ($ty:ty, $expr:expr) => {
        $crate::Fixed::<$ty>::new($expr)
    };
    ($ty:ty, [$($val:expr),+ $(,)?]) => {
        $crate::Fixed::<$ty>::new([$($val),+])
    };
}

/// Define a fixed-size secret type alias.
#[macro_export]
macro_rules! fixed_secret {
    ($name:ident, $size:literal) => {
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}
