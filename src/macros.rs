// ==========================================================================
// src/macros.rs
// ==========================================================================

/// Creates a type alias for a fixed-size secure secret.
///
/// # Examples
///
/// ```
/// use secure_gate::fixed_alias;
///
/// fixed_alias!(Aes256Key, 32);                    // pub by default
/// fixed_alias!(pub(crate) InternalKey, 64);       // crate-internal
/// fixed_alias!(pub(in super) ParentKey, 16);      // only parent module
/// ```
#[macro_export]
macro_rules! fixed_alias {
    // Full visibility control
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", $size, " bytes)")]
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    // Convenience: default = pub
    ($name:ident, $size:literal) => {
        $crate::fixed_alias!(pub $name, $size);
    };
}

/// Creates a generic fixed-size secure buffer type.
///
/// # Examples
///
/// ```
/// use secure_gate::fixed_generic_alias;
///
/// fixed_generic_alias!(GenericKey, "My custom fixed-size key");
/// fixed_generic_alias!(Buffer); // uses default doc
/// ```
#[macro_export]
macro_rules! fixed_generic_alias {
    ($vis:vis $name:ident, $doc:literal) => {
        #[doc = $doc]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident, $doc:literal) => {
        $crate::fixed_generic_alias!(pub $name, $doc);
    };
    ($vis:vis $name:ident) => {
        #[doc = "Fixed-size secure byte buffer"]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident) => {
        $crate::fixed_generic_alias!(pub $name);
    };
}

/// Creates a type alias for a random-only fixed-size secret.
///
/// Can only be instantiated via cryptographically secure RNG.
#[macro_export]
macro_rules! fixed_alias_rng {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", $size, " bytes)")]
        $vis type $name = $crate::rng::FixedRng<$size>;
    };
    ($name:ident, $size:literal) => {
        $crate::fixed_alias_rng!(pub $name, $size);
    };
}

/// Creates a type alias for a heap-allocated secure secret.
#[macro_export]
macro_rules! dynamic_alias {
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty) => {
        $crate::dynamic_alias!(pub $name, $inner);
    };
}

/// Creates a generic heap-allocated secure secret type alias.
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty, $doc:literal) => {
        $crate::dynamic_generic_alias!(pub $name, $inner, $doc);
    };
    ($vis:vis $name:ident, $inner:ty) => {
        $crate::dynamic_generic_alias!(
            $vis $name,
            $inner,
            concat!("Secure heap-allocated ", stringify!($inner))
        );
    };
    ($name:ident, $inner:ty) => {
        $crate::dynamic_generic_alias!(pub $name, $inner);
    };
}
