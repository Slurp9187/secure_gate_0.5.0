// src/fixed.rs
//! Stack-allocated, zero-cost secure wrappers for fixed-size secrets.
//!
//! `Fixed<T>` is a transparent wrapper around any type `T` that lives entirely on the stack.
//! It provides:
//! - Zero-cost abstraction (`Deref`/`DerefMut`)
//! - Automatic redaction in `Debug`
//! - Full `expose_secret()` API (the canonical way to access the secret)
//! - Special ergonomics for `[u8; N]` arrays (crypto keys, nonces, etc.)

use core::convert::From;
use core::ops::{Deref, DerefMut};

/// A zero-cost, stack-allocated wrapper for sensitive data.
///
/// `Fixed<T>` stores its value directly in the struct (no heap allocation).
/// It behaves exactly like `T` thanks to `Deref`/`DerefMut`, but:
/// - Prints as `[REDACTED]` in debug output
/// - Provides `.expose_secret()` as the explicit, loud way to access the secret
/// - Works perfectly with `fixed_alias!` for beautiful type aliases
///
/// # Examples
///
/// ```
/// use secure_gate::{Fixed, fixed_alias};
///
/// // Define a beautiful type alias (this is the recommended pattern)
/// fixed_alias!(Aes256Key, 32);
///
/// // Generate a random key and convert it directly
/// let raw_key = [42u8; 32];  // In real code: use rand::Rng::gen()
/// let key: Aes256Key = raw_key.into();
///
/// // Access the bytes
/// let bytes: &[u8] = key.expose_secret();
/// assert_eq!(bytes.len(), 32);
/// ```
pub struct Fixed<T>(pub T);

impl<T> Fixed<T> {
    /// Create a new `Fixed` wrapper around a value.
    ///
    /// This is usually not called directly — prefer `fixed_alias!` + `.into()`.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
    }
}

impl<T> Deref for Fixed<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Fixed<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Convert a byte slice into a fixed-size secret.
///
/// Panics if the slice length doesn't match exactly.
///
/// # Panics
///
/// Panics with "slice length mismatch" if `bytes.len() != N`.
impl<const N: usize> Fixed<[u8; N]> {
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

/// Convert a raw array into a fixed-size secret.
///
/// This enables the beautiful `let key: Aes256Key = rng.gen().into();` pattern.
impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

/// Borrow as a byte slice — useful for crypto APIs.
impl<const N: usize> AsRef<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Mutably borrow as a byte slice — e.g. for key scheduling.
impl<const N: usize> AsMut<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// All `Fixed<T>` values print as `[REDACTED]` to prevent accidental leakage.
impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> Fixed<T> {
    /// Access the secret value immutably.
    ///
    /// This is the **canonical** way to read the secret — loud and clear.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::{Fixed, fixed_alias};
    ///
    /// fixed_alias!(Aes256Key, 32);
    ///
    /// let key: Aes256Key = [1u8; 32].into();
    /// let bytes: &[u8] = key.expose_secret();
    /// assert_eq!(bytes[0], 1);
    /// ```
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Access the secret value mutably.
    ///
    /// Use this for in-place operations like key derivation.
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// **Deprecated**: Use [`expose_secret`] instead.
    ///
    /// Kept for backward compatibility with v0.5.x.
    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    /// **Deprecated**: Use [`expose_secret_mut`] instead.
    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// This is useful when you need to pass the secret to a function that takes ownership.
    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// `Clone` is implemented when the inner type is `Clone`.
impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// `Copy` is implemented for small fixed-size byte arrays.
impl<const N: usize> Copy for Fixed<[u8; N]> where [u8; N]: Copy {}
