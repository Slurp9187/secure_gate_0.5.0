// src/fixed.rs
//! Stack-allocated, zero-cost secure wrappers for fixed-size secrets.
//!
//! `Fixed<T>` is a transparent wrapper around any type `T` that lives entirely on the stack.
//! It provides:
//! - Zero-cost abstraction via `Deref`/`DerefMut`.
//! - Automatic redaction in `Debug` output.
//! - Explicit access via `.expose_secret()` (canonical API).
//! - Specialized ergonomics for `[u8; N]` arrays (e.g., crypto keys, nonces).
//!
//! # Examples
//!
//! ```
//! use secure_gate::{fixed_alias, Fixed};
//!
//! fixed_alias!(Aes256Key, 32);
//!
//! let raw_key = [42u8; 32]; // In real code: use rand::Rng::gen()
//! let key: Aes256Key = raw_key.into();
//!
//! assert_eq!(key.expose_secret()[0], 42);
//! ```

use core::convert::From;
use core::ops::{Deref, DerefMut};

/// A zero-cost, stack-allocated wrapper for sensitive data.
///
/// `Fixed<T>` stores its value directly in the struct (no heap allocation).
/// It behaves exactly like `T` via `Deref`/`DerefMut`, but redacts itself
/// in debug output and requires explicit access to the inner value.
///
/// Use this for fixed-size secrets like encryption keys or nonces.
///
/// # Examples
///
/// ```
/// use secure_gate::Fixed;
///
/// let secret: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
/// assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
/// ```
pub struct Fixed<T>(pub T);

impl<T> Fixed<T> {
    /// Creates a new `Fixed` wrapper around the given value.
    ///
    /// This is zero-cost and usually not called directly—prefer `fixed_alias!` + `.into()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([42u8; 32]);
    /// assert_eq!(secret.len(), 32);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
    }
}

impl<T> Deref for Fixed<T> {
    type Target = T;

    /// Dereferences the wrapper to access the inner value immutably.
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Fixed<T> {
    /// Dereferences the wrapper mutably to access the inner value.
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Converts a byte slice into a fixed-size secret array.
///
/// # Panics
///
/// Panics if `bytes.len() != N` with the message "slice length mismatch".
///
/// # Examples
///
/// ```
/// use secure_gate::Fixed;
///
/// let bytes = [42u8; 32];
/// let secret = Fixed::from_slice(&bytes);
/// assert_eq!(secret.expose_secret(), &[42u8; 32]);
/// ```
impl<const N: usize> Fixed<[u8; N]> {
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

/// Converts a raw array into a fixed-size secret.
///
/// Enables idiomatic construction like `Aes256Key::from(rng.gen())`.
///
/// # Examples
///
/// ```
/// use secure_gate::Fixed;
///
/// let secret: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
/// assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
/// ```
impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

/// Borrows the fixed byte array as a slice.
///
/// Useful for passing to crypto APIs expecting `&[u8]`.
///
/// # Examples
///
/// ```
/// use secure_gate::Fixed;
///
/// let secret: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
/// let slice: &[u8] = secret.as_ref();
/// assert_eq!(slice, &[1, 2, 3, 4]);
/// ```
impl<const N: usize> AsRef<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Mutably borrows the fixed byte array as a slice.
///
/// Useful for in-place modifications like key scheduling.
///
/// # Examples
///
/// ```
/// use secure_gate::Fixed;
///
/// let mut secret: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
/// let slice: &mut [u8] = secret.as_mut();
/// slice[0] = 42;
/// assert_eq!(secret.expose_secret(), &[42, 2, 3, 4]);
/// ```
impl<const N: usize> AsMut<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// All `Fixed<T>` values print as "[REDACTED]" to prevent accidental leakage.
impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> Fixed<T> {
    /// Accesses the secret value immutably.
    ///
    /// This is the canonical, explicit way to read the secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Fixed;
    ///
    /// let secret: Fixed<i32> = Fixed::new(42);
    /// assert_eq!(*secret.expose_secret(), 42);
    /// ```
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Accesses the secret value mutably.
    ///
    /// Use for in-place modifications.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Fixed;
    ///
    /// let mut secret: Fixed<i32> = Fixed::new(42);
    /// *secret.expose_secret_mut() += 1;
    /// assert_eq!(*secret.expose_secret(), 43);
    /// ```
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// **Deprecated**: Use [`expose_secret`] instead.
    ///
    /// This method forwards to [`expose_secret`] for compatibility.
    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    /// **Deprecated**: Use [`expose_secret_mut`] instead.
    ///
    /// This method forwards to [`expose_secret_mut`] for compatibility.
    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    /// Consumes the wrapper and returns the inner value.
    ///
    /// Useful for passing ownership to functions expecting `T`.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Fixed;
    ///
    /// let secret: Fixed<i32> = Fixed::new(42);
    /// let value: i32 = secret.into_inner();
    /// assert_eq!(value, 42);
    /// ```
    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Implements `Clone` when the inner type is `Clone`.
impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Implements `Copy` for small fixed-size byte arrays.
impl<const N: usize> Copy for Fixed<[u8; N]> where [u8; N]: Copy {}
