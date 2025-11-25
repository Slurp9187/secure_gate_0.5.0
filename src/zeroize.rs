// src/zeroize.rs — FIXED VERSION with newtype for DynamicZeroizing
// Changes:
// - Added T: Zeroize bound on struct definition to enforce at compile time
// - Added T: DefaultIsZeroes to ?Sized impls where required for Zeroize on unsized types
// - Fixed ExposeSecret impl to use generic S (matches secrecy's trait definition)
// - Implemented redacted Debug manually (avoids derive issues with bounds)
// - Kept From impls with proper bounds

#[cfg(feature = "zeroize")]
use zeroize::{DefaultIsZeroes, Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "zeroize")]
pub type FixedZeroizing<T> = Zeroizing<T>;

// NEWTYPE: Wrap SecretBox to own the type and impl foreign traits safely
#[cfg(feature = "zeroize")]
pub struct DynamicZeroizing<T: ?Sized + Zeroize>(SecretBox<T>);

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> DynamicZeroizing<T> {
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        Self(SecretBox::new(value))
    }
}

// Redacted Debug (manual impl to avoid bound issues)
#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> core::fmt::Debug for DynamicZeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Forward ExposeSecret (fixed with generic S)
#[cfg(feature = "zeroize")]
impl<S: ?Sized + Zeroize> ExposeSecret<S> for DynamicZeroizing<S> {
    #[inline(always)]
    fn expose_secret(&self) -> &S {
        self.0.expose_secret()
    }
}

// Forward Zeroize
#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes> Zeroize for DynamicZeroizing<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Forward ZeroizeOnDrop (no additional bounds needed)
#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicZeroizing<T> {}

// Conversions from non-zeroizing wrappers
#[cfg(feature = "zeroize")]
impl<T: Zeroize> From<crate::Fixed<T>> for FixedZeroizing<T> {
    #[inline(always)]
    fn from(fixed: crate::Fixed<T>) -> Self {
        Zeroizing::new(fixed.0)
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> From<crate::Dynamic<T>> for DynamicZeroizing<T> {
    #[inline(always)]
    fn from(dynamic: crate::Dynamic<T>) -> Self {
        Self(SecretBox::new(dynamic.0))
    }
}

// Zeroize impls for non-zeroizing wrappers
#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for crate::Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes> Zeroize for crate::Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for crate::Fixed<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for crate::Dynamic<T> {}

// ————————————————————————————————————————————————————————————————
// Ergonomics: .into() support
// ————————————————————————————————————————————————————————————————

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Send + 'static> From<T> for DynamicZeroizing<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self::new(Box::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes + Send + 'static> From<Box<T>> for DynamicZeroizing<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self::new(boxed)
    }
}

#[cfg(feature = "zeroize")]
impl From<&str> for DynamicZeroizing<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self::new(Box::new(s.to_string()))
    }
}
