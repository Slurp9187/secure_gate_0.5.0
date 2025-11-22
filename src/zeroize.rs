// src/zeroize.rs — FINAL VERSION
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "zeroize")]
use secrecy::SecretBox;

#[cfg(feature = "zeroize")]
pub type FixedZeroizing<T> = Zeroizing<T>;

#[cfg(feature = "zeroize")]
pub type DynamicZeroizing<T> = SecretBox<T>;

#[cfg(feature = "zeroize")]
impl<T: Zeroize> From<crate::Fixed<T>> for FixedZeroizing<T> {
    fn from(fixed: crate::Fixed<T>) -> Self {
        Zeroizing::new(fixed.0)
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> From<crate::Dynamic<T>> for DynamicZeroizing<T> {
    fn from(dynamic: crate::Dynamic<T>) -> Self {
        SecretBox::new(dynamic.0)
    }
}

// Zeroize — no Copy bound
#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for crate::Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> Zeroize for crate::Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// ZeroizeOnDrop — no Copy bound
#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for crate::Fixed<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for crate::Dynamic<T> {}
