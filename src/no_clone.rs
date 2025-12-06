// src/no_clone.rs
//! Unconditional, compiler-enforced non-cloneable secret wrappers.
//!
//! These types are **never** `Clone` or `Copy` — under any feature combination.
//! They exist solely to make accidental duplication of master keys, HSM seeds,
//! or root passwords a **hard compiler error**.
//!
//! Use via `.no_clone()` — loud, intentional, and per-variable.
//!
//! This is the crown jewel of secure-gate 0.6.0.

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

extern crate alloc;
use alloc::boxed::Box;

/// Private marker to prevent `Clone`/`Copy` — stable Rust workaround for negative impls.
#[doc(hidden)]
pub enum PhantomNonClone {}

/// Stack-allocated secret that can **never** be cloned or copied.
pub struct FixedNoClone<T>(T, PhantomData<PhantomNonClone>);

/// Heap-allocated secret that can **never** be cloned.
pub struct DynamicNoClone<T: ?Sized>(Box<T>, PhantomData<PhantomNonClone>);

// ───── Constructors ─────

impl<T> FixedNoClone<T> {
    /// Create a new non-cloneable fixed secret.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        FixedNoClone(value, PhantomData)
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    /// Create a new non-cloneable dynamic secret from a boxed value.
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        DynamicNoClone(value, PhantomData)
    }
}

// ───── Core ergonomics (identical to Fixed/Dynamic) ─────

impl<T> Deref for FixedNoClone<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for FixedNoClone<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> Deref for DynamicNoClone<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for DynamicNoClone<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> fmt::Debug for FixedNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

impl<T: ?Sized> fmt::Debug for DynamicNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

// ───── Canonical secret access ─────

impl<T> FixedNoClone<T> {
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

// ───── Specialized helpers (finish_mut) ─────

impl DynamicNoClone<String> {
    /// Shrink capacity to exact length — eliminates slack.
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut **self;
        s.shrink_to_fit();
        s
    }
}

impl DynamicNoClone<Vec<u8>> {
    /// Shrink capacity to exact length — eliminates slack.
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut **self;
        v.shrink_to_fit();
        v
    }
}

// ───── Zeroize integration (only when enabled) ─────

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for FixedNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> Zeroize for DynamicNoClone<T> {
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for FixedNoClone<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicNoClone<T> {}
