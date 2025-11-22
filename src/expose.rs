// src/expose.rs
// Zero-cost views into secrets — no unsafe, ever

use alloc::string::String;
use core::ops::{Deref, DerefMut};

/// Immutable view into a secret value
pub struct Expose<'a, T: ?Sized>(pub &'a T);

/// Mutable view into a secret value
pub struct ExposeMut<'a, T: ?Sized>(pub &'a mut T);

impl<'a, T: ?Sized> Deref for Expose<'a, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> Deref for ExposeMut<'a, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> DerefMut for ExposeMut<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

// === String views ===

impl<'a> Expose<'a, String> {
    #[inline(always)]
    pub fn as_string(&self) -> &String {
        self.0
    }
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'a> ExposeMut<'a, String> {
    #[inline(always)]
    pub fn as_string(&mut self) -> &mut String {
        self.0
    }
    #[inline(always)]
    pub fn as_str_mut(&mut self) -> &mut str {
        self.0.as_mut_str()
    }
}

// === str views (immutable only) ===

impl<'a> Expose<'a, str> {
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.0
    }
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// === Vec<u8> views ===

impl<'a> Expose<'a, Vec<u8>> {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<'a> ExposeMut<'a, Vec<u8>> {
    #[inline(always)]
    pub fn as_vec(&mut self) -> &mut Vec<u8> {
        self.0
    }
    #[inline(always)]
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

// === [u8] slice views (immutable only) ===

impl<'a> Expose<'a, [u8]> {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.0
    }
}

// === AsRef / AsMut ===

impl<'a, T: ?Sized> AsRef<T> for Expose<'a, T> {
    #[inline(always)]
    fn as_ref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> AsRef<T> for ExposeMut<'a, T> {
    #[inline(always)]
    fn as_ref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> AsMut<T> for ExposeMut<'a, T> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut T {
        self.0
    }
}
