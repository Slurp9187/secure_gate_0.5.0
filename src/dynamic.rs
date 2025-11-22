// src/dynamic.rs
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

use crate::{Expose, ExposeMut};

pub struct Dynamic<T: ?Sized>(pub Box<T>); // ← pub field

impl<T: ?Sized> Dynamic<T> {
    #[inline(always)]
    pub fn new_boxed(value: Box<T>) -> Self {
        Dynamic(value)
    }

    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        Dynamic(value.into())
    }
}

impl<T: ?Sized> Deref for Dynamic<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for Dynamic<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Dynamic<[REDACTED]>")
    }
}

// src/dynamic.rs — add these methods
impl<T: ?Sized> Dynamic<T> {
    pub fn view(&self) -> Expose<'_, T> {
        Expose(&self.0)
    }

    pub fn view_mut(&mut self) -> ExposeMut<'_, T> {
        ExposeMut(&mut self.0)
    }
}
