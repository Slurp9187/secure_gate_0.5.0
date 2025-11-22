// src/lib.rs
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

mod dynamic;
mod expose;
mod fixed;
mod macros;

#[cfg(feature = "zeroize")]
mod zeroize;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

pub use expose::{Expose, ExposeMut};
