// src/lib.rs
// secure-gate v0.5.0 — The Final Form

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod expose;
mod fixed;
mod macros;

// Feature-gated modules
#[cfg(feature = "zeroize")]
mod zeroize;

#[cfg(feature = "serde")]
mod serde;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

pub use expose::{Expose, ExposeMut};

// Zeroize integration (opt-in)
#[cfg(feature = "zeroize")]
pub use zeroize::{DynamicZeroizing, FixedZeroizing};
