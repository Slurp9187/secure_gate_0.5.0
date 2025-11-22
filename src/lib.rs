// src/lib.rs
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

mod dynamic;
mod fixed;
mod macros;

#[cfg(feature = "zeroize")]
mod zeroize;

// Public types
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// src/lib.rs — add this line
// pub use macros::{fixed_secret, secure};
