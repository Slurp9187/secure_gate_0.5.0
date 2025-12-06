// src/lib.rs
//! # secure-gate: Zero-cost secure wrappers for secrets
//!
//! This crate provides safe, ergonomic wrappers for handling sensitive data in memory
//! with zero runtime overhead. It supports both stack-allocated fixed-size secrets
//! and heap-allocated dynamic secrets, with optional automatic zeroing on drop.
//!
//! Key components:
//! - [`Fixed<T>`]: Stack-allocated for fixed-size secrets (e.g., keys, nonces).
//! - [`Dynamic<T>`]: Heap-allocated for dynamic secrets (e.g., passwords, vectors).
//! - Zeroizing variants: [`FixedZeroizing<T>`] and [`DynamicZeroizing<T>`] for auto-wiping (with `zeroize` feature).
//! - Macros: [`fixed_alias!`], [`dynamic_alias!`], [`fixed_alias_rng!`], [`dynamic_alias_rng!`] for ergonomic usage.
//!
//! # Features
//!
//! - `zeroize`: Enables automatic memory wiping on drop via `zeroize` and `secrecy`.
//! - `rand`: Enables cryptographically secure random generation via `.rng()`.
//! - `conversions`: **Optional** — adds `.to_hex()`, `.to_hex_lowercase()`, `.to_base64url()`, and `.ct_eq()`.
//! - `serde`: Optional serialization support (deserialization disabled for `Dynamic<T>` for security).
//! - Works in `no_std` + `alloc` environments.
//!
//! # Quick Start
//!
//! ```
//! use secure_gate::{fixed_alias, dynamic_alias, fixed_alias_rng, dynamic_alias_rng};
//!
//! fixed_alias!(Aes256Key, 32);
//! dynamic_alias!(Password, String);
//!
//! #[cfg(feature = "rand")]
//! {
//!     fixed_alias_rng!(RandomAes256Key, 32);
//!     let key = RandomAes256Key::rng();  // ← only way to generate
//!     let _ = key.expose_secret();
//! }
//!
//! #[cfg(all(feature = "rand", feature = "conversions"))]
//! {
//!     use secure_gate::SecureConversionsExt;
//!     fixed_alias_rng!(RandomAes256Key, 32);
//!     let key = RandomAes256Key::rng();
//!     let hex = key.expose_secret().to_hex_lowercase();
//!     let b64 = key.expose_secret().to_base64url();
//!     assert!(key.expose_secret().ct_eq(key.expose_secret()));
//! }
//!
//! let pw: Password = "hunter2".into();
//! assert_eq!(pw.expose_secret(), "hunter2");
//! ```
//!
//! See individual modules for detailed documentation.

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod fixed;
mod macros;

// Feature-gated modules
#[cfg(feature = "zeroize")]
mod no_clone;

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "conversions")]
pub mod conversions;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// Zeroize integration (opt-in)
#[cfg(feature = "zeroize")]
pub use no_clone::DynamicNoClone;
#[cfg(feature = "zeroize")]
pub use no_clone::FixedNoClone;

// Re-export Zeroizing cleanly — no privacy conflict
#[cfg(feature = "zeroize")]
pub type Zeroizing<T> = ::zeroize::Zeroizing<T>;

#[cfg(feature = "zeroize")]
pub use ::zeroize::{Zeroize, ZeroizeOnDrop};

// RNG integration (opt-in)
#[cfg(feature = "rand")]
pub mod rng;

#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

// Conversions integration (opt-in)
#[cfg(feature = "conversions")]
pub use conversions::SecureConversionsExt;

#[cfg(all(feature = "rand", feature = "conversions"))]
pub use conversions::HexString;
#[cfg(all(feature = "rand", feature = "conversions"))]
pub use conversions::RandomHex;
