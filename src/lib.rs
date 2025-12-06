//! # secure-gate: Zero-cost secure wrappers for secrets
//!
//! This crate provides safe, ergonomic wrappers for handling sensitive data in memory
//! with zero runtime overhead. It supports both stack-allocated fixed-size secrets
//! and heap-allocated dynamic secrets.
//!
//! ## Core Types
//!
//! - [`Fixed<T>`] — Stack-allocated, zero-cost wrapper
//! - [`Dynamic<T>`] — Heap-allocated wrapper with full `.into()` ergonomics
//! - [`FixedNoClone<T>`] / [`DynamicNoClone<T>`] — **Unconditionally non-cloneable** versions (v0.6.0)
//!   → Use via `.no_clone()` — prevents accidental duplication of master keys
//!
//! ## Features
//!
//! | Feature       | Description                                                                 |
//! |---------------|-----------------------------------------------------------------------------|
//! | `zeroize`     | Automatic zeroing on drop (including spare capacity)                       |
//! | `rand`        | Type-safe random generation via `RandomBytes<N>::new()` and `random_alias!` |
//! | `conversions` | `.to_hex()`, `.to_base64url()`, `.ct_eq()`, `HexString`, `RandomHex`        |
//! | `serde`       | Serialization (deserialization of `Dynamic<T>` intentionally disabled)     |
//!
//! Works in `no_std` + `alloc`. Only pay for what you use.
//!
//! # Quick Start (v0.6.0)
//!
//! ```rust
//! use secure_gate::{fixed_alias, dynamic_alias};
//!
//! fixed_alias!(Aes256Key, 32);
//! dynamic_alias!(Password, String);
//!
//! // Normal — cloneable (rarely needed)
//! let session_key = Aes256Key::new(rng.gen());
//!
//! // Critical — **impossible to clone** (compiler-enforced)
//! let master_key = Aes256Key::no_clone(rng.gen());
//! // master_key.clone(); // ← hard compile error
//!
//! let pw: Password = "hunter2".into();
//! let root_pw = pw.no_clone(); // also impossible to clone
//! ```
//!
//! See individual modules for detailed documentation.

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod fixed;
mod macros;

// Always-public modules (v0.6.0+)
pub mod no_clone; // ← now unconditional
pub use no_clone::{DynamicNoClone, FixedNoClone};

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "conversions")]
pub mod conversions;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// RNG integration (opt-in)
#[cfg(feature = "rand")]
pub mod rng;

#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

// Conversions integration (opt-in)
#[cfg(feature = "conversions")]
pub use conversions::SecureConversionsExt;

#[cfg(all(feature = "rand", feature = "conversions"))]
pub use conversions::{HexString, RandomHex};
