// src/serde.rs
//! Serde integration for secure-gate types.
//!
//! This module provides optional serialization/deserialization support via the `serde` feature.
//!
//! - `Fixed<T>` serializes/deserializes transparently like `T`
//! - `Dynamic<T>` serializes like `T`, but deserialization is **intentionally disabled** for security
//!
//! Always deserialize secrets from trusted sources only, then wrap manually with `Dynamic::new()`.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::{Dynamic, Fixed};

/// Serialize `Fixed<T>` as if it were the inner `T`.
///
/// Forwards directly to `T::serialize()`.
#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Deserialize into `Fixed<T>` from the inner `T`.
///
/// Forwards directly to `T::deserialize()`.
#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Fixed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Fixed)
    }
}

/// Serialize `Dynamic<T>` as if it were the inner `T`.
///
/// Forwards directly to `T::serialize()`.
#[cfg(feature = "serde")]
impl<T: ?Sized + Serialize> Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

/// Deserialization for `Dynamic<T>` is intentionally disabled.
///
/// # Security Note
///
/// Secrets should **never** be deserialized from untrusted input automatically.
/// Deserialize into the inner type first, then wrap manually with `Dynamic::new()`.
#[cfg(feature = "serde")]
impl<'de, T: ?Sized> Deserialize<'de> for Dynamic<T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "Deserialization of Dynamic<T> is intentionally disabled for security reasons. \
             Secrets should never be automatically loaded from untrusted input. \
             Instead, deserialize into the inner type first, then wrap with Dynamic::new().",
        ))
    }
}
