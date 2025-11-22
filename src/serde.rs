// src/serde.rs
// Serde integration — only compiled when feature is enabled

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::{Dynamic, Fixed};

// Fixed<T> — Serialize/Deserialize via inner T
#[cfg(feature = "serde")]
impl<T> Serialize for Fixed<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for Fixed<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Fixed)
    }
}

// Dynamic<T> — Serialize via deref, Deserialize not supported (security)
#[cfg(feature = "serde")]
impl<T: ?Sized> Serialize for Dynamic<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

// Deserialization for Dynamic is intentionally not implemented
// Loading secrets from untrusted input is a security risk
// Users can do: Dynamic::new_boxed(serde_json::from_str(...)?)
