// ==========================================================================
// src/rng.rs
// ==========================================================================
use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::TryRngCore;

pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Fixed::new(bytes))
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    pub fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Dynamic::from(bytes))
    }

    pub fn generate_string(len: usize) -> Dynamic<String> {
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let byte = loop {
                let val = OsRng
                    .try_next_u32()
                    .expect("OsRng failed — this should never happen on supported platforms");
                let candidate = val % 62;
                if val < (u32::MAX / 62) * 62 {
                    break candidate as u8;
                }
            };
            let c = if byte < 10 {
                (b'0' + byte) as char
            } else if byte < 36 {
                (b'a' + (byte - 10)) as char
            } else {
                (b'A' + (byte - 36)) as char
            };
            s.push(c);
        }
        Dynamic::from(s)
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }

    #[inline(always)]
    pub fn into_inner(self) -> Dynamic<Vec<u8>> {
        self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
