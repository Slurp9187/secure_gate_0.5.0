   # secure-gate

   Zero-cost secure wrappers for secrets — stack for fixed, heap for dynamic.

   ## Quick Start

   ```rust
   use secure_gate::{Fixed, Dynamic, secure, fixed_secret};

   // Fixed-size key (stack-only when zeroize off)
   fixed_secret!(Aes256Key, 32);
   let key: Aes256Key = [0u8; 32].into();

   // Dynamic password (heap, full protection)
   let pw = Dynamic::<String>::new("hunter2".to_string());

   // Natural borrowing
   assert_eq!(pw.len(), 7);
   pw.push('!');
   assert_eq!(&*pw, "hunter2!");

   // Macros
   let iv = secure!([u8; 16], [1u8; 16]);
   ```

   ## Features

   - `zeroize`: Full wiping + auto-drop zeroing
   - `serde`: Serialization support

   ## License

   MIT OR Apache-2.0