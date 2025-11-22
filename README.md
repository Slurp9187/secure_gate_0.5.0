// v0.4.3
let pw: SecurePassword = "hunter2".into();
pw.expose_secret_mut().push('!');

// v0.5.0
let mut pw = Dynamic::<String>::new("hunter2".to_string());
pw.push('!');   // DerefMut