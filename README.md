# iam-rust-common

Shared Rust library for the IAM microservices: config, JWT, password hashing
(argon2), telemetry, email, and the NATS JetStream event contract/helpers.
Consumed via a git dependency by the auth, user and gateway services.

```toml
common = { git = "https://github.com/malvinpratama/iam-rust-common", tag = "v0.4.0" }
```

Part of the [iam-rust](https://github.com/malvinpratama/iam-rust) platform.
