# Rust-HMAC-SHA1

![crates.io version](https://img.shields.io/crates/v/hmac-sha1.svg)

A pure rust implementation of the Hash-based Message Authentication Code Algoritm for SHA1.

## Usage

To import rust-hmac-sha1 add the following to your Cargo.toml:
```toml
[dependencies]
hmac-sha1 = "^0.2"
```

To use rust-hmac-sha1, simply use the single provided function:
```rust
    let hmac_digest: [u8; hmac_sha1::SHA1_DIGEST_BYTES]  = hmac_sha1::hmac_sha1(key, message);
```
## Contributions

Any contributions are welcome.

This was implemented as a learning experience - an implementation for hmac-sha1 from just a SHA1 hasher is included in 0.1.x versions.

## License

This crate is licensed under the BSD 3-Clause license.

This crate also depends on the [RustCrypto Project](https://github.com/RustCrypto) to provide the underlying cryptographic implementations.
These crates are dual licensed under MIT and Apache-2.0.
