# Rust-HMAC-SHA

![CI status](https://github.com/lrazovic/rust-hmac-sha1/actions/workflows/ci.yml/badge.svg)
![creates.io version](https://img.shields.io/crates/v/hmac-sha)

A pure Rust implementation of the Hash-based Message Authentication Code Algoritm for SHA-{1,2,3}.

## Origins and motivations

This repo is a fork of [Rust-HMAC-SHA1](https://github.com/pantsman0/rust-hmac-sha1) by @pantsman0/Philip Woolford.
Unlike the original version, it supports SHA-2 and SHA-3 in addition to SHA-1. In addition this fork uses the implementations of SHA provided by [RustCrypto](https://github.com/RustCrypto/hashes)

## Usage

To import rust-hmac-sha add the following to your Cargo.toml:

```toml
[dependencies]
hmac-sha = "0.2"
```

To use rust-hmac-sha add the following to your crate root:

```rust
use hex;
use hmacsha::hmac_sha1;

let mut digest = [0u8; 20];
let secret_key = "A very strong secret".as_bytes();
let message = "My secret message".as_bytes();
hmac_sha1(secret_key, &message, &mut digest);
println!("{}", hex::encode(digest));
```

## Contributions

Any contributions are welcome. This was implemented as a learning experience and any advice is appreciated.

## License

This crate is licensed under the MIT or Apache licenses, as is its dependancies of the [RustCrypto](https://github.com/RustCrypto/hashes) family.
The original crate was licensed under the BSD 3-Clause license, as the old dependency [sha1](https://github.com/mitsuhiko/rust-sha1)