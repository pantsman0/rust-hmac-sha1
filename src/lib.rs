extern crate sha1;

const INNER_PAD_BYTE: u8 = 0x36;
const OUTER_PAD_BYTE: u8 = 0x5c;
const KEY_PAD_BYTE: u8 = 0x00;

const SHA1_DIGEST_BYTES: usize = 20;
const SHA1_KEY_BYTES: usize = 64;

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; SHA1_DIGEST_BYTES] {
    let mut sha1_ctx = sha1::Sha1::new();
    let mut auth_key: &mut [u8; SHA1_KEY_BYTES] = &mut [KEY_PAD_BYTE; SHA1_KEY_BYTES];

    // if the key is longer than the hasher's block length, it should be truncated using the hasher
    if { key.len() > SHA1_KEY_BYTES } {
        // derive new authentication from provided key
        sha1_ctx.update(key);

        // assign derived authentication key
        auth_key[..SHA1_DIGEST_BYTES].copy_from_slice(&(sha1_ctx.digest().bytes()));

        // reset hash for reuse
        sha1_ctx.reset();
    } else {
        auth_key[..key.len()].copy_from_slice(key);
    }

    // generate padding arrays
    let mut inner_padding: [u8; SHA1_KEY_BYTES] = [INNER_PAD_BYTE; SHA1_KEY_BYTES];
    let mut outer_padding: [u8; SHA1_KEY_BYTES] = [OUTER_PAD_BYTE; SHA1_KEY_BYTES];

    for offset in 0..auth_key.len() {
        inner_padding[offset] ^= auth_key[offset];
        outer_padding[offset] ^= auth_key[offset];
    }

    // perform inner hash
    sha1_ctx.update(&inner_padding);
    sha1_ctx.update(message);
    let inner_hash = sha1_ctx.digest().bytes();
    sha1_ctx.reset();

    // perform outer hash
    sha1_ctx.update(&outer_padding);
    sha1_ctx.update(&inner_hash);
    sha1_ctx.digest().bytes()
}


#[cfg(test)]extern crate rustc_serialize;
#[cfg(test)]use rustc_serialize::hex::ToHex;
#[cfg(test)]
mod tests {

    use SHA1_KEY_BYTES;
    use SHA1_DIGEST_BYTES;
    use hmac_sha1;

    use rustc_serialize::hex::ToHex;


    #[test]
    fn test_vector1() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }

    #[test]
    fn test_vector2() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }

    #[test]
    fn test_vector3() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }

    #[test]
    fn test_vector4() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }
}