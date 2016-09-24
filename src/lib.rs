extern crate sha1;

// define hash constants
pub const SHA1_DIGEST_BYTES: usize = 20;
const SHA1_KEY_BYTES: usize = 64;

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; SHA1_DIGEST_BYTES] {
    // set constants for HMAC
    let inner_pad_byte: u8 = 0x36;
    let outer_pad_byte: u8 = 0x5c;
    let key_pad_byte:   u8 = 0x00;

    // instantiate internal structures
    let mut sha1_ctx = sha1::Sha1::new();
    let mut auth_key: &mut [u8; SHA1_KEY_BYTES] = &mut [key_pad_byte; SHA1_KEY_BYTES];

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
    let mut inner_padding: [u8; SHA1_KEY_BYTES] = [inner_pad_byte; SHA1_KEY_BYTES];
    let mut outer_padding: [u8; SHA1_KEY_BYTES] = [outer_pad_byte; SHA1_KEY_BYTES];

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
#[cfg(test)]
mod tests {

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
        let data = "what do ya want for nothing?".as_bytes();
        let key = "Jefe".as_bytes();
        let expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }

    #[test]
    fn test_vector3() {
        // tuples of (data, key, expected hex string)
        let data = &[0xdd; 50];
        let key = &[0xaa; 20];
        let expected = "125d7342b9ac11cd91a39af48aa17b4f63f175d3".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }

    #[test]
    fn test_vector4() {
        // tuples of (data, key, expected hex string)
        let data = &[0xcd; 50];
        let key = &[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25];
        let expected = "4c9007f4026250c6bc8414f9bf50c86c2d7235da".to_string();

        let hash = hmac_sha1(key, data);
        assert_eq!(hash.to_hex(),expected);
    }
}
