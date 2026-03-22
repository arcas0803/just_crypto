#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm = 0,
    Chacha20Poly1305 = 1,
    Argon2id = 2,
    Ed25519 = 3,
    X25519 = 4,
    Sha256 = 5,
    Blake3 = 6,
    Aes128Cbc = 7,
    Aes256Cbc = 8,
    HmacSha256 = 9,
}

use aes::{Aes128, Aes256};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

impl Algorithm {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Aes256Gcm),
            1 => Some(Self::Chacha20Poly1305),
            2 => Some(Self::Argon2id),
            3 => Some(Self::Ed25519),
            4 => Some(Self::X25519),
            5 => Some(Self::Sha256),
            6 => Some(Self::Blake3),
            7 => Some(Self::Aes128Cbc),
            8 => Some(Self::Aes256Cbc),
            9 => Some(Self::HmacSha256),
            _ => None,
        }
    }
}

pub fn encrypt(
    algorithm: Algorithm,
    message: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> crate::JCResult {
    match algorithm {
        Algorithm::Aes256Gcm => aes256_gcm_encrypt(message, key, nonce, aad),
        Algorithm::Chacha20Poly1305 => chacha20_poly1305_encrypt(message, key, nonce, aad),
        Algorithm::Aes128Cbc => aes128_cbc_encrypt(message, key, nonce),
        Algorithm::Aes256Cbc => aes256_cbc_encrypt(message, key, nonce),
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn decrypt(
    algorithm: Algorithm,
    message: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> crate::JCResult {
    match algorithm {
        Algorithm::Aes256Gcm => aes256_gcm_decrypt(message, key, nonce, aad),
        Algorithm::Chacha20Poly1305 => chacha20_poly1305_decrypt(message, key, nonce, aad),
        Algorithm::Aes128Cbc => aes128_cbc_decrypt(message, key, nonce),
        Algorithm::Aes256Cbc => aes256_cbc_decrypt(message, key, nonce),
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

fn aes256_gcm_encrypt(message: &[u8], key: &[u8], nonce: &[u8], aad: &[u8]) -> crate::JCResult {
    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if nonce.len() != 12 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_NONCE_SIZE);
    }

    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let n = AesNonce::from_slice(nonce);
    let payload = Payload { msg: message, aad };

    match cipher.encrypt(n, payload) {
        Ok(ciphertext) => crate::helpers::make_success(ciphertext),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_UNKNOWN),
    }
}

fn aes256_gcm_decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: &[u8]) -> crate::JCResult {
    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if nonce.len() != 12 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_NONCE_SIZE);
    }

    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let n = AesNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match cipher.decrypt(n, payload) {
        Ok(plaintext) => crate::helpers::make_success(plaintext),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_DECRYPTION_FAILED),
    }
}

fn chacha20_poly1305_encrypt(
    message: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> crate::JCResult {
    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if nonce.len() != 12 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_NONCE_SIZE);
    }

    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let n = ChaChaNonce::from_slice(nonce);
    let payload = Payload { msg: message, aad };

    match cipher.encrypt(n, payload) {
        Ok(ciphertext) => crate::helpers::make_success(ciphertext),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_UNKNOWN),
    }
}

fn chacha20_poly1305_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> crate::JCResult {
    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if nonce.len() != 12 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_NONCE_SIZE);
    }

    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let n = ChaChaNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match cipher.decrypt(n, payload) {
        Ok(plaintext) => crate::helpers::make_success(plaintext),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_DECRYPTION_FAILED),
    }
}

fn aes128_cbc_encrypt(message: &[u8], key: &[u8], iv: &[u8]) -> crate::JCResult {
    type Aes128CbcEnc = cbc::Encryptor<Aes128>;

    if key.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if iv.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_IV_SIZE);
    }

    let cipher = match Aes128CbcEnc::new_from_slices(key, iv) {
        Ok(cipher) => cipher,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM),
    };
    let mut buffer = vec![0u8; message.len() + 16];
    buffer[..message.len()].copy_from_slice(message);

    let result = match cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, message.len()) {
        Ok(ciphertext) => crate::helpers::make_success(ciphertext.to_vec()),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_UNKNOWN),
    };
    buffer.zeroize();
    result
}

fn aes128_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> crate::JCResult {
    type Aes128CbcDec = cbc::Decryptor<Aes128>;

    if key.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if iv.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_IV_SIZE);
    }

    let cipher = match Aes128CbcDec::new_from_slices(key, iv) {
        Ok(cipher) => cipher,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM),
    };
    let mut buffer = ciphertext.to_vec();

    let result = match cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(plaintext) => crate::helpers::make_success(plaintext.to_vec()),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_DECRYPTION_FAILED),
    };
    buffer.zeroize();
    result
}

fn aes256_cbc_encrypt(message: &[u8], key: &[u8], iv: &[u8]) -> crate::JCResult {
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if iv.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_IV_SIZE);
    }

    let cipher = match Aes256CbcEnc::new_from_slices(key, iv) {
        Ok(cipher) => cipher,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM),
    };
    let mut buffer = vec![0u8; message.len() + 16];
    buffer[..message.len()].copy_from_slice(message);

    let result = match cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, message.len()) {
        Ok(ciphertext) => crate::helpers::make_success(ciphertext.to_vec()),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_UNKNOWN),
    };
    buffer.zeroize();
    result
}

fn aes256_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> crate::JCResult {
    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    if key.len() != 32 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
    }
    if iv.len() != 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_IV_SIZE);
    }

    let cipher = match Aes256CbcDec::new_from_slices(key, iv) {
        Ok(cipher) => cipher,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM),
    };
    let mut buffer = ciphertext.to_vec();

    let result = match cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(plaintext) => crate::helpers::make_success(plaintext.to_vec()),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_DECRYPTION_FAILED),
    };
    buffer.zeroize();
    result
}

pub fn sign(algorithm: Algorithm, message: &[u8], priv_key: &[u8]) -> crate::JCResult {
    match algorithm {
        Algorithm::Ed25519 => ed25519_sign(message, priv_key),
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn verify(algorithm: Algorithm, message: &[u8], sig: &[u8], pub_key: &[u8]) -> i32 {
    match algorithm {
        Algorithm::Ed25519 => ed25519_verify(message, sig, pub_key),
        _ => crate::errors::JC_ERR_UNSUPPORTED_ALGO,
    }
}

fn ed25519_sign(message: &[u8], priv_key: &[u8]) -> crate::JCResult {
    use ed25519_dalek::{Signer, SigningKey};
    let mut private_key_copy = priv_key.to_vec();
    let signing_key = match SigningKey::try_from(private_key_copy.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            private_key_copy.zeroize();
            return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
        }
    };
    let signature = signing_key.sign(message);
    private_key_copy.zeroize();
    crate::helpers::make_success(signature.to_bytes().to_vec())
}

fn ed25519_verify(message: &[u8], sig: &[u8], pub_key: &[u8]) -> i32 {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return crate::errors::JC_ERR_INVALID_SIGNATURE,
    };
    let verifying_key = match VerifyingKey::try_from(pub_key) {
        Ok(k) => k,
        Err(_) => return crate::errors::JC_ERR_INVALID_KEY_SIZE,
    };
    match verifying_key.verify(message, &signature) {
        Ok(_) => crate::errors::JC_SUCCESS,
        Err(_) => crate::errors::JC_ERR_INVALID_SIGNATURE,
    }
}

pub fn derive_key(
    algorithm: Algorithm,
    input: &[u8],
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_length: u32,
) -> crate::JCResult {
    match algorithm {
        Algorithm::Argon2id => argon2id_derive(
            input,
            salt,
            memory_cost,
            time_cost,
            parallelism,
            output_length,
        ),
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_length: u32,
) -> crate::JCResult {
    use argon2::{Argon2, Params};
    if salt.len() < 16 {
        return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_SALT_SIZE);
    }

    let mut password_copy = password.to_vec();
    let mut salt_copy = salt.to_vec();
    let params = match Params::new(
        if memory_cost == 0 { 65536 } else { memory_cost },
        if time_cost == 0 { 3 } else { time_cost },
        if parallelism == 0 { 4 } else { parallelism },
        if output_length == 0 {
            Some(32)
        } else {
            Some(output_length as usize)
        },
    ) {
        Ok(p) => p,
        Err(_) => {
            password_copy.zeroize();
            salt_copy.zeroize();
            return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM);
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = vec![
        0u8;
        if output_length == 0 {
            32
        } else {
            output_length as usize
        }
    ];

    let result = match argon2.hash_password_into(
        password_copy.as_slice(),
        salt_copy.as_slice(),
        &mut output,
    ) {
        Ok(_) => crate::helpers::make_success(output),
        Err(_) => crate::helpers::make_error(crate::errors::JC_ERR_INVALID_PARAM),
    };
    password_copy.zeroize();
    salt_copy.zeroize();
    result
}

pub fn generate_random(length: usize) -> crate::JCResult {
    use rand_core::{OsRng, RngCore};
    let mut data = vec![0u8; length];
    OsRng.fill_bytes(&mut data);
    crate::helpers::make_success(data)
}

pub fn generate_key_pair(algorithm: Algorithm) -> crate::JCResult {
    match algorithm {
        Algorithm::Ed25519 => {
            use ed25519_dalek::SigningKey;
            use rand_core::OsRng;
            let signing_key = SigningKey::generate(&mut OsRng);
            let mut keypair_bytes = Vec::with_capacity(64);
            keypair_bytes.extend_from_slice(signing_key.as_bytes()); // 32 bytes private
            keypair_bytes.extend_from_slice(signing_key.verifying_key().as_bytes()); // 32 bytes public
            crate::helpers::make_success(keypair_bytes)
        }
        Algorithm::X25519 => {
            use rand_core::OsRng;
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let mut keypair_bytes = Vec::with_capacity(64);
            keypair_bytes.extend_from_slice(secret.to_bytes().as_ref()); // 32 bytes private
            keypair_bytes.extend_from_slice(public.as_bytes()); // 32 bytes public
            crate::helpers::make_success(keypair_bytes)
        }
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn derive_shared_secret(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: &[u8],
) -> crate::JCResult {
    match algorithm {
        Algorithm::X25519 => x25519_derive_shared_secret(private_key, public_key),
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

fn x25519_derive_shared_secret(private_key: &[u8], public_key: &[u8]) -> crate::JCResult {
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut private_bytes: [u8; 32] = match private_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE),
    };
    let public_bytes: [u8; 32] = match public_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE),
    };

    let secret = StaticSecret::from(private_bytes);
    let remote_public = PublicKey::from(public_bytes);
    let shared = secret.diffie_hellman(&remote_public);
    private_bytes.zeroize();
    crate::helpers::make_success(shared.as_bytes().to_vec())
}

pub fn hash_message(algorithm: Algorithm, message: &[u8]) -> crate::JCResult {
    match algorithm {
        Algorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            crate::helpers::make_success(Sha256::digest(message).to_vec())
        }
        Algorithm::Blake3 => {
            let hash = blake3::hash(message);
            crate::helpers::make_success(hash.as_bytes().to_vec())
        }
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn hmac_message(algorithm: Algorithm, message: &[u8], key: &[u8]) -> crate::JCResult {
    use hmac::{Hmac, Mac};
    match algorithm {
        Algorithm::HmacSha256 => {
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut key_copy = key.to_vec();
            let mut mac = match <HmacSha256 as hmac::Mac>::new_from_slice(key_copy.as_slice()) {
                Ok(m) => m,
                Err(_) => {
                    key_copy.zeroize();
                    return crate::helpers::make_error(crate::errors::JC_ERR_INVALID_KEY_SIZE);
                }
            };
            mac.update(message);
            let result = crate::helpers::make_success(mac.finalize().into_bytes().to_vec());
            key_copy.zeroize();
            result
        }
        _ => crate::helpers::make_error(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha256_matches_known_vector() {
        let result = hash_message(Algorithm::Sha256, b"abc");
        assert_eq!(result.code, crate::errors::JC_SUCCESS);
        let bytes = unsafe { std::slice::from_raw_parts(result.buffer.ptr, result.buffer.len) };
        assert_eq!(
            hex(bytes),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        crate::helpers::jc_buffer_free(result.buffer);
    }

    #[test]
    fn hmac_sha256_matches_known_vector() {
        let key = [0x0b_u8; 20];
        let result = hmac_message(Algorithm::HmacSha256, b"Hi There", &key);
        assert_eq!(result.code, crate::errors::JC_SUCCESS);
        let bytes = unsafe { std::slice::from_raw_parts(result.buffer.ptr, result.buffer.len) };
        assert_eq!(
            hex(bytes),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        crate::helpers::jc_buffer_free(result.buffer);
    }

    #[test]
    fn x25519_shared_secret_is_symmetric() {
        let alice = generate_key_pair(Algorithm::X25519);
        let bob = generate_key_pair(Algorithm::X25519);

        let alice_bytes = unsafe { std::slice::from_raw_parts(alice.buffer.ptr, alice.buffer.len) };
        let bob_bytes = unsafe { std::slice::from_raw_parts(bob.buffer.ptr, bob.buffer.len) };
        let alice_private = &alice_bytes[..32];
        let alice_public = &alice_bytes[32..64];
        let bob_private = &bob_bytes[..32];
        let bob_public = &bob_bytes[32..64];

        let alice_shared = derive_shared_secret(Algorithm::X25519, alice_private, bob_public);
        let bob_shared = derive_shared_secret(Algorithm::X25519, bob_private, alice_public);

        let alice_shared_bytes =
            unsafe { std::slice::from_raw_parts(alice_shared.buffer.ptr, alice_shared.buffer.len) };
        let bob_shared_bytes =
            unsafe { std::slice::from_raw_parts(bob_shared.buffer.ptr, bob_shared.buffer.len) };

        assert_eq!(alice_shared_bytes, bob_shared_bytes);

        crate::helpers::jc_buffer_free(alice.buffer);
        crate::helpers::jc_buffer_free(bob.buffer);
        crate::helpers::jc_buffer_free(alice_shared.buffer);
        crate::helpers::jc_buffer_free(bob_shared.buffer);
    }

    #[test]
    fn aes256_gcm_roundtrip_succeeds() {
        let key = [0x11_u8; 32];
        let nonce = [0x22_u8; 12];
        let aad = [0x33_u8; 4];
        let message = b"roundtrip message";

        let encrypted = encrypt(Algorithm::Aes256Gcm, message, &key, &nonce, &aad);
        assert_eq!(encrypted.code, crate::errors::JC_SUCCESS);
        let encrypted_bytes =
            unsafe { std::slice::from_raw_parts(encrypted.buffer.ptr, encrypted.buffer.len) };

        let decrypted = decrypt(Algorithm::Aes256Gcm, encrypted_bytes, &key, &nonce, &aad);
        assert_eq!(decrypted.code, crate::errors::JC_SUCCESS);
        let decrypted_bytes =
            unsafe { std::slice::from_raw_parts(decrypted.buffer.ptr, decrypted.buffer.len) };

        assert_eq!(decrypted_bytes, message);

        crate::helpers::jc_buffer_free(encrypted.buffer);
        crate::helpers::jc_buffer_free(decrypted.buffer);
    }

    #[test]
    fn aes256_gcm_rejects_tampered_ciphertext() {
        let key = [0x44_u8; 32];
        let nonce = [0x55_u8; 12];
        let aad = [0x66_u8; 3];
        let message = b"tamper check";

        let encrypted = encrypt(Algorithm::Aes256Gcm, message, &key, &nonce, &aad);
        assert_eq!(encrypted.code, crate::errors::JC_SUCCESS);
        let mut tampered = unsafe {
            std::slice::from_raw_parts(encrypted.buffer.ptr, encrypted.buffer.len).to_vec()
        };
        tampered[0] ^= 0x01;

        let decrypted = decrypt(Algorithm::Aes256Gcm, &tampered, &key, &nonce, &aad);
        assert_eq!(decrypted.code, crate::errors::JC_ERR_DECRYPTION_FAILED);

        crate::helpers::jc_buffer_free(encrypted.buffer);
    }

    #[test]
    fn aes_cbc_roundtrips_non_block_aligned_payloads() {
        let key128 = [0x77_u8; 16];
        let key256 = [0x88_u8; 32];
        let iv = [0x99_u8; 16];
        let message = b"payload that is not aligned to sixteen";

        let encrypted128 = encrypt(Algorithm::Aes128Cbc, message, &key128, &iv, &[]);
        assert_eq!(encrypted128.code, crate::errors::JC_SUCCESS);
        let encrypted128_bytes =
            unsafe { std::slice::from_raw_parts(encrypted128.buffer.ptr, encrypted128.buffer.len) };
        let decrypted128 = decrypt(Algorithm::Aes128Cbc, encrypted128_bytes, &key128, &iv, &[]);
        assert_eq!(decrypted128.code, crate::errors::JC_SUCCESS);
        let decrypted128_bytes =
            unsafe { std::slice::from_raw_parts(decrypted128.buffer.ptr, decrypted128.buffer.len) };
        assert_eq!(decrypted128_bytes, message);

        let encrypted256 = encrypt(Algorithm::Aes256Cbc, message, &key256, &iv, &[]);
        assert_eq!(encrypted256.code, crate::errors::JC_SUCCESS);
        let encrypted256_bytes =
            unsafe { std::slice::from_raw_parts(encrypted256.buffer.ptr, encrypted256.buffer.len) };
        let decrypted256 = decrypt(Algorithm::Aes256Cbc, encrypted256_bytes, &key256, &iv, &[]);
        assert_eq!(decrypted256.code, crate::errors::JC_SUCCESS);
        let decrypted256_bytes =
            unsafe { std::slice::from_raw_parts(decrypted256.buffer.ptr, decrypted256.buffer.len) };
        assert_eq!(decrypted256_bytes, message);

        crate::helpers::jc_buffer_free(encrypted128.buffer);
        crate::helpers::jc_buffer_free(decrypted128.buffer);
        crate::helpers::jc_buffer_free(encrypted256.buffer);
        crate::helpers::jc_buffer_free(decrypted256.buffer);
    }

    #[test]
    fn ed25519_signature_tampering_is_rejected() {
        let keypair = generate_key_pair(Algorithm::Ed25519);
        assert_eq!(keypair.code, crate::errors::JC_SUCCESS);
        let keypair_bytes =
            unsafe { std::slice::from_raw_parts(keypair.buffer.ptr, keypair.buffer.len) };
        let private_key = &keypair_bytes[..32];
        let public_key = &keypair_bytes[32..64];
        let message = b"signature tamper";

        let signature = sign(Algorithm::Ed25519, message, private_key);
        assert_eq!(signature.code, crate::errors::JC_SUCCESS);
        let mut signature_bytes = unsafe {
            std::slice::from_raw_parts(signature.buffer.ptr, signature.buffer.len).to_vec()
        };
        signature_bytes[0] ^= 0x01;

        assert_eq!(
            verify(Algorithm::Ed25519, message, &signature_bytes, public_key),
            crate::errors::JC_ERR_INVALID_SIGNATURE
        );

        crate::helpers::jc_buffer_free(keypair.buffer);
        crate::helpers::jc_buffer_free(signature.buffer);
    }

    #[test]
    fn constant_time_compare_distinguishes_equal_and_different_inputs() {
        assert!(constant_time_equals(b"same", b"same"));
        assert!(!constant_time_equals(b"same", b"different"));
    }
}
