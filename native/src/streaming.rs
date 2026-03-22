use crate::algorithms::Algorithm;
use sha2::Digest;
use hmac::Mac;

pub enum StreamState {
    Sha256(sha2::Sha256),
    Blake3(blake3::Hasher),
    HmacSha256(hmac::Hmac<sha2::Sha256>),
}

pub fn init_hash(algorithm: Algorithm) -> Result<StreamState, i32> {
    match algorithm {
        Algorithm::Sha256 => Ok(StreamState::Sha256(sha2::Sha256::new())),
        Algorithm::Blake3 => Ok(StreamState::Blake3(blake3::Hasher::new())),
        _ => Err(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn init_hmac(algorithm: Algorithm, key: &[u8]) -> Result<StreamState, i32> {
    match algorithm {
        Algorithm::HmacSha256 => {
            let mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
                .map_err(|_| crate::errors::JC_ERR_INVALID_KEY_SIZE)?;
            Ok(StreamState::HmacSha256(mac))
        },
        _ => Err(crate::errors::JC_ERR_UNSUPPORTED_ALGO),
    }
}

pub fn update(state: &mut StreamState, data: &[u8]) {
    match state {
        StreamState::Sha256(hasher) => hasher.update(data),
        StreamState::Blake3(hasher) => { hasher.update(data); },
        StreamState::HmacSha256(mac) => mac.update(data),
    }
}

pub fn finalize(state: StreamState) -> Vec<u8> {
    match state {
        StreamState::Sha256(hasher) => hasher.finalize().to_vec(),
        StreamState::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
        StreamState::HmacSha256(mac) => mac.finalize().into_bytes().to_vec(),
    }
}
