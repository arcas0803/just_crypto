pub mod algorithms;
pub mod errors;
pub mod helpers;
pub mod streaming;

#[repr(C)]
pub struct JCBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct JCResult {
    pub code: i32,
    pub buffer: JCBuffer,
}

#[repr(C)]
pub struct JCContext {
    _private: [u8; 0],
}

#[no_mangle]
pub extern "C" fn jc_encrypt(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };

    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let key = match unsafe { JCBuffer::as_slice(key_ptr, key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let nonce = match unsafe { JCBuffer::as_slice(nonce_ptr, nonce_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let aad = match unsafe { JCBuffer::as_slice(aad_ptr, aad_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };

    algorithms::encrypt(algorithm, message, key, nonce, aad)
}

#[no_mangle]
pub extern "C" fn jc_decrypt(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };

    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let key = match unsafe { JCBuffer::as_slice(key_ptr, key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let nonce = match unsafe { JCBuffer::as_slice(nonce_ptr, nonce_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let aad = match unsafe { JCBuffer::as_slice(aad_ptr, aad_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };

    algorithms::decrypt(algorithm, message, key, nonce, aad)
}


#[no_mangle]
pub extern "C" fn jc_sign(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
    priv_key_ptr: *const u8,
    priv_key_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };

    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let priv_key = match unsafe { JCBuffer::as_slice(priv_key_ptr, priv_key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };

    algorithms::sign(algorithm, message, priv_key)
}

#[no_mangle]
pub extern "C" fn jc_verify(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    pub_key_ptr: *const u8,
    pub_key_len: usize,
) -> i32 {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return errors::JC_ERR_UNSUPPORTED_ALGO,
    };

    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let sig = match unsafe { JCBuffer::as_slice(sig_ptr, sig_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let pub_key = match unsafe { JCBuffer::as_slice(pub_key_ptr, pub_key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    
    algorithms::verify(algorithm, message, sig, pub_key)
}

#[no_mangle]
pub extern "C" fn jc_derive_key(
    alg: i32,
    input_ptr: *const u8,
    input_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_length: u32,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };

    let input = match unsafe { JCBuffer::as_slice(input_ptr, input_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let salt = match unsafe { JCBuffer::as_slice(salt_ptr, salt_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };

    algorithms::derive_key(algorithm, input, salt, memory_cost, time_cost, parallelism, output_length)
}

#[no_mangle]
pub extern "C" fn jc_generate_random(length: usize) -> JCResult {
    algorithms::generate_random(length)
}

#[no_mangle]
pub extern "C" fn jc_generate_key_pair(alg: i32) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };
    algorithms::generate_key_pair(algorithm)
}

#[no_mangle]
pub extern "C" fn jc_shared_secret(
    alg: i32,
    private_key_ptr: *const u8,
    private_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };

    let private_key = match unsafe { JCBuffer::as_slice(private_key_ptr, private_key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let public_key = match unsafe { JCBuffer::as_slice(public_key_ptr, public_key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };

    algorithms::derive_shared_secret(algorithm, private_key, public_key)
}

#[no_mangle]
pub extern "C" fn jc_hash_message(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };
    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    algorithms::hash_message(algorithm, message)
}

#[no_mangle]
pub extern "C" fn jc_hmac_message(
    alg: i32,
    msg_ptr: *const u8,
    msg_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> JCResult {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return helpers::make_error(errors::JC_ERR_UNSUPPORTED_ALGO),
    };
    let message = match unsafe { JCBuffer::as_slice(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    let key = match unsafe { JCBuffer::as_slice(key_ptr, key_len) } {
        Ok(bytes) => bytes,
        Err(code) => return helpers::make_error(code),
    };
    algorithms::hmac_message(algorithm, message, key)
}

#[no_mangle]
pub extern "C" fn jc_constant_time_eq(
    left_ptr: *const u8,
    left_len: usize,
    right_ptr: *const u8,
    right_len: usize,
) -> i32 {
    let left = match unsafe { JCBuffer::as_slice(left_ptr, left_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let right = match unsafe { JCBuffer::as_slice(right_ptr, right_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };

    if algorithms::constant_time_equals(left, right) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn jc_stream_init_hash(alg: i32) -> *mut JCContext {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return std::ptr::null_mut(),
    };
    match streaming::init_hash(algorithm) {
        Ok(state) => Box::into_raw(Box::new(state)) as *mut JCContext,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn jc_stream_init_hmac(alg: i32, key_ptr: *const u8, key_len: usize) -> *mut JCContext {
    let algorithm = match algorithms::Algorithm::from_i32(alg) {
        Some(a) => a,
        None => return std::ptr::null_mut(),
    };
    let key = match unsafe { JCBuffer::as_slice(key_ptr, key_len) } {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    match streaming::init_hmac(algorithm, key) {
        Ok(state) => Box::into_raw(Box::new(state)) as *mut JCContext,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn jc_stream_update(ctx: *mut JCContext, data_ptr: *const u8, data_len: usize) -> i32 {
    if ctx.is_null() {
        return errors::JC_ERR_INVALID_STATE;
    }
    let data = match unsafe { JCBuffer::as_slice(data_ptr, data_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let state = unsafe { &mut *(ctx as *mut streaming::StreamState) };
    streaming::update(state, data);
    errors::JC_SUCCESS
}

#[no_mangle]
pub extern "C" fn jc_stream_finalize(ctx: *mut JCContext) -> JCResult {
    if ctx.is_null() {
        return helpers::make_error(errors::JC_ERR_INVALID_STATE);
    }
    let state_box = unsafe { Box::from_raw(ctx as *mut streaming::StreamState) };
    let result = streaming::finalize(*state_box);
    helpers::make_success(result)
}

#[no_mangle]
pub extern "C" fn jc_stream_free(ctx: *mut JCContext) {
    if !ctx.is_null() {
        unsafe { let _ = Box::from_raw(ctx as *mut streaming::StreamState); }
    }
}
