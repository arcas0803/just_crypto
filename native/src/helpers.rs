use crate::{JCBuffer, JCResult};
use std::slice;
use zeroize::Zeroize;

impl JCBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        let mut buf = data.into_boxed_slice();
        let ptr = buf.as_mut_ptr();
        let len = buf.len();
        std::mem::forget(buf);
        JCBuffer { ptr, len }
    }

    pub fn empty() -> Self {
        JCBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Converts a pointer + length FFI inputs into a slice safely
    pub unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
        if ptr.is_null() {
            if len == 0 {
                Ok(&[])
            } else {
                Err(crate::errors::JC_ERR_INVALID_POINTER)
            }
        } else {
            Ok(slice::from_raw_parts(ptr, len))
        }
    }
}

#[no_mangle]
pub extern "C" fn jc_buffer_free(buffer: JCBuffer) {
    if !buffer.ptr.is_null() && buffer.len > 0 {
        unsafe {
            // Reconstruct the box, wipe the memory in place, and then drop it.
            let boxed = Box::from_raw(slice::from_raw_parts_mut(buffer.ptr, buffer.len));
            let mut boxed = boxed;
            boxed.zeroize();
        }
    }
}

pub fn make_success(data: Vec<u8>) -> JCResult {
    JCResult {
        code: crate::errors::JC_SUCCESS,
        buffer: JCBuffer::new(data),
    }
}

pub fn make_error(code: i32) -> JCResult {
    JCResult {
        code,
        buffer: JCBuffer::empty(),
    }
}
