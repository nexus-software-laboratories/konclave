use std::ptr::null_mut;

use thiserror::Error;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_PLAINTEXT_BYTES: usize = 1024;
const MAX_PROTECTED_BYTES: usize = 4096;
const MAX_CONTEXT_BYTES: usize = 128;

/// Bounded failures from non-interactive, current-user Windows DPAPI.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowsDataProtectionError {
    /// An input or output exceeds the supported bounded record shape.
    #[error("Windows protected data has an invalid length")]
    InvalidLength,
    /// Windows refused protection or authenticated opening for this user/context.
    #[error("Windows current-user data protection failed")]
    ProtectionFailed,
}

/// Protects bounded bytes for the current Windows user, bound to `context`.
///
/// Uses user-scoped DPAPI without machine scope or interactive prompts. The
/// returned ciphertext may be stored in an owner-restricted file.
///
/// # Errors
///
/// Rejects empty/oversized inputs and returns a finite error on Windows failure.
pub fn protect_current_user_data(
    plaintext: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WindowsDataProtectionError> {
    transform(plaintext, context, false)
}

/// Opens bounded DPAPI bytes for the current user and exact protection context.
///
/// The caller owns the returned zeroizing plaintext. There is no alternate-user,
/// machine-scope, prompt, or plaintext fallback.
///
/// # Errors
///
/// Rejects invalid lengths, another context, damaged data, and Windows failures.
pub fn unprotect_current_user_data(
    protected: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WindowsDataProtectionError> {
    transform(protected, context, true)
}

fn validate_lengths(
    input: usize,
    context: usize,
    opening: bool,
) -> Result<(), WindowsDataProtectionError> {
    let maximum = if opening {
        MAX_PROTECTED_BYTES
    } else {
        MAX_PLAINTEXT_BYTES
    };
    if input == 0 || input > maximum || context == 0 || context > MAX_CONTEXT_BYTES {
        return Err(WindowsDataProtectionError::InvalidLength);
    }
    Ok(())
}

fn transform(
    input: &[u8],
    context: &[u8],
    opening: bool,
) -> Result<Zeroizing<Vec<u8>>, WindowsDataProtectionError> {
    validate_lengths(input.len(), context.len(), opening)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr().cast_mut(),
    };
    let context = CRYPT_INTEGER_BLOB {
        cbData: context.len() as u32,
        pbData: context.as_ptr().cast_mut(),
    };
    let mut output = LocalOutput(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    });
    // SAFETY: DPAPI borrows the bounded input/context buffers without modifying
    // them. Output is initialized and exclusively owned; LocalOutput zeroes and
    // releases the LocalAlloc buffer on every return path. Optional pointers are
    // null and UI is prohibited.
    let success = unsafe {
        if opening {
            CryptUnprotectData(
                &input,
                null_mut(),
                &context,
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptProtectData(
                &input,
                null_mut(),
                &context,
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if success == 0 {
        return Err(WindowsDataProtectionError::ProtectionFailed);
    }
    let maximum = if opening {
        MAX_PLAINTEXT_BYTES
    } else {
        MAX_PROTECTED_BYTES
    };
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData as usize > maximum {
        return Err(WindowsDataProtectionError::InvalidLength);
    }
    // SAFETY: successful DPAPI returns an initialized allocation of cbData bytes,
    // kept alive by output until the owned zeroizing copy has been made.
    let bytes = unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

struct LocalOutput(CRYPT_INTEGER_BLOB);

impl Drop for LocalOutput {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: this buffer is exclusively owned, allocated by DPAPI with
            // LocalAlloc, and valid for cbData bytes until LocalFree below.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_protection_lengths_are_bounded_before_ffi() {
        for (input, context, opening, valid) in [
            (0, 1, false, false),
            (1, 0, false, false),
            (1024, 128, false, true),
            (1025, 1, false, false),
            (1, 129, false, false),
            (4096, 128, true, true),
            (4097, 1, true, false),
            (0, 1, true, false),
        ] {
            assert_eq!(validate_lengths(input, context, opening).is_ok(), valid);
        }
    }

    #[test]
    fn current_user_dpapi_authenticates_data_and_context() {
        let plaintext = Zeroizing::new(vec![7; 32]);
        let protected = protect_current_user_data(&plaintext, b"test-profile:slot-1").unwrap();
        let reopened = unprotect_current_user_data(&protected, b"test-profile:slot-1").unwrap();
        assert!(reopened.as_slice() == plaintext.as_slice());
        assert!(unprotect_current_user_data(&protected, b"other-profile:slot-1").is_err());
        let mut corrupted = protected;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(unprotect_current_user_data(&corrupted, b"test-profile:slot-1").is_err());
    }
}
