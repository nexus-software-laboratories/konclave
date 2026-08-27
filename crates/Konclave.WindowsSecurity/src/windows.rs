use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::null_mut;

use thiserror::Error;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    GetFileInformationByHandle, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// A Windows account or integrity check could not be completed safely.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowsSecurityError {
    /// Windows did not expose the identity required to make an authorization decision.
    #[error("Windows peer identity is unavailable")]
    IdentityUnavailable,

    /// The connected process belongs to another Windows account.
    #[error("Windows peer belongs to another account")]
    ForeignAccount,

    /// The connected process has a lower integrity level than the verifier.
    #[error("Windows peer integrity is too low")]
    LowerIntegrity,
}

/// Verifies named-pipe peers against the account and integrity of this process.
pub struct WindowsAccountVerifier {
    expected: TokenIdentity,
}

impl WindowsAccountVerifier {
    /// Captures the current process account and integrity level.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsSecurityError::IdentityUnavailable`] when the current process
    /// token cannot be inspected.
    pub fn current() -> Result<Self, WindowsSecurityError> {
        Ok(Self {
            expected: current_process_identity()?,
        })
    }

    /// Verifies the client connected to a server-side named-pipe instance.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsSecurityError::ForeignAccount`] for another account,
    /// [`WindowsSecurityError::LowerIntegrity`] for a lower-integrity process, and
    /// [`WindowsSecurityError::IdentityUnavailable`] when Windows cannot establish
    /// the client identity.
    pub fn verify_client(&self, connection: &NamedPipeServer) -> Result<(), WindowsSecurityError> {
        let mut process_id = 0_u32;
        let handle = connection.as_raw_handle().cast::<c_void>();
        // SAFETY: `handle` is borrowed from a live connected named-pipe server and
        // `process_id` points to initialized writable storage for the duration of the
        // call.
        if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        self.verify_process(process_id)
    }

    /// Verifies the server behind a client-side named-pipe connection.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsSecurityError::ForeignAccount`] for another account,
    /// [`WindowsSecurityError::LowerIntegrity`] for a lower-integrity process, and
    /// [`WindowsSecurityError::IdentityUnavailable`] when Windows cannot establish
    /// the server identity.
    pub fn verify_server(&self, connection: &NamedPipeClient) -> Result<(), WindowsSecurityError> {
        let mut process_id = 0_u32;
        let handle = connection.as_raw_handle().cast::<c_void>();
        // SAFETY: `handle` is borrowed from a live named-pipe client and `process_id`
        // points to initialized writable storage for the duration of the call.
        if unsafe { GetNamedPipeServerProcessId(handle, &mut process_id) } == 0 {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        self.verify_process(process_id)
    }

    fn verify_process(&self, process_id: u32) -> Result<(), WindowsSecurityError> {
        if process_id == 0 {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        let actual = process_identity(process_id)?;
        if !self.expected.sid.equals(&actual.sid) {
            return Err(WindowsSecurityError::ForeignAccount);
        }
        if actual.integrity_level < self.expected.integrity_level {
            return Err(WindowsSecurityError::LowerIntegrity);
        }
        Ok(())
    }
}

impl core::fmt::Debug for WindowsAccountVerifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WindowsAccountVerifier")
            .finish_non_exhaustive()
    }
}

/// Creates one named-pipe server instance with an explicit owner-only DACL.
///
/// The security descriptor is copied by Windows during creation and is released
/// before this function returns. The created descriptor is read back from the pipe
/// handle and rejected unless its owner and sole allow ACE are the current account.
///
/// # Errors
///
/// Returns an operating-system error when the current process identity cannot be
/// inspected, the descriptor cannot be constructed, the pipe cannot be created, or
/// Windows does not apply the expected owner-only descriptor.
pub fn create_owner_restricted_named_pipe(
    options: &ServerOptions,
    name: &str,
) -> io::Result<NamedPipeServer> {
    let (identity, descriptor) = owner_only_security(false)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` and its self-relative descriptor remain alive and
    // unchanged for the complete call. Windows copies the descriptor when it creates
    // the pipe, and the returned Tokio object owns the resulting handle.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            name,
            std::ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }?;
    verify_owner_only_handle(server.as_raw_handle().cast::<c_void>(), &identity.sid, 0)?;
    Ok(server)
}

/// Creates or verifies one directory with an explicit current-account-only DACL.
///
/// # Errors
///
/// Returns an operating-system error when the path is invalid, another object owns
/// it, it is a reparse point, or its owner/DACL differs from the required descriptor.
pub fn ensure_owner_restricted_directory(path: &Path) -> io::Result<()> {
    let encoded = wide_path(path)?;
    let (identity, descriptor) = owner_only_security(true)?;
    let mut attributes = security_attributes(&descriptor)?;
    // SAFETY: `encoded` is NUL-terminated, `attributes` references a live
    // self-relative descriptor, and Windows copies that descriptor on creation.
    if unsafe { CreateDirectoryW(encoded.as_ptr(), &mut attributes) } == 0 {
        // SAFETY: the immediately preceding Win32 call failed on this thread.
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(error).unwrap_or(i32::MAX),
            ));
        }
    }
    let handle = open_path_handle(path, GENERIC_READ, true)?;
    verify_directory_handle(&handle)?;
    verify_owner_only_handle(
        handle.as_raw_handle().cast::<c_void>(),
        &identity.sid,
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
    )
}

/// Creates one owner-only ordinary file or verifies an existing exact value.
///
/// The file is created with its explicit DACL before any bytes are written. Existing
/// content is never overwritten.
///
/// # Errors
///
/// Returns an operating-system error for unsafe metadata, conflicting bytes, or an
/// unavailable path.
pub fn create_or_verify_owner_restricted_file(path: &Path, expected: &[u8]) -> io::Result<()> {
    if expected.is_empty() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    verify_owner_restricted_directory_path(
        path.parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
    )?;
    let encoded = wide_path(path)?;
    let (identity, descriptor) = owner_only_security(false)?;
    let mut attributes = security_attributes(&descriptor)?;
    // SAFETY: every pointer references live initialized storage, the path is
    // NUL-terminated, and the returned handle is adopted exactly once below.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            &mut attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw != INVALID_HANDLE_VALUE {
        // SAFETY: `raw` is a newly owned valid handle returned by `CreateFileW`.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        verify_file_handle(&handle)?;
        verify_owner_only_handle(handle.as_raw_handle().cast::<c_void>(), &identity.sid, 0)?;
        let mut file = File::from(handle);
        if file.write_all(expected).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(io::Error::other("owner-restricted file write failed"));
        }
        return Ok(());
    }

    // SAFETY: the immediately preceding `CreateFileW` call failed on this thread.
    let error = unsafe { GetLastError() };
    if error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(error).unwrap_or(i32::MAX),
        ));
    }
    let mut file = open_owner_restricted_file(path)?;
    let maximum = expected
        .len()
        .checked_add(1)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut actual = Vec::with_capacity(maximum);
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64)
        .read_to_end(&mut actual)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }
}

/// Opens an owner-only ordinary file without following its final reparse point.
///
/// # Errors
///
/// Returns an operating-system error when the file is absent, linked, not owned by
/// this account, or has any additional allow ACE.
pub fn open_owner_restricted_file(path: &Path) -> io::Result<File> {
    verify_owner_restricted_directory_path(
        path.parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
    )?;
    let identity = current_process_identity().map_err(security_io_error)?;
    let handle = open_path_handle(path, GENERIC_READ, false)?;
    verify_file_handle(&handle)?;
    verify_owner_only_handle(handle.as_raw_handle().cast::<c_void>(), &identity.sid, 0)?;
    Ok(File::from(handle))
}

fn verify_owner_restricted_directory_path(path: &Path) -> io::Result<()> {
    let identity = current_process_identity().map_err(security_io_error)?;
    let handle = open_path_handle(path, GENERIC_READ, true)?;
    verify_directory_handle(&handle)?;
    verify_owner_only_handle(
        handle.as_raw_handle().cast::<c_void>(),
        &identity.sid,
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
    )
}

fn owner_only_security(inheritable: bool) -> io::Result<(TokenIdentity, OwnedSecurityDescriptor)> {
    let identity = current_process_identity().map_err(security_io_error)?;
    let sid = identity.sid.to_string().map_err(security_io_error)?;
    let inheritance = if inheritable { "OICI" } else { "" };
    let descriptor = OwnedSecurityDescriptor::from_sddl(&format!(
        "O:{sid}G:{sid}D:P(A;{inheritance};GA;;;{sid})"
    ))?;
    Ok((identity, descriptor))
}

fn security_attributes(descriptor: &OwnedSecurityDescriptor) -> io::Result<SECURITY_ATTRIBUTES> {
    Ok(SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    })
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    encoded.push(0);
    Ok(encoded)
}

fn open_path_handle(path: &Path, access: u32, directory: bool) -> io::Result<OwnedHandle> {
    let encoded = wide_path(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    // SAFETY: `encoded` is live and NUL-terminated, no security-attribute pointer is
    // supplied, and the returned owned handle is adopted exactly once.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly owned valid handle returned by `CreateFileW`.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn verify_file_handle(handle: &OwnedHandle) -> io::Result<()> {
    let information = file_information(handle)?;
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn verify_directory_handle(handle: &OwnedHandle) -> io::Result<()> {
    let information = file_information(handle)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn file_information(handle: &OwnedHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `information` is writable storage of the exact
    // structure expected by `GetFileInformationByHandle`.
    if unsafe {
        GetFileInformationByHandle(handle.as_raw_handle().cast::<c_void>(), &mut information)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn current_process_identity() -> Result<TokenIdentity, WindowsSecurityError> {
    let mut token = null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid in this process and
    // `token` points to writable storage that receives one owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    TokenHandle(token).identity()
}

fn process_identity(process_id: u32) -> Result<TokenIdentity, WindowsSecurityError> {
    // SAFETY: `process_id` came from the kernel for a connected pipe. The requested
    // access is query-only and no handle is inherited.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    let process = ProcessHandle(process);
    let mut token = null_mut();
    // SAFETY: `process.0` is a live process handle and `token` points to writable
    // storage that receives one owned token handle.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    TokenHandle(token).identity()
}

struct TokenIdentity {
    sid: OwnedSid,
    integrity_level: u32,
}

struct OwnedSid {
    storage: Box<[usize]>,
    byte_len: usize,
}

impl OwnedSid {
    fn copy_from(sid: PSID) -> Result<Self, WindowsSecurityError> {
        if sid.is_null() {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        // SAFETY: `sid` came from a token-information buffer or a Windows conversion
        // API and remains alive for this call.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        // SAFETY: validity was established immediately above.
        let byte_len = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| WindowsSecurityError::IdentityUnavailable)?;
        if byte_len == 0 {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        let word_len = byte_len.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; word_len].into_boxed_slice();
        // SAFETY: both pointers are valid for `byte_len` bytes, do not overlap, and
        // the aligned destination allocation is at least that large.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.cast::<u8>(),
                storage.as_mut_ptr().cast::<u8>(),
                byte_len,
            );
        }
        Ok(Self { storage, byte_len })
    }

    fn as_ptr(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast::<c_void>()
    }

    fn equals(&self, other: &Self) -> bool {
        // SAFETY: both pointers reference aligned, validated SID copies that remain
        // alive for this call.
        unsafe { EqualSid(self.as_ptr(), other.as_ptr()) != 0 }
    }

    fn to_string(&self) -> Result<String, WindowsSecurityError> {
        let mut value = null_mut();
        // SAFETY: `self.as_ptr()` is a live validated SID and `value` points to
        // writable storage for the LocalAlloc-owned UTF-16 result.
        if unsafe { ConvertSidToStringSidW(self.as_ptr(), &mut value) } == 0 || value.is_null() {
            return Err(WindowsSecurityError::IdentityUnavailable);
        }
        let value = LocalWideString(value);
        let mut length = 0_usize;
        // SAFETY: the conversion API returns a NUL-terminated UTF-16 string.
        unsafe {
            while *value.0.add(length) != 0 {
                length = length
                    .checked_add(1)
                    .ok_or(WindowsSecurityError::IdentityUnavailable)?;
            }
        }
        // SAFETY: `length` was found by scanning the live NUL-terminated allocation.
        let units = unsafe { std::slice::from_raw_parts(value.0, length) };
        String::from_utf16(units).map_err(|_| WindowsSecurityError::IdentityUnavailable)
    }
}

impl core::fmt::Debug for OwnedSid {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OwnedSid")
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the non-null process handle returned
        // by `OpenProcess`.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct TokenHandle(HANDLE);

impl TokenHandle {
    fn identity(&self) -> Result<TokenIdentity, WindowsSecurityError> {
        let user = token_information(self.0, TokenUser)?;
        // SAFETY: `token_information` returns an aligned buffer containing a
        // `TOKEN_USER` for the requested class.
        let user_sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let sid = OwnedSid::copy_from(user_sid)?;

        let integrity = token_information(self.0, TokenIntegrityLevel)?;
        // SAFETY: the requested token class returned an aligned
        // `TOKEN_MANDATORY_LABEL` buffer.
        let integrity_sid = unsafe {
            (*(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
                .Label
                .Sid
        };
        let integrity_level = integrity_rid(integrity_sid)?;
        Ok(TokenIdentity {
            sid,
            integrity_level,
        })
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the non-null token handle returned by
        // `OpenProcessToken`.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn token_information(token: HANDLE, class: i32) -> Result<Box<[usize]>, WindowsSecurityError> {
    let mut byte_len = 0_u32;
    // SAFETY: a null output buffer with length zero is the documented size probe;
    // `byte_len` points to writable storage.
    let probe = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut byte_len) };
    if probe != 0
        || byte_len == 0
        || io::Error::last_os_error().raw_os_error()
            != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
    {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    let bytes = usize::try_from(byte_len).map_err(|_| WindowsSecurityError::IdentityUnavailable)?;
    let mut buffer = vec![0_usize; bytes.div_ceil(size_of::<usize>())].into_boxed_slice();
    // SAFETY: the aligned output allocation has at least `byte_len` bytes and remains
    // exclusively borrowed for the call.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast::<c_void>(),
            byte_len,
            &mut byte_len,
        )
    } == 0
    {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    Ok(buffer)
}

fn integrity_rid(sid: PSID) -> Result<u32, WindowsSecurityError> {
    if sid.is_null() {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    // SAFETY: the SID comes from a live token-information buffer.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    // SAFETY: validity was established immediately above.
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    // SAFETY: Windows returned a pointer into the validated live SID.
    let count = unsafe { *count_ptr };
    if count == 0 {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    // SAFETY: `count - 1` is an in-range sub-authority index for the validated SID.
    let rid = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid.is_null() {
        return Err(WindowsSecurityError::IdentityUnavailable);
    }
    // SAFETY: Windows returned a pointer to the requested in-range sub-authority.
    Ok(unsafe { *rid })
}

struct OwnedSecurityDescriptor(*mut c_void);

impl OwnedSecurityDescriptor {
    fn from_sddl(value: &str) -> io::Result<Self> {
        let mut encoded: Vec<u16> = value.encode_utf16().collect();
        encoded.push(0);
        let mut descriptor = null_mut();
        // SAFETY: `encoded` is a live NUL-terminated UTF-16 string and `descriptor`
        // points to writable storage for the LocalAlloc-owned result.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the LocalAlloc allocation returned by
        // the security-descriptor conversion API.
        unsafe {
            let _ = LocalFree(self.0);
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the LocalAlloc allocation returned by
        // `ConvertSidToStringSidW`.
        unsafe {
            let _ = LocalFree(self.0.cast::<c_void>());
        }
    }
}

fn verify_owner_only_handle(
    handle: HANDLE,
    expected: &OwnedSid,
    expected_ace_flags: u32,
) -> io::Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: `handle` is borrowed from a live named pipe; every requested output
    // pointer references writable storage and the returned descriptor is released by
    // the RAII wrapper below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        if !descriptor.is_null() {
            drop(OwnedSecurityDescriptor(descriptor));
        }
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    if descriptor.is_null() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let _descriptor = OwnedSecurityDescriptor(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    // SAFETY: `owner` points inside the live descriptor returned by `GetSecurityInfo`
    // and `expected` is a validated SID.
    if unsafe { EqualSid(owner, expected.as_ptr()) } == 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points inside the live descriptor and `information` is writable
    // storage of the exact type and size requested.
    if unsafe {
        GetAclInformation(
            dacl,
            std::ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of_val(&information))
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }

    let mut ace = null_mut();
    // SAFETY: the ACL reports exactly one ACE, index zero is in range, and `ace`
    // points to writable storage for the borrowed ACE pointer.
    if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    // SAFETY: `ace` points to the first complete ACE in the live ACL.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if u32::from(allowed.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || u32::from(allowed.Header.AceFlags) != expected_ace_flags
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let ace_sid = std::ptr::addr_of!(allowed.SidStart)
        .cast_mut()
        .cast::<c_void>();
    // SAFETY: `SidStart` begins the variable-length SID contained in this complete
    // access-allowed ACE, and `expected` is a validated SID.
    if unsafe { EqualSid(ace_sid, expected.as_ptr()) } == 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn security_io_error(_error: WindowsSecurityError) -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle as _;

    use super::{
        WindowsAccountVerifier, create_or_verify_owner_restricted_file,
        create_owner_restricted_named_pipe, ensure_owner_restricted_directory,
        open_owner_restricted_file, verify_owner_only_handle,
    };

    fn endpoint(name: &str) -> String {
        format!(
            r"\\.\pipe\konclave-windows-security-test-{}-{name}",
            std::process::id()
        )
    }

    #[tokio::test]
    async fn owner_only_pipe_accepts_and_verifies_the_current_account() {
        let name = endpoint("same-account");
        let server = create_owner_restricted_named_pipe(
            tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(true),
            &name,
        )
        .unwrap();
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .unwrap();
        server.connect().await.unwrap();

        let verifier = WindowsAccountVerifier::current().unwrap();
        verifier.verify_client(&server).unwrap();
        verifier.verify_server(&client).unwrap();
    }

    #[tokio::test]
    async fn created_pipe_retains_the_exact_owner_only_descriptor() {
        let name = endpoint("descriptor");
        let server = create_owner_restricted_named_pipe(
            tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(true),
            &name,
        )
        .unwrap();
        let verifier = WindowsAccountVerifier::current().unwrap();
        verify_owner_only_handle(
            server.as_raw_handle().cast::<c_void>(),
            &verifier.expected.sid,
            0,
        )
        .unwrap();
    }

    #[test]
    fn owner_restricted_directories_and_files_are_exact() {
        use std::io::Read as _;

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        ensure_owner_restricted_directory(&directory).unwrap();
        let file = directory.join("record");
        create_or_verify_owner_restricted_file(&file, b"exact").unwrap();
        create_or_verify_owner_restricted_file(&file, b"exact").unwrap();
        assert!(create_or_verify_owner_restricted_file(&file, b"different").is_err());
        let mut value = Vec::new();
        open_owner_restricted_file(&file)
            .unwrap()
            .read_to_end(&mut value)
            .unwrap();
        assert_eq!(value, b"exact");
    }
}
