#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use crate::error::LocalServiceTransportError;

/// Largest accepted local endpoint string.
///
/// A Unix domain socket path is limited by the platform's `sun_path`, and a Windows
/// pipe name is short by convention. Bounding the configured value keeps a malformed
/// environment from reaching a platform call with an unbounded string.
pub const MAX_ENDPOINT_LENGTH: usize = 200;

/// The well-known local endpoint one per-user service listens on.
///
/// This is local inter-process communication only. Nothing here opens a loopback or
/// non-loopback TCP listener, so the service is unreachable from the network even
/// when the operating-system firewall would allow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalServiceEndpoint(String);

impl LocalServiceEndpoint {
    /// Validates a configured endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::InvalidEndpoint`] when the value is
    /// empty, longer than [`MAX_ENDPOINT_LENGTH`], contains a NUL, is not absolute on
    /// Unix, or is not a named pipe on Windows.
    pub fn parse(value: &str) -> Result<Self, LocalServiceTransportError> {
        if value.is_empty() || value.len() > MAX_ENDPOINT_LENGTH {
            return Err(LocalServiceTransportError::InvalidEndpoint);
        }
        if value.contains('\0') {
            return Err(LocalServiceTransportError::InvalidEndpoint);
        }
        #[cfg(unix)]
        if !Path::new(value).is_absolute() {
            return Err(LocalServiceTransportError::InvalidEndpoint);
        }
        #[cfg(windows)]
        if !value.starts_with(r"\\.\pipe\") || value.len() == r"\\.\pipe\".len() {
            return Err(LocalServiceTransportError::InvalidEndpoint);
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the endpoint as a path.
    #[must_use]
    pub fn as_path(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }

    /// Returns the endpoint string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The connected stream a client owns.
#[cfg(unix)]
pub type LocalServiceClientStream = tokio::net::UnixStream;

/// The connected stream a client owns.
#[cfg(windows)]
pub type LocalServiceClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// The connected stream the service owns for one accepted client.
#[cfg(unix)]
pub type LocalServiceServerStream = tokio::net::UnixStream;

/// The connected stream the service owns for one accepted client.
#[cfg(windows)]
pub type LocalServiceServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

/// Connects to the shared local service.
///
/// # Errors
///
/// Returns [`LocalServiceTransportError::EndpointUnavailable`] when the endpoint
/// cannot be reached, [`LocalServiceTransportError::EndpointNotOwnerProtected`] when
/// the existing endpoint is a link or is owned by another account,
/// [`LocalServiceTransportError::UnauthorizedPeer`] when the connected service runs
/// as another user, and [`LocalServiceTransportError::PeerVerificationUnavailable`]
/// when the kernel credential cannot be inspected. The error deliberately carries no
/// operating-system detail, because the endpoint path can encode a private runtime
/// directory name.
#[cfg(unix)]
pub async fn connect_local_service(
    endpoint: &LocalServiceEndpoint,
) -> Result<LocalServiceClientStream, LocalServiceTransportError> {
    assert_owner_owned_socket(&endpoint.as_path())?;
    let stream = tokio::net::UnixStream::connect(endpoint.as_path())
        .await
        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
    verify_unix_peer(&stream)?;
    Ok(stream)
}

/// Connects to the shared local service.
///
/// # Errors
///
/// Returns [`LocalServiceTransportError::EndpointUnavailable`] when the endpoint
/// cannot be reached, [`LocalServiceTransportError::EndpointNotOwnerProtected`] when
/// the server belongs to another account or runs below this client's integrity
/// level, and [`LocalServiceTransportError::PeerVerificationUnavailable`] when
/// Windows cannot establish the server identity.
#[cfg(windows)]
pub async fn connect_local_service(
    endpoint: &LocalServiceEndpoint,
) -> Result<LocalServiceClientStream, LocalServiceTransportError> {
    let stream = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(endpoint.as_str())
        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
    let verifier = KonclaveWindowsSecurity::WindowsAccountVerifier::current()
        .map_err(map_windows_verification_unavailable)?;
    verifier
        .verify_server(&stream)
        .map_err(map_windows_server_verification)?;
    Ok(stream)
}

/// The service's local listener.
///
/// One listener serves every concurrent client on one per-user endpoint. Accepting is
/// sequential and cheap; each accepted connection is handed to its own task, so a slow
/// handshake on one connection does not block another client from being accepted.
pub struct LocalServiceListener {
    endpoint: LocalServiceEndpoint,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(windows)]
    server: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    #[cfg(windows)]
    account_verifier: KonclaveWindowsSecurity::WindowsAccountVerifier,
}

impl LocalServiceListener {
    /// Returns the endpoint this listener owns.
    #[must_use]
    pub const fn endpoint(&self) -> &LocalServiceEndpoint {
        &self.endpoint
    }

    /// Creates the owner-restricted endpoint and starts listening.
    ///
    /// On Unix the parent directory is created owner-only when it is absent and is
    /// validated when it already exists. A symbolic link, a foreign-owned path, a
    /// non-socket file, and a socket that another live service is already serving are
    /// all refused; only a stale socket this account owns is replaced.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::EndpointNotOwnerProtected`] for an
    /// unsafe existing endpoint, [`LocalServiceTransportError::EndpointInUse`] when a
    /// live service already owns it, and
    /// [`LocalServiceTransportError::EndpointUnavailable`] when the platform refuses
    /// to create it.
    #[cfg(unix)]
    pub async fn bind(endpoint: &LocalServiceEndpoint) -> Result<Self, LocalServiceTransportError> {
        let path = endpoint.as_path();
        let parent = path
            .parent()
            .ok_or(LocalServiceTransportError::InvalidEndpoint)?;
        ensure_owner_only_directory(parent)?;
        prepare_socket_path(&path).await?;

        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
        restrict_socket(&path)?;
        Ok(Self {
            endpoint: endpoint.clone(),
            listener,
        })
    }

    /// Creates the named pipe and starts listening.
    ///
    /// The first instance is claimed exclusively and every instance receives an
    /// explicit DACL whose owner and sole allow ACE are the current account.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::EndpointInUse`] when the pipe name
    /// already exists and [`LocalServiceTransportError::PeerVerificationUnavailable`]
    /// when the current process account cannot be established.
    #[cfg(windows)]
    pub async fn bind(endpoint: &LocalServiceEndpoint) -> Result<Self, LocalServiceTransportError> {
        let account_verifier = KonclaveWindowsSecurity::WindowsAccountVerifier::current()
            .map_err(map_windows_verification_unavailable)?;
        let server = create_windows_server(endpoint, true)
            .map_err(|_| LocalServiceTransportError::EndpointInUse)?;
        Ok(Self {
            endpoint: endpoint.clone(),
            server: Some(server),
            account_verifier,
        })
    }

    /// Accepts one client connection whose peer ownership has been verified.
    ///
    /// A connection that fails verification is closed before this returns, and the
    /// caller continues accepting: one rejected peer must not stop the service.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnauthorizedPeer`] for a peer outside the
    /// owning account, [`LocalServiceTransportError::PeerVerificationUnavailable`]
    /// when ownership cannot be established, and
    /// [`LocalServiceTransportError::EndpointUnavailable`] when the platform refuses
    /// the accept.
    #[cfg(unix)]
    pub async fn accept(&mut self) -> Result<LocalServiceServerStream, LocalServiceTransportError> {
        let (stream, _address) = self
            .listener
            .accept()
            .await
            .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
        verify_unix_peer(&stream)?;
        Ok(stream)
    }

    /// Accepts one client connection whose peer ownership has been verified.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::EndpointUnavailable`] when the platform
    /// refuses the accept or the next pipe instance cannot be created,
    /// [`LocalServiceTransportError::UnauthorizedPeer`] when the client belongs to
    /// another account or runs below the service integrity level, and
    /// [`LocalServiceTransportError::PeerVerificationUnavailable`] when Windows
    /// cannot establish its identity.
    #[cfg(windows)]
    pub async fn accept(&mut self) -> Result<LocalServiceServerStream, LocalServiceTransportError> {
        loop {
            let connection = self
                .server
                .as_ref()
                .ok_or(LocalServiceTransportError::EndpointUnavailable)?
                .connect()
                .await;
            let server = self
                .server
                .take()
                .ok_or(LocalServiceTransportError::EndpointUnavailable)?;
            if connection.is_err() {
                self.server = Some(
                    create_windows_server(&self.endpoint, false)
                        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?,
                );
                continue;
            }
            self.server = Some(
                create_windows_server(&self.endpoint, false)
                    .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?,
            );
            self.account_verifier
                .verify_client(&server)
                .map_err(map_windows_client_verification)?;
            return Ok(server);
        }
    }
}

#[cfg(windows)]
fn create_windows_server(
    endpoint: &LocalServiceEndpoint,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, std::io::Error> {
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options.first_pipe_instance(first_instance);
    KonclaveWindowsSecurity::create_owner_restricted_named_pipe(&options, endpoint.as_str())
}

impl core::fmt::Debug for LocalServiceListener {
    /// Formats without the endpoint, because a local endpoint path can encode a
    /// private runtime directory name that should not reach a log line.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalServiceListener")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl Drop for LocalServiceListener {
    /// Removes this service's own socket by exact path.
    ///
    /// Neither the standard library nor tokio unlinks a bound socket, so a clean
    /// shutdown would otherwise leave a path that looks live until the next bind
    /// probes it. Ownership is rechecked first, so a path that was swapped for a link
    /// or for another account's socket is left untouched rather than deleted.
    fn drop(&mut self) {
        let path = self.endpoint.as_path();
        if assert_owner_owned_socket(&path).is_ok() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(unix)]
fn ensure_owner_only_directory(path: &Path) -> Result<(), LocalServiceTransportError> {
    use std::os::unix::fs::DirBuilderExt;

    if std::fs::symlink_metadata(path).is_err() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
    }
    assert_owner_only_directory(path)
}

#[cfg(unix)]
fn assert_owner_only_directory(path: &Path) -> Result<(), LocalServiceTransportError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    Ok(())
}

#[cfg(unix)]
async fn prepare_socket_path(path: &Path) -> Result<(), LocalServiceTransportError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    // A socket this account owns may still be served by a live service. Connecting
    // first is what distinguishes a crashed predecessor from a running one, so an
    // accidental second service cannot silently steal an endpoint from the first.
    if tokio::net::UnixStream::connect(path).await.is_ok() {
        return Err(LocalServiceTransportError::EndpointInUse);
    }
    std::fs::remove_file(path).map_err(|_| LocalServiceTransportError::EndpointUnavailable)
}

#[cfg(unix)]
fn restrict_socket(path: &Path) -> Result<(), LocalServiceTransportError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)
}

#[cfg(unix)]
fn verify_unix_peer(connection: &tokio::net::UnixStream) -> Result<(), LocalServiceTransportError> {
    let credentials = connection
        .peer_cred()
        .map_err(|_| LocalServiceTransportError::PeerVerificationUnavailable)?;
    if credentials.uid() == rustix::process::geteuid().as_raw() {
        Ok(())
    } else {
        Err(LocalServiceTransportError::UnauthorizedPeer)
    }
}

#[cfg(windows)]
fn map_windows_verification_unavailable(
    _error: KonclaveWindowsSecurity::WindowsSecurityError,
) -> LocalServiceTransportError {
    LocalServiceTransportError::PeerVerificationUnavailable
}

#[cfg(windows)]
fn map_windows_client_verification(
    error: KonclaveWindowsSecurity::WindowsSecurityError,
) -> LocalServiceTransportError {
    match error {
        KonclaveWindowsSecurity::WindowsSecurityError::ForeignAccount
        | KonclaveWindowsSecurity::WindowsSecurityError::LowerIntegrity => {
            LocalServiceTransportError::UnauthorizedPeer
        }
        _ => LocalServiceTransportError::PeerVerificationUnavailable,
    }
}

#[cfg(windows)]
fn map_windows_server_verification(
    error: KonclaveWindowsSecurity::WindowsSecurityError,
) -> LocalServiceTransportError {
    match error {
        KonclaveWindowsSecurity::WindowsSecurityError::ForeignAccount
        | KonclaveWindowsSecurity::WindowsSecurityError::LowerIntegrity => {
            LocalServiceTransportError::EndpointNotOwnerProtected
        }
        _ => LocalServiceTransportError::PeerVerificationUnavailable,
    }
}

#[cfg(unix)]
fn assert_owner_owned_socket(path: &Path) -> Result<(), LocalServiceTransportError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LocalServiceTransportError::EndpointUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(LocalServiceTransportError::EndpointNotOwnerProtected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LocalServiceEndpoint, MAX_ENDPOINT_LENGTH};
    use crate::error::LocalServiceTransportError;

    #[test]
    fn an_empty_oversized_or_nul_bearing_endpoint_is_rejected() {
        for value in [
            String::new(),
            "a".repeat(MAX_ENDPOINT_LENGTH + 1),
            "socket\0extra".to_string(),
        ] {
            assert_eq!(
                LocalServiceEndpoint::parse(&value).unwrap_err(),
                LocalServiceTransportError::InvalidEndpoint
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_endpoint_must_be_absolute() {
        assert_eq!(
            LocalServiceEndpoint::parse("relative/service.sock").unwrap_err(),
            LocalServiceTransportError::InvalidEndpoint
        );
        assert_eq!(
            LocalServiceEndpoint::parse("/run/konclave/service.sock")
                .unwrap()
                .as_str(),
            "/run/konclave/service.sock"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_endpoint_must_be_a_named_pipe() {
        for value in [r"C:\temp\service", r"\\.\pipe\", r"\\other\pipe\konclave"] {
            assert_eq!(
                LocalServiceEndpoint::parse(value).unwrap_err(),
                LocalServiceTransportError::InvalidEndpoint
            );
        }
        assert!(LocalServiceEndpoint::parse(r"\\.\pipe\konclave-service").is_ok());
    }
}
