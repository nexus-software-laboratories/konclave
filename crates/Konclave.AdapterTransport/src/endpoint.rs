use std::path::{Path, PathBuf};

use crate::error::AdapterTransportError;

/// Largest accepted local endpoint string.
///
/// Unix domain socket paths are limited by the platform's `sun_path`, and a Windows
/// pipe name is short by convention. Bounding the launch value keeps a malformed
/// environment from reaching a platform call with an unbounded string.
pub const MAX_ENDPOINT_LENGTH: usize = 200;

/// A local rendezvous point an adapter created before starting its daemon.
///
/// The daemon connects outward to this endpoint and never listens, so no inbound
/// socket exists on the device. The random name is defense in depth; the launch
/// capability is the authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterEndpoint(String);

impl AdapterEndpoint {
    /// Validates a launch-provided endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::InvalidEndpoint`] when the value is empty,
    /// longer than [`MAX_ENDPOINT_LENGTH`], contains a NUL, or is not absolute on
    /// Unix.
    pub fn parse(value: &str) -> Result<Self, AdapterTransportError> {
        if value.is_empty() || value.len() > MAX_ENDPOINT_LENGTH {
            return Err(AdapterTransportError::InvalidEndpoint);
        }
        if value.contains('\0') {
            return Err(AdapterTransportError::InvalidEndpoint);
        }
        #[cfg(unix)]
        if !Path::new(value).is_absolute() {
            return Err(AdapterTransportError::InvalidEndpoint);
        }
        #[cfg(windows)]
        if !value.starts_with(r"\\.\pipe\") {
            return Err(AdapterTransportError::InvalidEndpoint);
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

/// An established outbound connection to an adapter endpoint.
#[cfg(unix)]
pub type AdapterConnection = tokio::net::UnixStream;

/// An established outbound connection to an adapter endpoint.
#[cfg(windows)]
pub type AdapterConnection = tokio::net::windows::named_pipe::NamedPipeClient;

/// Connects outward to an adapter endpoint.
///
/// # Errors
///
/// Returns [`AdapterTransportError::EndpointUnavailable`] when the endpoint cannot be
/// reached. The error deliberately carries no operating-system detail, because the
/// endpoint path can encode an adapter-private directory name.
#[cfg(unix)]
pub async fn connect_adapter_endpoint(
    endpoint: &AdapterEndpoint,
) -> Result<AdapterConnection, AdapterTransportError> {
    tokio::net::UnixStream::connect(endpoint.as_path())
        .await
        .map_err(|_| AdapterTransportError::EndpointUnavailable)
}

/// Connects outward to an adapter endpoint.
///
/// # Errors
///
/// Returns [`AdapterTransportError::EndpointUnavailable`] when the endpoint cannot be
/// reached. The error deliberately carries no operating-system detail, because the
/// endpoint name can encode an adapter-private value.
#[cfg(windows)]
pub async fn connect_adapter_endpoint(
    endpoint: &AdapterEndpoint,
) -> Result<AdapterConnection, AdapterTransportError> {
    tokio::net::windows::named_pipe::ClientOptions::new()
        .open(endpoint.as_str())
        .map_err(|_| AdapterTransportError::EndpointUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{AdapterEndpoint, MAX_ENDPOINT_LENGTH};
    use crate::error::AdapterTransportError;

    #[test]
    fn rejects_empty_oversized_and_nul_bearing_endpoints() {
        for value in [
            String::new(),
            "a".repeat(MAX_ENDPOINT_LENGTH + 1),
            "/tmp/socket\0extra".to_string(),
        ] {
            assert_eq!(
                AdapterEndpoint::parse(&value).unwrap_err(),
                AdapterTransportError::InvalidEndpoint
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn requires_an_absolute_unix_path() {
        assert_eq!(
            AdapterEndpoint::parse("relative/socket").unwrap_err(),
            AdapterTransportError::InvalidEndpoint
        );
        assert_eq!(
            AdapterEndpoint::parse("/tmp/konclave/socket")
                .unwrap()
                .as_str(),
            "/tmp/konclave/socket"
        );
    }

    #[cfg(windows)]
    #[test]
    fn requires_a_named_pipe_prefix() {
        assert_eq!(
            AdapterEndpoint::parse(r"C:\temp\socket").unwrap_err(),
            AdapterTransportError::InvalidEndpoint
        );
        assert!(AdapterEndpoint::parse(r"\\.\pipe\konclave-abc").is_ok());
    }
}
