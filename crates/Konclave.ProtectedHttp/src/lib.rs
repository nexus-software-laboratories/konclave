#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use thiserror::Error;

/// Stable failure while preparing a credential-bearing HTTP client.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProtectedHttpError {
    /// No process-wide rustls cryptographic provider could be installed.
    #[error("protected HTTP TLS provider is unavailable")]
    TlsProviderUnavailable,
}

/// Creates a reqwest builder with a configured rustls provider, redirects disabled,
/// and ambient proxy discovery disabled.
///
/// Callers remain responsible for finite connect/request timeouts and response-body
/// bounds.
///
/// # Errors
///
/// Returns a typed error when no rustls provider is available after installation.
pub fn protected_http_client_builder() -> Result<reqwest::ClientBuilder, ProtectedHttpError> {
    ensure_tls_provider()?;
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy())
}

fn ensure_tls_provider() -> Result<(), ProtectedHttpError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        Ok(())
    } else {
        Err(ProtectedHttpError::TlsProviderUnavailable)
    }
}
