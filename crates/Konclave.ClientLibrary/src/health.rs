use crate::protected_http::ProtectedHttpClient;
use crate::{KonclaveClientError, RelayEndpoint};

const MAX_HEALTH_RESPONSE_BYTES: usize = 1024;

/// Checks the uncredentialed bounded relay health endpoint.
///
/// Redirects and automatic proxy discovery remain disabled, and the shared
/// TLS-or-loopback endpoint policy applies.
///
/// # Errors
///
/// Returns an endpoint, timeout, transport, rejection, or response-bounds error.
pub async fn check_relay_health(endpoint: RelayEndpoint) -> Result<(), KonclaveClientError> {
    let response = ProtectedHttpClient::new(endpoint)?
        .get("healthz", MAX_HEALTH_RESPONSE_BYTES)
        .await?;
    if response.status == 200 {
        Ok(())
    } else {
        Err(KonclaveClientError::InvalidResponse)
    }
}
