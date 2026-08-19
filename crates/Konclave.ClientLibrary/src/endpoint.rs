use std::net::IpAddr;

use url::{Host, Url};

use crate::KonclaveClientError;

/// Validated relay base endpoint with TLS required outside loopback.
#[derive(Clone)]
pub struct RelayEndpoint {
    base: Url,
}

impl RelayEndpoint {
    /// Parses an HTTP(S) relay endpoint.
    ///
    /// Plain HTTP is accepted only for `localhost` or a loopback IP address.
    /// User information, query parameters, and fragments are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveClientError::InvalidEndpoint`] when any endpoint invariant
    /// is violated.
    pub fn parse(value: &str) -> Result<Self, KonclaveClientError> {
        let mut base = Url::parse(value).map_err(|_| KonclaveClientError::InvalidEndpoint)?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(KonclaveClientError::InvalidEndpoint);
        }
        match base.scheme() {
            "https" => {}
            "http" if is_loopback(&base) => {}
            _ => return Err(KonclaveClientError::InvalidEndpoint),
        }
        if !base.path().ends_with('/') {
            let mut path = base.path().to_string();
            path.push('/');
            base.set_path(&path);
        }
        Ok(Self { base })
    }

    pub(crate) fn http_url(&self, relative: &str) -> Result<Url, KonclaveClientError> {
        self.base
            .join(relative)
            .map_err(|_| KonclaveClientError::InvalidEndpoint)
    }

    pub(crate) fn websocket_url(&self) -> Result<Url, KonclaveClientError> {
        let mut url = self.http_url("ws")?;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" => "ws",
            _ => return Err(KonclaveClientError::InvalidEndpoint),
        };
        url.set_scheme(scheme)
            .map_err(|_| KonclaveClientError::InvalidEndpoint)?;
        Ok(url)
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::RelayEndpoint;

    #[test]
    fn endpoint_requires_tls_except_on_loopback() {
        assert!(RelayEndpoint::parse("https://relay.example.com").is_ok());
        assert!(RelayEndpoint::parse("http://127.0.0.1:8080").is_ok());
        assert!(RelayEndpoint::parse("http://[::1]:8080/base").is_ok());
        assert!(RelayEndpoint::parse("http://relay.example.com").is_err());
        assert!(RelayEndpoint::parse("https://user@example.com").is_err());
        assert!(RelayEndpoint::parse("https://relay.example.com?token=value").is_err());
    }

    #[test]
    fn endpoint_preserves_an_explicit_base_path() {
        let endpoint = RelayEndpoint::parse("https://relay.example.com/konclave").unwrap();
        assert_eq!(
            endpoint.http_url("v1/replay").unwrap().as_str(),
            "https://relay.example.com/konclave/v1/replay"
        );
        assert_eq!(
            endpoint.websocket_url().unwrap().as_str(),
            "wss://relay.example.com/konclave/ws"
        );
    }
}
