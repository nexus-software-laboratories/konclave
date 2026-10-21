use std::sync::Arc;
use std::time::Duration;

use KonclaveDomainCore::{
    MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_REPLAY_PAGE_BYTES, ReplayPage, ReplayRequest,
};
use KonclaveProtocolContracts::v1::{decode_replay_page, encode_replay_request};
use futures_util::{SinkExt, StreamExt};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::GaiResolver;
use reqwest::header::AUTHORIZATION;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async_tls_with_config};
use tower_service::Service;

use crate::error::stable_relay_code;
use crate::{KonclaveClientError, RelayAccessCredential, RelayEndpoint};

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Caller-owned authenticated watch session.
///
/// Callers continuously read pages, persist processed cursors, and reconnect with
/// the last durable cursor after any returned error.
pub struct RelayWatchSession {
    socket: RelaySocket,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl RelayWatchSession {
    /// Reads the next replay page while servicing WebSocket heartbeat frames.
    ///
    /// # Errors
    ///
    /// Returns a timeout, transport, close, message-kind, or protocol error.
    pub async fn next_page(&mut self) -> Result<ReplayPage, KonclaveClientError> {
        loop {
            let message = timeout(self.read_timeout, self.socket.next())
                .await
                .map_err(|_| KonclaveClientError::Timeout)?
                .ok_or(KonclaveClientError::WatchClosed)?
                .map_err(|_| KonclaveClientError::TransportUnavailable)?;
            match message {
                Message::Binary(bytes) => return decode_replay_page(&bytes).map_err(Into::into),
                Message::Ping(payload) => {
                    timeout(self.write_timeout, self.socket.send(Message::Pong(payload)))
                        .await
                        .map_err(|_| KonclaveClientError::Timeout)?
                        .map_err(|_| KonclaveClientError::TransportUnavailable)?;
                }
                Message::Pong(_) => {}
                Message::Close(Some(frame)) => {
                    return Err(KonclaveClientError::WatchRejected {
                        close_code: frame.code.into(),
                        relay_code: stable_relay_code(&frame.reason),
                    });
                }
                Message::Close(None) => return Err(KonclaveClientError::WatchClosed),
                Message::Text(_) | Message::Frame(_) => {
                    return Err(KonclaveClientError::InvalidResponse);
                }
            }
        }
    }

    /// Sends a normal close frame.
    ///
    /// # Errors
    ///
    /// Returns a timeout or transport error when the close cannot be written.
    pub async fn close(mut self) -> Result<(), KonclaveClientError> {
        timeout(self.write_timeout, self.socket.close(None))
            .await
            .map_err(|_| KonclaveClientError::Timeout)?
            .map_err(|_| KonclaveClientError::TransportUnavailable)
    }
}

pub(crate) async fn connect_watch(
    endpoint: &RelayEndpoint,
    credential: Arc<RelayAccessCredential>,
    request: ReplayRequest,
    operation_timeout: Duration,
    watch_read_timeout: Duration,
) -> Result<RelayWatchSession, KonclaveClientError> {
    let tcp_uri = endpoint
        .http_url("ws")?
        .as_str()
        .parse::<Uri>()
        .map_err(|_| KonclaveClientError::InvalidEndpoint)?;
    let url = endpoint.websocket_url()?;
    let mut handshake = url
        .as_str()
        .into_client_request()
        .map_err(|_| KonclaveClientError::InvalidEndpoint)?;
    handshake
        .headers_mut()
        .insert(AUTHORIZATION, credential.authorization_header()?);
    let config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * MAX_RELAY_CONTROL_MESSAGE_BYTES)
        .max_message_size(Some(MAX_REPLAY_PAGE_BYTES))
        .max_frame_size(Some(MAX_REPLAY_PAGE_BYTES));
    let (mut socket, _) = timeout(operation_timeout, async {
        let stream = watch_tcp_connector(GaiResolver::new())
            .call(tcp_uri)
            .await
            .map_err(|_| KonclaveClientError::TransportUnavailable)?
            .into_inner();
        client_async_tls_with_config(handshake, stream, Some(config), None)
            .await
            .map_err(map_connect_error)
    })
    .await
    .map_err(|_| KonclaveClientError::Timeout)??;
    let request = encode_replay_request(request)?;
    timeout(
        operation_timeout,
        socket.send(Message::Binary(request.into())),
    )
    .await
    .map_err(|_| KonclaveClientError::Timeout)?
    .map_err(|_| KonclaveClientError::TransportUnavailable)?;
    Ok(RelayWatchSession {
        socket,
        read_timeout: watch_read_timeout,
        write_timeout: operation_timeout,
    })
}

fn watch_tcp_connector<R>(resolver: R) -> HttpConnector<R> {
    let mut connector = HttpConnector::new_with_resolver(resolver);
    // This selects TCP addresses only; tungstenite still verifies TLS against the original hostname.
    connector.enforce_http(false);
    connector
}

fn map_connect_error(error: tokio_tungstenite::tungstenite::Error) -> KonclaveClientError {
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            let relay_code = response
                .headers()
                .get("x-konclave-error-code")
                .and_then(|value| value.to_str().ok())
                .map(stable_relay_code)
                .unwrap_or_else(|| "relay_rejected".to_string());
            KonclaveClientError::RelayRejected {
                status: response.status().as_u16(),
                relay_code,
            }
        }
        _ => KonclaveClientError::TransportUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::{Ready, ready};
    use std::net::{Ipv6Addr, SocketAddr};
    use std::task::{Context, Poll};

    use hyper_util::client::legacy::connect::dns::Name;
    use tokio::net::{TcpListener, TcpSocket};

    use super::*;

    #[derive(Clone)]
    struct FixedResolver(Vec<SocketAddr>);

    impl Service<Name> for FixedResolver {
        type Response = std::vec::IntoIter<SocketAddr>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Name) -> Self::Future {
            ready(Ok(self.0.clone().into_iter()))
        }
    }

    #[tokio::test]
    async fn watch_connector_falls_back_from_unreachable_ipv6_to_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let unavailable = TcpSocket::new_v6().unwrap();
        let unavailable_address = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), address.port());
        unavailable.bind(unavailable_address).unwrap();
        let mut connector = watch_tcp_connector(FixedResolver(vec![unavailable_address, address]));
        let uri = format!("https://relay.invalid:{}", address.port())
            .parse()
            .unwrap();
        let stream = timeout(Duration::from_secs(5), connector.call(uri))
            .await
            .unwrap()
            .unwrap()
            .into_inner();
        assert_eq!(stream.peer_addr().unwrap(), address);
        let (_, accepted_peer) = listener.accept().await.unwrap();
        assert_eq!(accepted_peer, stream.local_addr().unwrap());
    }

    #[tokio::test]
    async fn watch_connector_rejects_empty_resolution() {
        let mut connector = watch_tcp_connector(FixedResolver(Vec::new()));
        assert!(
            connector
                .call("https://relay.invalid".parse().unwrap())
                .await
                .is_err()
        );
    }
}
