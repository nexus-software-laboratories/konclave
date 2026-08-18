use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, bail};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use axum_server::Handle;
use serde::Serialize;
use tokio::sync::watch;

#[derive(Clone)]
struct HttpState {
    service_name: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: String,
}

pub fn router(service_name: impl Into<String>, _shutdown: watch::Receiver<bool>) -> Router {
    let router = Router::new().route("/healthz", get(health));
    let websocket_shutdown = _shutdown.clone();
    let router = router.route(
        "/ws",
        get(move |upgrade| crate::websocket::upgrade(upgrade, websocket_shutdown.clone())),
    );
    router.with_state(HttpState {
        service_name: service_name.into(),
    })
}

#[allow(dead_code)]
pub(crate) fn check_health() -> anyhow::Result<()> {
    let address = std::env::var("SERVICE_HEALTH_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()
        .context("parsing SERVICE_HEALTH_ADDRESS")?;
    check_health_at(address)
}

fn check_health_at(address: SocketAddr) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("connecting to health endpoint at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting healthcheck read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting healthcheck write timeout")?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .context("writing healthcheck request")?;

    let mut response = [0_u8; 128];
    let mut response_length = 0;
    while response_length < response.len() {
        let read_length = stream
            .read(&mut response[response_length..])
            .context("reading healthcheck response")?;
        if read_length == 0 {
            break;
        }
        response_length += read_length;
        if response[..response_length].contains(&b'\n') {
            break;
        }
    }
    let status_line = std::str::from_utf8(&response[..response_length])
        .context("decoding healthcheck response")?
        .lines()
        .next()
        .unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        bail!("health endpoint returned a non-success status");
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn serve_until(
    mut shutdown: watch::Receiver<bool>,
    shutdown_grace_period: Duration,
) -> anyhow::Result<()> {
    let address = std::env::var("SERVICE_HTTP_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()
        .context("parsing SERVICE_HTTP_ADDRESS")?;
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let router_shutdown = shutdown.clone();

    let server = async move {
        axum_server::bind(address)
            .handle(handle)
            .serve(router(env!("CARGO_PKG_NAME"), router_shutdown).into_make_service())
            .await
            .context("serving HTTP requests")
    };
    let shutdown_signal = async move {
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        shutdown_handle.graceful_shutdown(Some(shutdown_grace_period));
        anyhow::Result::<()>::Ok(())
    };

    tokio::try_join!(server, shutdown_signal)?;
    Ok(())
}

async fn health(State(state): State<HttpState>) -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: state.service_name,
        }),
    )
}

#[cfg(test)]
mod healthcheck_tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn start_server(status: &'static str) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        (address, handle)
    }

    #[test]
    fn healthcheck_accepts_success_status() {
        let (address, server) = start_server("200 OK");
        check_health_at(address).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn healthcheck_rejects_failure_status() {
        let (address, server) = start_server("503 Service Unavailable");
        let error = check_health_at(address).unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("non-success"));
    }
}
