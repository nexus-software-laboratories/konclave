use std::future::{Future, IntoFuture as _};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use KonclaveA2AArtifactHttp::{
    A2AArtifactHttpServerConfig, A2AArtifactHttpState, a2a_artifact_router,
};
use KonclaveA2AArtifactStorage::FileA2AArtifactObjectStore;
use KonclaveA2AGateway::{
    A2AGatewayApplication, A2AGatewayWaitConfig, A2AHttpConfig, A2AHttpState,
    SystemA2AGatewayClock, a2a_router,
};
use KonclaveA2AKonclaveBridge::{A2AKonclaveBridge, A2AKonclaveBridgeConfig};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveLocalServiceClient::LocalServiceJsonClient;
use KonclaveSecretStorage::ensure_owner_protected_directory;
use anyhow::{Context as _, bail};
use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::config::RuntimeConfig;

const DEFAULT_HEALTH_ADDRESS: &str = "127.0.0.1:8090";
const HTTP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const BRIDGE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the self-hosted A2A gateway until the supplied shutdown future completes.
///
/// # Errors
///
/// Returns a bounded configuration, local-service, storage, listener, server, or
/// shutdown failure.
pub async fn run_until<F>(config_path: PathBuf, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let config = tokio::task::spawn_blocking(move || RuntimeConfig::load(&config_path))
        .await
        .context("joining A2A gateway configuration load")??;
    let local_service = Arc::new(
        LocalServiceJsonClient::connect(config.local_service)
            .await
            .context("connecting authenticated local-service client")?,
    );
    let database_path = config.task_database_file.clone();
    let store = Arc::new(
        tokio::task::spawn_blocking(move || {
            let parent = database_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or_else(|| anyhow::anyhow!("A2A task database has no parent"))?;
            ensure_owner_protected_directory(parent)
                .context("protecting A2A task database directory")?;
            A2ASqliteTaskStore::open(database_path, A2ASqliteTaskStoreConfig::default())
                .context("opening A2A task store")
        })
        .await
        .context("joining A2A task-store open")??,
    );
    let artifact_object_directory = config.artifact_object_directory.clone();
    let artifact_store = Arc::new(
        tokio::task::spawn_blocking(move || {
            FileA2AArtifactObjectStore::open(artifact_object_directory)
                .context("opening A2A artifact object store")
        })
        .await
        .context("joining A2A artifact object-store open")??,
    );
    let clock = Arc::new(SystemA2AGatewayClock);
    let bridge = Arc::new(
        A2AKonclaveBridge::new(
            store.clone(),
            local_service,
            clock.clone(),
            A2AKonclaveBridgeConfig::default(),
        )
        .context("building A2A-to-Konclave bridge")?,
    );
    let application = A2AGatewayApplication::new(
        config.route,
        config.publication,
        store,
        bridge.clone(),
        clock,
        A2AGatewayWaitConfig::default(),
    )
    .context("building A2A gateway application")?;
    let state = A2AHttpState::new(application, config.access, A2AHttpConfig::default())
        .context("building A2A HTTP state")?;
    let router = Router::new()
        .route("/healthz", get(health))
        .nest(
            "/objects",
            a2a_artifact_router(A2AArtifactHttpState::new(
                artifact_store,
                A2AArtifactHttpServerConfig::default(),
            )),
        )
        .merge(a2a_router(state));
    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .context("binding A2A gateway listener")?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let shutdown_trigger = async move {
        shutdown.await;
        let _ = shutdown_sender.send(());
    };
    let server_result = {
        let server = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_receiver.await;
            })
            .into_future();
        tokio::pin!(server);
        tokio::pin!(shutdown_trigger);
        tokio::select! {
            result = &mut server => result.context("serving A2A gateway"),
            _ = &mut shutdown_trigger => {
                match timeout(HTTP_SHUTDOWN_TIMEOUT, &mut server).await {
                    Ok(result) => result.context("serving A2A gateway"),
                    Err(_) => Err(anyhow::anyhow!("A2A HTTP shutdown deadline exceeded")),
                }
            }
        }
    };
    let shutdown_result = bridge
        .shutdown(BRIDGE_SHUTDOWN_TIMEOUT)
        .await
        .context("stopping A2A response observers");
    server_result?;
    shutdown_result
}

async fn health() -> StatusCode {
    StatusCode::OK
}

/// Probes the configured A2A gateway health endpoint.
///
/// # Errors
///
/// Returns a finite address, connection, I/O, encoding, or non-success failure.
pub fn check_health() -> anyhow::Result<()> {
    let address = std::env::var("SERVICE_HEALTH_ADDRESS")
        .unwrap_or_else(|_| DEFAULT_HEALTH_ADDRESS.to_owned())
        .parse::<SocketAddr>()
        .context("parsing SERVICE_HEALTH_ADDRESS")?;
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("connecting to A2A health endpoint at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting A2A healthcheck read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting A2A healthcheck write timeout")?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .context("writing A2A healthcheck request")?;

    let mut response = [0_u8; 128];
    let mut response_length = 0;
    while response_length < response.len() {
        let read_length = stream
            .read(&mut response[response_length..])
            .context("reading A2A healthcheck response")?;
        if read_length == 0 {
            break;
        }
        response_length += read_length;
        if response[..response_length].contains(&b'\n') {
            break;
        }
    }
    let status_line = std::str::from_utf8(&response[..response_length])
        .context("decoding A2A healthcheck response")?
        .lines()
        .next()
        .unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        bail!("A2A health endpoint returned a non-success status");
    }
    Ok(())
}
