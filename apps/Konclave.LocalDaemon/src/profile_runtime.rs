use std::future::Future;
use std::time::Duration;

use KonclaveClientLibrary::RelayClient;
use anyhow::Context as _;
use tokio::sync::watch;

use crate::adapter::AdapterLaunchConfig;
use crate::application::ApplicationService;
use crate::conversation::ConversationCoordinator;
use crate::pairing_service::PairingService;
use crate::service::Service;

/// One fully initialized logical profile hosted by the daemon process.
pub(crate) struct ProfileRuntime {
    pub(crate) conversations: ConversationCoordinator,
    pub(crate) applications: Option<ApplicationService<RelayClient>>,
    pub(crate) pairings: Option<PairingService<RelayClient>>,
    pub(crate) allow_mcp_write: bool,
    pub(crate) profile_id: String,
}

/// Runs one profile through the legacy stdio MCP and adapter bindings.
///
/// The profile itself contains no process-global configuration. The compatibility
/// host supplies every binding explicitly so the shared-service supervisor can reuse
/// the same initialized profile without inheriting process environment assumptions.
pub(crate) async fn run_legacy_until<F>(
    profile: ProfileRuntime,
    adapter_config: Option<AdapterLaunchConfig>,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let health = crate::health::DeliveryHealth::default();
    let mcp_server = crate::mcp::StdioServer::new(
        profile.conversations.clone(),
        profile.applications.clone(),
        profile.pairings.clone(),
        health.clone(),
        crate::mcp::local_stdio_authorization(profile.allow_mcp_write),
    );
    let service_applications = profile.applications.clone();
    let pairing_service = profile.pairings.clone();
    let pairing_retry_seed = profile
        .conversations
        .device_id()
        .context("loading pairing retry identity")?;
    let adapter_store = profile.conversations.store();
    let adapter_health = health.clone();
    let adapter_profile = profile.profile_id.clone();
    let _profile = profile;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let external_shutdown_tx = shutdown_tx.clone();
    let external_shutdown_rx = shutdown_rx.clone();
    let external_shutdown = async move {
        tokio::select! {
            _ = shutdown => {
                let _ = external_shutdown_tx.send(true);
            }
            _ = wait_for_shutdown(external_shutdown_rx) => {}
        }
        anyhow::Result::<()>::Ok(())
    };
    let mcp_shutdown_tx = shutdown_tx.clone();
    let mcp_shutdown_rx = shutdown_rx.clone();
    let mcp_server = async move {
        let result = crate::mcp::run_stdio_server(mcp_server, mcp_shutdown_rx).await;
        let _ = mcp_shutdown_tx.send(true);
        result
    };
    let service_shutdown_tx = shutdown_tx.clone();
    let service_shutdown_rx = shutdown_rx.clone();
    let service = async move {
        let result = Service::new(service_applications, Duration::from_secs(30), health)
            .run_until(wait_for_shutdown(service_shutdown_rx))
            .await;
        let _ = service_shutdown_tx.send(true);
        result
    };
    let pairing_shutdown_tx = shutdown_tx.clone();
    let pairing_shutdown_rx = shutdown_rx.clone();
    let pairing = async move {
        let result =
            crate::pairing_supervisor::PairingSupervisor::new(pairing_service, pairing_retry_seed)
                .run_until(wait_for_shutdown(pairing_shutdown_rx))
                .await;
        let _ = pairing_shutdown_tx.send(true);
        result
    };
    let adapter_shutdown_rx = shutdown_rx.clone();
    let adapter = async move {
        crate::adapter::run_adapter_channel(
            adapter_config,
            adapter_store,
            &adapter_profile,
            adapter_health,
            adapter_shutdown_rx,
        )
        .await;
        anyhow::Result::<()>::Ok(())
    };

    tokio::try_join!(service, pairing, mcp_server, adapter, external_shutdown)?;
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}
