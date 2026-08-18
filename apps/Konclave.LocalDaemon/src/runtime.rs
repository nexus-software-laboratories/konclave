use std::future::Future;
use std::time::Duration;

use crate::service::Service;
use tokio::sync::watch;

pub async fn run_until<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let _telemetry_guard = crate::observability::init()?;
    run_with_capabilities(shutdown).await
}

async fn run_with_capabilities<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
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
        let result =
            crate::mcp::run_stdio_server(crate::mcp::allow_all_authorization(), mcp_shutdown_rx)
                .await;
        let _ = mcp_shutdown_tx.send(true);
        result
    };

    tokio::try_join!(
        Service::new(Duration::from_secs(30)).run_until(wait_for_shutdown(shutdown_rx.clone())),
        mcp_server,
        external_shutdown
    )?;

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
