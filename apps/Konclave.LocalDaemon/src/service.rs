use std::future::Future;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::watch;
use tokio::time::{self, timeout};

/// Owns the long-running task, its shutdown signal, and graceful completion.
pub struct Service {
    tick_interval: Duration,
    shutdown_timeout: Duration,
}

impl Service {
    #[must_use]
    pub fn new(tick_interval: Duration) -> Self {
        Self {
            tick_interval,
            shutdown_timeout: Duration::from_secs(5),
        }
    }

    pub async fn run_until<F>(self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()>,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(run_worker(self.tick_interval, shutdown_rx));

        shutdown.await;
        shutdown_tx
            .send(true)
            .context("signaling service shutdown")?;

        timeout(self.shutdown_timeout, worker)
            .await
            .context("waiting for service shutdown")??
    }
}

async fn run_worker(
    tick_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut ticker = time::interval(tick_interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                run_iteration().await?;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn run_iteration() -> anyhow::Result<()> {
    tokio::task::yield_now().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::Service;

    #[tokio::test]
    async fn shuts_down_when_requested() {
        let service = Service::new(Duration::from_millis(1));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let handle = tokio::spawn(service.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        shutdown_tx.send(()).unwrap();

        let result = timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().unwrap().is_ok());
    }
}
