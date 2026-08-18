use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::ServerInitializeError;
use rmcp::{ServerHandler, ServiceExt};
use tokio::sync::watch;
use tokio::time::timeout;

pub struct AuthorizationContext<'a> {
    pub method: &'a str,
}

pub type AuthorizationHook =
    Arc<dyn Fn(AuthorizationContext<'_>) -> anyhow::Result<()> + Send + Sync>;

#[derive(Clone, Default)]
struct StdioServer;

impl ServerHandler for StdioServer {
    #[allow(deprecated)]
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::default()).with_server_info(Implementation::new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
        ))
    }
}

#[must_use]
pub fn allow_all_authorization() -> AuthorizationHook {
    Arc::new(|_| Ok(()))
}

pub async fn run_stdio_server(
    authorize: AuthorizationHook,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    authorize(AuthorizationContext {
        method: "initialize",
    })?;
    ensure_stdout_safe_diagnostics("stderr")?;

    let service = tokio::select! {
        result = StdioServer.serve(rmcp::transport::stdio()) => {
            match result {
                Ok(service) => service,
                Err(
                    ServerInitializeError::ConnectionClosed(_) |
                    ServerInitializeError::Cancelled,
                ) => return Ok(()),
                Err(error) => {
                    return Err(error).context("starting MCP stdio transport");
                }
            }
        }
        _ = wait_for_shutdown(&mut shutdown) => {
            close_stdio_input();
            return Ok(());
        }
    };
    let cancellation = service.cancellation_token();
    let mut waiting = tokio::spawn(service.waiting());

    tokio::select! {
        result = &mut waiting => {
            result
                .context("joining MCP stdio service")?
                .context("waiting for MCP stdio service")?;
        }
        _ = wait_for_shutdown(&mut shutdown) => {
            close_stdio_input();
            cancellation.cancel();
            timeout(Duration::from_secs(5), &mut waiting)
                .await
                .context("waiting for MCP stdio shutdown")?
                .context("joining MCP stdio service")?
                .context("waiting for MCP stdio service")?;
        }
    }

    Ok(())
}

fn close_stdio_input() {
    #[cfg(unix)]
    unsafe {
        // SAFETY: the process is shutting down its stdio protocol transport, and
        // closing this process-owned descriptor unblocks Tokio's stdin reader.
        let _ = libc::close(libc::STDIN_FILENO);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

        // SAFETY: GetStdHandle returns the process-owned stdin handle. It is closed
        // only during coordinated shutdown to unblock the stdio transport reader.
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            let _ = CloseHandle(handle);
        }
    }
}

pub fn ensure_stdout_safe_diagnostics(stream_name: &str) -> anyhow::Result<()> {
    ensure!(
        stream_name != "stdout",
        "stdout is reserved for the MCP stdio transport"
    );
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::{ClientHandler, ServiceExt};

    use super::{
        AuthorizationContext, AuthorizationHook, StdioServer, allow_all_authorization,
        ensure_stdout_safe_diagnostics,
    };

    #[derive(Clone, Default)]
    struct TestClient;

    impl ClientHandler for TestClient {}

    #[test]
    fn authorization_hook_is_explicit_and_deterministic() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = called.clone();
        let hook: AuthorizationHook = Arc::new(move |context: AuthorizationContext<'_>| {
            assert_eq!(context.method, "initialize");
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

        hook(AuthorizationContext {
            method: "initialize",
        })
        .unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
        allow_all_authorization()(AuthorizationContext {
            method: "initialize",
        })
        .unwrap();
    }

    #[test]
    fn stdout_is_rejected_for_diagnostics() {
        let error = ensure_stdout_safe_diagnostics("stdout").unwrap_err();
        assert!(error.to_string().contains("stdout"));
        assert!(ensure_stdout_safe_diagnostics("stderr").is_ok());
    }

    #[tokio::test]
    async fn in_memory_client_observes_deterministic_server_identity() {
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            StdioServer
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let mut client = TestClient.serve(client_transport).await.unwrap();
        let peer = client.peer_info().unwrap();
        let server_info = peer.server_info.as_ref().unwrap();
        assert_eq!(server_info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(server_info.version, env!("CARGO_PKG_VERSION"));

        client.close().await.unwrap();
        server.await.unwrap();
    }
}
