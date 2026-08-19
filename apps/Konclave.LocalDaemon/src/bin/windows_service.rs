#[allow(dead_code)]
#[cfg(windows)]
#[path = "../application.rs"]
mod application;
#[allow(dead_code)]
#[cfg(windows)]
#[path = "../conversation.rs"]
mod conversation;
#[allow(dead_code)]
#[cfg(windows)]
#[path = "../mcp.rs"]
mod mcp;
#[allow(dead_code)]
#[cfg(windows)]
#[path = "../observability.rs"]
mod observability;
#[allow(dead_code)]
#[cfg(windows)]
#[path = "../persistence.rs"]
mod persistence;
#[cfg(windows)]
#[path = "../runtime.rs"]
mod runtime;
#[cfg(windows)]
#[path = "../service.rs"]
mod service;

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    service_host::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The Windows Service host can run only on Windows.");
}

#[cfg(windows)]
mod service_host {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{Result, service_dispatcher};

    const SERVICE_NAME: &str = "KonclaveLocalDaemon";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> anyhow::Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let event_handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let service_result = runtime.block_on(super::runtime::run_until(async move {
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
        }));
        let exit_code = if service_result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        };

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        std::process::exit(if service_result.is_ok() { 0 } else { 1 });
    }
}
