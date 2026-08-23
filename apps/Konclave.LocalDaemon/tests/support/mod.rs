//! Shared fixtures for the daemon's integration tests.
//!
//! This module is compiled into several test binaries and no single binary uses all
//! of it, so unused items here are expected rather than dead code.
#![allow(
    dead_code,
    unused_imports,
    reason = "shared support module is built into several test binaries"
)]

use std::process::Command;

use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

pub struct TestProfile {
    _directory: TempDir,
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
}

impl TestProfile {
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("profiles");
        let key_file = directory.path().join("wrapping.key");
        std::fs::write(&key_file, [7_u8; 32]).unwrap();
        Self {
            _directory: directory,
            root,
            key_file,
        }
    }

    pub fn configure(&self, command: &mut Command) {
        command
            .env("KONCLAVE_PROFILE_ROOT", &self.root)
            .env("KONCLAVE_PROFILE_ID", "integration")
            .env("KONCLAVE_WRAPPING_KEY_FILE", &self.key_file);
    }

    /// Path the daemon creates when it begins opening this profile.
    ///
    /// The lock appears before identity material is generated, so its existence marks
    /// the middle of profile initialization rather than its completion.
    pub fn lock_path(&self) -> std::path::PathBuf {
        self.root.join("integration").join("profile.lock")
    }
}

/// A Community Relay instance backed by a real database and served over loopback.
///
/// Tests drive daemons against this rather than a stub so that relay behaviour under
/// test is the shipped behaviour, including what the database is allowed to contain.
pub struct TestRelay {
    directory: TempDir,
    endpoint: String,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
}

impl TestRelay {
    /// Starts a relay that grants one principal every permission on every route.
    pub async fn start(token: [u8; RelayPrincipalId::LENGTH], service: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let access_path = directory.path().join("access.json");
        let principal = RelayPrincipalId::from_access_token(&token);
        std::fs::write(
            &access_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "principals": [{
                    "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                    "grants": [{
                        "route": "*",
                        "permissions": ["send", "replay", "acknowledge"]
                    }]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application =
            RelayApplication::connect(&directory.path().join("relay.sqlite"), access.clone())
                .await
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let service = service.to_string();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(
                    HttpState::new(&service, application),
                    access,
                    shutdown_rx.clone(),
                ),
            )
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        });
        Self {
            directory,
            endpoint: format!("http://{address}"),
            shutdown,
            server,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn stop(self) {
        self.shutdown.send(true).unwrap();
        timeout(Duration::from_secs(5), self.server)
            .await
            .unwrap()
            .unwrap();
    }

    /// Fails when any relay database file contains a sentinel byte sequence.
    ///
    /// The write-ahead log and shared-memory files are included, because plaintext
    /// that only ever reached the log would still have left the device.
    pub fn assert_opaque(&self, sentinels: &[&[u8]]) {
        for entry in std::fs::read_dir(self.directory.path()).unwrap() {
            let path = entry.unwrap().path();
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("relay.sqlite"))
            {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            for sentinel in sentinels {
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|window| window == *sentinel),
                    "relay file {} contains application plaintext",
                    path.display()
                );
            }
        }
    }
}

#[cfg(unix)]
pub use adapter_host::{AdapterHost, AdapterSession};

#[cfg(unix)]
mod adapter_host {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use KonclaveAdapterTransport::{
        AdapterRequest, AdapterResponse, AdapterTransportError, LaunchCapability,
        MAX_AUTHENTICATED_FRAME_BYTES, OsChallenges, complete_adapter_handshake, read_frame,
        write_frame,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use tempfile::TempDir;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::time::{Duration, timeout};

    /// How long a test waits for the daemon to connect outward and authenticate.
    ///
    /// The daemon retries with backoff after a failure, so this is long enough to
    /// cover one retry and short enough to fail a hung test rather than hang CI.
    const ATTACH_TIMEOUT: Duration = Duration::from_secs(20);

    /// Byte width of a canonical adapter consumer identifier.
    const CONSUMER_ID_LENGTH: usize = 16;

    /// An adapter-owned rendezvous point plus the launch capability a daemon needs.
    ///
    /// ADR 0005 makes the adapter the listener and the daemon the outbound connector,
    /// so this fixture owns the endpoint and never asks the daemon to open one.
    pub struct AdapterHost {
        _directory: TempDir,
        listener: UnixListener,
        socket: PathBuf,
        capability_file: PathBuf,
        capability: LaunchCapability,
        profile: String,
        consumer: String,
    }

    impl AdapterHost {
        /// Creates an owner-only endpoint and capability file for one profile.
        ///
        /// The consumer identifier is derived from a seed rather than supplied as a
        /// string, because the daemon requires a canonical fixed-width value and a
        /// hand-written one is easy to get wrong.
        pub fn new(profile: &str, consumer_seed: u8, capability_seed: u8) -> Self {
            let consumer = URL_SAFE_NO_PAD.encode([consumer_seed; CONSUMER_ID_LENGTH]);
            let directory = tempfile::tempdir().unwrap();
            restrict_to_owner(directory.path(), 0o700);
            let socket = directory.path().join("adapter.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            restrict_to_owner(&socket, 0o700);
            let capability =
                LaunchCapability::from_bytes([capability_seed; LaunchCapability::LENGTH]);
            let capability_file = directory.path().join("adapter.capability");
            std::fs::write(
                &capability_file,
                URL_SAFE_NO_PAD.encode(capability.as_bytes()),
            )
            .unwrap();
            restrict_to_owner(&capability_file, 0o600);
            Self {
                _directory: directory,
                listener,
                socket,
                capability_file,
                capability,
                profile: profile.to_string(),
                consumer,
            }
        }

        /// Applies the launch environment a daemon reads to find this host.
        pub fn configure(&self, command: &mut Command) {
            for (name, value) in self.launch_environment() {
                command.env(name, value);
            }
        }

        /// The three launch variables a daemon needs to reach this host.
        ///
        /// They are returned together because the daemon rejects a partial set, so a
        /// caller cannot accidentally forward only some of them.
        pub fn launch_environment(&self) -> [(&'static str, std::ffi::OsString); 3] {
            [
                (
                    "KONCLAVE_ADAPTER_ENDPOINT",
                    self.socket.clone().into_os_string(),
                ),
                (
                    "KONCLAVE_ADAPTER_CAPABILITY_FILE",
                    self.capability_file.clone().into_os_string(),
                ),
                (
                    "KONCLAVE_ADAPTER_CONSUMER_ID",
                    std::ffi::OsString::from(&self.consumer),
                ),
            ]
        }

        pub fn consumer(&self) -> &str {
            &self.consumer
        }

        /// Accepts the daemon's outbound connection and authenticates it.
        ///
        /// Panics when the daemon does not attach, because a silent timeout would
        /// otherwise be indistinguishable from a slow test.
        pub async fn accept(&self) -> AdapterSession {
            self.try_accept()
                .await
                .expect("daemon did not attach to the adapter endpoint")
                .expect("daemon failed adapter authentication")
        }

        /// Accepts one connection, returning the authentication outcome.
        ///
        /// The outer `Option` distinguishes "nothing connected" from "connected and
        /// was rejected", which a cross-profile test has to tell apart.
        pub async fn try_accept(&self) -> Option<Result<AdapterSession, AdapterTransportError>> {
            let accepted = timeout(ATTACH_TIMEOUT, self.listener.accept()).await.ok()?;
            let (mut stream, _) = accepted.unwrap();
            let outcome = complete_adapter_handshake(
                &mut stream,
                &self.profile,
                &self.consumer,
                &self.capability,
                &mut OsChallenges::new(),
            )
            .await;
            Some(outcome.map(|_| AdapterSession { stream }))
        }
    }

    /// One authenticated adapter session over which requests and responses flow.
    pub struct AdapterSession {
        stream: UnixStream,
    }

    impl AdapterSession {
        /// Sends one request and returns the daemon's answer.
        pub async fn request(&mut self, request: &AdapterRequest) -> AdapterResponse {
            let encoded = request.encode();
            write_frame(&mut self.stream, &encoded, MAX_AUTHENTICATED_FRAME_BYTES)
                .await
                .unwrap();
            let payload = read_frame(&mut self.stream, MAX_AUTHENTICATED_FRAME_BYTES)
                .await
                .unwrap();
            AdapterResponse::decode(&payload).unwrap()
        }

        /// Claims a bounded batch, waiting up to the supplied budget.
        pub async fn claim(
            &mut self,
            max_events: u16,
            wait_milliseconds: u32,
        ) -> Vec<KonclaveAdapterTransport::DeliveredEvent> {
            match self
                .request(&AdapterRequest::WaitAndClaim {
                    max_events,
                    wait_milliseconds,
                })
                .await
            {
                AdapterResponse::Batch(batch) => batch,
                other => panic!("expected a batch, observed {other:?}"),
            }
        }

        /// Drops the session without acknowledging, modelling an adapter crash.
        pub fn abandon(self) {
            drop(self.stream);
        }
    }

    fn restrict_to_owner(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}
