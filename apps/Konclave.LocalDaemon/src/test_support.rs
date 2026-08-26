use std::path::{Path, PathBuf};

use KonclaveClientLibrary::RelayEnrollmentAuthorityId;
use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

use crate::persistence::{LockedProfile, ProfileId, ProfileStoreError};
use crate::runtime::{ProfileConfig, ProfileCustody, ProfileSource, read_relay_installation};

/// Domain separator for test wrapping keys.
///
/// This is a test fixture, not a key-derivation contract: it exists so every test
/// profile gets its own distinct external key without a shared file, and it never
/// derives production custody.
const TEST_KEY_DOMAIN: &[u8] = b"konclave.test.profile-wrapping-key.v1\0";

/// A profile source that binds every profile to its own external wrapping key.
///
/// Production resolves native per-profile custody, which needs a platform keychain a
/// headless runner does not have. Tests therefore supply external custody, but they
/// supply it the way production must: one key per profile, never one file shared
/// across profiles.
pub(crate) struct TestProfileSettings {
    root: PathBuf,
    keys: PathBuf,
}

impl TestProfileSettings {
    pub(crate) fn new(root: PathBuf, keys: PathBuf) -> Self {
        Self { root, keys }
    }

    /// Returns the wrapping-key path this source binds to one profile.
    pub(crate) fn key_path(&self, profile: &str) -> PathBuf {
        self.keys.join(format!("{profile}.key"))
    }

    /// Returns the deterministic, distinct key bytes for one profile.
    pub(crate) fn key_bytes(profile: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(TEST_KEY_DOMAIN);
        digest.update(profile.as_bytes());
        digest.finalize().into()
    }

    /// Creates the profile's key file if it does not exist yet.
    pub(crate) fn ensure_key(&self, profile: &str) -> PathBuf {
        let path = self.key_path(profile);
        if !path.exists() {
            std::fs::create_dir_all(&self.keys).unwrap();
            std::fs::write(&path, Self::key_bytes(profile)).unwrap();
        }
        path
    }
}

impl ProfileSource for TestProfileSettings {
    fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
        let key = self.ensure_key(profile.as_str());
        Ok(ProfileConfig::for_profile(
            self.root.clone(),
            profile.clone(),
            ProfileCustody::ExternalFile(key),
            read_relay_installation(&self.root)?,
            false,
        ))
    }
}

/// An isolated profile root whose profiles each own an external wrapping key.
///
/// Tests never touch native platform custody: it is machine state that would leak
/// between runs and is unavailable on a headless runner.
pub(crate) struct TestProfileRoot {
    directory: tempfile::TempDir,
    root: PathBuf,
    keys: PathBuf,
}

impl TestProfileRoot {
    pub(crate) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("profiles");
        let keys = directory.path().join("keys");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&keys).unwrap();
        Self {
            directory,
            root,
            keys,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the wrapping-key path bound to one profile.
    pub(crate) fn key_path(&self, profile: &str) -> PathBuf {
        self.settings().key_path(profile)
    }

    /// Creates one profile's wrapping key and returns its path.
    pub(crate) fn ensure_key(&self, profile: &str) -> PathBuf {
        self.settings().ensure_key(profile)
    }

    pub(crate) fn settings(&self) -> TestProfileSettings {
        TestProfileSettings::new(self.root.clone(), self.keys.clone())
    }

    pub(crate) fn config(&self, profile: &str) -> ProfileConfig {
        self.settings()
            .configure(&ProfileId::parse(profile).unwrap())
            .unwrap()
    }

    /// Reports whether one profile's exclusive lock is currently held.
    pub(crate) fn is_locked(&self, profile: &str) -> bool {
        matches!(
            LockedProfile::acquire(&self.root, ProfileId::parse(profile).unwrap()),
            Err(ProfileStoreError::ProfileLocked)
        )
    }

    /// Waits for one profile's lock to be released, within a bounded deadline.
    ///
    /// Aborting a task is asynchronous: the runtime drops its future after the abort
    /// is requested. A deadline is therefore the only way to assert the release, and
    /// it yields rather than sleeps so a correct implementation converges at once.
    pub(crate) async fn wait_until_unlocked(&self, profile: &str) {
        let released = timeout(Duration::from_secs(5), async {
            while self.is_locked(profile) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(released.is_ok(), "{profile} lock was never released");
    }
}

pub(crate) struct TestRelay {
    _directory: tempfile::TempDir,
    pub(crate) endpoint: String,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
}

impl TestRelay {
    pub(crate) async fn start_static(token: [u8; RelayPrincipalId::LENGTH]) -> Self {
        let principal = RelayPrincipalId::from_access_token(&token);
        Self::start(json!({
            "version": 1,
            "principals": [{
                "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                "grants": [{
                    "route": "*",
                    "permissions": ["send", "replay", "acknowledge"]
                }]
            }]
        }))
        .await
    }

    pub(crate) async fn start_enrollment(token: [u8; RelayEnrollmentAuthorityId::LENGTH]) -> Self {
        let authority = RelayEnrollmentAuthorityId::from_enrollment_token(&token);
        Self::start(json!({
            "version": 2,
            "principals": [],
            "enrollment": {
                "authority": URL_SAFE_NO_PAD.encode(authority.as_bytes())
            }
        }))
        .await
    }

    async fn start(access_document: serde_json::Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let access_path = directory.path().join("access.json");
        std::fs::write(&access_path, serde_json::to_vec(&access_document).unwrap()).unwrap();
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application =
            RelayApplication::connect(&directory.path().join("relay.sqlite"), access.clone())
                .await
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(
                    HttpState::new("local-daemon-test", application),
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
            _directory: directory,
            endpoint: format!("http://{address}"),
            shutdown,
            server,
        }
    }

    pub(crate) async fn stop(self) {
        self.shutdown.send(true).unwrap();
        timeout(Duration::from_secs(2), self.server)
            .await
            .unwrap()
            .unwrap();
    }
}
