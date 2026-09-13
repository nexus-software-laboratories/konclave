use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveLocalAuthorizationStore::installation_fingerprint;
use KonclaveLocalServiceTransport::{
    LocalServiceIdentitySource, LocalServiceInstallation, LocalServiceProfileCustody,
};
use KonclaveSecretStorage::{NativeLocalServiceIdentityStore, open_owner_protected_file};
use anyhow::{Context as _, ensure};

use crate::authorization_runtime::LiveAuthorizationRuntime;
use crate::local_service::{SharedLocalServiceConfig, run_shared_local_service_until};
use crate::profile_supervisor::ProfileSupervisorConfig;
use crate::runtime::ServiceProfileSettings;

pub(crate) async fn run_until<F>(installation_path: &Path, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let _telemetry_guard = crate::observability::init()?;
    let installation_path_owned = installation_path.to_path_buf();
    let (installation, identity) = tokio::task::spawn_blocking(move || {
        let file = open_owner_protected_file(&installation_path_owned)
            .context("opening owner-protected local-service installation")?;
        let installation = LocalServiceInstallation::from_reader(file)
            .context("reading local-service installation")?;
        let seed = match installation.service_identity_source() {
            LocalServiceIdentitySource::Native => {
                let seed = NativeLocalServiceIdentityStore
                    .load()
                    .context("loading native local-service identity")?;
                LocalServiceSigningSeed::from_reader(seed.as_slice())
                    .context("validating native local-service identity")?
            }
            LocalServiceIdentitySource::ExternalFile(path) => {
                let file = open_owner_protected_file(path)
                    .context("opening external local-service identity")?;
                LocalServiceSigningSeed::from_reader(file)
                    .context("validating external local-service identity")?
            }
        };
        let identity = LocalServiceIdentity::from_signing_seed(&seed)
            .context("importing local-service identity")?;
        ensure!(
            identity.public_key() == installation.service_public_key(),
            "native local-service identity does not match the installation"
        );
        Ok::<_, anyhow::Error>((installation, identity))
    })
    .await
    .context("joining local-service installation load")??;
    let fingerprint = installation_fingerprint(&installation)
        .context("binding durable authorization state to the installation")?;
    let authorization = LiveAuthorizationRuntime::open(installation_path, fingerprint)
        .await
        .context("opening durable local authorization state")?;
    let profile_source = Arc::new(match installation.profile_custody() {
        LocalServiceProfileCustody::Native => {
            ServiceProfileSettings::new(installation.profile_root().to_path_buf(), false)
        }
        LocalServiceProfileCustody::ExternalDirectory(directory) => {
            ServiceProfileSettings::with_external_custody(
                installation.profile_root().to_path_buf(),
                directory.clone(),
                false,
            )
        }
    });
    run_shared_local_service_until(
        SharedLocalServiceConfig {
            endpoint: installation.endpoint().clone(),
            service_identity: Arc::new(identity),
            authorization,
            profile_source,
            supervisor: ProfileSupervisorConfig::default(),
        },
        shutdown,
    )
    .await
}
