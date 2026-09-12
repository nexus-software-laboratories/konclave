use std::collections::HashSet;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use KonclaveA2AContracts::{
    InitialA2AAgentSecurityKind, InitialA2AInterfaceEnvironment,
};
use KonclaveA2ADiscovery::{
    CompiledA2AAgentPublication, compile_a2a_agent_publication_file,
};
use KonclaveA2ADomain::{A2AAgentRoute, A2AContextId, A2ATenantId};
use KonclaveA2AGateway::{
    A2ABearerCredential, A2AGatewayError, A2AHttpAccess, A2AHttpAction,
    A2AHttpAuthorizationDecision, A2AHttpPrincipalId, StaticBearerAccess,
    validate_a2a_binding,
};
use KonclaveBoundedDocuments::{
    BoundedVec, deserialize_strict, read_bounded_regular_file,
};
use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveDomainCore::{ConversationId, DeviceId};
use KonclaveLocalServiceClient::{
    LocalServiceIssuerCredential, LocalServiceJsonClientConfig,
};
use KonclaveLocalServiceTransport::{
    HarnessKind, LocalServiceInstallation, ServiceProfileId, decode_lowercase_hex,
};
use KonclaveSecretStorage::open_owner_protected_file;
use anyhow::{Context as _, bail};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

const CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_BEARER_FILES: usize = 64;
const MAX_BEARER_FILE_BYTES: usize = 514;

/// Fully validated process configuration with secret-bearing access kept opaque.
pub(crate) struct RuntimeConfig {
    pub(crate) listen_address: SocketAddr,
    pub(crate) publication: CompiledA2AAgentPublication,
    pub(crate) route: A2AAgentRoute,
    pub(crate) task_database_file: PathBuf,
    pub(crate) local_service: LocalServiceJsonClientConfig,
    pub(crate) access: Arc<dyn A2AHttpAccess>,
}

impl RuntimeConfig {
    /// Loads one bounded, non-linked strict-JSON configuration.
    ///
    /// All referenced publication, local-service, issuer, and bearer inputs are
    /// validated before the runtime creates storage or binds a listener.
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.is_absolute() {
            bail!("A2A gateway configuration path must be absolute");
        }
        let bytes = read_bounded_regular_file(path, MAX_CONFIG_BYTES)
            .context("reading bounded A2A gateway configuration")?;
        let source: ConfigSource =
            deserialize_strict(&bytes, MAX_CONFIG_BYTES)
                .context("decoding A2A gateway configuration")?;
        source.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigSource {
    schema_version: u32,
    interface_environment: InterfaceEnvironment,
    listener: ListenerSource,
    publication_file: PathBuf,
    task_database_file: PathBuf,
    route: RouteSource,
    local_service: LocalServiceSource,
    bearer_token_files: BoundedVec<PathBuf, MAX_BEARER_FILES>,
}

impl ConfigSource {
    fn validate(self) -> anyhow::Result<RuntimeConfig> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            bail!("A2A gateway configuration schema version is unsupported");
        }
        let listen_address = self
            .listener
            .address
            .parse::<SocketAddr>()
            .context("parsing A2A gateway listener address")?;
        validate_a2a_binding(listen_address.ip(), self.listener.tls_terminated)
            .context("validating A2A gateway listener trust boundary")?;

        let publication_file = require_absolute(self.publication_file, "publication file")?;
        let task_database_file =
            require_absolute(self.task_database_file, "task database file")?;
        let installation_file = require_absolute(
            self.local_service.installation_file,
            "local-service installation file",
        )?;
        let issuer_key_file =
            require_absolute(self.local_service.issuer_key_file, "issuer key file")?;
        let bearer_token_files = self
            .bearer_token_files
            .into_inner()
            .into_iter()
            .map(|path| require_absolute(path, "bearer token file"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        reject_duplicate_paths(&bearer_token_files)?;

        let database_parent = task_database_file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .context("task database file has no parent")?;
        if !database_parent.is_absolute() {
            bail!("task database parent must be absolute");
        }

        let environment = self.interface_environment.into_contract();
        let publication = compile_a2a_agent_publication_file(&publication_file, environment)
            .context("compiling A2A agent publication")?;
        for interface in publication.card().interfaces() {
            let url = Url::parse(interface.url()).context("parsing validated A2A interface URL")?;
            if url.path() != "/" {
                bail!("self-hosted A2A interfaces must use a dedicated origin root");
            }
        }

        let context_id = A2AContextId::parse(self.route.context_id)
            .context("validating A2A context identifier")?;
        let conversation_id = ConversationId::from_bytes(
            decode_lowercase_hex::<{ ConversationId::LENGTH }>(&self.route.conversation_id)
                .context("validating Konclave conversation identifier")?,
        );
        let target_device_id = DeviceId::from_bytes(
            decode_lowercase_hex::<{ DeviceId::LENGTH }>(&self.route.target_device_id)
                .context("validating Konclave target device identifier")?,
        );
        let tenant = publication
            .card()
            .interfaces()
            .first()
            .and_then(|interface| interface.tenant())
            .map(|tenant| A2ATenantId::parse(tenant.to_owned()))
            .transpose()
            .context("validating A2A tenant identifier")?;
        let route = A2AAgentRoute::new(
            publication.id().clone(),
            context_id,
            tenant,
            conversation_id,
            target_device_id,
        );

        let profile = ServiceProfileId::parse(self.local_service.profile)
            .context("validating local-service profile")?;
        let local_service = load_local_service(
            &installation_file,
            &issuer_key_file,
            &profile,
        )?;
        let access = build_access(
            publication.card().security().map(|security| security.kind()),
            listen_address,
            self.listener.tls_terminated,
            bearer_token_files,
        )?;

        Ok(RuntimeConfig {
            listen_address,
            publication,
            route,
            task_database_file,
            local_service,
            access,
        })
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InterfaceEnvironment {
    Production,
    LoopbackDevelopment,
}

impl InterfaceEnvironment {
    const fn into_contract(self) -> InitialA2AInterfaceEnvironment {
        match self {
            Self::Production => InitialA2AInterfaceEnvironment::Production,
            Self::LoopbackDevelopment => InitialA2AInterfaceEnvironment::LoopbackDevelopment,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListenerSource {
    address: String,
    tls_terminated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RouteSource {
    context_id: String,
    conversation_id: String,
    target_device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalServiceSource {
    installation_file: PathBuf,
    issuer_key_file: PathBuf,
    profile: String,
}

fn require_absolute(path: PathBuf, field: &str) -> anyhow::Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{field} must be absolute");
    }
    Ok(path)
}

fn reject_duplicate_paths(paths: &[PathBuf]) -> anyhow::Result<()> {
    let unique = paths.iter().collect::<HashSet<_>>();
    if unique.len() != paths.len() {
        bail!("A2A bearer token files must be unique");
    }
    Ok(())
}

fn load_local_service(
    installation_file: &Path,
    issuer_key_file: &Path,
    profile: &ServiceProfileId,
) -> anyhow::Result<LocalServiceJsonClientConfig> {
    let installation = LocalServiceInstallation::from_reader(
        open_owner_protected_file(installation_file)
            .context("opening owner-protected local-service installation")?,
    )
    .context("decoding local-service installation")?;
    let issuer_seed = LocalServiceSigningSeed::from_reader(
        open_owner_protected_file(issuer_key_file)
            .context("opening owner-protected local-service issuer key")?,
    )
    .context("decoding local-service issuer key")?;
    let issuer_identity = LocalServiceIdentity::from_signing_seed(&issuer_seed)
        .context("loading local-service issuer identity")?;
    let matching = installation
        .issuers()
        .iter()
        .filter(|issuer| {
            let registration = issuer.registration();
            registration.public_key() == issuer_identity.public_key()
                && matches!(
                    registration.harness(),
                    HarnessKind::Generic | HarnessKind::A2AGateway
                )
                && registration.profiles().permits(profile)
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        bail!("local-service issuer does not authorize the A2A gateway profile");
    }
    let issuer = matching[0];
    LocalServiceJsonClientConfig::new(
        installation.endpoint().clone(),
        LocalServiceIssuerCredential::new(
            issuer.issuer_key_id(),
            issuer.issuer_key_version(),
            issuer_identity,
        ),
        installation.service_public_key(),
        profile.clone(),
        HarnessKind::A2AGateway,
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .context("building local-service A2A gateway client")
}

fn build_access(
    security: Option<InitialA2AAgentSecurityKind>,
    listen_address: SocketAddr,
    tls_terminated: bool,
    bearer_token_files: Vec<PathBuf>,
) -> anyhow::Result<Arc<dyn A2AHttpAccess>> {
    match security {
        Some(InitialA2AAgentSecurityKind::Bearer) => {
            if bearer_token_files.is_empty() {
                bail!("bearer-secured A2A publication requires a token file");
            }
            let credentials = bearer_token_files
                .into_iter()
                .map(|path| load_bearer(&path))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Arc::new(
                StaticBearerAccess::new(credentials)
                    .context("building static A2A bearer access")?,
            ))
        }
        Some(InitialA2AAgentSecurityKind::MutualTls) => {
            bail!("standalone A2A mutual-TLS access is not implemented")
        }
        None => {
            if !listen_address.ip().is_loopback()
                || tls_terminated
                || !bearer_token_files.is_empty()
            {
                bail!("unauthenticated A2A access is restricted to direct loopback");
            }
            Ok(Arc::new(LoopbackAccess))
        }
    }
}

fn load_bearer(path: &Path) -> anyhow::Result<A2ABearerCredential> {
    let mut file =
        open_owner_protected_file(path).context("opening owner-protected A2A bearer file")?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BEARER_FILE_BYTES + 1));
    file.by_ref()
        .take((MAX_BEARER_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading bounded A2A bearer file")?;
    if bytes.len() > MAX_BEARER_FILE_BYTES {
        bail!("A2A bearer file exceeds its byte bound");
    }
    let length = if bytes.ends_with(b"\r\n") {
        bytes.len() - 2
    } else if bytes.ends_with(b"\n") {
        bytes.len() - 1
    } else {
        bytes.len()
    };
    let value = std::str::from_utf8(&bytes[..length])
        .context("A2A bearer file is not UTF-8")?
        .to_owned();
    A2ABearerCredential::parse(value).context("A2A bearer file is invalid")
}

struct LoopbackAccess;

impl A2AHttpAccess for LoopbackAccess {
    fn authentication_kind(&self) -> Option<InitialA2AAgentSecurityKind> {
        None
    }

    fn authenticate(
        &self,
        _request: &axum::http::request::Parts,
    ) -> Result<A2AHttpPrincipalId, A2AGatewayError> {
        Ok(A2AHttpPrincipalId::from_bytes([0; 32]))
    }

    fn authorize(
        &self,
        _principal: A2AHttpPrincipalId,
        _action: A2AHttpAction,
    ) -> A2AHttpAuthorizationDecision {
        A2AHttpAuthorizationDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintained_gateway_source_decodes_strictly() {
        let source = deserialize_strict::<ConfigSource>(
            include_bytes!("../../../a2a/examples/gateway-config.json"),
            MAX_CONFIG_BYTES,
        )
        .unwrap();
        assert_eq!(source.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(source.bearer_token_files.len(), 1);
    }

    #[test]
    fn strict_source_rejects_unknown_fields_and_excess_bearer_files() {
        let base = r#"{
          "schemaVersion":1,
          "interfaceEnvironment":"production",
          "listener":{"address":"127.0.0.1:8090","tlsTerminated":false},
          "publicationFile":"/etc/konclave/a2a/agent.json",
          "taskDatabaseFile":"/var/lib/konclave/a2a/tasks.sqlite",
          "route":{
            "contextId":"context-a",
            "conversationId":"0000000000000000000000000000000000000000000000000000000000000000",
            "targetDeviceId":"1111111111111111111111111111111111111111111111111111111111111111"
          },
          "localService":{
            "installationFile":"/etc/konclave/konclave-local-service.json",
            "issuerKeyFile":"/etc/konclave/account-issuer.key",
            "profile":"a2a-gateway"
          },
          "bearerTokenFiles":[],
          "unknown":true
        }"#;
        assert!(deserialize_strict::<ConfigSource>(base.as_bytes(), MAX_CONFIG_BYTES).is_err());

        let files = (0..=MAX_BEARER_FILES)
            .map(|index| format!(r#""/run/secrets/token-{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        let oversized = format!(
            r#"{{
              "schemaVersion":1,
              "interfaceEnvironment":"production",
              "listener":{{"address":"127.0.0.1:8090","tlsTerminated":false}},
              "publicationFile":"/etc/konclave/a2a/agent.json",
              "taskDatabaseFile":"/var/lib/konclave/a2a/tasks.sqlite",
              "route":{{
                "contextId":"context-a",
                "conversationId":"0000000000000000000000000000000000000000000000000000000000000000",
                "targetDeviceId":"1111111111111111111111111111111111111111111111111111111111111111"
              }},
              "localService":{{
                "installationFile":"/etc/konclave/konclave-local-service.json",
                "issuerKeyFile":"/etc/konclave/account-issuer.key",
                "profile":"a2a-gateway"
              }},
              "bearerTokenFiles":[{files}]
            }}"#
        );
        assert!(
            deserialize_strict::<ConfigSource>(oversized.as_bytes(), MAX_CONFIG_BYTES).is_err()
        );
    }
}
