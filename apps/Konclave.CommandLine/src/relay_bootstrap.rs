use anyhow::{bail, Context as _};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use KonclaveClientLibrary::{
    RelayEndpoint, RelayEnrollmentCredential, RelayEnrollmentSourceConfig, RelayInstallationConfig,
};
use KonclaveSecretStorage::NativeEnrollmentCredentialStore;

use crate::cli::RelayBootstrapArgs;
use crate::installation;

pub(crate) fn run(args: RelayBootstrapArgs) -> anyhow::Result<()> {
    if args.external_source.is_some() && args.profile_root.is_some() {
        bail!("profile root cannot be combined with an external enrollment source");
    }
    let endpoint =
        RelayEndpoint::parse(&args.relay_endpoint).context("validating relay endpoint")?;
    let (credential, source_label) = match args.external_source {
        Some(path) => (load_or_create_external(&endpoint, path)?, "external_file"),
        None => (
            load_or_create_native(&endpoint, args.profile_root)?,
            "native",
        ),
    };
    let authority = URL_SAFE_NO_PAD.encode(credential.authority_id().as_bytes());
    let mut access_document = serde_json::to_vec_pretty(&serde_json::json!({
        "version": 2,
        "principals": [],
        "enrollment": {
            "authority": authority
        }
    }))
    .context("encoding relay access document")?;
    access_document.push(b'\n');
    let access_path = resolve_output_path(args.access_document)?;
    installation::write_exact_file(&access_path, &access_document, "relay access document")?;
    println!("Relay bootstrap is ready using {source_label} custody.");
    Ok(())
}

fn load_or_create_external(
    endpoint: &RelayEndpoint,
    path: std::path::PathBuf,
) -> anyhow::Result<RelayEnrollmentCredential> {
    let config = RelayInstallationConfig::new(
        endpoint.clone(),
        RelayEnrollmentSourceConfig::ExternalFile { path: path.clone() },
    )
    .context("validating external enrollment source")?;
    if !path.exists() {
        let credential =
            RelayEnrollmentCredential::generate().context("generating enrollment credential")?;
        config
            .create_external_credential(&credential)
            .context("creating protected external enrollment source")?;
    }
    config
        .load_external_credential()
        .context("loading protected external enrollment source")?
        .ok_or_else(|| anyhow::anyhow!("external enrollment source is unavailable"))
}

fn load_or_create_native(
    endpoint: &RelayEndpoint,
    profile_root: Option<std::path::PathBuf>,
) -> anyhow::Result<RelayEnrollmentCredential> {
    let root = installation::resolve_profile_root(profile_root)?;
    if let Some(existing) = installation::load(&root)? {
        installation::require_existing_match(&existing, endpoint, None)?;
        return installation::load_credential(&existing);
    }

    let credential =
        RelayEnrollmentCredential::generate().context("generating enrollment credential")?;
    let installation_id = installation::native_installation_id(&credential, endpoint);
    let record = credential
        .encode_bound(endpoint)
        .context("binding enrollment credential to endpoint")?;
    NativeEnrollmentCredentialStore::new(installation_id.clone())
        .context("creating native enrollment custody")?
        .store(&record)
        .context("storing native enrollment credential")?;
    let config = RelayInstallationConfig::new(
        endpoint.clone(),
        RelayEnrollmentSourceConfig::Native { installation_id },
    )
    .context("building relay installation configuration")?;
    installation::write_exact(&root, &config)?;
    Ok(credential)
}

fn resolve_output_path(path: std::path::PathBuf) -> anyhow::Result<std::path::PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolving current directory")?
            .join(path))
    }
}
