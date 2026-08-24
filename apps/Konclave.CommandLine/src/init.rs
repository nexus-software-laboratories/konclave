use std::io::{IsTerminal as _, Read as _};

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;
use KonclaveClientLibrary::{
    RelayEndpoint, RelayEnrollmentCredential, RelayEnrollmentSourceConfig, RelayInstallationConfig,
};
use KonclaveSecretStorage::NativeEnrollmentCredentialStore;

use crate::cli::InitArgs;
use crate::installation;

pub(crate) fn run(args: InitArgs) -> anyhow::Result<()> {
    let root = installation::resolve_profile_root(args.profile_root)?;
    let endpoint =
        RelayEndpoint::parse(&args.relay_endpoint).context("validating relay endpoint")?;
    if let Some(existing) = installation::load(&root)? {
        require_existing_match(&existing, &endpoint, args.external_source.as_deref())?;
        installation::load_credential(&existing)
            .context("validating protected enrollment source")?;
        println!(
            "Relay enrollment is already initialized using {} custody.",
            installation::source_label(existing.source())
        );
        return Ok(());
    }

    let config = match args.external_source {
        Some(path) => {
            let config = RelayInstallationConfig::new(
                endpoint.clone(),
                RelayEnrollmentSourceConfig::ExternalFile { path: path.clone() },
            )
            .context("validating external enrollment source")?;
            if !path.exists() {
                let credential = read_enrollment_credential()?;
                config
                    .create_external_credential(&credential)
                    .context("creating protected external enrollment source")?;
            }
            installation::load_credential(&config)
                .context("validating endpoint-bound external enrollment source")?;
            config
        }
        None => {
            let credential = read_enrollment_credential()?;
            let installation_id = native_installation_id(&credential, &endpoint);
            let record = credential
                .encode_bound(&endpoint)
                .context("binding enrollment credential to endpoint")?;
            NativeEnrollmentCredentialStore::new(installation_id.clone())
                .context("creating native enrollment custody")?
                .store(&record)
                .context("storing native enrollment credential")?;
            RelayInstallationConfig::new(
                endpoint,
                RelayEnrollmentSourceConfig::Native { installation_id },
            )
            .context("building relay installation configuration")?
        }
    };
    installation::write_exact(&root, &config)?;
    println!(
        "Initialized relay enrollment using {} custody.",
        installation::source_label(config.source())
    );
    Ok(())
}

fn native_installation_id(
    credential: &RelayEnrollmentCredential,
    endpoint: &RelayEndpoint,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"konclave:relay-enrollment-installation:1\0");
    digest.update(credential.authority_id().as_bytes());
    digest.update(endpoint.as_str().as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn require_existing_match(
    existing: &RelayInstallationConfig,
    endpoint: &RelayEndpoint,
    external_source: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    if existing.endpoint().as_str() != endpoint.as_str() {
        bail!("relay installation already targets another endpoint");
    }
    match (existing.source(), external_source) {
        (RelayEnrollmentSourceConfig::ExternalFile { path }, Some(requested))
            if path == requested =>
        {
            Ok(())
        }
        (RelayEnrollmentSourceConfig::Native { .. }, None) => Ok(()),
        _ => bail!("relay installation already uses another protected source"),
    }
}

fn read_enrollment_credential() -> anyhow::Result<RelayEnrollmentCredential> {
    let mut value = if std::io::stdin().is_terminal() {
        Zeroizing::new(
            rpassword::prompt_password("Relay enrollment credential: ")
                .context("reading enrollment credential")?,
        )
    } else {
        let mut value = Zeroizing::new(String::new());
        std::io::stdin()
            .take(46)
            .read_to_string(&mut value)
            .context("reading enrollment credential from stdin")?;
        value
    };
    if value.len() > 45 {
        bail!("enrollment credential input is invalid");
    }
    if value.ends_with("\r\n") {
        let length = value.len();
        value.truncate(length - 2);
    } else if value.ends_with('\n') {
        let length = value.len();
        value.truncate(length - 1);
    }
    RelayEnrollmentCredential::from_base64(&value).context("validating enrollment credential")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_source_matching_is_explicit() {
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let native = RelayInstallationConfig::new(
            endpoint.clone(),
            RelayEnrollmentSourceConfig::Native {
                installation_id: "installation-a".to_string(),
            },
        )
        .unwrap();
        assert!(require_existing_match(&native, &endpoint, None).is_ok());
        assert!(require_existing_match(
            &native,
            &RelayEndpoint::parse("https://other.example.com").unwrap(),
            None,
        )
        .is_err());
    }

    #[test]
    fn native_installation_identity_binds_authority_and_endpoint() {
        let first = RelayEnrollmentCredential::from_bytes([1; 32]);
        let second = RelayEnrollmentCredential::from_bytes([2; 32]);
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let other_endpoint = RelayEndpoint::parse("https://other.example.com").unwrap();

        assert_eq!(
            native_installation_id(&first, &endpoint),
            native_installation_id(&first, &endpoint)
        );
        assert_ne!(
            native_installation_id(&first, &endpoint),
            native_installation_id(&first, &other_endpoint)
        );
        assert_ne!(
            native_installation_id(&first, &endpoint),
            native_installation_id(&second, &endpoint)
        );
    }
}
