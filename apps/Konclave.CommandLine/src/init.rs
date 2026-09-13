use std::io::{IsTerminal as _, Read as _};

use anyhow::{bail, Context};
use zeroize::Zeroizing;
use KonclaveClientLibrary::{
    RelayEndpoint, RelayEnrollmentCredential, RelayEnrollmentSourceConfig, RelayInstallationConfig,
};
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion,
};
use KonclaveSecretStorage::NativeEnrollmentCredentialStore;
use KonclaveUserPresence::native_user_presence_supported;

use crate::cli::{AuthorizationPolicyChoice, InitArgs};
use crate::installation;
use crate::local_service_installation;

pub(crate) fn run(args: InitArgs) -> anyhow::Result<()> {
    let authorization_policy =
        select_authorization_policy(args.authorization_policy, args.allow_no_recovery)?;
    let root = installation::resolve_profile_root(args.profile_root)?;
    let endpoint =
        RelayEndpoint::parse(&args.relay_endpoint).context("validating relay endpoint")?;
    if let Some(existing) = installation::load(&root)? {
        installation::require_existing_match(
            &existing,
            &endpoint,
            args.external_source.as_deref(),
        )?;
        installation::load_credential(&existing)
            .context("validating protected enrollment source")?;
        println!(
            "Relay enrollment is already initialized using {} custody.",
            installation::source_label(existing.source())
        );
    } else {
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
                let installation_id = installation::native_installation_id(&credential, &endpoint);
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
    }

    let local = local_service_installation::install(
        &root,
        args.copilot_extension_root,
        args.local_service_endpoint.as_deref(),
        args.local_service_identity_file,
        args.local_service_profile_key_directory,
        authorization_policy,
    )?;
    println!(
        "Initialized shared local service for the Copilot extension at {}.",
        local.extension_root.display()
    );
    Ok(())
}

fn select_authorization_policy(
    choice: Option<AuthorizationPolicyChoice>,
    allow_no_recovery: bool,
) -> anyhow::Result<AuthorizationPolicy> {
    match choice {
        Some(AuthorizationPolicyChoice::AccountTrusted) => {
            Ok(AuthorizationPolicy::account_trusted())
        }
        Some(AuthorizationPolicyChoice::UserPresence) => {
            require_user_presence_selection(allow_no_recovery, native_user_presence_supported())
        }
        None if !std::io::stdin().is_terminal() => {
            bail!("--authorization-policy is required for noninteractive initialization")
        }
        None => {
            eprintln!("Choose local authorization policy:");
            eprintln!("1. AccountTrusted");
            eprintln!("   Automatic session access.");
            eprintln!("   All processes under this OS account are trusted.");
            eprintln!("   This does not provide same-user session isolation.");
            if native_user_presence_supported() {
                eprintln!("2. UserPresence");
                eprintln!("   Windows requires native user verification for each new process.");
                eprintln!("   Losing the credential can strand administration without recovery.");
                eprintln!("   Selection requires --allow-no-recovery.");
            }
            let mut value = String::new();
            std::io::stdin()
                .read_line(&mut value)
                .context("reading authorization policy")?;
            match value.trim() {
                "1" => Ok(AuthorizationPolicy::account_trusted()),
                "2" if native_user_presence_supported() => {
                    require_user_presence_selection(allow_no_recovery, true)
                }
                _ => bail!("authorization policy selection is invalid"),
            }
        }
    }
}

fn require_user_presence_selection(
    allow_no_recovery: bool,
    native_supported: bool,
) -> anyhow::Result<AuthorizationPolicy> {
    if !allow_no_recovery {
        bail!("--allow-no-recovery is required for a UserPresence-only installation")
    }
    if !native_supported {
        bail!("UserPresence is unavailable on this platform")
    }
    let evidence = AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::UserPresence])
        .context("constructing UserPresence evidence")?;
    AuthorizationPolicy::new(
        AuthorizationPolicyVersion::new(1).context("constructing policy version")?,
        vec![evidence],
    )
    .context("constructing UserPresence policy")
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
        assert!(installation::require_existing_match(&native, &endpoint, None).is_ok());
        assert!(installation::require_existing_match(
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
            installation::native_installation_id(&first, &endpoint),
            installation::native_installation_id(&first, &endpoint)
        );
        assert_ne!(
            installation::native_installation_id(&first, &endpoint),
            installation::native_installation_id(&first, &other_endpoint)
        );
        assert_ne!(
            installation::native_installation_id(&first, &endpoint),
            installation::native_installation_id(&second, &endpoint)
        );
    }

    #[test]
    fn user_presence_selection_requires_recovery_acknowledgement_and_native_support() {
        assert!(require_user_presence_selection(false, true)
            .unwrap_err()
            .to_string()
            .contains("--allow-no-recovery"));
        assert!(require_user_presence_selection(true, false)
            .unwrap_err()
            .to_string()
            .contains("unavailable"));
        let policy = require_user_presence_selection(true, true).unwrap();
        let presence =
            AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::UserPresence]).unwrap();
        assert!(policy.accepts(presence));
    }
}
