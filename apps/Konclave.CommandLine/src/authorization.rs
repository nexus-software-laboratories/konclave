use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalAuthorizationStore::{
    installation_fingerprint, ExistingGrantDisposition, IssuerAvailability, LocalAuthorizationStore,
};
use KonclaveLocalServiceTransport::{
    decode_lowercase_hex, AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion, HarnessKind, InstalledIssuerRegistration, IssuerKeyId,
    IssuerKeyVersion, IssuerRegistration, LocalServiceInstallation, ProfileAuthorization,
    ServiceProfileId, SessionGrantId, MAX_GRANTS_PER_ISSUER, MAX_GRANTS_PER_PROFILE,
    MAX_SESSION_GRANTS,
};
use KonclaveSecretStorage::open_owner_protected_file;

use crate::cli::{
    AuthorizationArgs, AuthorizationCommand, AuthorizationGrantArgs, AuthorizationHarnessChoice,
    AuthorizationIssuerArgs, AuthorizationIssuerDispositionArgs,
    AuthorizationIssuerRegistrationArgs, AuthorizationPolicyArgs, AuthorizationProfileArgs,
    AuthorizationStateArgs, ExistingGrantDispositionChoice,
};

const SERVICE_DIRECTORY: &str = "service";

pub(crate) fn run(args: AuthorizationArgs) -> anyhow::Result<()> {
    match args.command {
        AuthorizationCommand::Status(args) => status(args),
        AuthorizationCommand::RevokeGrant(args) => revoke_grant(args),
        AuthorizationCommand::SuspendProfile(args) => suspend_profile(args),
        AuthorizationCommand::ResumeProfile(args) => resume_profile(args),
        AuthorizationCommand::DisableIssuer(args) => disable_issuer(args),
        AuthorizationCommand::EnableIssuer(args) => enable_issuer(args),
        AuthorizationCommand::RegisterIssuer(args) => register_issuer(args),
        AuthorizationCommand::RemoveIssuer(args) => remove_issuer(args),
        AuthorizationCommand::ReplacePolicy(args) => replace_policy(args),
    }
}

fn status(args: AuthorizationStateArgs) -> anyhow::Result<()> {
    let store = open_store(args.profile_root)?;
    let snapshot = store
        .load_snapshot(now_unix_milliseconds()?, None)
        .context("loading durable authorization state")?;
    println!("generation: {}", snapshot.generation().get());
    println!("policy version: {}", snapshot.policy().version().get());
    println!("issuers: {}", snapshot.issuers().len());
    println!(
        "disabled issuers: {}",
        snapshot
            .issuers()
            .iter()
            .filter(|issuer| issuer.availability() == IssuerAvailability::Disabled)
            .count()
    );
    println!(
        "suspended profiles: {}",
        snapshot.suspended_profiles().len()
    );
    println!(
        "active grants: {}/{}",
        snapshot.active_grants().len(),
        MAX_SESSION_GRANTS
    );
    println!(
        "grant bounds: issuer {}, profile {}",
        MAX_GRANTS_PER_ISSUER, MAX_GRANTS_PER_PROFILE
    );
    Ok(())
}

fn revoke_grant(args: AuthorizationGrantArgs) -> anyhow::Result<()> {
    let store = open_administrative_store(args.profile_root)?;
    let grant_id = SessionGrantId::from_bytes(
        decode_lowercase_hex(&args.grant_id).context("grant identifier is invalid")?,
    );
    let mutation = store
        .revoke_grant(grant_id, now_unix_milliseconds()?)
        .context("revoking durable session grant")?;
    println!(
        "grant revocation: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn suspend_profile(args: AuthorizationProfileArgs) -> anyhow::Result<()> {
    let store = open_administrative_store(args.profile_root)?;
    let profile = ServiceProfileId::parse(&args.profile).context("profile is invalid")?;
    let mutation = store
        .suspend_profile(&profile, now_unix_milliseconds()?)
        .context("suspending profile authorization")?;
    println!(
        "profile suspension: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn resume_profile(args: AuthorizationProfileArgs) -> anyhow::Result<()> {
    let store = open_administrative_store(args.profile_root)?;
    let profile = ServiceProfileId::parse(&args.profile).context("profile is invalid")?;
    let mutation = store
        .resume_profile(&profile, now_unix_milliseconds()?)
        .context("resuming profile authorization")?;
    println!(
        "profile resume: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn disable_issuer(args: AuthorizationIssuerDispositionArgs) -> anyhow::Result<()> {
    let (issuer_key_id, issuer_key_version) = parse_issuer(&args.issuer)?;
    let store = open_administrative_store(args.issuer.profile_root)?;
    let mutation = store
        .set_issuer_state(
            issuer_key_id,
            issuer_key_version,
            IssuerAvailability::Disabled,
            disposition(args.existing_grants),
            now_unix_milliseconds()?,
        )
        .context("disabling authorization issuer")?;
    println!(
        "issuer disablement: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn enable_issuer(args: AuthorizationIssuerArgs) -> anyhow::Result<()> {
    let (issuer_key_id, issuer_key_version) = parse_issuer(&args)?;
    let store = open_administrative_store(args.profile_root)?;
    let mutation = store
        .set_issuer_state(
            issuer_key_id,
            issuer_key_version,
            IssuerAvailability::Enabled,
            ExistingGrantDisposition::RetainUntilExpiry,
            now_unix_milliseconds()?,
        )
        .context("enabling authorization issuer")?;
    println!(
        "issuer enablement: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn register_issuer(args: AuthorizationIssuerRegistrationArgs) -> anyhow::Result<()> {
    let (issuer_key_id, issuer_key_version) = parse_issuer(&args.issuer)?;
    let public_key = Ed25519PublicKey::from_bytes(
        decode_lowercase_hex(&args.public_key).context("issuer public key is invalid")?,
    );
    let profiles = parse_profile_scope(&args.profile_scope)?;
    let store = open_administrative_store(args.issuer.profile_root)?;
    let issuer = InstalledIssuerRegistration::new(
        issuer_key_id,
        issuer_key_version,
        IssuerRegistration::new(public_key, harness(args.harness), profiles),
    );
    let mutation = store
        .register_issuer(&issuer, now_unix_milliseconds()?)
        .context("registering authorization issuer")?;
    println!(
        "issuer registration: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn remove_issuer(args: AuthorizationIssuerDispositionArgs) -> anyhow::Result<()> {
    let (issuer_key_id, issuer_key_version) = parse_issuer(&args.issuer)?;
    let store = open_administrative_store(args.issuer.profile_root)?;
    let mutation = store
        .remove_issuer(
            issuer_key_id,
            issuer_key_version,
            disposition(args.existing_grants),
            now_unix_milliseconds()?,
        )
        .context("removing authorization issuer")?;
    println!(
        "issuer removal: {}; generation {}",
        effect_name(mutation.effect()),
        mutation.generation().get()
    );
    Ok(())
}

fn replace_policy(args: AuthorizationPolicyArgs) -> anyhow::Result<()> {
    let store = open_administrative_store(args.profile_root)?;
    let current = store
        .load_snapshot(now_unix_milliseconds()?, None)
        .context("loading current authorization policy")?;
    let policy = build_policy(current.policy().version(), &args.clauses)?;
    let version = policy.version();
    let mutation = store
        .replace_policy(&policy, now_unix_milliseconds()?)
        .context("replacing authorization policy")?;
    println!(
        "authorization policy: {}; version {}; generation {}",
        effect_name(mutation.effect()),
        version.get(),
        mutation.generation().get()
    );
    Ok(())
}

fn build_policy(
    current_version: AuthorizationPolicyVersion,
    clauses: &[String],
) -> anyhow::Result<AuthorizationPolicy> {
    let mut clauses = clauses
        .iter()
        .map(|clause| parse_clause(clause))
        .collect::<anyhow::Result<Vec<_>>>()?;
    clauses.sort_unstable();
    if clauses.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("authorization evidence clauses contain a duplicate");
    }
    let account_trusted =
        AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
            .context("constructing AccountTrusted evidence")?;
    if !clauses.contains(&account_trusted) {
        bail!("this CLI cannot remove the AccountTrusted administrative authority");
    }
    let version = current_version
        .get()
        .checked_add(1)
        .and_then(|value| AuthorizationPolicyVersion::new(value).ok())
        .context("authorization policy version is exhausted")?;
    AuthorizationPolicy::new(version, clauses).context("authorization evidence clauses are invalid")
}

fn open_store(profile_root: Option<PathBuf>) -> anyhow::Result<LocalAuthorizationStore> {
    let profile_root = crate::installation::resolve_profile_root(profile_root)?;
    let installation_path = profile_root
        .parent()
        .context("profile root has no installation parent")?
        .join(SERVICE_DIRECTORY)
        .join(KonclaveLocalServiceTransport::LOCAL_SERVICE_INSTALLATION_FILE);
    let installation = LocalServiceInstallation::from_reader(
        open_owner_protected_file(&installation_path)
            .context("opening local-service installation")?,
    )
    .context("reading local-service installation")?;
    let fingerprint = installation_fingerprint(&installation)
        .context("binding authorization state to the installation")?;
    LocalAuthorizationStore::open(&installation_path, fingerprint, None)
        .context("opening durable authorization state")
}

fn open_administrative_store(
    profile_root: Option<PathBuf>,
) -> anyhow::Result<LocalAuthorizationStore> {
    let store = open_store(profile_root)?;
    let snapshot = store
        .load_snapshot(now_unix_milliseconds()?, None)
        .context("loading current authorization policy")?;
    let account_trusted =
        AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
            .context("constructing AccountTrusted evidence")?;
    if !snapshot.policy().accepts(account_trusted) {
        bail!("current authorization policy requires a stronger administrative authority");
    }
    Ok(store)
}

fn parse_issuer(args: &AuthorizationIssuerArgs) -> anyhow::Result<(IssuerKeyId, IssuerKeyVersion)> {
    let issuer_key_id = IssuerKeyId::from_bytes(
        decode_lowercase_hex(&args.issuer_key_id).context("issuer key identifier is invalid")?,
    );
    let issuer_key_version =
        IssuerKeyVersion::new(args.issuer_key_version).context("issuer key version is invalid")?;
    Ok((issuer_key_id, issuer_key_version))
}

fn parse_clause(value: &str) -> anyhow::Result<AuthorizationEvidenceSet> {
    let kinds = value
        .split('+')
        .map(|kind| match kind {
            "account_trusted" => Ok(AuthorizationEvidenceKind::AccountTrusted),
            "user_presence" => Ok(AuthorizationEvidenceKind::UserPresence),
            "harness_attested" => Ok(AuthorizationEvidenceKind::HarnessAttested),
            "workload_identity" => Ok(AuthorizationEvidenceKind::WorkloadIdentity),
            _ => bail!("authorization evidence kind is invalid"),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    AuthorizationEvidenceSet::new(kinds).context("authorization evidence clause is invalid")
}

fn parse_profile_scope(value: &str) -> anyhow::Result<ProfileAuthorization> {
    if value == "all" {
        return Ok(ProfileAuthorization::All);
    }
    if let Some(profile) = value.strip_prefix("profile:") {
        return ServiceProfileId::parse(profile)
            .map(ProfileAuthorization::Profile)
            .context("issuer profile scope is invalid");
    }
    if let Some(namespace) = value.strip_prefix("namespace:") {
        return ServiceProfileId::parse(namespace)
            .map(ProfileAuthorization::Namespace)
            .context("issuer namespace scope is invalid");
    }
    bail!("issuer profile scope is invalid")
}

const fn harness(choice: AuthorizationHarnessChoice) -> HarnessKind {
    match choice {
        AuthorizationHarnessChoice::Copilot => HarnessKind::Copilot,
        AuthorizationHarnessChoice::ClaudeCode => HarnessKind::ClaudeCode,
        AuthorizationHarnessChoice::Codex => HarnessKind::Codex,
        AuthorizationHarnessChoice::Generic => HarnessKind::Generic,
        AuthorizationHarnessChoice::A2aGateway => HarnessKind::A2AGateway,
    }
}

const fn disposition(choice: ExistingGrantDispositionChoice) -> ExistingGrantDisposition {
    match choice {
        ExistingGrantDispositionChoice::Retain => ExistingGrantDisposition::RetainUntilExpiry,
        ExistingGrantDispositionChoice::Revoke => ExistingGrantDisposition::Revoke,
    }
}

const fn effect_name(effect: KonclaveLocalAuthorizationStore::MutationEffect) -> &'static str {
    match effect {
        KonclaveLocalAuthorizationStore::MutationEffect::Applied => "applied",
        KonclaveLocalAuthorizationStore::MutationEffect::Unchanged => "unchanged",
    }
}

fn now_unix_milliseconds() -> anyhow::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("reading system time")?
            .as_millis(),
    )
    .context("converting system time")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_clauses_are_canonical_and_preserve_account_trusted_administration() {
        let current = AuthorizationPolicyVersion::new(7).unwrap();
        let account = build_policy(current, &["account_trusted".to_string()]).unwrap();
        assert_eq!(account.version().get(), 8);
        assert!(account.accepts(
            AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted]).unwrap()
        ));

        assert!(build_policy(current, &["user_presence".to_string()])
            .unwrap_err()
            .to_string()
            .contains("cannot remove the AccountTrusted"));
        assert!(build_policy(
            current,
            &["account_trusted".to_string(), "account_trusted".to_string(),],
        )
        .is_err());
        assert!(parse_clause("account_trusted+account_trusted").is_err());
        assert!(parse_clause("unknown").is_err());
        assert_eq!(
            parse_profile_scope("all").unwrap(),
            ProfileAuthorization::All
        );
        assert!(matches!(
            parse_profile_scope("profile:generic-client").unwrap(),
            ProfileAuthorization::Profile(profile) if profile.as_str() == "generic-client"
        ));
        assert!(matches!(
            parse_profile_scope("namespace:generic").unwrap(),
            ProfileAuthorization::Namespace(profile) if profile.as_str() == "generic"
        ));
        assert!(parse_profile_scope("profile:session/invalid").is_err());
    }
}
