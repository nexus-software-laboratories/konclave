use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// KonclaveCommandLine is a command-line application.
#[derive(Parser)]
#[command(name = "konclave", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print version information
    Version,
    /// Configure protected relay enrollment for later session profiles
    Init(InitArgs),
    /// Create a self-hosted relay access document and protected enrollment source
    RelayBootstrap(RelayBootstrapArgs),
    /// Check installation, custody, profile, and relay health
    Doctor(DoctorArgs),
    /// Inspect and update durable local authorization state
    Authorization(AuthorizationArgs),
    /// Create, validate, inspect, compile, diff, and list collaboration policies
    Policy(PolicyArgs),
    /// Internal native user-presence bridge
    #[command(hide = true)]
    UserPresenceHelper(UserPresenceHelperArgs),
}

#[derive(Args)]
pub struct UserPresenceHelperArgs {
    #[command(subcommand)]
    pub command: UserPresenceHelperCommand,
}

#[derive(Subcommand)]
pub enum UserPresenceHelperCommand {
    /// Create one native WebAuthn credential
    Register,
    /// Complete one native WebAuthn assertion
    Authenticate,
}

#[derive(Args)]
pub struct InitArgs {
    /// Relay base URL; TLS is required outside loopback
    #[arg(long)]
    pub relay_endpoint: String,
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Absolute path for an endpoint-bound Unix headless credential record
    #[arg(long)]
    pub external_source: Option<PathBuf>,
    /// Legacy raw-extension directory inspected only for sidecar migration
    #[arg(long)]
    pub copilot_extension_root: Option<PathBuf>,
    /// Absolute client configuration path override for tests and development
    #[arg(long)]
    pub local_service_client_config: Option<PathBuf>,
    /// Explicit local named-pipe or Unix-socket endpoint
    #[arg(long)]
    pub local_service_endpoint: Option<String>,
    /// Owner-protected service identity seed for headless environments
    #[arg(long)]
    pub local_service_identity_file: Option<PathBuf>,
    /// Directory containing one owner-protected wrapping key per profile
    #[arg(long)]
    pub local_service_profile_key_directory: Option<PathBuf>,
    /// Local authorization policy; required for noninteractive initialization
    #[arg(long, value_enum)]
    pub authorization_policy: Option<AuthorizationPolicyChoice>,
    /// Acknowledge that losing every UserPresence credential can strand administration
    #[arg(long)]
    pub allow_no_recovery: bool,
}

/// Authorization policies available during initial installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthorizationPolicyChoice {
    /// Trust every process running under the configured operating-system account.
    AccountTrusted,
    /// Require native user verification for each new session process.
    UserPresence,
}

#[derive(Args)]
pub struct RelayBootstrapArgs {
    /// Relay base URL; TLS is required outside loopback
    #[arg(long)]
    pub relay_endpoint: String,
    /// Non-secret relay access document to create
    #[arg(long)]
    pub access_document: PathBuf,
    /// Shared profile root for native custody; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Owner-protected Unix enrollment source; omit to use native custody
    #[arg(long)]
    pub external_source: Option<PathBuf>,
}

#[derive(Args)]
pub struct DoctorArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Installation root containing bin/ and share/konclave/
    #[arg(long)]
    pub install_root: Option<PathBuf>,
    /// Absolute client configuration path override for tests and development
    #[arg(long)]
    pub local_service_client_config: Option<PathBuf>,
}

#[derive(Args)]
pub struct AuthorizationArgs {
    #[command(subcommand)]
    pub command: AuthorizationCommand,
}

#[derive(Subcommand)]
pub enum AuthorizationCommand {
    /// Show bounded live authorization status
    Status(AuthorizationStateArgs),
    /// Revoke one exact session grant
    RevokeGrant(AuthorizationGrantArgs),
    /// Suspend new and active grants for one exact profile
    SuspendProfile(AuthorizationProfileArgs),
    /// Permit new grants for one previously suspended profile
    ResumeProfile(AuthorizationProfileArgs),
    /// Disable new grants from one exact issuer key version
    DisableIssuer(AuthorizationIssuerDispositionArgs),
    /// Re-enable one exact issuer key version
    EnableIssuer(AuthorizationIssuerArgs),
    /// Register one higher issuer key version before rotating clients
    RegisterIssuer(AuthorizationIssuerRegistrationArgs),
    /// Remove one exact issuer key version from the installation
    RemoveIssuer(AuthorizationIssuerDispositionArgs),
    /// Replace the evidence policy with a strictly newer generation
    ReplacePolicy(AuthorizationPolicyArgs),
}

#[derive(Args)]
pub struct AuthorizationStateArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
}

#[derive(Args)]
pub struct AuthorizationGrantArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Exact 16-byte grant identifier as 32 lowercase hexadecimal characters
    #[arg(long)]
    pub grant_id: String,
}

#[derive(Args)]
pub struct AuthorizationProfileArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Exact canonical profile identifier
    #[arg(long)]
    pub profile: String,
}

#[derive(Args)]
pub struct AuthorizationIssuerArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Exact 16-byte issuer identifier as 32 lowercase hexadecimal characters
    #[arg(long)]
    pub issuer_key_id: String,
    /// Exact nonzero issuer key version
    #[arg(long)]
    pub issuer_key_version: u32,
}

#[derive(Args)]
pub struct AuthorizationIssuerDispositionArgs {
    #[command(flatten)]
    pub issuer: AuthorizationIssuerArgs,
    /// Treatment of grants already issued by this key version
    #[arg(long, value_enum)]
    pub existing_grants: ExistingGrantDispositionChoice,
}

#[derive(Args)]
pub struct AuthorizationIssuerRegistrationArgs {
    #[command(flatten)]
    pub issuer: AuthorizationIssuerArgs,
    /// Exact Ed25519 public key as 64 lowercase hexadecimal characters
    #[arg(long)]
    pub public_key: String,
    /// Harness metadata authorized for this issuer
    #[arg(long, value_enum)]
    pub harness: AuthorizationHarnessChoice,
    /// Profile scope: all, profile:<id>, or namespace:<prefix>
    #[arg(long)]
    pub profile_scope: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthorizationHarnessChoice {
    Copilot,
    ClaudeCode,
    Codex,
    Generic,
    A2aGateway,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExistingGrantDispositionChoice {
    /// Keep existing grants valid until expiry or another terminal condition
    Retain,
    /// Revoke existing grants in the same durable transaction
    Revoke,
}

#[derive(Args)]
pub struct AuthorizationPolicyArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// One all-of evidence clause; repeat for OR and join evidence with '+'
    #[arg(long = "clause", required = true)]
    pub clauses: Vec<String>,
}

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Create a new strict-JSON policy source without overwriting a file
    Create(PolicyCreateArgs),
    /// Validate and identify one explicit policy source
    Validate(PolicySourceArgs),
    /// Show a bounded summary of one explicit policy source
    Inspect(PolicySourceArgs),
    /// Compile one explicit source into immutable canonical bundle bytes
    Compile(PolicyCompileArgs),
    /// Compare the canonical identities of two explicit sources
    Diff(PolicyDiffArgs),
    /// List names from one explicit descriptor-backed file catalog
    List(PolicyCatalogListArgs),
    /// Compile every entry in one explicit descriptor-backed file catalog
    ValidateCatalog(PolicyCatalogArgs),
}

#[derive(Args)]
pub struct PolicyCreateArgs {
    /// Canonical policy name
    #[arg(long)]
    pub name: String,
    /// New JSON source file to create
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct PolicySourceArgs {
    /// Explicit JSON policy source file
    #[arg(long)]
    pub source: PathBuf,
    #[command(flatten)]
    pub defaults: PolicyLimitDefaults,
}

#[derive(Args)]
pub struct PolicyCompileArgs {
    /// Explicit JSON policy source file
    #[arg(long)]
    pub source: PathBuf,
    /// New canonical bundle file to create
    #[arg(long)]
    pub output: PathBuf,
    #[command(flatten)]
    pub defaults: PolicyLimitDefaults,
}

#[derive(Args)]
pub struct PolicyDiffArgs {
    /// First explicit JSON policy source
    #[arg(long)]
    pub left: PathBuf,
    /// Second explicit JSON policy source
    #[arg(long)]
    pub right: PathBuf,
    #[command(flatten)]
    pub defaults: PolicyLimitDefaults,
}

#[derive(Args)]
pub struct PolicyCatalogArgs {
    /// Explicit JSON catalog descriptor
    #[arg(long)]
    pub catalog: PathBuf,
    #[command(flatten)]
    pub defaults: PolicyLimitDefaults,
}

#[derive(Args)]
pub struct PolicyCatalogListArgs {
    /// Explicit JSON catalog descriptor
    #[arg(long)]
    pub catalog: PathBuf,
}

#[derive(Args, Clone, Copy, Default)]
pub struct PolicyLimitDefaults {
    /// Default finite duration in milliseconds; omit for unlimited
    #[arg(long)]
    pub default_duration_milliseconds: Option<u64>,
    /// Default finite turn count; omit for unlimited
    #[arg(long)]
    pub default_turns: Option<u64>,
    /// Default finite token count; omit for unlimited
    #[arg(long)]
    pub default_tokens: Option<u64>,
    /// Default finite concurrent-request count; omit for unlimited
    #[arg(long)]
    pub default_concurrent_requests: Option<u32>,
}
