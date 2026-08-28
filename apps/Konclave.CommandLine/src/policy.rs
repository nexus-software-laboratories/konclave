use KonclaveCollaborationPolicies::{
    compile_collaboration_policy_file, create_collaboration_policy_source_file,
    write_compiled_collaboration_policy_file, CompiledCollaborationPolicy,
    FileCollaborationPolicyCatalog,
};
use KonclaveDomainCore::CollaborationPolicyLimits;

use crate::cli::{
    PolicyArgs, PolicyCatalogArgs, PolicyCommand, PolicyCompileArgs, PolicyDiffArgs,
    PolicyLimitDefaults, PolicySourceArgs,
};
use crate::encoding::encode_hex;

pub fn run(args: PolicyArgs) -> anyhow::Result<()> {
    match args.command {
        PolicyCommand::Create(args) => {
            create_collaboration_policy_source_file(&args.output, &args.name)?;
            println!("created policy source: {}", args.name);
        }
        PolicyCommand::Validate(args) => {
            let compiled = compile_source(&args)?;
            println!(
                "valid policy: {} sha256:{}",
                compiled.bundle().name(),
                encode_hex(compiled.digest().as_bytes())
            );
        }
        PolicyCommand::Inspect(args) => {
            render_policy(&compile_source(&args)?);
        }
        PolicyCommand::Compile(args) => {
            compile_to_file(args)?;
        }
        PolicyCommand::Diff(args) => {
            render_diff(args)?;
        }
        PolicyCommand::List(args) => {
            let catalog = FileCollaborationPolicyCatalog::open(&args.catalog)?;
            for name in catalog.names() {
                println!("{name}");
            }
        }
        PolicyCommand::ValidateCatalog(args) => {
            validate_catalog(args)?;
        }
    }
    Ok(())
}

fn compile_source(args: &PolicySourceArgs) -> anyhow::Result<CompiledCollaborationPolicy> {
    Ok(compile_collaboration_policy_file(
        &args.source,
        policy_defaults(args.defaults)?,
    )?)
}

fn compile_to_file(args: PolicyCompileArgs) -> anyhow::Result<()> {
    let compiled =
        compile_collaboration_policy_file(&args.source, policy_defaults(args.defaults)?)?;
    write_compiled_collaboration_policy_file(&args.output, &compiled)?;
    println!(
        "compiled policy: {} sha256:{}",
        compiled.bundle().name(),
        encode_hex(compiled.digest().as_bytes())
    );
    Ok(())
}

fn render_diff(args: PolicyDiffArgs) -> anyhow::Result<()> {
    let defaults = policy_defaults(args.defaults)?;
    let left = compile_collaboration_policy_file(&args.left, defaults)?;
    let right = compile_collaboration_policy_file(&args.right, defaults)?;
    println!("left: sha256:{}", encode_hex(left.digest().as_bytes()));
    println!("right: sha256:{}", encode_hex(right.digest().as_bytes()));
    println!(
        "definition match: {}",
        if left.digest() == right.digest() {
            "exact"
        } else {
            "different"
        }
    );
    Ok(())
}

fn validate_catalog(args: PolicyCatalogArgs) -> anyhow::Result<()> {
    let defaults = policy_defaults(args.defaults)?;
    let catalog = FileCollaborationPolicyCatalog::open(&args.catalog)?;
    let names = catalog.names().map(str::to_string).collect::<Vec<_>>();
    for name in names {
        let compiled = catalog.compile(&name, defaults)?;
        println!(
            "valid policy: {} sha256:{}",
            name,
            encode_hex(compiled.digest().as_bytes())
        );
    }
    Ok(())
}

fn render_policy(compiled: &CompiledCollaborationPolicy) {
    let limits = compiled.bundle().limits();
    println!("name: {}", compiled.bundle().name());
    println!(
        "digest: sha256:{}",
        encode_hex(compiled.digest().as_bytes())
    );
    println!("statements: {}", compiled.bundle().statements().len());
    println!(
        "required harness claims: {}",
        compiled.bundle().required_harness_claims().len()
    );
    println!(
        "duration milliseconds: {}",
        format_limit(limits.duration_milliseconds())
    );
    println!("turns: {}", format_limit(limits.turns()));
    println!("tokens: {}", format_limit(limits.tokens()));
    println!(
        "concurrent requests: {}",
        format_limit(limits.concurrent_requests())
    );
}

fn policy_defaults(
    defaults: PolicyLimitDefaults,
) -> Result<CollaborationPolicyLimits, KonclaveDomainCore::KonclaveDomainError> {
    CollaborationPolicyLimits::new(
        defaults.default_duration_milliseconds,
        defaults.default_turns,
        defaults.default_tokens,
        defaults.default_concurrent_requests,
    )
}

fn format_limit<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "unlimited".to_string(), |value| value.to_string())
}
