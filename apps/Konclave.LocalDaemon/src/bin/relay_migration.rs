use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let report = konclave_local_daemon::run_relay_migration(std::env::args_os().skip(1)).await?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
