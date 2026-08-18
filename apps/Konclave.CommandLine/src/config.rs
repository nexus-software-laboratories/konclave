use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

/// Application configuration, deserialized from a `KonclaveCommandLine.toml` file in
/// the working directory when present; missing fields fall back to `Default`.
/// For environment-variable overrides, bind a flag with clap's `env` feature
/// (`#[arg(env = "...")]`).
#[derive(Debug, Deserialize)]
#[serde(default)]
struct Settings {
    log_level: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    let path = "KonclaveCommandLine.toml";
    let settings = if Path::new(path).exists() {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        toml::from_str::<Settings>(&text).with_context(|| format!("parsing {path}"))?
    } else {
        Settings::default()
    };

    println!("log_level = {}", settings.log_level);
    Ok(())
}
