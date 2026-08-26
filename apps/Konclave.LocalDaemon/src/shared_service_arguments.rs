use std::path::PathBuf;

use anyhow::{Context as _, bail};

pub(crate) fn parse_installation_path(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> anyhow::Result<PathBuf> {
    let Some(flag) = arguments.next() else {
        bail!("--config and one absolute installation path are required");
    };
    if flag != "--config" {
        bail!("the only supported argument is --config");
    }
    let path = arguments
        .next()
        .map(PathBuf::from)
        .context("--config requires one installation path")?;
    if arguments.next().is_some() || !path.is_absolute() {
        bail!("--config requires exactly one absolute installation path");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::parse_installation_path;

    #[test]
    fn config_argument_is_exact_and_absolute() {
        let absolute = if cfg!(windows) {
            r"C:\Konclave\service.json"
        } else {
            "/tmp/konclave/service.json"
        };
        assert_eq!(
            parse_installation_path(
                ["--config", absolute]
                    .into_iter()
                    .map(std::ffi::OsString::from)
            )
            .unwrap(),
            std::path::PathBuf::from(absolute)
        );
        for arguments in [
            Vec::<&str>::new(),
            vec!["--other", absolute],
            vec!["--config", "relative.json"],
            vec!["--config", absolute, "extra"],
        ] {
            assert!(
                parse_installation_path(arguments.into_iter().map(std::ffi::OsString::from))
                    .is_err()
            );
        }
    }
}
