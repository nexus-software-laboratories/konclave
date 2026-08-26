use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::bail;
use rusqlite::{Connection, OpenFlags};
use KonclaveClientLibrary::{check_relay_health, RelayInstallationConfig};
use KonclaveLocalServiceTransport::{
    connect_local_service, LocalServiceInstallation, LOCAL_SERVICE_INSTALLATION_FILE,
};
use KonclaveSecretStorage::{open_owner_protected_file, NativeWrappingKeyProvider};

use crate::cli::DoctorArgs;
use crate::installation;

const MAX_PROFILES: usize = 128;
const MAX_PROFILE_ROOT_ENTRIES: usize = 1024;
const MAX_PLUGIN_MANIFEST_BYTES: u64 = 64 * 1024;

pub(crate) async fn run(args: DoctorArgs) -> anyhow::Result<()> {
    let profile_root = installation::resolve_profile_root(args.profile_root)?;
    let install_root = match args.install_root {
        Some(root) if root.is_absolute() => root,
        Some(root) => std::env::current_dir()?.join(root),
        None => default_install_root()?,
    };
    let mut report = DoctorReport::default();
    check_installation_layout(&install_root, &mut report);
    let config = match installation::load(&profile_root) {
        Ok(Some(config)) => {
            report.pass("installation_config", "configuration is valid");
            Some(config)
        }
        Ok(None) => {
            report.fail("installation_config", "run `konclave init`");
            None
        }
        Err(_) => {
            report.fail(
                "installation_config",
                "configuration is unreadable or invalid",
            );
            None
        }
    };
    if let Some(config) = config.as_ref() {
        check_source(config, &mut report);
        match check_relay_health(config.endpoint().clone()).await {
            Ok(()) => report.pass("relay_reachable", "health endpoint responded"),
            Err(error) => report.fail("relay_reachable", error.code()),
        }
    }
    check_local_service(&profile_root, &mut report).await;
    check_profiles(&profile_root, &mut report);
    report.print();
    if report.failures == 0 {
        Ok(())
    } else {
        bail!("doctor found {} failing check(s)", report.failures)
    }
}

fn check_source(config: &RelayInstallationConfig, report: &mut DoctorReport) {
    match installation::load_credential(config) {
        Ok(_) => report.pass(
            "enrollment_source",
            "protected source is available and bound",
        ),
        Err(_) => report.fail(
            "enrollment_source",
            "relay_installation_credential_unavailable",
        ),
    }
}

fn check_installation_layout(root: &Path, report: &mut DoctorReport) {
    let executable = if cfg!(windows) {
        "KonclaveLocalService.exe"
    } else {
        "KonclaveLocalService"
    };
    if root.join("bin").join(executable).is_file() || root.join(executable).is_file() {
        report.pass(
            "local_service_binary",
            "shared local-service binary is present",
        );
    } else {
        report.fail(
            "local_service_binary",
            "shared local-service binary is missing",
        );
    }

    let plugin = root
        .join("share")
        .join("konclave")
        .join("plugin")
        .join("plugin.json");
    if valid_plugin_manifest(&plugin) {
        report.pass("copilot_plugin", "plugin manifest is present");
    } else {
        report.fail("copilot_plugin", "plugin manifest is missing or invalid");
    }
}

async fn check_local_service(profile_root: &Path, report: &mut DoctorReport) {
    let Some(parent) = profile_root.parent() else {
        report.fail("local_service_config", "profile root has no parent");
        return;
    };
    let path = parent.join("service").join(LOCAL_SERVICE_INSTALLATION_FILE);
    let installation = open_owner_protected_file(&path)
        .map_err(anyhow::Error::from)
        .and_then(|file| LocalServiceInstallation::from_reader(file).map_err(anyhow::Error::from));
    let Ok(installation) = installation else {
        report.fail(
            "local_service_config",
            "configuration is unavailable or invalid",
        );
        return;
    };
    if installation.profile_root() != profile_root {
        report.fail(
            "local_service_config",
            "configuration targets another profile root",
        );
        return;
    }
    report.pass("local_service_config", "configuration is valid");
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        connect_local_service(installation.endpoint()),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            report.pass(
                "local_service_running",
                "owner-authenticated endpoint accepted",
            );
        }
        _ => report.fail(
            "local_service_running",
            "shared local service is unavailable",
        ),
    }
}

fn valid_plugin_manifest(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_PLUGIN_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_PLUGIN_MANIFEST_BYTES
    {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .is_some_and(|name| name == "konclave")
}

fn check_profiles(root: &Path, report: &mut DoctorReport) {
    let Ok(entries) = std::fs::read_dir(root) else {
        report.warn("profiles", "no profile root exists yet");
        return;
    };
    let mut profiles = 0_usize;
    let mut databases_readable = true;
    for (index, entry) in entries.enumerate() {
        if index == MAX_PROFILE_ROOT_ENTRIES {
            report.fail(
                "profiles",
                "profile root entry count exceeds diagnostic bound",
            );
            return;
        }
        let Ok(entry) = entry else {
            report.fail("profiles", "profile root contains an unreadable entry");
            databases_readable = false;
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            report.fail("profiles", "profile root contains an unreadable entry");
            databases_readable = false;
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(profile_id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let database = entry.path().join("profile.sqlite");
        if !database.is_file() {
            continue;
        }
        if profiles == MAX_PROFILES {
            report.fail("profiles", "profile count exceeds diagnostic bound");
            return;
        }
        profiles += 1;
        databases_readable &= check_profile_database(&database, report);
        match NativeWrappingKeyProvider::verify_existing(&profile_id) {
            Ok(()) => report.pass("profile_custody", "native profile custody is available"),
            Err(_) => report.warn(
                "profile_custody",
                "profile uses external custody or native custody is unavailable",
            ),
        }
    }
    if profiles == 0 {
        report.warn("profiles", "no session profile exists yet");
    } else if databases_readable {
        report.pass("profiles", "profile databases are readable");
    }
}

fn check_profile_database(path: &Path, report: &mut DoctorReport) -> bool {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    );
    let Ok(connection) = connection else {
        report.fail("profile_database", "profile database is unreadable");
        return false;
    };
    let active = connection.query_row(
        "SELECT CASE WHEN relay_endpoint IS NOT NULL THEN 1 ELSE 0 END
         FROM daemon_profile WHERE singleton_id = 1",
        [],
        |row| row.get::<_, i64>(0),
    );
    let enrollment_table = connection.query_row(
        "SELECT count(*) FROM sqlite_schema
         WHERE type = 'table' AND name = 'daemon_relay_enrollment'",
        [],
        |row| row.get::<_, i64>(0),
    );
    let pending = match enrollment_table {
        Ok(1) => connection.query_row("SELECT count(*) FROM daemon_relay_enrollment", [], |row| {
            row.get::<_, i64>(0)
        }),
        Ok(0) => Ok(0),
        _ => Err(rusqlite::Error::InvalidQuery),
    };
    match (active, pending) {
        (Ok(1), Ok(0)) => {
            report.pass("profile_relay", "profile relay is configured");
            true
        }
        (Ok(0), Ok(1)) => {
            report.warn("profile_relay", "profile enrollment is pending");
            true
        }
        (Ok(0), Ok(0)) => {
            report.warn("profile_relay", "profile relay is not configured");
            true
        }
        _ => {
            report.fail("profile_database", "profile relay state is inconsistent");
            false
        }
    }
}

fn default_install_root() -> anyhow::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CLI executable has no parent directory"))?;
    if parent.file_name().is_some_and(|name| name == "bin") {
        Ok(parent
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installation bin has no parent"))?
            .to_path_buf())
    } else {
        Ok(parent.to_path_buf())
    }
}

#[derive(Default)]
struct DoctorReport {
    checks: Vec<DoctorCheck>,
    failures: usize,
}

impl DoctorReport {
    fn pass(&mut self, code: &'static str, message: impl Into<String>) {
        self.checks.push(DoctorCheck {
            status: "PASS",
            code,
            message: message.into(),
        });
    }

    fn warn(&mut self, code: &'static str, message: impl Into<String>) {
        self.checks.push(DoctorCheck {
            status: "WARN",
            code,
            message: message.into(),
        });
    }

    fn fail(&mut self, code: &'static str, message: impl Into<String>) {
        self.failures += 1;
        self.checks.push(DoctorCheck {
            status: "FAIL",
            code,
            message: message.into(),
        });
    }

    fn print(&self) {
        for check in &self.checks {
            println!("{} {}: {}", check.status, check.code, check.message);
        }
    }
}

struct DoctorCheck {
    status: &'static str,
    code: &'static str,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_counts_failures_but_not_warnings() {
        let mut report = DoctorReport::default();
        report.pass("one", "pass");
        report.warn("two", "warn");
        report.fail("three", "fail");
        assert_eq!(report.failures, 1);
        assert_eq!(report.checks.len(), 3);
    }

    #[test]
    fn unreadable_profile_database_is_never_reported_as_readable() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile-a");
        std::fs::create_dir(&profile).unwrap();
        std::fs::write(profile.join("profile.sqlite"), b"not a database").unwrap();
        let mut report = DoctorReport::default();

        check_profiles(root.path(), &mut report);

        assert!(report
            .checks
            .iter()
            .any(|check| { check.status == "FAIL" && check.code == "profile_database" }));
        assert!(!report
            .checks
            .iter()
            .any(|check| { check.status == "PASS" && check.code == "profiles" }));
    }
}
