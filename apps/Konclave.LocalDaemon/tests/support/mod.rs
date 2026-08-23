use std::process::Command;

pub struct TestProfile {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
}

impl TestProfile {
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("profiles");
        let key_file = directory.path().join("wrapping.key");
        std::fs::write(&key_file, [7_u8; 32]).unwrap();
        Self {
            _directory: directory,
            root,
            key_file,
        }
    }

    pub fn configure(&self, command: &mut Command) {
        command
            .env("KONCLAVE_PROFILE_ROOT", &self.root)
            .env("KONCLAVE_PROFILE_ID", "integration")
            .env("KONCLAVE_WRAPPING_KEY_FILE", &self.key_file);
    }

    /// Path the daemon creates when it begins opening this profile.
    ///
    /// The lock appears before identity material is generated, so its existence marks
    /// the middle of profile initialization rather than its completion.
    #[allow(
        dead_code,
        reason = "shared support module is built into several test binaries"
    )]
    pub fn lock_path(&self) -> std::path::PathBuf {
        self.root.join("integration").join("profile.lock")
    }
}
