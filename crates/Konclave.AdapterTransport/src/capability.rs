use std::fs;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AdapterTransportError;

/// A launch capability shared between one adapter and the daemon child it starts.
///
/// The value never crosses the channel and never enters arguments, logs, telemetry,
/// or persisted records; only proofs computed under it are exchanged.
pub struct LaunchCapability([u8; Self::LENGTH]);

impl LaunchCapability {
    /// Byte length of a launch capability.
    pub const LENGTH: usize = 32;

    /// Largest accepted capability file size, in bytes.
    ///
    /// A canonical value plus one optional trailing newline is 44 bytes, so a small
    /// bound stops an oversized or attacker-grown file before any allocation.
    pub const MAX_FILE_BYTES: u64 = 64;

    /// Wraps exactly [`LaunchCapability::LENGTH`] random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the capability bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Reads a capability from an owner-protected launch file.
    ///
    /// The file must be an ordinary owner-owned file that no other account can reach,
    /// must not be a link or reparse point, and must hold one canonical unpadded
    /// base64url value. Every intermediate buffer is zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnusableCapabilityFile`],
    /// [`AdapterTransportError::CapabilityFileNotOwnerProtected`], or
    /// [`AdapterTransportError::MalformedCapability`].
    pub fn read_launch_file(path: &Path) -> Result<Self, AdapterTransportError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| AdapterTransportError::UnusableCapabilityFile)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AdapterTransportError::UnusableCapabilityFile);
        }
        if metadata.len() == 0 || metadata.len() > Self::MAX_FILE_BYTES {
            return Err(AdapterTransportError::UnusableCapabilityFile);
        }
        assert_owner_protected(&metadata)?;

        let mut content = Zeroizing::new(
            fs::read(path).map_err(|_| AdapterTransportError::UnusableCapabilityFile)?,
        );
        if content.len() as u64 > Self::MAX_FILE_BYTES {
            return Err(AdapterTransportError::UnusableCapabilityFile);
        }
        let capability = Self::parse(&content);
        content.zeroize();
        capability
    }

    fn parse(content: &[u8]) -> Result<Self, AdapterTransportError> {
        let trimmed = trim_one_trailing_newline(content);
        if trimmed.is_empty() {
            return Err(AdapterTransportError::MalformedCapability);
        }
        let mut decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(trimmed)
                .map_err(|_| AdapterTransportError::MalformedCapability)?,
        );
        if decoded.len() != Self::LENGTH {
            return Err(AdapterTransportError::MalformedCapability);
        }
        let mut bytes = [0_u8; Self::LENGTH];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();
        Ok(Self(bytes))
    }
}

impl Drop for LaunchCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for LaunchCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LaunchCapability")
            .finish_non_exhaustive()
    }
}

/// Removes at most one trailing newline so a file written with a terminating newline
/// stays canonical, while embedded or repeated newlines still fail as malformed.
fn trim_one_trailing_newline(content: &[u8]) -> &[u8] {
    let without_newline = content.strip_suffix(b"\n").unwrap_or(content);
    without_newline
        .strip_suffix(b"\r")
        .unwrap_or(without_newline)
}

#[cfg(unix)]
fn assert_owner_protected(metadata: &fs::Metadata) -> Result<(), AdapterTransportError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.mode() & 0o077 != 0 {
        return Err(AdapterTransportError::CapabilityFileNotOwnerProtected);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(AdapterTransportError::CapabilityFileNotOwnerProtected);
    }
    // An extra hard link would let a second path retain the capability after the
    // adapter removes its own, so a shared inode is treated as unusable.
    if metadata.nlink() != 1 {
        return Err(AdapterTransportError::UnusableCapabilityFile);
    }
    Ok(())
}

#[cfg(windows)]
fn assert_owner_protected(metadata: &fs::Metadata) -> Result<(), AdapterTransportError> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AdapterTransportError::UnusableCapabilityFile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::LaunchCapability;
    use crate::error::AdapterTransportError;

    fn write_capability(
        directory: &std::path::Path,
        name: &str,
        content: &[u8],
    ) -> std::path::PathBuf {
        let path = directory.join(name);
        fs::write(&path, content).unwrap();
        restrict(&path);
        path
    }

    #[cfg(unix)]
    fn restrict(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(windows)]
    fn restrict(_path: &std::path::Path) {}

    #[test]
    fn reads_a_canonical_capability_with_and_without_a_trailing_newline() {
        let directory = tempfile::tempdir().unwrap();
        let expected = [7_u8; LaunchCapability::LENGTH];
        let encoded = URL_SAFE_NO_PAD.encode(expected);

        let plain = write_capability(directory.path(), "plain", encoded.as_bytes());
        assert_eq!(
            LaunchCapability::read_launch_file(&plain)
                .unwrap()
                .as_bytes(),
            &expected
        );

        let terminated = write_capability(
            directory.path(),
            "terminated",
            format!("{encoded}\n").as_bytes(),
        );
        assert_eq!(
            LaunchCapability::read_launch_file(&terminated)
                .unwrap()
                .as_bytes(),
            &expected
        );
    }

    #[test]
    fn rejects_a_missing_empty_or_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            LaunchCapability::read_launch_file(&directory.path().join("absent")).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );

        let empty = write_capability(directory.path(), "empty", b"");
        assert_eq!(
            LaunchCapability::read_launch_file(&empty).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );

        let oversized = write_capability(
            directory.path(),
            "oversized",
            &vec![b'A'; usize::try_from(LaunchCapability::MAX_FILE_BYTES).unwrap() + 1],
        );
        assert_eq!(
            LaunchCapability::read_launch_file(&oversized).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );
    }

    #[test]
    fn rejects_a_directory_in_place_of_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        assert_eq!(
            LaunchCapability::read_launch_file(&nested).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );
    }

    #[test]
    fn rejects_non_canonical_and_wrong_length_encodings() {
        let directory = tempfile::tempdir().unwrap();
        let raw = [7_u8; LaunchCapability::LENGTH];

        let padded = write_capability(directory.path(), "padded", STANDARD.encode(raw).as_bytes());
        assert_eq!(
            LaunchCapability::read_launch_file(&padded).unwrap_err(),
            AdapterTransportError::MalformedCapability
        );

        let short = write_capability(
            directory.path(),
            "short",
            URL_SAFE_NO_PAD.encode([7_u8; 16]).as_bytes(),
        );
        assert_eq!(
            LaunchCapability::read_launch_file(&short).unwrap_err(),
            AdapterTransportError::MalformedCapability
        );

        let embedded = write_capability(
            directory.path(),
            "embedded",
            format!("{}\n\n", URL_SAFE_NO_PAD.encode(raw)).as_bytes(),
        );
        assert_eq!(
            LaunchCapability::read_launch_file(&embedded).unwrap_err(),
            AdapterTransportError::MalformedCapability
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_file_reachable_by_another_account() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-readable");
        fs::write(
            &path,
            URL_SAFE_NO_PAD.encode([7_u8; LaunchCapability::LENGTH]),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            LaunchCapability::read_launch_file(&path).unwrap_err(),
            AdapterTransportError::CapabilityFileNotOwnerProtected
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symbolic_link_to_a_valid_capability() {
        let directory = tempfile::tempdir().unwrap();
        let target = write_capability(
            directory.path(),
            "target",
            URL_SAFE_NO_PAD
                .encode([7_u8; LaunchCapability::LENGTH])
                .as_bytes(),
        );
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            LaunchCapability::read_launch_file(&link).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_an_additional_hard_link_to_the_capability() {
        let directory = tempfile::tempdir().unwrap();
        let target = write_capability(
            directory.path(),
            "hard-target",
            URL_SAFE_NO_PAD
                .encode([7_u8; LaunchCapability::LENGTH])
                .as_bytes(),
        );
        fs::hard_link(&target, directory.path().join("hard-link")).unwrap();
        assert_eq!(
            LaunchCapability::read_launch_file(&target).unwrap_err(),
            AdapterTransportError::UnusableCapabilityFile
        );
    }
}
