use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use crate::CollaborationPolicySourceError;

pub(crate) fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
    document: &'static str,
) -> Result<Vec<u8>, CollaborationPolicySourceError> {
    let link_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| CollaborationPolicySourceError::FileUnavailable { document })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CollaborationPolicySourceError::FileUnavailable { document });
    }
    let file = File::open(path)
        .map_err(|_| CollaborationPolicySourceError::FileUnavailable { document })?;
    let metadata = file
        .metadata()
        .map_err(|_| CollaborationPolicySourceError::FileUnavailable { document })?;
    if !metadata.is_file() {
        return Err(CollaborationPolicySourceError::FileUnavailable { document });
    }
    if usize::try_from(metadata.len())
        .ok()
        .is_none_or(|length| length > maximum)
    {
        return Err(CollaborationPolicySourceError::DocumentTooLarge { document, maximum });
    }
    let take_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(CollaborationPolicySourceError::DocumentTooLarge { document, maximum })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(maximum));
    file.take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| CollaborationPolicySourceError::FileUnavailable { document })?;
    if bytes.len() > maximum {
        return Err(CollaborationPolicySourceError::DocumentTooLarge { document, maximum });
    }
    Ok(bytes)
}

pub(crate) fn create_new_file(
    path: &Path,
    bytes: &[u8],
    document: &'static str,
) -> Result<(), CollaborationPolicySourceError> {
    use std::io::Write;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| CollaborationPolicySourceError::FileUnavailable { document })?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(CollaborationPolicySourceError::FileUnavailable { document });
    }
    Ok(())
}
