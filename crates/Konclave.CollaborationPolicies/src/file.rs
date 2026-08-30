use std::fs::OpenOptions;
use std::path::Path;

use crate::CollaborationPolicySourceError;

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
