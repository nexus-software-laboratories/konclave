use std::io::{Read as _, Write as _};

use anyhow::{bail, Context as _};
use KonclaveUserPresence::{
    perform_native_authentication_json, perform_native_registration_json,
    MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES,
};

use crate::cli::{UserPresenceHelperArgs, UserPresenceHelperCommand};

pub(crate) fn run(args: UserPresenceHelperArgs) -> anyhow::Result<()> {
    let mut request = Vec::with_capacity(MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES + 1);
    std::io::stdin()
        .take(
            u64::try_from(MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES + 1)
                .context("measuring native user-presence input")?,
        )
        .read_to_end(&mut request)
        .context("reading native user-presence request")?;
    if request.is_empty() || request.len() > MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES {
        bail!("native user-presence request is invalid");
    }
    let response = match args.command {
        UserPresenceHelperCommand::Register => perform_native_registration_json(&request),
        UserPresenceHelperCommand::Authenticate => perform_native_authentication_json(&request),
    }
    .context("performing native user presence")?;
    std::io::stdout()
        .write_all(&response)
        .context("writing native user-presence response")?;
    Ok(())
}
