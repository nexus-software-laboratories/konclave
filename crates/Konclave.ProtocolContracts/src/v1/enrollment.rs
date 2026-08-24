use KonclaveDomainCore::MAX_RELAY_CONTROL_MESSAGE_BYTES;
use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayEnrollmentResponse,
    RelayPrincipalId,
};

use super::common::{decode_bounded, encode_bounded, required, version_from_wire, version_to_wire};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const ENROLLMENT_REQUEST_CONTRACT: &str = "RelayEnrollmentRequest";
const ENROLLMENT_RESPONSE_CONTRACT: &str = "RelayEnrollmentResponse";

/// Encodes one bounded principal-registration request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds the relay control bound.
pub fn encode_relay_enrollment_request(
    value: &RelayEnrollmentRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::RelayEnrollmentRequest {
            version: Some(version_to_wire(value.version())),
            request_id: Some(request_id_to_wire(value.request_id())),
            principal_id: Some(principal_id_to_wire(value.principal_id())),
        },
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        ENROLLMENT_REQUEST_CONTRACT,
    )
}

/// Decodes and validates one untrusted principal-registration request.
///
/// # Errors
///
/// Returns a protocol, version, or exact-length validation error.
pub fn decode_relay_enrollment_request(
    bytes: &[u8],
) -> Result<RelayEnrollmentRequest, KonclaveProtocolError> {
    let value: wire::RelayEnrollmentRequest = decode_bounded(
        bytes,
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        ENROLLMENT_REQUEST_CONTRACT,
    )?;
    Ok(RelayEnrollmentRequest::new(
        version_from_wire(value.version, ENROLLMENT_REQUEST_CONTRACT)?,
        request_id_from_wire(value.request_id)?,
        principal_id_from_wire(value.principal_id)?,
    ))
}

/// Encodes one bounded principal-registration response.
///
/// # Errors
///
/// Returns a size error when the encoded response exceeds the relay control bound.
pub fn encode_relay_enrollment_response(
    value: &RelayEnrollmentResponse,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::RelayEnrollmentResponse {
            version: Some(version_to_wire(value.version())),
            request_id: Some(request_id_to_wire(value.request_id())),
            principal_id: Some(principal_id_to_wire(value.principal_id())),
            outcome: outcome_to_wire(value.outcome())?,
        },
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        ENROLLMENT_RESPONSE_CONTRACT,
    )
}

/// Decodes and validates one untrusted principal-registration response.
///
/// # Errors
///
/// Returns a protocol, version, identifier, or finite-outcome validation error.
pub fn decode_relay_enrollment_response(
    bytes: &[u8],
) -> Result<RelayEnrollmentResponse, KonclaveProtocolError> {
    let value: wire::RelayEnrollmentResponse = decode_bounded(
        bytes,
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        ENROLLMENT_RESPONSE_CONTRACT,
    )?;
    Ok(RelayEnrollmentResponse::new(
        version_from_wire(value.version, ENROLLMENT_RESPONSE_CONTRACT)?,
        request_id_from_wire(value.request_id)?,
        principal_id_from_wire(value.principal_id)?,
        outcome_from_wire(value.outcome)?,
    ))
}

fn request_id_to_wire(value: EnrollmentRequestId) -> wire::EnrollmentRequestId {
    wire::EnrollmentRequestId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn request_id_from_wire(
    value: Option<wire::EnrollmentRequestId>,
) -> Result<EnrollmentRequestId, KonclaveProtocolError> {
    Ok(EnrollmentRequestId::from_slice(
        &required(value, "enrollment_request_id")?.value,
    )?)
}

fn principal_id_to_wire(value: RelayPrincipalId) -> wire::RelayPrincipalId {
    wire::RelayPrincipalId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn principal_id_from_wire(
    value: Option<wire::RelayPrincipalId>,
) -> Result<RelayPrincipalId, KonclaveProtocolError> {
    Ok(RelayPrincipalId::from_slice(
        &required(value, "relay_principal_id")?.value,
    )?)
}

fn outcome_to_wire(value: RelayEnrollmentOutcome) -> Result<i32, KonclaveProtocolError> {
    Ok(match value {
        RelayEnrollmentOutcome::Registered => wire::RelayEnrollmentOutcome::Registered as i32,
        RelayEnrollmentOutcome::AlreadyRegistered => {
            wire::RelayEnrollmentOutcome::AlreadyRegistered as i32
        }
        _ => {
            return Err(KonclaveProtocolError::UnsupportedEnum {
                field: "relay_enrollment_outcome",
                value: -1,
            });
        }
    })
}

fn outcome_from_wire(value: i32) -> Result<RelayEnrollmentOutcome, KonclaveProtocolError> {
    match wire::RelayEnrollmentOutcome::try_from(value).ok() {
        Some(wire::RelayEnrollmentOutcome::Registered) => Ok(RelayEnrollmentOutcome::Registered),
        Some(wire::RelayEnrollmentOutcome::AlreadyRegistered) => {
            Ok(RelayEnrollmentOutcome::AlreadyRegistered)
        }
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "relay_enrollment_outcome",
            value,
        }),
    }
}
