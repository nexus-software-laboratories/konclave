use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::LocalServiceTransportError;

/// Byte length of a request identifier.
pub const REQUEST_ID_LENGTH: usize = 16;

/// Largest accepted operation name, in bytes.
pub const MAX_OPERATION_LENGTH: usize = 64;

/// Largest accepted request or response payload, in bytes.
pub const MAX_RPC_PAYLOAD_BYTES: usize = 1_048_576;

/// Hard limit for one authenticated request or response frame.
///
/// The value is the exact maximum encoding rather than a rounded guess, so a peer
/// cannot declare a length that this build would accept but never produce.
pub const MAX_RPC_FRAME_BYTES: usize =
    1 + REQUEST_ID_LENGTH + 1 + MAX_OPERATION_LENGTH + 4 + MAX_RPC_PAYLOAD_BYTES;

const KIND_REQUEST: u8 = 16;
const KIND_SUCCESS: u8 = 32;
const KIND_FAILURE: u8 = 33;

const ERROR_INVALID_REQUEST: u16 = 1;
const ERROR_UNKNOWN_OPERATION: u16 = 2;
const ERROR_NOT_AUTHORIZED: u16 = 3;
const ERROR_PROFILE_UNAVAILABLE: u16 = 4;
const ERROR_BUSY: u16 = 5;
const ERROR_DEADLINE_EXCEEDED: u16 = 6;
const ERROR_PAYLOAD_TOO_LARGE: u16 = 7;
const ERROR_CONFLICT: u16 = 8;
const ERROR_INTERNAL: u16 = 9;

/// Stable identifier for one request on one connection.
///
/// This value is the idempotency key for the operation it carries. A client that
/// retries after a disconnect reuses the same identifier, and a service that has
/// already applied that identifier answers with the recorded outcome instead of
/// repeating the side effect. Nothing else in the frame is safe to deduplicate on,
/// because two distinct operations may otherwise be byte-identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; REQUEST_ID_LENGTH]);

impl RequestId {
    /// Wraps exactly [`REQUEST_ID_LENGTH`] bytes.
    #[must_use]
    pub const fn from_bytes(value: [u8; REQUEST_ID_LENGTH]) -> Self {
        Self(value)
    }

    /// Parses an identifier from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::InvalidIdentifier`] when `value` does
    /// not contain exactly [`REQUEST_ID_LENGTH`] bytes.
    pub fn from_slice(value: &[u8]) -> Result<Self, LocalServiceTransportError> {
        let bytes = value
            .try_into()
            .map_err(|_| LocalServiceTransportError::InvalidIdentifier { field: "request" })?;
        Ok(Self(bytes))
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REQUEST_ID_LENGTH] {
        &self.0
    }
}

/// A validated operation name.
///
/// The name is a bounded ASCII identifier, never a path, command line, or free-text
/// value, so it can be matched against a finite service-side table without any
/// normalization step that could disagree with the sender.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationName(String);

impl OperationName {
    /// Parses a bounded operation name.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::InvalidIdentifier`] when the value is
    /// empty, longer than [`MAX_OPERATION_LENGTH`], does not start with an ASCII
    /// alphanumeric, or contains a character outside ASCII alphanumerics, `.`, `-`,
    /// and `_`.
    pub fn parse(value: &str) -> Result<Self, LocalServiceTransportError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_OPERATION_LENGTH {
            return Err(LocalServiceTransportError::InvalidIdentifier { field: "operation" });
        }
        if !bytes[0].is_ascii_alphanumeric() {
            return Err(LocalServiceTransportError::InvalidIdentifier { field: "operation" });
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(LocalServiceTransportError::InvalidIdentifier { field: "operation" });
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the operation name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The finite set of stable failure codes a service may return.
///
/// The set is closed so a client can branch on an outcome without parsing text, and
/// unimplemented wire values are rejected rather than surfaced as an opaque number.
/// No variant carries a message, path, identifier, or plaintext.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalServiceErrorCode {
    /// The request payload did not satisfy the operation's contract.
    InvalidRequest,
    /// The operation name is not implemented by this service.
    UnknownOperation,
    /// The connection binding does not authorize this operation.
    NotAuthorized,
    /// The bound profile could not be opened or is shutting down.
    ProfileUnavailable,
    /// The service is at capacity and the client should retry later.
    Busy,
    /// The operation did not complete within its deadline.
    DeadlineExceeded,
    /// The request payload exceeded the operation's own bound.
    PayloadTooLarge,
    /// The request conflicts with the current state of the bound profile.
    Conflict,
    /// The service failed for a reason it does not disclose.
    Internal,
}

impl LocalServiceErrorCode {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn wire_value(&self) -> u16 {
        match self {
            Self::InvalidRequest => ERROR_INVALID_REQUEST,
            Self::UnknownOperation => ERROR_UNKNOWN_OPERATION,
            Self::NotAuthorized => ERROR_NOT_AUTHORIZED,
            Self::ProfileUnavailable => ERROR_PROFILE_UNAVAILABLE,
            Self::Busy => ERROR_BUSY,
            Self::DeadlineExceeded => ERROR_DEADLINE_EXCEEDED,
            Self::PayloadTooLarge => ERROR_PAYLOAD_TOO_LARGE,
            Self::Conflict => ERROR_CONFLICT,
            Self::Internal => ERROR_INTERNAL,
        }
    }

    /// Parses a wire value.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnknownErrorCode`] for any value this
    /// build does not implement.
    pub const fn from_wire_value(value: u16) -> Result<Self, LocalServiceTransportError> {
        match value {
            ERROR_INVALID_REQUEST => Ok(Self::InvalidRequest),
            ERROR_UNKNOWN_OPERATION => Ok(Self::UnknownOperation),
            ERROR_NOT_AUTHORIZED => Ok(Self::NotAuthorized),
            ERROR_PROFILE_UNAVAILABLE => Ok(Self::ProfileUnavailable),
            ERROR_BUSY => Ok(Self::Busy),
            ERROR_DEADLINE_EXCEEDED => Ok(Self::DeadlineExceeded),
            ERROR_PAYLOAD_TOO_LARGE => Ok(Self::PayloadTooLarge),
            ERROR_CONFLICT => Ok(Self::Conflict),
            ERROR_INTERNAL => Ok(Self::Internal),
            _ => Err(LocalServiceTransportError::UnknownErrorCode),
        }
    }

    /// Returns the stable machine-readable name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnknownOperation => "unknown_operation",
            Self::NotAuthorized => "not_authorized",
            Self::ProfileUnavailable => "profile_unavailable",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Conflict => "conflict",
            Self::Internal => "internal",
        }
    }
}

/// One bounded request from an authenticated client.
///
/// The transport carries the operation name and an opaque payload. It does not know
/// what any operation means, so a new operation needs no transport change and the
/// bounds here apply uniformly to every one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalServiceRequest {
    request_id: RequestId,
    operation: OperationName,
    payload: Vec<u8>,
}

impl LocalServiceRequest {
    /// Creates a bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::RequestOutOfBounds`] when the payload
    /// exceeds [`MAX_RPC_PAYLOAD_BYTES`].
    pub fn new(
        request_id: RequestId,
        operation: OperationName,
        payload: Vec<u8>,
    ) -> Result<Self, LocalServiceTransportError> {
        if payload.len() > MAX_RPC_PAYLOAD_BYTES {
            return Err(LocalServiceTransportError::RequestOutOfBounds);
        }
        Ok(Self {
            request_id,
            operation,
            payload,
        })
    }

    /// Returns the idempotency key for this request.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the requested operation.
    #[must_use]
    pub const fn operation(&self) -> &OperationName {
        &self.operation
    }

    /// Returns the opaque request payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the canonical request frame payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let operation = self.operation.as_str().as_bytes();
        let mut encoded = Vec::with_capacity(
            1 + REQUEST_ID_LENGTH + 1 + operation.len() + 4 + self.payload.len(),
        );
        encoded.push(KIND_REQUEST);
        encoded.extend_from_slice(self.request_id.as_bytes());
        encoded.push(u8::try_from(operation.len()).unwrap_or(u8::MAX));
        encoded.extend_from_slice(operation);
        encoded.extend_from_slice(&payload_length(self.payload.len()));
        encoded.extend_from_slice(&self.payload);
        encoded
    }

    /// Decodes one request frame payload.
    ///
    /// The declared payload length is checked against the bound and against the bytes
    /// actually present before the payload is copied, so an oversized or lying length
    /// never reserves a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnknownMessageKind`],
    /// [`LocalServiceTransportError::MalformedFrame`],
    /// [`LocalServiceTransportError::InvalidIdentifier`], or
    /// [`LocalServiceTransportError::RequestOutOfBounds`].
    pub fn decode(payload: &[u8]) -> Result<Self, LocalServiceTransportError> {
        let (kind, mut rest) = split_kind(payload)?;
        if kind != KIND_REQUEST {
            return Err(LocalServiceTransportError::UnknownMessageKind);
        }
        let request_id = RequestId::from_bytes(take::<REQUEST_ID_LENGTH>(&mut rest)?);
        let operation = take_operation(&mut rest)?;
        let payload = take_payload(&mut rest)?;
        finish(rest)?;
        Ok(Self {
            request_id,
            operation,
            payload,
        })
    }
}

/// What the service answers for exactly one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalServiceResponse {
    /// The operation succeeded and returned an opaque payload.
    Success {
        request_id: RequestId,
        payload: Vec<u8>,
    },
    /// The operation failed with a stable code that carries no plaintext.
    Failure {
        request_id: RequestId,
        code: LocalServiceErrorCode,
    },
}

impl LocalServiceResponse {
    /// Creates a bounded success response.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::RequestOutOfBounds`] when the payload
    /// exceeds [`MAX_RPC_PAYLOAD_BYTES`].
    pub fn success(
        request_id: RequestId,
        payload: Vec<u8>,
    ) -> Result<Self, LocalServiceTransportError> {
        if payload.len() > MAX_RPC_PAYLOAD_BYTES {
            return Err(LocalServiceTransportError::RequestOutOfBounds);
        }
        Ok(Self::Success {
            request_id,
            payload,
        })
    }

    /// Creates a failure response.
    #[must_use]
    pub const fn failure(request_id: RequestId, code: LocalServiceErrorCode) -> Self {
        Self::Failure { request_id, code }
    }

    /// Returns the request this response answers.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::Success { request_id, .. } | Self::Failure { request_id, .. } => *request_id,
        }
    }

    /// Encodes the canonical response frame payload.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::RequestOutOfBounds`] when a payload
    /// exceeds its bound, so an oversized response fails here rather than being
    /// truncated on the wire.
    pub fn encode(&self) -> Result<Vec<u8>, LocalServiceTransportError> {
        let mut encoded = Vec::new();
        match self {
            Self::Success {
                request_id,
                payload,
            } => {
                if payload.len() > MAX_RPC_PAYLOAD_BYTES {
                    return Err(LocalServiceTransportError::RequestOutOfBounds);
                }
                encoded.reserve(1 + REQUEST_ID_LENGTH + 4 + payload.len());
                encoded.push(KIND_SUCCESS);
                encoded.extend_from_slice(request_id.as_bytes());
                encoded.extend_from_slice(&payload_length(payload.len()));
                encoded.extend_from_slice(payload);
            }
            Self::Failure { request_id, code } => {
                encoded.reserve(1 + REQUEST_ID_LENGTH + 2);
                encoded.push(KIND_FAILURE);
                encoded.extend_from_slice(request_id.as_bytes());
                encoded.extend_from_slice(&code.wire_value().to_be_bytes());
            }
        }
        Ok(encoded)
    }

    /// Decodes one response frame payload.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnknownMessageKind`],
    /// [`LocalServiceTransportError::UnknownErrorCode`],
    /// [`LocalServiceTransportError::MalformedFrame`], or
    /// [`LocalServiceTransportError::RequestOutOfBounds`].
    pub fn decode(payload: &[u8]) -> Result<Self, LocalServiceTransportError> {
        let (kind, mut rest) = split_kind(payload)?;
        let response = match kind {
            KIND_SUCCESS => {
                let request_id = RequestId::from_bytes(take::<REQUEST_ID_LENGTH>(&mut rest)?);
                Self::Success {
                    request_id,
                    payload: take_payload(&mut rest)?,
                }
            }
            KIND_FAILURE => {
                let request_id = RequestId::from_bytes(take::<REQUEST_ID_LENGTH>(&mut rest)?);
                Self::Failure {
                    request_id,
                    code: LocalServiceErrorCode::from_wire_value(u16::from_be_bytes(take::<2>(
                        &mut rest,
                    )?))?,
                }
            }
            _ => return Err(LocalServiceTransportError::UnknownMessageKind),
        };
        finish(rest)?;
        Ok(response)
    }
}

/// Writes one request over an authenticated channel.
///
/// # Errors
///
/// Returns [`LocalServiceTransportError::FrameTooLarge`] when the encoding exceeds
/// [`MAX_RPC_FRAME_BYTES`] or [`LocalServiceTransportError::ChannelClosed`] when the
/// peer stops.
pub async fn write_request<S>(
    stream: &mut S,
    request: &LocalServiceRequest,
) -> Result<(), LocalServiceTransportError>
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(stream, &request.encode(), MAX_RPC_FRAME_BYTES)
        .await
        .map_err(LocalServiceTransportError::from)
}

/// Reads one request from an authenticated channel.
///
/// # Errors
///
/// Returns a frame, bound, identifier, or channel failure. The declared frame length
/// is refused before any buffer is reserved.
pub async fn read_request<S>(
    stream: &mut S,
) -> Result<LocalServiceRequest, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
{
    let payload = KonclaveLocalFraming::read_frame(stream, MAX_RPC_FRAME_BYTES).await?;
    LocalServiceRequest::decode(&payload)
}

/// Writes one response over an authenticated channel.
///
/// # Errors
///
/// Returns a bound, frame, or channel failure.
pub async fn write_response<S>(
    stream: &mut S,
    response: &LocalServiceResponse,
) -> Result<(), LocalServiceTransportError>
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(stream, &response.encode()?, MAX_RPC_FRAME_BYTES)
        .await
        .map_err(LocalServiceTransportError::from)
}

/// Reads one response from an authenticated channel.
///
/// # Errors
///
/// Returns a frame, bound, code, or channel failure.
pub async fn read_response<S>(
    stream: &mut S,
) -> Result<LocalServiceResponse, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
{
    let payload = KonclaveLocalFraming::read_frame(stream, MAX_RPC_FRAME_BYTES).await?;
    LocalServiceResponse::decode(&payload)
}

fn payload_length(length: usize) -> [u8; 4] {
    debug_assert!(length <= MAX_RPC_PAYLOAD_BYTES);
    u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes()
}

fn split_kind(payload: &[u8]) -> Result<(u8, &[u8]), LocalServiceTransportError> {
    let (kind, rest) = payload
        .split_first()
        .ok_or(LocalServiceTransportError::MalformedFrame)?;
    Ok((*kind, rest))
}

fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], LocalServiceTransportError> {
    if rest.len() < N {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(N);
    let mut value = [0_u8; N];
    value.copy_from_slice(head);
    *rest = tail;
    Ok(value)
}

fn take_operation(rest: &mut &[u8]) -> Result<OperationName, LocalServiceTransportError> {
    let length = usize::from(take::<1>(rest)?[0]);
    if length == 0 || length > MAX_OPERATION_LENGTH {
        return Err(LocalServiceTransportError::InvalidIdentifier { field: "operation" });
    }
    if rest.len() < length {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(length);
    *rest = tail;
    let value = core::str::from_utf8(head)
        .map_err(|_| LocalServiceTransportError::InvalidIdentifier { field: "operation" })?;
    OperationName::parse(value)
}

fn take_payload(rest: &mut &[u8]) -> Result<Vec<u8>, LocalServiceTransportError> {
    let declared = u32::from_be_bytes(take::<4>(rest)?) as usize;
    if declared > MAX_RPC_PAYLOAD_BYTES {
        return Err(LocalServiceTransportError::RequestOutOfBounds);
    }
    if rest.len() < declared {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(declared);
    *rest = tail;
    Ok(head.to_vec())
}

fn finish(rest: &[u8]) -> Result<(), LocalServiceTransportError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(LocalServiceTransportError::MalformedFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse, MAX_OPERATION_LENGTH,
        MAX_RPC_FRAME_BYTES, MAX_RPC_PAYLOAD_BYTES, OperationName, REQUEST_ID_LENGTH, RequestId,
    };
    use crate::error::LocalServiceTransportError;

    fn request_id() -> RequestId {
        RequestId::from_bytes([7_u8; REQUEST_ID_LENGTH])
    }

    fn request_with(payload: Vec<u8>) -> LocalServiceRequest {
        LocalServiceRequest::new(
            request_id(),
            OperationName::parse("delivery.wait").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn a_request_round_trips_with_an_empty_and_a_full_payload() {
        for payload in [Vec::new(), vec![9_u8; 4_096]] {
            let request = request_with(payload);
            let encoded = request.encode();
            assert!(encoded.len() <= MAX_RPC_FRAME_BYTES);
            assert_eq!(LocalServiceRequest::decode(&encoded).unwrap(), request);
        }
    }

    #[test]
    fn a_maximal_request_still_fits_the_frame_bound() {
        let request = LocalServiceRequest::new(
            request_id(),
            OperationName::parse(&"a".repeat(MAX_OPERATION_LENGTH)).unwrap(),
            vec![1_u8; MAX_RPC_PAYLOAD_BYTES],
        )
        .unwrap();
        assert_eq!(request.encode().len(), MAX_RPC_FRAME_BYTES);
    }

    #[test]
    fn a_payload_above_the_bound_is_refused_at_construction() {
        assert_eq!(
            LocalServiceRequest::new(
                request_id(),
                OperationName::parse("delivery.wait").unwrap(),
                vec![0_u8; MAX_RPC_PAYLOAD_BYTES + 1],
            )
            .unwrap_err(),
            LocalServiceTransportError::RequestOutOfBounds
        );
        assert_eq!(
            LocalServiceResponse::success(request_id(), vec![0_u8; MAX_RPC_PAYLOAD_BYTES + 1])
                .unwrap_err(),
            LocalServiceTransportError::RequestOutOfBounds
        );
    }

    #[test]
    fn a_declared_payload_length_above_the_bound_is_refused_before_allocation() {
        let mut encoded = request_with(vec![1_u8; 8]).encode();
        let declared = u32::try_from(MAX_RPC_PAYLOAD_BYTES + 1)
            .unwrap()
            .to_be_bytes();
        let offset = encoded.len() - 8 - 4;
        encoded[offset..offset + 4].copy_from_slice(&declared);
        assert_eq!(
            LocalServiceRequest::decode(&encoded).unwrap_err(),
            LocalServiceTransportError::RequestOutOfBounds
        );
    }

    #[test]
    fn a_declared_payload_length_beyond_the_frame_is_refused() {
        let mut encoded = request_with(vec![1_u8; 8]).encode();
        let offset = encoded.len() - 8 - 4;
        encoded[offset..offset + 4].copy_from_slice(&4_096_u32.to_be_bytes());
        assert_eq!(
            LocalServiceRequest::decode(&encoded).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );
    }

    #[test]
    fn trailing_bytes_are_rejected_on_every_frame() {
        let mut request = request_with(vec![1_u8; 4]).encode();
        request.push(0);
        assert_eq!(
            LocalServiceRequest::decode(&request).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );

        for response in [
            LocalServiceResponse::success(request_id(), vec![2_u8; 4]).unwrap(),
            LocalServiceResponse::failure(request_id(), LocalServiceErrorCode::Busy),
        ] {
            let mut encoded = response.encode().unwrap();
            encoded.push(0);
            assert_eq!(
                LocalServiceResponse::decode(&encoded).unwrap_err(),
                LocalServiceTransportError::MalformedFrame
            );
        }
    }

    #[test]
    fn a_truncated_frame_is_rejected_at_every_field() {
        let request = request_with(vec![1_u8; 4]).encode();
        for length in 1..request.len() {
            assert!(
                LocalServiceRequest::decode(&request[..length]).is_err(),
                "prefix of {length} bytes must not decode"
            );
        }
        let response = LocalServiceResponse::success(request_id(), vec![2_u8; 4])
            .unwrap()
            .encode()
            .unwrap();
        for length in 1..response.len() {
            assert!(
                LocalServiceResponse::decode(&response[..length]).is_err(),
                "prefix of {length} bytes must not decode"
            );
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected_on_both_directions() {
        assert_eq!(
            LocalServiceRequest::decode(&[99_u8, 0, 0]).unwrap_err(),
            LocalServiceTransportError::UnknownMessageKind
        );
        assert_eq!(
            LocalServiceResponse::decode(&[99_u8, 0, 0]).unwrap_err(),
            LocalServiceTransportError::UnknownMessageKind
        );
        let request = request_with(Vec::new()).encode();
        assert_eq!(
            LocalServiceResponse::decode(&request).unwrap_err(),
            LocalServiceTransportError::UnknownMessageKind
        );
        assert_eq!(
            LocalServiceRequest::decode(&[]).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );
    }

    #[test]
    fn an_invalid_operation_name_is_rejected() {
        for value in [
            String::new(),
            "a".repeat(MAX_OPERATION_LENGTH + 1),
            ".leading".to_string(),
            "has space".to_string(),
            "path/traversal".to_string(),
            "unicodé".to_string(),
        ] {
            assert_eq!(
                OperationName::parse(&value).unwrap_err(),
                LocalServiceTransportError::InvalidIdentifier { field: "operation" },
                "value must not parse: {value:?}"
            );
        }
        assert_eq!(
            OperationName::parse("delivery.wait-1_x").unwrap().as_str(),
            "delivery.wait-1_x"
        );
    }

    #[test]
    fn an_operation_name_on_the_wire_is_validated_on_decode() {
        let mut encoded = request_with(Vec::new()).encode();
        let operation_offset = 1 + REQUEST_ID_LENGTH + 1;
        encoded[operation_offset] = b'/';
        assert_eq!(
            LocalServiceRequest::decode(&encoded).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "operation" }
        );

        let mut empty = request_with(Vec::new()).encode();
        empty[1 + REQUEST_ID_LENGTH] = 0;
        assert_eq!(
            LocalServiceRequest::decode(&empty).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "operation" }
        );

        let mut overrun = request_with(Vec::new()).encode();
        overrun[1 + REQUEST_ID_LENGTH] = u8::try_from(MAX_OPERATION_LENGTH).unwrap();
        assert_eq!(
            LocalServiceRequest::decode(&overrun).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );
    }

    #[test]
    fn every_error_code_round_trips_and_unknown_values_fail_closed() {
        for code in [
            LocalServiceErrorCode::InvalidRequest,
            LocalServiceErrorCode::UnknownOperation,
            LocalServiceErrorCode::NotAuthorized,
            LocalServiceErrorCode::ProfileUnavailable,
            LocalServiceErrorCode::Busy,
            LocalServiceErrorCode::DeadlineExceeded,
            LocalServiceErrorCode::PayloadTooLarge,
            LocalServiceErrorCode::Conflict,
            LocalServiceErrorCode::Internal,
        ] {
            let response = LocalServiceResponse::failure(request_id(), code);
            let encoded = response.encode().unwrap();
            assert_eq!(LocalServiceResponse::decode(&encoded).unwrap(), response);
            assert_eq!(
                LocalServiceErrorCode::from_wire_value(code.wire_value()).unwrap(),
                code
            );
        }
        for value in [0_u16, 10, u16::MAX] {
            assert_eq!(
                LocalServiceErrorCode::from_wire_value(value).unwrap_err(),
                LocalServiceTransportError::UnknownErrorCode
            );
        }
    }

    #[test]
    fn an_unknown_error_code_on_the_wire_is_rejected() {
        let mut encoded = LocalServiceResponse::failure(request_id(), LocalServiceErrorCode::Busy)
            .encode()
            .unwrap();
        let offset = encoded.len() - 2;
        encoded[offset..].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            LocalServiceResponse::decode(&encoded).unwrap_err(),
            LocalServiceTransportError::UnknownErrorCode
        );
    }

    #[test]
    fn a_response_reports_the_request_it_answers() {
        assert_eq!(
            LocalServiceResponse::success(request_id(), Vec::new())
                .unwrap()
                .request_id(),
            request_id()
        );
        assert_eq!(
            LocalServiceResponse::failure(request_id(), LocalServiceErrorCode::Conflict)
                .request_id(),
            request_id()
        );
    }
}
