use KonclaveDomainCore::{
    AcknowledgeRequest, MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_PAGE_SIZE, RelayEnvelope, ReplayPage,
    ReplayRequest,
};
use KonclaveProtocolContracts::v1::{decode_replay_page, encode_relay_envelope};
use KonclaveRelayAuthentication::{RelayEnrollmentRequest, RelayEnrollmentResponse};
use async_trait::async_trait;

use crate::{RelayError, RelayPrincipalId};

/// Outcome of one accepted or idempotently retried submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitResult {
    cursor: u64,
    duplicate: bool,
}

impl SubmitResult {
    /// Creates a submission outcome.
    #[must_use]
    pub const fn new(cursor: u64, duplicate: bool) -> Self {
        Self { cursor, duplicate }
    }
}

/// Bounded replay response that retains exact nested envelope encodings.
pub struct EncodedReplayPage {
    bytes: Vec<u8>,
    next_cursor: u64,
    has_more: bool,
    envelope_count: usize,
}

impl EncodedReplayPage {
    /// Creates an encoded page after validating its semantic metadata.
    ///
    /// # Errors
    ///
    /// Returns a protocol or stored-data error when the bytes are malformed,
    /// oversized, or disagree with the supplied cursor, continuation, or count.
    pub fn new(
        bytes: Vec<u8>,
        after_cursor: u64,
        next_cursor: u64,
        has_more: bool,
        envelope_count: usize,
    ) -> Result<Self, RelayError> {
        if bytes.len() > MAX_REPLAY_PAGE_BYTES || envelope_count > MAX_REPLAY_PAGE_SIZE {
            return Err(RelayError::InvalidStoredData);
        }
        let decoded = decode_replay_page(&bytes)?;
        if decoded.next_cursor() != next_cursor
            || decoded.has_more() != has_more
            || decoded.envelopes().len() != envelope_count
            || (has_more && envelope_count == 0)
            || (envelope_count == 0 && next_cursor != after_cursor)
            || (envelope_count > 0 && next_cursor <= after_cursor)
        {
            return Err(RelayError::InvalidStoredData);
        }
        Ok(Self {
            bytes,
            next_cursor,
            has_more,
            envelope_count,
        })
    }

    /// Returns the exact encoded replay-page bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns and consumes the exact encoded replay-page bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the cursor for the next replay request.
    #[must_use]
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    /// Returns whether more durable envelopes are immediately available.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    /// Returns the number of envelopes in this page.
    #[must_use]
    pub const fn envelope_count(&self) -> usize {
        self.envelope_count
    }
}

impl SubmitResult {
    /// Returns the durable route cursor.
    #[must_use]
    pub const fn cursor(self) -> u64 {
        self.cursor
    }

    /// Returns whether an identical prior submission produced this result.
    #[must_use]
    pub const fn duplicate(self) -> bool {
        self.duplicate
    }
}

/// Durable relay operations whose implementations preserve route atomicity.
#[async_trait]
pub trait RelayRepository: Send + Sync {
    /// Verifies that the exact encoded bytes represent `envelope`, then atomically
    /// checks idempotency and expected epoch, assigns one cursor, and stores those
    /// bytes without re-encoding.
    async fn submit_encoded(
        &self,
        envelope: &RelayEnvelope,
        encoded_envelope: &[u8],
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError>;

    /// Canonically encodes and submits one validated envelope.
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError> {
        let encoded_envelope = encode_relay_envelope(envelope)?;
        self.submit_encoded(envelope, &encoded_envelope, now_unix_seconds)
            .await
    }

    /// Returns one bounded page after the requested cursor.
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, RelayError>;

    /// Returns one bounded page that embeds each original envelope encoding without
    /// decoding and re-encoding it.
    async fn replay_encoded(&self, request: ReplayRequest)
    -> Result<EncodedReplayPage, RelayError>;

    /// Monotonically acknowledges one route cursor for one authenticated principal.
    async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError>;
}

/// Durable registry for self-hosted dynamic relay principals.
#[async_trait]
pub trait RelayPrincipalRegistry: Send + Sync {
    /// Atomically registers one principal or returns its exact idempotent outcome.
    ///
    /// # Errors
    ///
    /// Returns a version, conflict, revocation, capacity, malformed-data, or storage
    /// error.
    async fn register_principal(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, RelayError>;

    /// Returns whether one dynamic principal is currently active.
    ///
    /// # Errors
    ///
    /// Returns a malformed-data or storage error.
    async fn is_principal_active(&self, principal: RelayPrincipalId) -> Result<bool, RelayError>;

    /// Idempotently revokes one registered principal.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    async fn revoke_principal(&self, principal: RelayPrincipalId) -> Result<bool, RelayError>;
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::ReplayPage;
    use KonclaveProtocolContracts::v1::encode_replay_page;

    use super::EncodedReplayPage;

    #[test]
    fn encoded_replay_page_metadata_must_match_its_bytes() {
        let bytes = encode_replay_page(&ReplayPage::new(Vec::new(), 0, false).unwrap()).unwrap();
        assert!(EncodedReplayPage::new(bytes.clone(), 0, 0, false, 0).is_ok());
        assert!(EncodedReplayPage::new(bytes.clone(), 0, 1, false, 0).is_err());
        assert!(EncodedReplayPage::new(bytes, 0, 0, true, 0).is_err());
    }
}
