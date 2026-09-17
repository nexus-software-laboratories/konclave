use std::sync::Arc;
use std::time::Duration;

use KonclaveDomainCore::{
    AcknowledgeRequest, MAX_PAIRING_RENDEZVOUS_RECORD_BYTES, MAX_RELAY_CONTROL_MESSAGE_BYTES,
    MAX_RELAY_ENVELOPE_BYTES, MAX_REPLAY_PAGE_BYTES, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
    MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES, PairingRendezvousRecord, PairingRendezvousTakeRequest,
    RelayEnvelope, ReplayPage, ReplayRequest, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodeAttemptSnapshot, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_pairing_rendezvous_record, decode_replay_page,
    decode_short_code_attempt_snapshot, decode_short_code_capability_response,
    decode_stored_relay_envelope, encode_acknowledge_request, encode_pairing_rendezvous_record,
    encode_pairing_rendezvous_take_request, encode_relay_envelope, encode_replay_request,
    encode_short_code_attempt_claim_request, encode_short_code_attempt_message_request,
    encode_short_code_attempt_publish_request, encode_short_code_attempt_read_request,
};
use async_trait::async_trait;

use crate::protected_http::{DEFAULT_OPERATION_TIMEOUT, ProtectedHttpClient};
use crate::websocket::connect_watch;
use crate::{KonclaveClientError, RelayAccessCredential, RelayEndpoint, RelayWatchSession};

const DEFAULT_WATCH_READ_TIMEOUT: Duration = Duration::from_secs(75);
const STORED_ENVELOPE_MAX_BYTES: usize = MAX_RELAY_ENVELOPE_BYTES + 32;

/// Outbound relay operations shared by daemon and command adapters.
#[async_trait]
pub trait RelayTransport: Send + Sync {
    /// Submits one opaque envelope.
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError>;

    /// Reads one bounded replay page.
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError>;

    /// Advances and returns one principal's effective acknowledgment.
    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError>;

    /// Opens one authenticated WebSocket watch after the supplied durable cursor.
    async fn connect_watch(
        &self,
        request: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError>;
}

/// Result of one authenticated pairing rendezvous publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRendezvousPublishResult {
    /// A new encrypted record was committed.
    Published,
    /// The same encrypted record was already present for this principal.
    AlreadyPublished,
}

/// Outbound pairing rendezvous operations kept separate from routed relay envelopes.
#[async_trait]
pub trait PairingRendezvousTransport: Send + Sync {
    /// Publishes one bounded opaque record.
    async fn publish_pairing_rendezvous(
        &self,
        record: &PairingRendezvousRecord,
    ) -> Result<PairingRendezvousPublishResult, KonclaveClientError>;

    /// Atomically takes one bounded opaque record.
    async fn take_pairing_rendezvous(
        &self,
        request: PairingRendezvousTakeRequest,
    ) -> Result<PairingRendezvousRecord, KonclaveClientError>;
}

/// Result of publishing one authenticated short-code attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeAttemptPublishResult {
    /// A new attempt was committed.
    Published,
    /// The exact attempt was already present for this creator.
    AlreadyPublished,
}

/// Result of publishing one authenticated opaque short-code stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeAttemptMessageResult {
    /// A new stage was committed.
    Published,
    /// The exact stage was already present for its expected participant.
    AlreadyPublished,
}

/// Outbound short-code pairing relay operations kept separate from routed envelopes.
#[async_trait]
pub trait ShortCodePairingTransport: Send + Sync {
    /// Publishes one bounded attempt locator and identifier.
    async fn publish_short_code_attempt(
        &self,
        request: ShortCodeAttemptPublishRequest,
    ) -> Result<ShortCodeAttemptPublishResult, KonclaveClientError>;

    /// Atomically claims one locator with an opaque OPAQUE credential request.
    async fn claim_short_code_attempt(
        &self,
        request: &ShortCodeAttemptClaimRequest,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError>;

    /// Publishes one role- and order-checked opaque exchange stage.
    async fn publish_short_code_message(
        &self,
        request: &ShortCodeAttemptMessageRequest,
    ) -> Result<ShortCodeAttemptMessageResult, KonclaveClientError>;

    /// Reads one bounded attempt snapshot as its creator or claimant.
    async fn read_short_code_attempt(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError>;

    /// Cancels one attempt as its creator or claimant.
    async fn cancel_short_code_attempt(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<(), KonclaveClientError>;

    /// Atomically consumes the mutually confirmed encrypted capability as claimant.
    async fn take_short_code_capability(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<Vec<u8>, KonclaveClientError>;
}

/// Cloneable outbound HTTP/WebSocket relay client sharing one protected credential.
#[derive(Clone)]
pub struct RelayClient {
    http: ProtectedHttpClient,
    endpoint: RelayEndpoint,
    credential: Arc<RelayAccessCredential>,
    operation_timeout: Duration,
}

impl RelayClient {
    /// Creates a relay client with redirects disabled and bounded request deadlines.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the underlying HTTP client cannot initialize.
    pub fn new(
        endpoint: RelayEndpoint,
        credential: RelayAccessCredential,
    ) -> Result<Self, KonclaveClientError> {
        let http = ProtectedHttpClient::new(endpoint.clone())?;
        Ok(Self {
            http,
            endpoint,
            credential: Arc::new(credential),
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        })
    }

    async fn post(
        &self,
        relative: &str,
        body: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, KonclaveClientError> {
        let authorization = self.credential.authorization_header()?;
        Ok(self
            .http
            .post(relative, authorization, body, maximum_response_bytes)
            .await?
            .body)
    }
}

#[async_trait]
impl RelayTransport for RelayClient {
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
        let request = encode_relay_envelope(envelope)?;
        let response = self
            .post("v1/envelopes", request, STORED_ENVELOPE_MAX_BYTES)
            .await?;
        decode_stored_relay_envelope(&response).map_err(Into::into)
    }

    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
        let request = encode_replay_request(request)?;
        let response = self
            .post("v1/replay", request, MAX_REPLAY_PAGE_BYTES)
            .await?;
        decode_replay_page(&response).map_err(Into::into)
    }

    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError> {
        let request = encode_acknowledge_request(request)?;
        let response = self
            .post(
                "v1/acknowledgments",
                request,
                MAX_RELAY_CONTROL_MESSAGE_BYTES,
            )
            .await?;
        decode_acknowledge_request(&response).map_err(Into::into)
    }

    async fn connect_watch(
        &self,
        request: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError> {
        connect_watch(
            &self.endpoint,
            Arc::clone(&self.credential),
            request,
            self.operation_timeout,
            DEFAULT_WATCH_READ_TIMEOUT,
        )
        .await
    }
}

#[async_trait]
impl PairingRendezvousTransport for RelayClient {
    async fn publish_pairing_rendezvous(
        &self,
        record: &PairingRendezvousRecord,
    ) -> Result<PairingRendezvousPublishResult, KonclaveClientError> {
        let request = encode_pairing_rendezvous_record(record)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post_empty("v1/pairing-rendezvous", authorization, request)
            .await?;
        match response.status {
            201 => Ok(PairingRendezvousPublishResult::Published),
            200 => Ok(PairingRendezvousPublishResult::AlreadyPublished),
            _ => Err(KonclaveClientError::InvalidResponse),
        }
    }

    async fn take_pairing_rendezvous(
        &self,
        request: PairingRendezvousTakeRequest,
    ) -> Result<PairingRendezvousRecord, KonclaveClientError> {
        let request = encode_pairing_rendezvous_take_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(
                "v1/pairing-rendezvous/take",
                authorization,
                request,
                MAX_PAIRING_RENDEZVOUS_RECORD_BYTES,
            )
            .await?;
        if response.status != 200 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        decode_pairing_rendezvous_record(&response.body).map_err(Into::into)
    }
}

#[async_trait]
impl ShortCodePairingTransport for RelayClient {
    async fn publish_short_code_attempt(
        &self,
        request: ShortCodeAttemptPublishRequest,
    ) -> Result<ShortCodeAttemptPublishResult, KonclaveClientError> {
        let body = encode_short_code_attempt_publish_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post_empty("v1/short-code-attempts", authorization, body)
            .await?;
        match response.status {
            201 => Ok(ShortCodeAttemptPublishResult::Published),
            200 => Ok(ShortCodeAttemptPublishResult::AlreadyPublished),
            _ => Err(KonclaveClientError::InvalidResponse),
        }
    }

    async fn claim_short_code_attempt(
        &self,
        request: &ShortCodeAttemptClaimRequest,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
        let body = encode_short_code_attempt_claim_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(
                "v1/short-code-attempts/claim",
                authorization,
                body,
                MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES,
            )
            .await?;
        if response.status != 200 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        decode_short_code_attempt_snapshot(&response.body).map_err(Into::into)
    }

    async fn publish_short_code_message(
        &self,
        request: &ShortCodeAttemptMessageRequest,
    ) -> Result<ShortCodeAttemptMessageResult, KonclaveClientError> {
        let body = encode_short_code_attempt_message_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post_empty("v1/short-code-attempts/messages", authorization, body)
            .await?;
        match response.status {
            201 => Ok(ShortCodeAttemptMessageResult::Published),
            200 => Ok(ShortCodeAttemptMessageResult::AlreadyPublished),
            _ => Err(KonclaveClientError::InvalidResponse),
        }
    }

    async fn read_short_code_attempt(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
        let body = encode_short_code_attempt_read_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(
                "v1/short-code-attempts/read",
                authorization,
                body,
                MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES,
            )
            .await?;
        if response.status != 200 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        decode_short_code_attempt_snapshot(&response.body).map_err(Into::into)
    }

    async fn cancel_short_code_attempt(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<(), KonclaveClientError> {
        let body = encode_short_code_attempt_read_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post_empty("v1/short-code-attempts/cancel", authorization, body)
            .await?;
        if response.status == 200 {
            Ok(())
        } else {
            Err(KonclaveClientError::InvalidResponse)
        }
    }

    async fn take_short_code_capability(
        &self,
        request: ShortCodeAttemptReadRequest,
    ) -> Result<Vec<u8>, KonclaveClientError> {
        let body = encode_short_code_attempt_read_request(request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(
                "v1/short-code-attempts/capability/take",
                authorization,
                body,
                MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
            )
            .await?;
        if response.status != 200 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        let (version, attempt_id, payload) = decode_short_code_capability_response(&response.body)?;
        if version != request.version() || attempt_id != request.attempt_id() {
            return Err(KonclaveClientError::InvalidResponse);
        }
        Ok(payload)
    }
}
