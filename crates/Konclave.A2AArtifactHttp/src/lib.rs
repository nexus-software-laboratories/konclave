#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use KonclaveA2AArtifactStorage::{
    A2A_ARTIFACT_OBJECT_TAG_BYTES, A2AArtifactObjectId, A2AArtifactObjectReader,
    A2AArtifactObjectStore, A2AArtifactStorageError, MAX_A2A_ARTIFACT_OBJECT_BYTES,
    MAX_A2A_ARTIFACT_PLAINTEXT_BYTES, open_artifact_ciphertext,
};
use KonclaveA2AContracts::{
    InitialA2AArtifactReferenceDescriptor, InitialA2AEncryptedArtifactReference,
    parse_initial_encrypted_artifact_reference,
};
use KonclaveProtectedHttp::protected_http_client_builder;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RANGE,
    RETRY_AFTER,
};
use axum::http::{Response, StatusCode};
use axum::routing::get;
use futures_util::stream;
use futures_util::{Stream, StreamExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use zeroize::Zeroizing;

/// Ciphertext media type emitted and requested by the reference implementation.
pub const A2A_ARTIFACT_CIPHERTEXT_MEDIA_TYPE: &str = "application/octet-stream";
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_CACHE_CONTROL: &str = "private, max-age=31536000, immutable";
const RESPONSE_CHANNEL_CAPACITY: usize = 1;

/// Stable failures from encrypted artifact HTTP serving and explicit retrieval.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum A2AArtifactHttpError {
    /// A timeout, bound, descriptor, reference, or client configuration is invalid.
    #[error("A2A artifact HTTP configuration is invalid")]
    InvalidConfiguration,
    /// The outbound request could not complete.
    #[error("A2A artifact transport is unavailable")]
    TransportUnavailable,
    /// The object host returned a non-success status.
    #[error("A2A artifact object host returned HTTP {status}")]
    RemoteFailure { status: u16 },
    /// The object host response violated the bounded ciphertext contract.
    #[error("A2A artifact object response is invalid")]
    ResponseContract,
    /// Ciphertext content addressing or authenticated decryption failed.
    #[error("A2A artifact integrity validation failed")]
    ArtifactIntegrity,
}

/// Finite outbound behavior for explicit artifact retrieval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AArtifactHttpClientConfig {
    connect_timeout: Duration,
    request_timeout: Duration,
    maximum_plaintext_bytes: usize,
}

impl A2AArtifactHttpClientConfig {
    /// Creates one finite retrieval configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for zero, reversed, or oversized values.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        maximum_plaintext_bytes: usize,
    ) -> Result<Self, A2AArtifactHttpError> {
        if connect_timeout.is_zero()
            || connect_timeout > MAX_CONNECT_TIMEOUT
            || request_timeout < connect_timeout
            || request_timeout > MAX_REQUEST_TIMEOUT
            || !(1..=MAX_A2A_ARTIFACT_PLAINTEXT_BYTES).contains(&maximum_plaintext_bytes)
        {
            return Err(A2AArtifactHttpError::InvalidConfiguration);
        }
        Ok(Self {
            connect_timeout,
            request_timeout,
            maximum_plaintext_bytes,
        })
    }

    fn maximum_ciphertext_bytes(self) -> usize {
        self.maximum_plaintext_bytes + A2A_ARTIFACT_OBJECT_TAG_BYTES
    }
}

impl Default for A2AArtifactHttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(5 * 60),
            maximum_plaintext_bytes: MAX_A2A_ARTIFACT_PLAINTEXT_BYTES,
        }
    }
}

/// Finite body-lifetime capacity for the self-hosted ciphertext router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AArtifactHttpServerConfig {
    maximum_object_bytes: usize,
    maximum_in_flight_bytes: usize,
}

impl A2AArtifactHttpServerConfig {
    /// Creates one bounded server configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when one object or the aggregate byte budget is
    /// outside the supported bounds.
    pub fn new(
        maximum_object_bytes: usize,
        maximum_in_flight_bytes: usize,
    ) -> Result<Self, A2AArtifactHttpError> {
        if !(A2A_ARTIFACT_OBJECT_TAG_BYTES..=MAX_A2A_ARTIFACT_OBJECT_BYTES)
            .contains(&maximum_object_bytes)
            || maximum_in_flight_bytes < maximum_object_bytes
            || maximum_in_flight_bytes > u32::MAX as usize
        {
            return Err(A2AArtifactHttpError::InvalidConfiguration);
        }
        Ok(Self {
            maximum_object_bytes,
            maximum_in_flight_bytes,
        })
    }
}

impl Default for A2AArtifactHttpServerConfig {
    fn default() -> Self {
        Self {
            maximum_object_bytes: MAX_A2A_ARTIFACT_OBJECT_BYTES,
            maximum_in_flight_bytes: MAX_A2A_ARTIFACT_OBJECT_BYTES * 4,
        }
    }
}

/// Explicit encrypted-artifact retrieval boundary.
#[async_trait]
pub trait A2AArtifactRetriever: Send + Sync {
    /// Retrieves, verifies, and decrypts one exact encrypted reference.
    ///
    /// # Errors
    ///
    /// Returns configuration, transport, response-contract, digest, or authenticated
    /// decryption failures.
    async fn retrieve(
        &self,
        descriptor: &InitialA2AArtifactReferenceDescriptor,
        reference_url: &str,
    ) -> Result<Zeroizing<Vec<u8>>, A2AArtifactHttpError>;
}

/// Outbound-only HTTPS client for explicit encrypted artifact retrieval.
#[derive(Clone)]
pub struct A2AArtifactHttpClient {
    client: reqwest::Client,
    config: A2AArtifactHttpClientConfig,
}

impl A2AArtifactHttpClient {
    /// Creates a client with redirects and ambient proxy discovery disabled.
    ///
    /// The client owns no A2A or object-host credential and never adds an
    /// `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the protected HTTP client cannot be built.
    pub fn new(config: A2AArtifactHttpClientConfig) -> Result<Self, A2AArtifactHttpError> {
        let client = protected_http_client_builder()
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)?;
        Ok(Self { client, config })
    }

    fn prepare_reference(
        &self,
        descriptor: &InitialA2AArtifactReferenceDescriptor,
        reference_url: &str,
    ) -> Result<(InitialA2AEncryptedArtifactReference, usize), A2AArtifactHttpError> {
        let reference = parse_initial_encrypted_artifact_reference(reference_url)
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)?;
        let plaintext_bytes = usize::try_from(reference.plaintext_bytes())
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)?;
        let descriptor_plaintext_bytes = usize::try_from(descriptor.plaintext_bytes())
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)?;
        if plaintext_bytes != descriptor_plaintext_bytes
            || plaintext_bytes > self.config.maximum_plaintext_bytes
        {
            return Err(A2AArtifactHttpError::InvalidConfiguration);
        }
        let ciphertext_bytes = plaintext_bytes
            .checked_add(A2A_ARTIFACT_OBJECT_TAG_BYTES)
            .filter(|bytes| *bytes <= self.config.maximum_ciphertext_bytes())
            .ok_or(A2AArtifactHttpError::InvalidConfiguration)?;
        Ok((reference, ciphertext_bytes))
    }

    fn build_request(
        &self,
        reference: &InitialA2AEncryptedArtifactReference,
    ) -> Result<reqwest::Request, A2AArtifactHttpError> {
        self.client
            .get(reference.request_url())
            .header(ACCEPT, A2A_ARTIFACT_CIPHERTEXT_MEDIA_TYPE)
            .build()
            .map_err(|_| A2AArtifactHttpError::InvalidConfiguration)
    }
}

#[async_trait]
impl A2AArtifactRetriever for A2AArtifactHttpClient {
    async fn retrieve(
        &self,
        descriptor: &InitialA2AArtifactReferenceDescriptor,
        reference_url: &str,
    ) -> Result<Zeroizing<Vec<u8>>, A2AArtifactHttpError> {
        let (reference, expected_ciphertext_bytes) =
            self.prepare_reference(descriptor, reference_url)?;
        let request = self.build_request(&reference)?;
        let request_url = request.url().as_str().to_owned();
        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| A2AArtifactHttpError::TransportUnavailable)?;
        if response.status() != StatusCode::OK {
            return Err(A2AArtifactHttpError::RemoteFailure {
                status: response.status().as_u16(),
            });
        }
        if response.url().as_str() != request_url {
            return Err(A2AArtifactHttpError::ResponseContract);
        }
        if response
            .content_length()
            .is_some_and(|length| length != expected_ciphertext_bytes as u64)
        {
            return Err(A2AArtifactHttpError::ResponseContract);
        }
        let chunks = response.bytes_stream().map(|chunk| {
            chunk
                .map(|bytes| bytes.to_vec())
                .map_err(|_| A2AArtifactHttpError::TransportUnavailable)
        });
        let ciphertext = collect_ciphertext(chunks, expected_ciphertext_bytes).await?;
        open_artifact_ciphertext(descriptor, &reference, ciphertext)
            .map_err(map_artifact_integrity_error)
    }
}

/// Immutable state for the self-hosted ciphertext HTTP router.
#[derive(Clone)]
pub struct A2AArtifactHttpState {
    store: Arc<dyn A2AArtifactObjectStore>,
    config: A2AArtifactHttpServerConfig,
    byte_budget: Arc<Semaphore>,
}

impl A2AArtifactHttpState {
    /// Creates router state for one object store and body-lifetime byte budget.
    #[must_use]
    pub fn new(
        store: Arc<dyn A2AArtifactObjectStore>,
        config: A2AArtifactHttpServerConfig,
    ) -> Self {
        Self {
            store,
            config,
            byte_budget: Arc::new(Semaphore::new(config.maximum_in_flight_bytes)),
        }
    }
}

/// Builds `GET /sha256/{digest}` for nesting beneath an operator-owned HTTPS prefix.
///
/// The router emits ciphertext only. Non-loopback listeners require trusted TLS
/// termination, and deployments may wrap the router with their own download
/// authorization and rate policy.
pub fn a2a_artifact_router(state: A2AArtifactHttpState) -> Router {
    Router::new()
        .route(
            "/sha256/{object_id}",
            get(get_artifact_object).head(method_not_allowed),
        )
        .with_state(state)
}

async fn get_artifact_object(
    State(state): State<A2AArtifactHttpState>,
    Path(object_id): Path<String>,
    headers: HeaderMap,
) -> Response<Body> {
    if headers.contains_key(RANGE) {
        return empty_response(StatusCode::RANGE_NOT_SATISFIABLE);
    }
    let object_id = match A2AArtifactObjectId::parse(&object_id) {
        Ok(object_id) => object_id,
        Err(_) => return empty_response(StatusCode::NOT_FOUND),
    };
    let reservation = match u32::try_from(state.config.maximum_object_bytes) {
        Ok(reservation) => reservation,
        Err(_) => return empty_response(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut permit = match Arc::clone(&state.byte_budget).try_acquire_many_owned(reservation) {
        Ok(permit) => permit,
        Err(_) => return capacity_unavailable_response(),
    };
    let store = Arc::clone(&state.store);
    let maximum = state.config.maximum_object_bytes;
    let object =
        match tokio::task::spawn_blocking(move || store.open_object(object_id, maximum)).await {
            Ok(Ok(object)) => object,
            Ok(Err(A2AArtifactStorageError::ObjectNotFound)) => {
                return empty_response(StatusCode::NOT_FOUND);
            }
            Ok(Err(_)) | Err(_) => return empty_response(StatusCode::SERVICE_UNAVAILABLE),
        };
    let excess = maximum - object.length();
    if excess > 0 {
        let Some(excess_permit) = permit.split(excess) else {
            return empty_response(StatusCode::SERVICE_UNAVAILABLE);
        };
        drop(excess_permit);
    }
    let length = object.length();
    let body = stream_object(object, permit);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, A2A_ARTIFACT_CIPHERTEXT_MEDIA_TYPE)
        .header(CONTENT_LENGTH, length.to_string())
        .header(CACHE_CONTROL, DEFAULT_CACHE_CONTROL)
        .header(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        )
        .header(
            HeaderName::from_static("accept-ranges"),
            HeaderValue::from_static("none"),
        )
        .body(body)
        .unwrap_or_else(|_| empty_response(StatusCode::SERVICE_UNAVAILABLE))
}

async fn method_not_allowed() -> Response<Body> {
    empty_response(StatusCode::METHOD_NOT_ALLOWED)
}

fn stream_object(mut object: A2AArtifactObjectReader, permit: OwnedSemaphorePermit) -> Body {
    let (sender, receiver) = mpsc::channel::<Result<Vec<u8>, io::Error>>(RESPONSE_CHANNEL_CAPACITY);
    let lease = Arc::new(ResponseByteLease { _permit: permit });
    let producer_lease = Arc::clone(&lease);
    let _producer = tokio::task::spawn_blocking(move || {
        let _lease = producer_lease;
        loop {
            match object.next_chunk() {
                Ok(Some(chunk)) => {
                    if sender.blocking_send(Ok(chunk)).is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(_) => {
                    let _ = sender
                        .blocking_send(Err(io::Error::other("A2A artifact object stream failed")));
                    return;
                }
            }
        }
    });
    let stream = stream::unfold((receiver, lease), |(mut receiver, lease)| async move {
        receiver.recv().await.map(|item| (item, (receiver, lease)))
    });
    Body::from_stream(stream)
}

struct ResponseByteLease {
    _permit: OwnedSemaphorePermit,
}

fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn capacity_unavailable_response() -> Response<Body> {
    let mut response = empty_response(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

async fn collect_ciphertext<S>(
    chunks: S,
    expected_bytes: usize,
) -> Result<Vec<u8>, A2AArtifactHttpError>
where
    S: Stream<Item = Result<Vec<u8>, A2AArtifactHttpError>>,
{
    let mut ciphertext = Vec::with_capacity(expected_bytes.min(64 * 1_024));
    futures_util::pin_mut!(chunks);
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        if ciphertext
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > expected_bytes)
        {
            return Err(A2AArtifactHttpError::ResponseContract);
        }
        ciphertext.extend_from_slice(&chunk);
    }
    if ciphertext.len() != expected_bytes {
        return Err(A2AArtifactHttpError::ResponseContract);
    }
    Ok(ciphertext)
}

fn map_artifact_integrity_error(error: A2AArtifactStorageError) -> A2AArtifactHttpError {
    match error {
        A2AArtifactStorageError::InvalidConfiguration => A2AArtifactHttpError::InvalidConfiguration,
        _ => A2AArtifactHttpError::ArtifactIntegrity,
    }
}

#[cfg(test)]
mod tests {
    use KonclaveA2AArtifactStorage::{
        A2AArtifactObjectId, FileA2AArtifactObjectStore, seal_and_store_artifact,
    };
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::http::header::AUTHORIZATION;
    use futures_util::stream;
    use tower::ServiceExt as _;

    use super::*;

    struct MemoryObjectStore {
        object_id: A2AArtifactObjectId,
        bytes: Vec<u8>,
    }

    impl A2AArtifactObjectStore for MemoryObjectStore {
        fn put(
            &self,
            _object_id: A2AArtifactObjectId,
            _ciphertext: &[u8],
        ) -> Result<(), A2AArtifactStorageError> {
            Err(A2AArtifactStorageError::StorageUnavailable)
        }

        fn get(
            &self,
            object_id: A2AArtifactObjectId,
            maximum_bytes: usize,
        ) -> Result<Vec<u8>, A2AArtifactStorageError> {
            if object_id != self.object_id {
                return Err(A2AArtifactStorageError::ObjectNotFound);
            }
            if self.bytes.len() > maximum_bytes {
                return Err(A2AArtifactStorageError::InvalidConfiguration);
            }
            Ok(self.bytes.clone())
        }
    }

    #[test]
    fn client_request_strips_fragment_and_carries_no_credential() {
        let root = tempfile::tempdir().unwrap();
        let store = FileA2AArtifactObjectStore::open(root.path().join("objects")).unwrap();
        let descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        let stored = seal_and_store_artifact(
            &store,
            "https://objects.example.com/a2a",
            &descriptor,
            b"secret",
        )
        .unwrap();
        let reference_url = match stored.part().content.as_ref().unwrap() {
            KonclaveA2AContracts::wire::part::Content::Url(url) => url,
            _ => panic!("stored artifact must be a URL Part"),
        };
        let client = A2AArtifactHttpClient::new(A2AArtifactHttpClientConfig::default()).unwrap();
        let (reference, expected_bytes) = client
            .prepare_reference(&descriptor, reference_url)
            .unwrap();
        let request = client.build_request(&reference).unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(request.url().fragment(), None);
        assert_eq!(
            request.url().as_str(),
            format!(
                "https://objects.example.com/a2a/sha256/{}",
                stored.object_id().to_hex()
            )
        );
        assert_eq!(expected_bytes, A2A_ARTIFACT_OBJECT_TAG_BYTES + 6);
        assert!(!request.headers().contains_key(AUTHORIZATION));

        let limited = A2AArtifactHttpClient::new(
            A2AArtifactHttpClientConfig::new(Duration::from_secs(1), Duration::from_secs(2), 5)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            limited.prepare_reference(&descriptor, reference_url).err(),
            Some(A2AArtifactHttpError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn bounded_collection_opens_only_exact_authenticated_ciphertext() {
        let root = tempfile::tempdir().unwrap();
        let store = FileA2AArtifactObjectStore::open(root.path().join("objects")).unwrap();
        let descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        let stored = seal_and_store_artifact(
            &store,
            "https://objects.example.com/a2a",
            &descriptor,
            b"secret",
        )
        .unwrap();
        let reference_url = match stored.part().content.as_ref().unwrap() {
            KonclaveA2AContracts::wire::part::Content::Url(url) => url,
            _ => panic!("stored artifact must be a URL Part"),
        };
        let reference = parse_initial_encrypted_artifact_reference(reference_url).unwrap();
        let ciphertext = store
            .get(stored.object_id(), A2A_ARTIFACT_OBJECT_TAG_BYTES + 6)
            .unwrap();
        let split = ciphertext.len() / 2;
        let collected = collect_ciphertext(
            stream::iter([
                Ok(ciphertext[..split].to_vec()),
                Ok(ciphertext[split..].to_vec()),
            ]),
            ciphertext.len(),
        )
        .await
        .unwrap();
        assert_eq!(
            open_artifact_ciphertext(&descriptor, &reference, collected)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert_eq!(
            collect_ciphertext(
                stream::iter([Ok::<_, A2AArtifactHttpError>(ciphertext.clone())]),
                ciphertext.len() - 1,
            )
            .await
            .err(),
            Some(A2AArtifactHttpError::ResponseContract)
        );
        assert_eq!(
            collect_ciphertext(
                stream::iter([Ok::<_, A2AArtifactHttpError>(
                    ciphertext[..ciphertext.len() - 1].to_vec(),
                )]),
                ciphertext.len(),
            )
            .await
            .err(),
            Some(A2AArtifactHttpError::ResponseContract)
        );
    }

    #[tokio::test]
    async fn router_holds_byte_capacity_for_the_complete_body_lifetime() {
        let bytes = b"0123456789abcdef".to_vec();
        let object_id = A2AArtifactObjectId::from_ciphertext(&bytes);
        let store = Arc::new(MemoryObjectStore {
            object_id,
            bytes: bytes.clone(),
        });
        let config = A2AArtifactHttpServerConfig::new(bytes.len(), bytes.len()).unwrap();
        let state = A2AArtifactHttpState::new(store, config);
        let byte_budget = Arc::clone(&state.byte_budget);
        let router = a2a_artifact_router(state);
        let uri = format!("/sha256/{}", object_id.to_hex());

        let first = router
            .clone()
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[CONTENT_LENGTH], bytes.len().to_string());

        let blocked = router
            .clone()
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(blocked.headers()[RETRY_AFTER], "1");

        assert_eq!(
            to_bytes(first.into_body(), bytes.len())
                .await
                .unwrap()
                .as_ref(),
            bytes
        );
        let resumed = router
            .clone()
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resumed.status(), StatusCode::OK);
        drop(resumed);
        let released = tokio::time::timeout(
            Duration::from_secs(1),
            byte_budget.acquire_many_owned(bytes.len() as u32),
        )
        .await
        .unwrap()
        .unwrap();
        drop(released);
        let after_disconnect = router
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(after_disconnect.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_rejects_ranges_missing_objects_and_corrupt_streams() {
        let bytes = b"0123456789abcdef".to_vec();
        let object_id = A2AArtifactObjectId::from_ciphertext(&bytes);
        let store = Arc::new(MemoryObjectStore {
            object_id,
            bytes: b"fedcba9876543210".to_vec(),
        });
        let config = A2AArtifactHttpServerConfig::new(bytes.len(), bytes.len()).unwrap();
        let router = a2a_artifact_router(A2AArtifactHttpState::new(store, config));
        let uri = format!("/sha256/{}", object_id.to_hex());

        let range = router
            .clone()
            .oneshot(
                Request::get(&uri)
                    .header(RANGE, "bytes=0-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(range.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        let head = router
            .clone()
            .oneshot(Request::head(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::METHOD_NOT_ALLOWED);

        let malformed = router
            .clone()
            .oneshot(
                Request::get("/sha256/not-a-digest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::NOT_FOUND);

        let missing = router
            .clone()
            .oneshot(
                Request::get(format!("/sha256/{}", "00".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let corrupt = router
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(corrupt.status(), StatusCode::OK);
        assert!(to_bytes(corrupt.into_body(), bytes.len()).await.is_err());
    }

    #[test]
    fn configurations_reject_unbounded_or_reversed_values() {
        assert_eq!(
            A2AArtifactHttpClientConfig::new(Duration::ZERO, Duration::from_secs(1), 1).err(),
            Some(A2AArtifactHttpError::InvalidConfiguration)
        );
        assert_eq!(
            A2AArtifactHttpClientConfig::new(Duration::from_secs(2), Duration::from_secs(1), 1,)
                .err(),
            Some(A2AArtifactHttpError::InvalidConfiguration)
        );
        assert_eq!(
            A2AArtifactHttpServerConfig::new(
                A2A_ARTIFACT_OBJECT_TAG_BYTES,
                A2A_ARTIFACT_OBJECT_TAG_BYTES - 1,
            )
            .err(),
            Some(A2AArtifactHttpError::InvalidConfiguration)
        );
    }
}
