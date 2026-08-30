use std::time::Duration;

use KonclaveProtectedHttp::protected_http_client_builder;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use reqwest::Response;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use zeroize::Zeroizing;

use crate::error::stable_relay_code;
use crate::{KonclaveClientError, RelayEndpoint};

const PROTOBUF_MEDIA_TYPE: &str = "application/protobuf";
const ERROR_CODE_HEADER: &str = "x-konclave-error-code";
pub(crate) const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct ProtectedHttpClient {
    client: reqwest::Client,
    endpoint: RelayEndpoint,
}

pub(crate) struct ProtectedHttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl ProtectedHttpClient {
    pub(crate) fn new(endpoint: RelayEndpoint) -> Result<Self, KonclaveClientError> {
        let client = protected_http_client_builder()
            .map_err(|_| KonclaveClientError::TransportUnavailable)?
            .connect_timeout(DEFAULT_OPERATION_TIMEOUT)
            .timeout(DEFAULT_OPERATION_TIMEOUT)
            .user_agent(concat!("KonclaveClientLibrary/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| KonclaveClientError::TransportUnavailable)?;
        Ok(Self { client, endpoint })
    }

    pub(crate) async fn post(
        &self,
        relative: &str,
        authorization: HeaderValue,
        body: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<ProtectedHttpResponse, KonclaveClientError> {
        let url = self.endpoint.http_url(relative)?;
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, PROTOBUF_MEDIA_TYPE)
            .body(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        complete_response(response, maximum_response_bytes, true).await
    }

    pub(crate) async fn get(
        &self,
        relative: &str,
        maximum_response_bytes: usize,
    ) -> Result<ProtectedHttpResponse, KonclaveClientError> {
        let url = self.endpoint.http_url(relative)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        complete_response(response, maximum_response_bytes, false).await
    }
}

async fn complete_response(
    response: Response,
    maximum_response_bytes: usize,
    require_protobuf: bool,
) -> Result<ProtectedHttpResponse, KonclaveClientError> {
    if !response.status().is_success() {
        return Err(relay_rejection(&response));
    }
    if require_protobuf
        && response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(PROTOBUF_MEDIA_TYPE)
    {
        return Err(KonclaveClientError::InvalidResponse);
    }
    let status = response.status().as_u16();
    let body = read_bounded(response, maximum_response_bytes).await?;
    Ok(ProtectedHttpResponse { status, body })
}

pub(crate) fn decode_canonical_credential(value: &str) -> Option<[u8; 32]> {
    if value.len() != 43 {
        return None;
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).ok()?);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_str() != value {
        return None;
    }
    decoded.as_slice().try_into().ok()
}

pub(crate) fn authorization_header(bytes: &[u8; 32]) -> Option<HeaderValue> {
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
    let mut value = Zeroizing::new(Vec::with_capacity(7 + encoded.len()));
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(encoded.as_bytes());
    let mut header = HeaderValue::from_bytes(&value).ok()?;
    header.set_sensitive(true);
    Some(header)
}

async fn read_bounded(response: Response, maximum: usize) -> Result<Vec<u8>, KonclaveClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(KonclaveClientError::ResponseTooLarge { maximum });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(maximum),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| KonclaveClientError::TransportUnavailable)?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(KonclaveClientError::ResponseTooLarge { maximum })?;
        if next_length > maximum {
            return Err(KonclaveClientError::ResponseTooLarge { maximum });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn relay_rejection(response: &Response) -> KonclaveClientError {
    let relay_code = response
        .headers()
        .get(ERROR_CODE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(stable_relay_code)
        .unwrap_or_else(|| "relay_rejected".to_string());
    KonclaveClientError::RelayRejected {
        status: response.status().as_u16(),
        relay_code,
    }
}

fn map_reqwest_error(error: reqwest::Error) -> KonclaveClientError {
    if error.is_timeout() {
        KonclaveClientError::Timeout
    } else {
        KonclaveClientError::TransportUnavailable
    }
}
