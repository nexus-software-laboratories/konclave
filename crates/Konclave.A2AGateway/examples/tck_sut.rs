use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use KonclaveA2AContracts::{InitialA2AInterfaceEnvironment, decode_initial_artifact_json};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2ADomain::{
    A2AAgentId, A2AAgentRoute, A2AArtifactId, A2AContextId, A2AMessageId, A2ATaskState,
};
use KonclaveA2AGateway::{
    A2AGatewayClock, A2AGatewayClockError, A2AGatewayError, A2AGatewayWaitConfig, A2AHttpAccess,
    A2AHttpAction, A2AHttpAuthorizationDecision, A2AHttpConfig, A2AHttpPrincipalId, A2AHttpState,
    A2ATaskSubmission, A2ATaskSubmissionError, A2ATaskSubmitter, a2a_router, validate_a2a_binding,
};
use KonclaveA2ATaskStore::{
    A2ATaskArtifact, A2ATaskMessage, A2ATaskMessageRole, A2ATaskStore, A2ATaskTransition,
};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId};
use async_trait::async_trait;
use axum::http::request::Parts;
use serde_json::json;

const DEFAULT_ADDRESS: &str = "127.0.0.1:9999";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_owned())
        .parse::<SocketAddr>()?;
    validate_a2a_binding(address.ip(), false)?;
    let root = tempfile::tempdir()?;
    let store = Arc::new(A2ASqliteTaskStore::open(
        root.path().join("tasks.sqlite"),
        A2ASqliteTaskStoreConfig::default(),
    )?);
    let publication = serde_json::to_vec(&json!({
        "apiVersion": "konclave.dev/v1",
        "kind": "A2AAgentPublication",
        "metadata": {"name": "tck-agent"},
        "spec": {
            "publicWellKnown": true,
            "name": "Konclave TCK agent",
            "description": "Deterministic loopback conformance target.",
            "version": "1.0.0",
            "interfaces": [{"url": format!("http://{address}/")}],
            "skills": [{
                "id": "complete-task",
                "name": "Complete task",
                "description": "Completes one bounded text task.",
                "tags": ["text", "conformance"]
            }]
        }
    }))?;
    let clock = Arc::new(TckClock::new(100));
    let application = KonclaveA2AGateway::A2AGatewayApplication::new(
        A2AAgentRoute::new(
            A2AAgentId::parse("tck-agent")?,
            A2AContextId::parse("tck-context")?,
            None,
            ConversationId::from_bytes([4; ConversationId::LENGTH]),
            DeviceId::from_bytes([5; DeviceId::LENGTH]),
        ),
        compile_a2a_agent_publication_source(
            &publication,
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
        )?,
        store.clone(),
        Arc::new(CompletingSubmitter {
            store,
            clock: clock.clone(),
        }),
        clock,
        A2AGatewayWaitConfig::default(),
    )?;
    let state = A2AHttpState::new(
        application,
        Arc::new(AllowLoopbackAccess),
        A2AHttpConfig::default(),
    )?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Konclave A2A TCK SUT listening on http://{address}");
    axum::serve(listener, a2a_router(state)).await?;
    Ok(())
}

struct CompletingSubmitter {
    store: Arc<A2ASqliteTaskStore>,
    clock: Arc<TckClock>,
}

#[async_trait]
impl A2ATaskSubmitter for CompletingSubmitter {
    async fn submit(&self, submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError> {
        let key = submission.key().clone();
        let message_at = self.clock.next();
        self.store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    A2AMessageId::parse(format!(
                        "response-{}",
                        submission.source_message_id().as_str()
                    ))
                    .map_err(|_| A2ATaskSubmissionError)?,
                    A2ATaskMessageRole::Agent,
                    "completed",
                    message_at,
                )
                .map_err(|_| A2ATaskSubmissionError)?,
                message_at,
            )
            .map_err(|_| A2ATaskSubmissionError)?;
        if let Some(artifact) = tck_artifact(submission.source_message_id().as_str())? {
            let artifact_id = A2AArtifactId::parse(artifact.artifact_id().to_owned())
                .map_err(|_| A2ATaskSubmissionError)?;
            let artifact_at = self.clock.next();
            self.store
                .append_artifact(
                    A2ATaskArtifact::new(
                        key.clone(),
                        artifact_id,
                        artifact.into_canonical_json(),
                        true,
                        artifact_at,
                    )
                    .map_err(|_| A2ATaskSubmissionError)?,
                    artifact_at,
                )
                .map_err(|_| A2ATaskSubmissionError)?;
        }
        let completed_at = self.clock.next();
        self.store
            .transition_task(A2ATaskTransition::new(
                key,
                0,
                A2ATaskState::Completed,
                None,
                completed_at,
            ))
            .map_err(|_| A2ATaskSubmissionError)?;
        Ok(())
    }
}

fn tck_artifact(
    source_message_id: &str,
) -> Result<Option<KonclaveA2AContracts::InitialA2AArtifact>, A2ATaskSubmissionError> {
    let artifact = if source_message_id.starts_with("tck-artifact-text") {
        Some(json!({
            "artifactId": "artifact-text",
            "parts": [{"text": "Generated text content"}]
        }))
    } else if source_message_id.starts_with("tck-artifact-file-url") {
        Some(json!({
            "artifactId": "artifact-file-url",
            "parts": [{
                "url": format!(
                    "https://objects.example.com/a2a/sha256/{}#konclave-aes256gcm-v1.{}.{}.1",
                    "ab".repeat(32),
                    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                    "AgICAgICAgICAgIC"
                ),
                "filename": "output.txt",
                "mediaType": "text/plain"
            }]
        }))
    } else if source_message_id.starts_with("tck-artifact-file") {
        Some(json!({
            "artifactId": "artifact-file",
            "parts": [{
                "raw": "R2VuZXJhdGVkIGZpbGUgY29udGVudA==",
                "filename": "output.txt",
                "mediaType": "text/plain"
            }]
        }))
    } else if source_message_id.starts_with("tck-artifact-data") {
        Some(json!({
            "artifactId": "artifact-data",
            "parts": [{"data": {"key": "value", "count": 42}}]
        }))
    } else {
        None
    };
    artifact
        .map(|artifact| {
            serde_json::to_vec(&artifact)
                .map_err(|_| A2ATaskSubmissionError)
                .and_then(|bytes| {
                    decode_initial_artifact_json(&bytes).map_err(|_| A2ATaskSubmissionError)
                })
        })
        .transpose()
}

struct TckClock(AtomicU64);

impl TckClock {
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    fn next(&self) -> u64 {
        self.0.fetch_add(10, Ordering::SeqCst) + 10
    }
}

impl A2AGatewayClock for TckClock {
    fn now_unix_milliseconds(&self) -> Result<u64, A2AGatewayClockError> {
        Ok(self.next())
    }
}

struct AllowLoopbackAccess;

impl A2AHttpAccess for AllowLoopbackAccess {
    fn authentication_kind(&self) -> Option<KonclaveA2AContracts::InitialA2AAgentSecurityKind> {
        None
    }

    fn authenticate(&self, _request: &Parts) -> Result<A2AHttpPrincipalId, A2AGatewayError> {
        Ok(A2AHttpPrincipalId::from_bytes([1; 32]))
    }

    fn authorize(
        &self,
        _principal: A2AHttpPrincipalId,
        _action: A2AHttpAction,
    ) -> A2AHttpAuthorizationDecision {
        A2AHttpAuthorizationDecision::Allow
    }
}
