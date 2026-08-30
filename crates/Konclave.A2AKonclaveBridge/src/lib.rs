#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! A2A task submission and exact-response projection over Konclave's authenticated
//! local service.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use KonclaveA2AContracts::MAX_A2A_TEXT_BYTES;
use KonclaveA2ADomain::{A2AMessageId, A2ATaskState};
use KonclaveA2AGateway::{
    A2AGatewayClock, A2ATaskSubmission, A2ATaskSubmissionError, A2ATaskSubmitter,
};
use KonclaveA2ATaskStore::{
    A2ATaskKey, A2ATaskMessage, A2ATaskMessageRole, A2ATaskStore, A2ATaskStoreError,
    A2ATaskTransition, A2ATerminalReason, TransitionA2ATaskOutcome,
};
use KonclaveBoundedDocuments::{BoundedVec, deserialize_strict};
use KonclaveCryptographicCore::fill_random;
use KonclaveLocalServiceClient::{LocalServiceJsonClient, LocalServiceJsonClientError};
use KonclaveLocalServiceTransport::{
    LocalServiceErrorCode, MAX_RPC_PAYLOAD_BYTES, RequestId, decode_lowercase_hex,
    encode_lowercase_hex,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::{sleep, timeout};

const SEND_DIRECTED_REQUEST_OPERATION: &str = "send_directed_request";
const READ_MESSAGES_OPERATION: &str = "read_messages";
const SYNC_MESSAGES_OPERATION: &str = "sync_messages";
const WATCH_MESSAGES_OPERATION: &str = "watch_messages";
const OBSERVATION_REQUEST_DOMAIN: &[u8] = b"konclave-a2a-observation-request-v1\0";
const MAX_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_HISTORY_PAGE: usize = 100;
const MAX_CONCURRENT_OBSERVERS: usize = 1024;
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const RESPONSE_OUT_OF_BOUNDS_REASON: &str = "konclave_response_out_of_bounds";

/// Validated retry and observation bounds for one bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AKonclaveBridgeConfig {
    observation_timeout: Duration,
    retry_delay: Duration,
    history_page_size: usize,
    max_concurrent_observers: usize,
}

impl A2AKonclaveBridgeConfig {
    /// Creates one bounded bridge configuration.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for zero values, values above hard
    /// bounds, or a retry delay longer than the observation window.
    pub fn new(
        observation_timeout: Duration,
        retry_delay: Duration,
        history_page_size: usize,
        max_concurrent_observers: usize,
    ) -> Result<Self, A2AKonclaveBridgeError> {
        if observation_timeout.is_zero()
            || observation_timeout > MAX_OBSERVATION_TIMEOUT
            || retry_delay.is_zero()
            || retry_delay > MAX_RETRY_DELAY
            || retry_delay > observation_timeout
            || history_page_size == 0
            || history_page_size > MAX_HISTORY_PAGE
            || max_concurrent_observers == 0
            || max_concurrent_observers > MAX_CONCURRENT_OBSERVERS
        {
            return Err(A2AKonclaveBridgeError::InvalidConfiguration);
        }
        Ok(Self {
            observation_timeout,
            retry_delay,
            history_page_size,
            max_concurrent_observers,
        })
    }
}

impl Default for A2AKonclaveBridgeConfig {
    fn default() -> Self {
        Self {
            observation_timeout: Duration::from_secs(5 * 60),
            retry_delay: Duration::from_millis(250),
            history_page_size: MAX_HISTORY_PAGE,
            max_concurrent_observers: 256,
        }
    }
}

/// Stable bridge failures that do not disclose message content or environment data.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2AKonclaveBridgeError {
    /// Bridge configuration is invalid.
    #[error("A2A Konclave bridge configuration is invalid")]
    InvalidConfiguration,
    /// The local Konclave service is temporarily unavailable.
    #[error("A2A Konclave local service is unavailable")]
    LocalServiceUnavailable,
    /// Observation request identity generation is unavailable.
    #[error("A2A Konclave observation request identity is unavailable")]
    RequestIdentityUnavailable,
    /// Konclave rejected the exact directed request before accepting it.
    #[error("A2A Konclave directed request was rejected")]
    RequestRejected,
    /// The local service response violated the bridge contract.
    #[error("A2A Konclave local service response is invalid")]
    InvalidLocalResponse,
    /// The portable task store could not reconcile bridge state.
    #[error("A2A Konclave task state is unavailable")]
    TaskStateUnavailable,
    /// Observer tasks did not stop within the caller's finite shutdown deadline.
    #[error("A2A Konclave bridge shutdown deadline exceeded")]
    ShutdownDeadlineExceeded,
}

/// Authenticated local-service operation boundary used by the bridge.
#[async_trait]
pub trait A2AKonclaveLocalService: Send + Sync {
    /// Invokes one bounded operation under a caller-stable local request identifier.
    async fn request(
        &self,
        request_id: RequestId,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, A2AKonclaveLocalServiceError>;
}

/// Closed failures exposed by a bridge local-service implementation.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum A2AKonclaveLocalServiceError {
    /// The local service or its authenticated session is temporarily unavailable.
    #[error("A2A Konclave local service is unavailable")]
    Unavailable,
    /// The local service rejected the exact directed request before acceptance.
    #[error("A2A Konclave directed request was rejected")]
    RequestRejected,
    /// An authenticated response violated the local operation contract.
    #[error("A2A Konclave local service response is invalid")]
    InvalidResponse,
}

#[async_trait]
impl A2AKonclaveLocalService for LocalServiceJsonClient {
    async fn request(
        &self,
        request_id: RequestId,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, A2AKonclaveLocalServiceError> {
        LocalServiceJsonClient::request(self, request_id, operation, payload)
            .await
            .map_err(map_client_error)
    }
}

/// Durable A2A submitter that maps one task to one exact Konclave directed request.
pub struct A2AKonclaveBridge {
    store: Arc<dyn A2ATaskStore>,
    local_service: Arc<dyn A2AKonclaveLocalService>,
    clock: Arc<dyn A2AGatewayClock>,
    config: A2AKonclaveBridgeConfig,
    observer_tasks: tokio::sync::Mutex<HashMap<A2ATaskKey, tokio::task::JoinHandle<()>>>,
    observer_slots: Arc<tokio::sync::Semaphore>,
    shutdown: tokio::sync::watch::Sender<bool>,
    submission_locks: Arc<tokio::sync::Mutex<HashMap<A2ATaskKey, Arc<tokio::sync::Mutex<()>>>>>,
    request_ids: Arc<ObservationRequestIds>,
}

impl A2AKonclaveBridge {
    /// Creates one bridge over the portable task store and authenticated local service.
    ///
    /// # Errors
    ///
    /// Returns a request-identity error when an observation nonce cannot be
    /// generated.
    pub fn new(
        store: Arc<dyn A2ATaskStore>,
        local_service: Arc<dyn A2AKonclaveLocalService>,
        clock: Arc<dyn A2AGatewayClock>,
        config: A2AKonclaveBridgeConfig,
    ) -> Result<Self, A2AKonclaveBridgeError> {
        let mut nonce = [0_u8; 16];
        fill_random(&mut nonce).map_err(|_| A2AKonclaveBridgeError::RequestIdentityUnavailable)?;
        Ok(Self::with_nonce(store, local_service, clock, config, nonce))
    }

    fn with_nonce(
        store: Arc<dyn A2ATaskStore>,
        local_service: Arc<dyn A2AKonclaveLocalService>,
        clock: Arc<dyn A2AGatewayClock>,
        config: A2AKonclaveBridgeConfig,
        nonce: [u8; 16],
    ) -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Self {
            store,
            local_service,
            clock,
            config,
            observer_tasks: tokio::sync::Mutex::new(HashMap::new()),
            observer_slots: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_observers)),
            shutdown,
            submission_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            request_ids: Arc::new(ObservationRequestIds {
                nonce,
                sequence: AtomicU64::new(1),
            }),
        }
    }

    async fn send_directed_request(
        &self,
        submission: &A2ATaskSubmission,
    ) -> Result<SentMessage, A2AKonclaveBridgeError> {
        let expected_conversation = encode_lowercase_hex(submission.conversation_id().as_bytes());
        let expected_message = encode_lowercase_hex(submission.request_message_id().as_bytes());
        let payload = serde_json::to_vec(&SendDirectedRequest {
            conversation_id: &expected_conversation,
            message_id: &expected_message,
            target_device_id: encode_lowercase_hex(submission.target_device_id().as_bytes()),
            text: submission.text(),
        })
        .map_err(|_| A2AKonclaveBridgeError::InvalidConfiguration)?;
        let request_id = RequestId::from_bytes(*submission.request_message_id().as_bytes());
        let response = self
            .local_service
            .request(request_id, SEND_DIRECTED_REQUEST_OPERATION, payload)
            .await
            .map_err(map_local_error)?;
        let sent: SentMessage = deserialize_strict(&response, MAX_RPC_PAYLOAD_BYTES)
            .map_err(|_| A2AKonclaveBridgeError::InvalidLocalResponse)?;
        if sent.conversation_id != expected_conversation || sent.message_id != expected_message {
            return Err(A2AKonclaveBridgeError::InvalidLocalResponse);
        }
        Ok(sent)
    }

    async fn mark_working(&self, key: A2ATaskKey) -> Result<bool, A2AKonclaveBridgeError> {
        transition_task(
            &self.store,
            &self.clock,
            key,
            A2ATaskState::Working,
            None,
            &[A2ATaskState::Submitted],
        )
        .await
        .map(|outcome| outcome == TaskTransitionResult::TargetState)
    }

    async fn mark_rejected_if_unaccepted(
        &self,
        key: A2ATaskKey,
    ) -> Result<bool, A2AKonclaveBridgeError> {
        let store = Arc::clone(&self.store);
        let lookup = key.clone();
        let record = tokio::task::spawn_blocking(move || store.get_task(&lookup))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
            .map_err(map_store_error)?;
        if record.state() == A2ATaskState::Rejected {
            return Ok(true);
        }
        if record.state() != A2ATaskState::Submitted {
            return Ok(false);
        }
        let reason =
            A2ATerminalReason::parse("konclave_request_rejected").map_err(map_store_error)?;
        transition_task(
            &self.store,
            &self.clock,
            key,
            A2ATaskState::Rejected,
            Some(reason),
            &[A2ATaskState::Submitted],
        )
        .await
        .map(|outcome| outcome == TaskTransitionResult::TargetState)
    }

    async fn start_observer(
        &self,
        key: A2ATaskKey,
        after_cursor: u64,
        observer_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), A2AKonclaveBridgeError> {
        if *self.shutdown.borrow() {
            return Err(A2AKonclaveBridgeError::LocalServiceUnavailable);
        }
        if self.observer_running(&key).await {
            return Ok(());
        }

        let observer = Observer {
            store: Arc::clone(&self.store),
            local_service: Arc::clone(&self.local_service),
            clock: Arc::clone(&self.clock),
            config: self.config,
            request_ids: Arc::clone(&self.request_ids),
        };
        let mut shutdown = self.shutdown.subscribe();
        let observer_key = key.clone();
        let mut tasks = self.observer_tasks.lock().await;
        if *self.shutdown.borrow() {
            return Err(A2AKonclaveBridgeError::LocalServiceUnavailable);
        }
        let handle = tokio::spawn(async move {
            let _observer_slot = observer_slot;
            observer
                .run(observer_key, after_cursor, &mut shutdown)
                .await;
        });
        tasks.insert(key, handle);
        Ok(())
    }

    async fn observer_running(&self, key: &A2ATaskKey) -> bool {
        self.reap_finished_observers().await;
        self.observer_tasks.lock().await.contains_key(key)
    }

    async fn reap_finished_observers(&self) {
        let finished = {
            let mut tasks = self.observer_tasks.lock().await;
            let keys = tasks
                .iter()
                .filter_map(|(key, task)| task.is_finished().then_some(key.clone()))
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| tasks.remove(&key))
                .collect::<Vec<_>>()
        };
        for task in finished {
            observe_task_completion(task.await);
        }
    }

    fn reserve_observer(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, A2ATaskSubmissionError> {
        Arc::clone(&self.observer_slots)
            .try_acquire_owned()
            .map_err(|_| A2ATaskSubmissionError)
    }

    async fn submission_lock(&self, key: &A2ATaskKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.submission_locks.lock().await;
        Arc::clone(
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    async fn release_submission_lock(
        &self,
        key: &A2ATaskKey,
        task_lock: &Arc<tokio::sync::Mutex<()>>,
    ) {
        let mut locks = self.submission_locks.lock().await;
        if Arc::strong_count(task_lock) == 2 {
            locks.remove(key);
        }
    }

    async fn submit_locked(
        &self,
        submission: A2ATaskSubmission,
    ) -> Result<(), A2ATaskSubmissionError> {
        let key = submission.key().clone();
        if *self.shutdown.borrow() {
            return Err(A2ATaskSubmissionError);
        }
        if is_terminal(
            self.task_state(&key)
                .await
                .map_err(|_| A2ATaskSubmissionError)?,
        ) {
            return Ok(());
        }
        if self.observer_running(&key).await {
            return Ok(());
        }
        let observer_slot = self.reserve_observer()?;
        let sent = match self.send_directed_request(&submission).await {
            Ok(sent) => sent,
            Err(A2AKonclaveBridgeError::RequestRejected) => {
                return if self
                    .mark_rejected_if_unaccepted(key)
                    .await
                    .map_err(|_| A2ATaskSubmissionError)?
                {
                    Ok(())
                } else {
                    Err(A2ATaskSubmissionError)
                };
            }
            Err(A2AKonclaveBridgeError::LocalServiceUnavailable) => {
                return Err(A2ATaskSubmissionError);
            }
            Err(A2AKonclaveBridgeError::InvalidLocalResponse)
            | Err(A2AKonclaveBridgeError::TaskStateUnavailable)
            | Err(A2AKonclaveBridgeError::InvalidConfiguration)
            | Err(A2AKonclaveBridgeError::RequestIdentityUnavailable)
            | Err(A2AKonclaveBridgeError::ShutdownDeadlineExceeded) => {
                return Err(A2ATaskSubmissionError);
            }
        };
        if !self
            .mark_working(key.clone())
            .await
            .map_err(|_| A2ATaskSubmissionError)?
        {
            return Ok(());
        }
        self.start_observer(key, sent.cursor, observer_slot)
            .await
            .map_err(|_| A2ATaskSubmissionError)
    }

    async fn task_state(&self, key: &A2ATaskKey) -> Result<A2ATaskState, A2AKonclaveBridgeError> {
        let store = Arc::clone(&self.store);
        let key = key.clone();
        tokio::task::spawn_blocking(move || store.get_task(&key).map(|record| record.state()))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
            .map_err(map_store_error)
    }

    /// Stops all owned response observers and waits for their completion.
    ///
    /// Once shutdown begins, this bridge rejects new submissions. Dropping a bridge
    /// without calling this method signals cancellation and aborts any handles it can
    /// acquire, but cannot await graceful completion.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for a zero or greater-than-60-second
    /// timeout, or a shutdown-deadline error when an observer does not stop in time.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), A2AKonclaveBridgeError> {
        if deadline.is_zero() || deadline > MAX_SHUTDOWN_TIMEOUT {
            return Err(A2AKonclaveBridgeError::InvalidConfiguration);
        }
        self.shutdown.send_replace(true);
        self.observer_slots.close();
        let tasks = {
            let mut tasks = self.observer_tasks.lock().await;
            tasks.drain().map(|(_, task)| task).collect::<Vec<_>>()
        };
        timeout(deadline, async {
            for task in tasks {
                observe_task_completion(task.await);
            }
        })
        .await
        .map_err(|_| A2AKonclaveBridgeError::ShutdownDeadlineExceeded)
    }
}

impl Drop for A2AKonclaveBridge {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.observer_slots.close();
        for (_, task) in self.observer_tasks.get_mut().drain() {
            task.abort();
        }
    }
}

#[async_trait]
impl A2ATaskSubmitter for A2AKonclaveBridge {
    async fn submit(&self, submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError> {
        let key = submission.key().clone();
        let task_lock = self.submission_lock(&key).await;
        let guard = task_lock.lock().await;
        let result = self.submit_locked(submission).await;
        drop(guard);
        self.release_submission_lock(&key, &task_lock).await;
        result
    }
}

struct Observer {
    store: Arc<dyn A2ATaskStore>,
    local_service: Arc<dyn A2AKonclaveLocalService>,
    clock: Arc<dyn A2AGatewayClock>,
    config: A2AKonclaveBridgeConfig,
    request_ids: Arc<ObservationRequestIds>,
}

impl Observer {
    async fn run(
        &self,
        key: A2ATaskKey,
        after_cursor: u64,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            result = timeout(
                self.config.observation_timeout,
                self.observe(&key, after_cursor),
            ) => {
                if result.is_err() {
                    log::warn!(
                        "A2A Konclave response observation reached its configured deadline; an exact task retry can resume it"
                    );
                }
            }
        }
    }

    async fn observe(&self, key: &A2ATaskKey, mut after_cursor: u64) {
        let Ok(record) = self.task_record(key).await else {
            log::warn!("A2A Konclave response observation could not load durable task state");
            return;
        };
        if is_terminal(record.state()) {
            return;
        }
        let expected = ExpectedResponse {
            conversation_id: encode_lowercase_hex(record.conversation_id().as_bytes()),
            sender_device_id: encode_lowercase_hex(record.target_device_id().as_bytes()),
            reply_to_message_id: encode_lowercase_hex(record.request_message_id().as_bytes()),
        };
        loop {
            match self
                .read_messages(key, &expected.conversation_id, after_cursor)
                .await
            {
                Ok(page) => {
                    if let Some(response) = exact_response(&expected, page.messages.as_slice()) {
                        if self.complete(key, response).await.is_ok() {
                            return;
                        }
                        log::warn!(
                            "A2A Konclave exact response could not be committed to durable task state"
                        );
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    after_cursor = maximum_cursor(after_cursor, page.messages.as_slice());
                    if page.has_more {
                        tokio::task::yield_now().await;
                        continue;
                    }
                }
                Err(_) => {
                    log::debug!(
                        "A2A Konclave history observation failed and will retry within its configured deadline"
                    );
                    sleep(self.config.retry_delay).await;
                    continue;
                }
            }

            match self
                .conversation_operation(key, &expected.conversation_id, SYNC_MESSAGES_OPERATION)
                .await
            {
                Ok(page) => {
                    if let Some(response) = exact_response(&expected, page.messages.as_slice()) {
                        if self.complete(key, response).await.is_ok() {
                            return;
                        }
                        log::warn!(
                            "A2A Konclave synchronized response could not be committed to durable task state"
                        );
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    after_cursor = maximum_cursor(after_cursor, page.messages.as_slice());
                    if page.has_more {
                        tokio::task::yield_now().await;
                        continue;
                    }
                }
                Err(_) => {
                    log::debug!(
                        "A2A Konclave relay synchronization failed and will retry within its configured deadline"
                    );
                    sleep(self.config.retry_delay).await;
                    continue;
                }
            }

            match self
                .conversation_operation(key, &expected.conversation_id, WATCH_MESSAGES_OPERATION)
                .await
            {
                Ok(page) => {
                    if let Some(response) = exact_response(&expected, page.messages.as_slice()) {
                        if self.complete(key, response).await.is_ok() {
                            return;
                        }
                        log::warn!(
                            "A2A Konclave watched response could not be committed to durable task state"
                        );
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    after_cursor = maximum_cursor(after_cursor, page.messages.as_slice());
                    sleep(self.config.retry_delay).await;
                }
                Err(_) => {
                    log::debug!(
                        "A2A Konclave relay watch failed and will retry within its configured deadline"
                    );
                    sleep(self.config.retry_delay).await;
                }
            }
        }
    }

    async fn read_messages(
        &self,
        key: &A2ATaskKey,
        conversation_id: &str,
        after_cursor: u64,
    ) -> Result<MessagePage, A2AKonclaveBridgeError> {
        let payload = serde_json::to_vec(&ReadMessages {
            conversation_id,
            after_cursor,
            limit: self.config.history_page_size,
        })
        .map_err(|_| A2AKonclaveBridgeError::InvalidConfiguration)?;
        self.request_page(key, READ_MESSAGES_OPERATION, payload)
            .await
    }

    async fn conversation_operation(
        &self,
        key: &A2ATaskKey,
        conversation_id: &str,
        operation: &'static str,
    ) -> Result<MessagePage, A2AKonclaveBridgeError> {
        let payload = serde_json::to_vec(&ConversationOperation { conversation_id })
            .map_err(|_| A2AKonclaveBridgeError::InvalidConfiguration)?;
        self.request_page(key, operation, payload).await
    }

    async fn request_page(
        &self,
        key: &A2ATaskKey,
        operation: &'static str,
        payload: Vec<u8>,
    ) -> Result<MessagePage, A2AKonclaveBridgeError> {
        let request_id = self.request_ids.next(key, operation)?;
        let response = self
            .local_service
            .request(request_id, operation, payload)
            .await
            .map_err(map_local_error)?;
        let page: MessagePage = deserialize_strict(&response, MAX_RPC_PAYLOAD_BYTES)
            .map_err(|_| A2AKonclaveBridgeError::InvalidLocalResponse)?;
        if page.messages.len() > self.config.history_page_size
            || page
                .messages
                .as_slice()
                .iter()
                .any(|message| !message.valid_shape())
        {
            return Err(A2AKonclaveBridgeError::InvalidLocalResponse);
        }
        Ok(page)
    }

    async fn task_record(
        &self,
        key: &A2ATaskKey,
    ) -> Result<KonclaveA2ATaskStore::A2ATaskRecord, A2AKonclaveBridgeError> {
        let store = Arc::clone(&self.store);
        let key = key.clone();
        tokio::task::spawn_blocking(move || store.get_task(&key))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
            .map_err(map_store_error)
    }

    async fn complete(
        &self,
        key: &A2ATaskKey,
        response: &ObservedMessage,
    ) -> Result<(), A2AKonclaveBridgeError> {
        if response.text().len() > MAX_A2A_TEXT_BYTES {
            let reason =
                A2ATerminalReason::parse(RESPONSE_OUT_OF_BOUNDS_REASON).map_err(map_store_error)?;
            return match transition_task(
                &self.store,
                &self.clock,
                key.clone(),
                A2ATaskState::Failed,
                Some(reason),
                &[A2ATaskState::Submitted, A2ATaskState::Working],
            )
            .await?
            {
                TaskTransitionResult::TargetState => Ok(()),
                TaskTransitionResult::DifferentState => {
                    Err(A2AKonclaveBridgeError::TaskStateUnavailable)
                }
            };
        }
        let message_id = A2AMessageId::parse(response.message_id.clone())
            .map_err(|_| A2AKonclaveBridgeError::InvalidLocalResponse)?;
        let now = self
            .clock
            .now_unix_milliseconds()
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?;
        let message = A2ATaskMessage::new(
            key.clone(),
            message_id,
            A2ATaskMessageRole::Agent,
            response.text().to_string(),
            now,
        )
        .map_err(map_store_error)?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.append_message(message, now))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
            .map_err(map_store_error)?;
        match transition_task(
            &self.store,
            &self.clock,
            key.clone(),
            A2ATaskState::Completed,
            None,
            &[A2ATaskState::Submitted, A2ATaskState::Working],
        )
        .await?
        {
            TaskTransitionResult::TargetState => Ok(()),
            TaskTransitionResult::DifferentState => {
                Err(A2AKonclaveBridgeError::TaskStateUnavailable)
            }
        }
    }
}

struct ObservationRequestIds {
    nonce: [u8; 16],
    sequence: AtomicU64,
}

impl ObservationRequestIds {
    fn next(&self, key: &A2ATaskKey, operation: &str) -> Result<RequestId, A2AKonclaveBridgeError> {
        let sequence = self
            .sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| A2AKonclaveBridgeError::LocalServiceUnavailable)?;
        let mut digest = Sha256::new();
        digest.update(OBSERVATION_REQUEST_DOMAIN);
        digest.update(self.nonce);
        digest.update(sequence.to_be_bytes());
        digest.update(key.task_id().as_str().as_bytes());
        digest.update(operation.as_bytes());
        let bytes: [u8; 16] = digest.finalize()[..16]
            .try_into()
            .map_err(|_| A2AKonclaveBridgeError::LocalServiceUnavailable)?;
        Ok(RequestId::from_bytes(bytes))
    }
}

#[derive(Serialize)]
struct SendDirectedRequest<'a> {
    conversation_id: &'a str,
    message_id: &'a str,
    target_device_id: String,
    text: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SentMessage {
    conversation_id: String,
    message_id: String,
    #[serde(rename = "sender_counter")]
    _sender_counter: u64,
    cursor: u64,
}

#[derive(Serialize)]
struct ReadMessages<'a> {
    conversation_id: &'a str,
    after_cursor: u64,
    limit: usize,
}

#[derive(Serialize)]
struct ConversationOperation<'a> {
    conversation_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagePage {
    messages: BoundedVec<ObservedMessage, MAX_HISTORY_PAGE>,
    has_more: bool,
}

#[derive(Deserialize)]
struct ObservedMessage {
    conversation_id: String,
    message_id: String,
    envelope_id: String,
    sender_device_id: String,
    epoch: u64,
    sender_counter: u64,
    sent_at_unix_milliseconds: u64,
    reply_to_message_id: Option<String>,
    cursor: u64,
    direction: String,
    content_type: String,
    text: Option<String>,
    target_device_id: Option<String>,
    proposal_id: Option<String>,
    policy_digest: Option<String>,
    replaces_policy_digest: Option<String>,
    outcome: Option<String>,
    duplicate: bool,
}

impl ObservedMessage {
    fn text(&self) -> &str {
        self.text.as_deref().unwrap_or_default()
    }

    fn valid_shape(&self) -> bool {
        decode_lowercase_hex::<32>(&self.conversation_id).is_some()
            && decode_lowercase_hex::<16>(&self.message_id).is_some()
            && decode_lowercase_hex::<16>(&self.envelope_id).is_some()
            && decode_lowercase_hex::<32>(&self.sender_device_id).is_some()
            && self
                .reply_to_message_id
                .as_deref()
                .is_none_or(|value| decode_lowercase_hex::<16>(value).is_some())
            && matches!(self.direction.as_str(), "inbound" | "outbound")
            && match self.content_type.as_str() {
                "text" => {
                    self.text.as_deref().is_some_and(|text| !text.is_empty())
                        && self.target_device_id.is_none()
                        && self.proposal_id.is_none()
                        && self.policy_digest.is_none()
                        && self.replaces_policy_digest.is_none()
                        && self.outcome.is_none()
                }
                _ => true,
            }
            && {
                let _ = (
                    self.epoch,
                    self.sender_counter,
                    self.sent_at_unix_milliseconds,
                    self.cursor,
                    self.duplicate,
                );
                true
            }
    }
}

struct ExpectedResponse {
    conversation_id: String,
    sender_device_id: String,
    reply_to_message_id: String,
}

fn exact_response<'a>(
    expected: &ExpectedResponse,
    messages: &'a [ObservedMessage],
) -> Option<&'a ObservedMessage> {
    messages.iter().find(|message| {
        message.conversation_id == expected.conversation_id
            && message.sender_device_id == expected.sender_device_id
            && message.direction == "inbound"
            && message.content_type == "text"
            && message.reply_to_message_id.as_deref() == Some(expected.reply_to_message_id.as_str())
    })
}

fn maximum_cursor(initial: u64, messages: &[ObservedMessage]) -> u64 {
    messages
        .iter()
        .map(|message| message.cursor)
        .fold(initial, u64::max)
}

fn is_terminal(state: A2ATaskState) -> bool {
    matches!(
        state,
        A2ATaskState::Completed
            | A2ATaskState::Failed
            | A2ATaskState::Canceled
            | A2ATaskState::InputRequired
            | A2ATaskState::Rejected
            | A2ATaskState::AuthRequired
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskTransitionResult {
    TargetState,
    DifferentState,
}

async fn transition_task(
    store: &Arc<dyn A2ATaskStore>,
    clock: &Arc<dyn A2AGatewayClock>,
    key: A2ATaskKey,
    state: A2ATaskState,
    reason: Option<A2ATerminalReason>,
    allowed_sources: &[A2ATaskState],
) -> Result<TaskTransitionResult, A2AKonclaveBridgeError> {
    for _ in 0..2 {
        let store_for_read = Arc::clone(store);
        let lookup = key.clone();
        let record = tokio::task::spawn_blocking(move || store_for_read.get_task(&lookup))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
            .map_err(map_store_error)?;
        if record.state() == state {
            return Ok(TaskTransitionResult::TargetState);
        }
        if is_terminal(record.state()) || !allowed_sources.contains(&record.state()) {
            return Ok(TaskTransitionResult::DifferentState);
        }
        let now = clock
            .now_unix_milliseconds()
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?;
        let transition =
            A2ATaskTransition::new(key.clone(), record.generation(), state, reason.clone(), now);
        let store_for_transition = Arc::clone(store);
        match tokio::task::spawn_blocking(move || store_for_transition.transition_task(transition))
            .await
            .map_err(|_| A2AKonclaveBridgeError::TaskStateUnavailable)?
        {
            Ok(
                TransitionA2ATaskOutcome::Applied(record)
                | TransitionA2ATaskOutcome::Existing(record),
            ) => {
                return Ok(if record.state() == state {
                    TaskTransitionResult::TargetState
                } else {
                    TaskTransitionResult::DifferentState
                });
            }
            Err(A2ATaskStoreError::Conflict) => continue,
            Err(error) => return Err(map_store_error(error)),
        }
    }
    Err(A2AKonclaveBridgeError::TaskStateUnavailable)
}

fn map_client_error(error: LocalServiceJsonClientError) -> A2AKonclaveLocalServiceError {
    match error {
        LocalServiceJsonClientError::Service(LocalServiceErrorCode::NotAuthorized)
        | LocalServiceJsonClientError::Service(LocalServiceErrorCode::InvalidRequest) => {
            A2AKonclaveLocalServiceError::RequestRejected
        }
        LocalServiceJsonClientError::InvalidResponse => {
            A2AKonclaveLocalServiceError::InvalidResponse
        }
        _ => A2AKonclaveLocalServiceError::Unavailable,
    }
}

fn map_local_error(error: A2AKonclaveLocalServiceError) -> A2AKonclaveBridgeError {
    match error {
        A2AKonclaveLocalServiceError::Unavailable => {
            A2AKonclaveBridgeError::LocalServiceUnavailable
        }
        A2AKonclaveLocalServiceError::RequestRejected => A2AKonclaveBridgeError::RequestRejected,
        A2AKonclaveLocalServiceError::InvalidResponse => {
            A2AKonclaveBridgeError::InvalidLocalResponse
        }
    }
}

fn map_store_error(_: A2ATaskStoreError) -> A2AKonclaveBridgeError {
    A2AKonclaveBridgeError::TaskStateUnavailable
}

fn observe_task_completion(result: Result<(), tokio::task::JoinError>) {
    if result.is_err() {
        log::warn!("A2A Konclave response observer ended unexpectedly");
    }
}

#[cfg(test)]
mod tests;
