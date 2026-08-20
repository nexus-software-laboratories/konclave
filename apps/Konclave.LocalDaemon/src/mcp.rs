use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::RelayClient;
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, EnvelopeId, MessageId,
};
use anyhow::{Context, bail, ensure};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::ServerInitializeError;
use rmcp::{Json, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::application::{ApplicationService, SendApplicationRequest};
use crate::conversation::{ConversationCoordinator, ProcessedApplication};
use crate::persistence::{MessageDirection, StoredHistoryMessage};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 100;
const MESSAGE_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
pub struct AuthorizationContext<'a> {
    pub method: &'a str,
}

pub type AuthorizationHook =
    Arc<dyn Fn(AuthorizationContext<'_>) -> anyhow::Result<()> + Send + Sync>;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ConversationRequest {
    conversation_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListConversationsRequest {
    after_conversation_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SendMessageRequest {
    conversation_id: String,
    message_id: String,
    text: String,
    reply_to_message_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadMessagesRequest {
    conversation_id: String,
    after_cursor: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ConversationResult {
    conversation_id: String,
    routing_id: String,
    epoch: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ConversationListResult {
    conversation_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct SentMessageResult {
    conversation_id: String,
    message_id: String,
    sender_counter: u64,
    cursor: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct MessageResult {
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
    text: String,
    duplicate: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct MessageListResult {
    messages: Vec<MessageResult>,
    has_more: bool,
}

#[derive(Clone)]
pub(crate) struct StdioServer {
    conversations: ConversationCoordinator,
    applications: Option<ApplicationService<RelayClient>>,
    authorize: AuthorizationHook,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl StdioServer {
    pub(crate) fn new(
        conversations: ConversationCoordinator,
        applications: Option<ApplicationService<RelayClient>>,
        authorize: AuthorizationHook,
    ) -> Self {
        Self {
            conversations,
            applications,
            authorize,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "create_conversation",
        description = "Create a sealed MLS conversation owned by this device."
    )]
    async fn create_conversation(&self) -> Result<Json<ConversationResult>, String> {
        self.authorize("create_conversation")?;
        let conversations = self.conversations.clone();
        let summary = tokio::task::spawn_blocking(move || conversations.create())
            .await
            .map_err(|_| "task_failed".to_string())?
            .map_err(tool_error)?;
        Ok(Json(ConversationResult {
            conversation_id: encode_hex(summary.conversation_id.as_bytes()),
            routing_id: encode_hex(summary.routing_id.as_bytes()),
            epoch: summary.epoch,
        }))
    }

    #[tool(
        name = "list_conversations",
        description = "List a bounded page of local sealed conversation identifiers."
    )]
    async fn list_conversations(
        &self,
        Parameters(request): Parameters<ListConversationsRequest>,
    ) -> Result<Json<ConversationListResult>, String> {
        self.authorize("list_conversations")?;
        let after = request
            .after_conversation_id
            .as_deref()
            .map(parse_conversation_id)
            .transpose()?;
        let limit = page_size(request.limit)?;
        let conversations = self.conversations.clone();
        let identifiers =
            tokio::task::spawn_blocking(move || conversations.conversation_ids(after, limit))
                .await
                .map_err(|_| "task_failed".to_string())?
                .map_err(tool_error)?;
        Ok(Json(ConversationListResult {
            conversation_ids: identifiers
                .into_iter()
                .map(|identifier| encode_hex(identifier.as_bytes()))
                .collect(),
        }))
    }

    #[tool(
        name = "send_message",
        description = "Encrypt, journal, and submit one text message using a caller-stable 16-byte message_id."
    )]
    async fn send_message(
        &self,
        Parameters(request): Parameters<SendMessageRequest>,
    ) -> Result<Json<SentMessageResult>, String> {
        self.authorize("send_message")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let message_id = parse_message_id(&request.message_id)?;
        let reply_to = request
            .reply_to_message_id
            .as_deref()
            .map(parse_message_id)
            .transpose()?;
        let content =
            ApplicationContent::text(request.text).map_err(|_| "invalid_text".to_string())?;
        let (sent_at, expires_at) = message_times()?;
        let sent = applications
            .send(SendApplicationRequest {
                conversation_id,
                message_id,
                content,
                reply_to,
                sent_at_unix_milliseconds: sent_at,
                expires_at_unix_seconds: expires_at,
            })
            .await
            .map_err(tool_error)?;
        Ok(Json(SentMessageResult {
            conversation_id: encode_hex(sent.conversation_id.as_bytes()),
            message_id: encode_hex(sent.message.message_id().as_bytes()),
            sender_counter: sent.message.sender_counter(),
            cursor: sent.cursor,
        }))
    }

    #[tool(
        name = "read_messages",
        description = "Read a bounded cursor-ordered page of sealed local message history."
    )]
    async fn read_messages(
        &self,
        Parameters(request): Parameters<ReadMessagesRequest>,
    ) -> Result<Json<MessageListResult>, String> {
        self.authorize("read_messages")?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let after_cursor = request.after_cursor.unwrap_or(0);
        let limit = page_size(request.limit)?;
        let conversations = self.conversations.clone();
        let history = tokio::task::spawn_blocking(move || {
            conversations.history(conversation_id, after_cursor, limit)
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;
        Ok(Json(MessageListResult {
            messages: history
                .messages
                .into_iter()
                .map(|message| history_result(conversation_id, message))
                .collect::<Result<Vec<_>, _>>()?,
            has_more: history.has_more,
        }))
    }

    #[tool(
        name = "sync_messages",
        description = "Replay, decrypt, persist, and acknowledge one bounded relay page."
    )]
    async fn sync_messages(
        &self,
        Parameters(request): Parameters<ConversationRequest>,
    ) -> Result<Json<MessageListResult>, String> {
        self.authorize("sync_messages")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let replay = applications
            .replay_once(conversation_id, MAX_PAGE_SIZE as u32)
            .await
            .map_err(tool_error)?;
        Ok(Json(MessageListResult {
            messages: replay
                .messages
                .into_iter()
                .map(processed_result)
                .collect::<Result<Vec<_>, _>>()?,
            has_more: replay.has_more,
        }))
    }

    #[tool(
        name = "watch_messages",
        description = "Wait for, persist, and acknowledge one bounded relay watch page."
    )]
    async fn watch_messages(
        &self,
        Parameters(request): Parameters<ConversationRequest>,
    ) -> Result<Json<MessageListResult>, String> {
        self.authorize("watch_messages")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let replay = applications
            .watch_once(conversation_id)
            .await
            .map_err(tool_error)?;
        Ok(Json(MessageListResult {
            messages: replay
                .messages
                .into_iter()
                .map(processed_result)
                .collect::<Result<Vec<_>, _>>()?,
            has_more: replay.has_more,
        }))
    }

    fn authorize(&self, method: &'static str) -> Result<(), String> {
        (self.authorize)(AuthorizationContext { method }).map_err(tool_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for StdioServer {
    #[allow(deprecated)]
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }
}

#[must_use]
pub(crate) fn local_stdio_authorization(allow_write: bool) -> AuthorizationHook {
    Arc::new(move |context| match context.method {
        "initialize" | "list_conversations" | "read_messages" => Ok(()),
        "create_conversation" | "send_message" | "sync_messages" | "watch_messages"
            if allow_write =>
        {
            Ok(())
        }
        _ => bail!("MCP method is not authorized"),
    })
}

pub(crate) async fn run_stdio_server(
    server: StdioServer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    (server.authorize)(AuthorizationContext {
        method: "initialize",
    })?;
    ensure_stdout_safe_diagnostics("stderr")?;

    let service = tokio::select! {
        result = server.serve(rmcp::transport::stdio()) => {
            match result {
                Ok(service) => service,
                Err(
                    ServerInitializeError::ConnectionClosed(_) |
                    ServerInitializeError::Cancelled,
                ) => return Ok(()),
                Err(error) => {
                    return Err(error).context("starting MCP stdio transport");
                }
            }
        }
        _ = wait_for_shutdown(&mut shutdown) => {
            close_stdio_input();
            return Ok(());
        }
    };
    let cancellation = service.cancellation_token();
    let mut waiting = tokio::spawn(service.waiting());

    tokio::select! {
        result = &mut waiting => {
            result
                .context("joining MCP stdio service")?
                .context("waiting for MCP stdio service")?;
        }
        _ = wait_for_shutdown(&mut shutdown) => {
            close_stdio_input();
            cancellation.cancel();
            timeout(Duration::from_secs(5), &mut waiting)
                .await
                .context("waiting for MCP stdio shutdown")?
                .context("joining MCP stdio service")?
                .context("waiting for MCP stdio service")?;
        }
    }

    Ok(())
}

fn parse_conversation_id(value: &str) -> Result<ConversationId, String> {
    decode_hex(value)
        .map(ConversationId::from_bytes)
        .map_err(|_| "invalid_conversation_id".to_string())
}

fn parse_message_id(value: &str) -> Result<MessageId, String> {
    decode_hex(value)
        .map(MessageId::from_bytes)
        .map_err(|_| "invalid_message_id".to_string())
}

fn page_size(value: Option<usize>) -> Result<usize, String> {
    let value = value.unwrap_or(DEFAULT_PAGE_SIZE);
    if (1..=MAX_PAGE_SIZE).contains(&value) {
        Ok(value)
    } else {
        Err("invalid_page_size".to_string())
    }
}

fn message_times() -> Result<(u64, u64), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_time_unavailable".to_string())?;
    let seconds = now.as_secs();
    let expires_at = seconds
        .checked_add(MESSAGE_RETENTION_SECONDS)
        .ok_or_else(|| "system_time_unavailable".to_string())?;
    let milliseconds = seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(now.subsec_millis())))
        .ok_or_else(|| "system_time_unavailable".to_string())?;
    Ok((milliseconds, expires_at))
}

fn history_result(
    conversation_id: ConversationId,
    history: StoredHistoryMessage,
) -> Result<MessageResult, String> {
    message_result(
        conversation_id,
        history.cursor,
        history.envelope_id,
        history.sender,
        history.epoch,
        history.message,
        match history.direction {
            MessageDirection::Outbound => "outbound",
            MessageDirection::Inbound => "inbound",
        },
        false,
    )
}

fn processed_result(processed: ProcessedApplication) -> Result<MessageResult, String> {
    let direction = match processed.direction {
        MessageDirection::Outbound => "outbound",
        MessageDirection::Inbound => "inbound",
    };
    message_result(
        processed.conversation_id,
        processed.cursor,
        processed.envelope_id,
        processed.sender,
        processed.epoch,
        processed.message,
        direction,
        processed.duplicate,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the MCP message contract remains explicit"
)]
fn message_result(
    conversation_id: ConversationId,
    cursor: u64,
    envelope_id: EnvelopeId,
    sender: KonclaveDomainCore::DeviceId,
    epoch: u64,
    message: ApplicationMessage,
    direction: &'static str,
    duplicate: bool,
) -> Result<MessageResult, String> {
    let text = match message.content() {
        ApplicationContent::Text(text) => text.clone(),
    };
    Ok(MessageResult {
        conversation_id: encode_hex(conversation_id.as_bytes()),
        message_id: encode_hex(message.message_id().as_bytes()),
        envelope_id: encode_hex(envelope_id.as_bytes()),
        sender_device_id: encode_hex(sender.as_bytes()),
        epoch,
        sender_counter: message.sender_counter(),
        sent_at_unix_milliseconds: message.sent_at_unix_milliseconds(),
        reply_to_message_id: message
            .reply_to()
            .map(|identifier| encode_hex(identifier.as_bytes())),
        cursor,
        direction: direction.to_string(),
        text,
        duplicate,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(());
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

const fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn tool_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn close_stdio_input() {
    #[cfg(unix)]
    unsafe {
        // SAFETY: the process is shutting down its stdio protocol transport, and
        // closing this process-owned descriptor unblocks Tokio's stdin reader.
        let _ = libc::close(libc::STDIN_FILENO);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

        // SAFETY: GetStdHandle returns the process-owned stdin handle. It is closed
        // only during coordinated shutdown to unblock the stdio transport reader.
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            let _ = CloseHandle(handle);
        }
    }
}

pub fn ensure_stdout_safe_diagnostics(stream_name: &str) -> anyhow::Result<()> {
    ensure!(
        stream_name != "stdout",
        "stdout is reserved for the MCP stdio transport"
    );
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use KonclaveDomainCore::{
        ApplicationContent, ApplicationMessage, ConversationId, DeviceId, EnvelopeId, MessageId,
        ProtocolVersion,
    };
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};
    use serde_json::json;

    use super::{
        AuthorizationContext, AuthorizationHook, StdioServer, ensure_stdout_safe_diagnostics,
        local_stdio_authorization,
    };
    use crate::conversation::ProcessedApplication;
    use crate::conversation::tests::open_coordinator;
    use crate::persistence::MessageDirection;

    #[derive(Clone, Default)]
    struct TestClient;

    impl ClientHandler for TestClient {}

    #[test]
    fn authorization_hook_is_explicit_and_deterministic() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = called.clone();
        let hook: AuthorizationHook = Arc::new(move |context: AuthorizationContext<'_>| {
            assert_eq!(context.method, "initialize");
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

        hook(AuthorizationContext {
            method: "initialize",
        })
        .unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
        let read_only = local_stdio_authorization(false);
        read_only(AuthorizationContext {
            method: "initialize",
        })
        .unwrap();
        read_only(AuthorizationContext {
            method: "list_conversations",
        })
        .unwrap();
        assert!(
            read_only(AuthorizationContext {
                method: "create_conversation",
            })
            .is_err()
        );
        let writable = local_stdio_authorization(true);
        writable(AuthorizationContext {
            method: "create_conversation",
        })
        .unwrap();
        assert!(writable(AuthorizationContext { method: "unknown" }).is_err());
    }

    #[test]
    fn stdout_is_rejected_for_diagnostics() {
        let error = ensure_stdout_safe_diagnostics("stdout").unwrap_err();
        assert!(error.to_string().contains("stdout"));
        assert!(ensure_stdout_safe_diagnostics("stderr").is_ok());
    }

    #[test]
    fn own_echo_result_preserves_outbound_direction() {
        let result = super::processed_result(ProcessedApplication {
            conversation_id: ConversationId::from_bytes([1; ConversationId::LENGTH]),
            cursor: 1,
            envelope_id: EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            sender: DeviceId::from_bytes([3; DeviceId::LENGTH]),
            epoch: 0,
            message: ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                MessageId::from_bytes([4; MessageId::LENGTH]),
                1,
                1_700_000_000_000,
                None,
                ApplicationContent::text("own echo").unwrap(),
            )
            .unwrap(),
            direction: MessageDirection::Outbound,
            duplicate: true,
        })
        .unwrap();
        assert_eq!(result.direction, "outbound");
    }

    #[tokio::test]
    async fn in_memory_client_observes_deterministic_server_identity() {
        let root = tempfile::tempdir().unwrap();
        let server_state = StdioServer::new(
            open_coordinator(root.path(), "mcp-test"),
            None,
            local_stdio_authorization(true),
        );
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let _root = root;
            server_state
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let mut client = TestClient.serve(client_transport).await.unwrap();
        let peer = client.peer_info().unwrap();
        let server_info = peer.server_info.as_ref().unwrap();
        assert_eq!(server_info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(server_info.version, env!("CARGO_PKG_VERSION"));
        assert!(peer.capabilities.tools.is_some());

        let created = client
            .call_tool(CallToolRequestParams::new("create_conversation"))
            .await
            .unwrap()
            .structured_content
            .unwrap();
        let conversation_id = created["conversation_id"].as_str().unwrap();
        assert_eq!(conversation_id.len(), ConversationId::LENGTH * 2);
        let listed = client
            .call_tool(
                CallToolRequestParams::new("list_conversations")
                    .with_arguments(json!({"limit": 10}).as_object().unwrap().clone()),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(
            listed["conversation_ids"][0].as_str(),
            Some(conversation_id)
        );

        client.close().await.unwrap();
        server.await.unwrap();
    }
}
