use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::RelayClient;
use KonclaveCryptographicCore::MlsWelcome;
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, DeviceId,
    Ed25519PublicKey, EnvelopeId, MAX_RELAY_PAYLOAD_BYTES, MessageId, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_device_credential_binding, decode_invitation, decode_join_proof,
    encode_device_credential_binding, encode_invitation, encode_join_proof,
};
use anyhow::{Context, bail, ensure};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::ServerInitializeError;
use rmcp::{Json, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::application::{ApplicationService, SendApplicationRequest, SentMembership};
use crate::conversation::{
    ConversationCoordinator, ConversationCoordinatorError, ConversationSummary,
    ProcessedApplication,
};
use crate::health::DeliveryHealth;
use crate::persistence::{MessageDirection, StoredHistoryMessage};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 100;
const MESSAGE_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
const INVITATION_VALIDITY_SECONDS: u64 = 24 * 60 * 60;
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateInvitationRequest {
    conversation_id: String,
    expected_device_id: String,
    role: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateJoinProofRequest {
    invitation: String,
    routing_id: String,
    issuer_public_key: String,
    peer_bindings: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddMemberRequest {
    conversation_id: String,
    join_proof: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AcceptWelcomeRequest {
    conversation_id: String,
    welcome: String,
    cursor: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RemoveMemberRequest {
    conversation_id: String,
    device_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ChangeMemberRoleRequest {
    conversation_id: String,
    device_id: String,
    role: String,
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
struct IdentityResult {
    device_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct InvitationResult {
    conversation_id: String,
    invitation: String,
    routing_id: String,
    issuer_public_key: String,
    peer_bindings: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct JoinProofResult {
    conversation_id: String,
    join_proof: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct MembershipResult {
    conversation_id: String,
    operation_id: String,
    cursor: u64,
    welcome: Option<String>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetAutoDeliveryRequest {
    conversation_id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeliveryStatusRequest {
    conversation_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct DeliveryStatusResult {
    pending_events: u32,
    claimed_events: u32,
    watched_conversations: u32,
    delivery_degraded: bool,
    auto_delivery_enabled: Option<bool>,
}

#[derive(Clone)]
pub(crate) struct StdioServer {
    conversations: ConversationCoordinator,
    applications: Option<ApplicationService<RelayClient>>,
    health: DeliveryHealth,
    authorize: AuthorizationHook,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl StdioServer {
    pub(crate) fn new(
        conversations: ConversationCoordinator,
        applications: Option<ApplicationService<RelayClient>>,
        health: DeliveryHealth,
        authorize: AuthorizationHook,
    ) -> Self {
        Self {
            conversations,
            applications,
            health,
            authorize,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "set_auto_delivery",
        description = "Enable or mute automatic delivery of remote events for one conversation."
    )]
    async fn set_auto_delivery(
        &self,
        Parameters(request): Parameters<SetAutoDeliveryRequest>,
    ) -> Result<Json<DeliveryStatusResult>, String> {
        self.authorize("set_auto_delivery")?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let conversations = self.conversations.clone();
        let enabled = request.enabled;
        tokio::task::spawn_blocking(move || {
            conversations.set_adapter_delivery_enabled(conversation_id, enabled)
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;
        self.delivery_status_for(Some(conversation_id)).await
    }

    #[tool(
        name = "delivery_status",
        description = "Report automatic delivery health, and one conversation's mute state when given."
    )]
    async fn delivery_status(
        &self,
        Parameters(request): Parameters<DeliveryStatusRequest>,
    ) -> Result<Json<DeliveryStatusResult>, String> {
        self.authorize("delivery_status")?;
        let conversation_id = request
            .conversation_id
            .as_deref()
            .map(parse_conversation_id)
            .transpose()?;
        self.delivery_status_for(conversation_id).await
    }

    async fn delivery_status_for(
        &self,
        conversation_id: Option<ConversationId>,
    ) -> Result<Json<DeliveryStatusResult>, String> {
        let conversations = self.conversations.clone();
        let (counts, enabled) = tokio::task::spawn_blocking(move || {
            let counts = conversations.remote_event_counts()?;
            let enabled = conversation_id
                .map(|identifier| conversations.adapter_delivery_enabled(identifier))
                .transpose()?;
            Ok::<_, ConversationCoordinatorError>((counts, enabled))
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;

        Ok(Json(DeliveryStatusResult {
            pending_events: counts.0,
            claimed_events: counts.1,
            watched_conversations: self.health.watched_conversations(),
            delivery_degraded: self.health.is_degraded(),
            auto_delivery_enabled: enabled,
        }))
    }

    #[tool(
        name = "get_identity",
        description = "Return this daemon profile's public device identifier."
    )]
    async fn get_identity(&self) -> Result<Json<IdentityResult>, String> {
        self.authorize("get_identity")?;
        Ok(Json(IdentityResult {
            device_id: encode_hex(
                self.conversations
                    .device_id()
                    .map_err(tool_error)?
                    .as_bytes(),
            ),
        }))
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
        name = "create_invitation",
        description = "Create a signed one-time invitation package for one expected device."
    )]
    async fn create_invitation(
        &self,
        Parameters(request): Parameters<CreateInvitationRequest>,
    ) -> Result<Json<InvitationResult>, String> {
        self.authorize("create_invitation")?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let expected_device_id = parse_device_id(&request.expected_device_id)?;
        let role = parse_role(&request.role)?;
        let expires_at = current_unix_seconds()?
            .checked_add(INVITATION_VALIDITY_SECONDS)
            .ok_or_else(|| "system_time_unavailable".to_string())?;
        let conversations = self.conversations.clone();
        let package = tokio::task::spawn_blocking(move || {
            conversations.issue_invitation(conversation_id, expected_device_id, role, expires_at)
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;
        Ok(Json(InvitationResult {
            conversation_id: encode_hex(package.invitation.conversation_id().as_bytes()),
            invitation: encode_hex(&encode_invitation(&package.invitation).map_err(tool_error)?),
            routing_id: encode_hex(package.routing_id.as_bytes()),
            issuer_public_key: encode_hex(package.issuer_public_key.as_bytes()),
            peer_bindings: package
                .peer_bindings
                .iter()
                .map(|binding| {
                    encode_device_credential_binding(binding)
                        .map(|bytes| encode_hex(&bytes))
                        .map_err(tool_error)
                })
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }

    #[tool(
        name = "create_join_proof",
        description = "Validate an invitation package and create a durable one-time JoinProof."
    )]
    async fn create_join_proof(
        &self,
        Parameters(request): Parameters<CreateJoinProofRequest>,
    ) -> Result<Json<JoinProofResult>, String> {
        self.authorize("create_join_proof")?;
        let invitation = decode_invitation(&decode_hex_bytes(
            &request.invitation,
            MAX_RELAY_PAYLOAD_BYTES,
            "invalid_invitation",
        )?)
        .map_err(tool_error)?;
        let conversation_id = invitation.conversation_id();
        let routing_id = parse_routing_id(&request.routing_id)?;
        let issuer_public_key = parse_public_key(&request.issuer_public_key)?;
        if request.peer_bindings.is_empty()
            || request.peer_bindings.len() > KonclaveDomainCore::MAX_MEMBERS
        {
            return Err("invalid_peer_bindings".to_string());
        }
        let peer_bindings = request
            .peer_bindings
            .iter()
            .map(|binding| {
                decode_device_credential_binding(&decode_hex_bytes(
                    binding,
                    MAX_RELAY_PAYLOAD_BYTES,
                    "invalid_peer_binding",
                )?)
                .map_err(tool_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let now_unix_seconds = current_unix_seconds()?;
        let conversations = self.conversations.clone();
        let proof = tokio::task::spawn_blocking(move || {
            conversations.create_join_proof(
                invitation,
                routing_id,
                issuer_public_key,
                peer_bindings,
                now_unix_seconds,
            )
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;
        Ok(Json(JoinProofResult {
            conversation_id: encode_hex(conversation_id.as_bytes()),
            join_proof: encode_hex(&encode_join_proof(&proof).map_err(tool_error)?),
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
        let (sent_at, now, expires_at) = message_times()?;
        let sent = applications
            .send(SendApplicationRequest {
                conversation_id,
                message_id,
                content,
                reply_to,
                sent_at_unix_milliseconds: sent_at,
                now_unix_seconds: now,
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
        name = "add_member",
        description = "Validate a JoinProof and submit its encrypted membership Commit."
    )]
    async fn add_member(
        &self,
        Parameters(request): Parameters<AddMemberRequest>,
    ) -> Result<Json<MembershipResult>, String> {
        self.authorize("add_member")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let proof = decode_join_proof(&decode_hex_bytes(
            &request.join_proof,
            MAX_RELAY_PAYLOAD_BYTES,
            "invalid_join_proof",
        )?)
        .map_err(tool_error)?;
        let now = current_unix_seconds()?;
        let expires_at = now
            .checked_add(MESSAGE_RETENTION_SECONDS)
            .ok_or_else(|| "system_time_unavailable".to_string())?;
        let sent = applications
            .add_member(conversation_id, proof, now, expires_at)
            .await
            .map_err(tool_error)?;
        Ok(Json(membership_result(sent)))
    }

    #[tool(
        name = "accept_welcome",
        description = "Accept an encrypted Welcome for a durable pending join."
    )]
    async fn accept_welcome(
        &self,
        Parameters(request): Parameters<AcceptWelcomeRequest>,
    ) -> Result<Json<ConversationResult>, String> {
        self.authorize("accept_welcome")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let welcome = MlsWelcome::from_bytes(&decode_hex_bytes(
            &request.welcome,
            MAX_RELAY_PAYLOAD_BYTES,
            "invalid_welcome",
        )?)
        .map_err(tool_error)?;
        let summary = applications
            .accept_welcome(conversation_id, welcome, request.cursor)
            .await
            .map_err(tool_error)?;
        Ok(Json(conversation_result(summary)))
    }

    #[tool(
        name = "remove_member",
        description = "Submit an encrypted Commit removing one conversation device."
    )]
    async fn remove_member(
        &self,
        Parameters(request): Parameters<RemoveMemberRequest>,
    ) -> Result<Json<MembershipResult>, String> {
        self.authorize("remove_member")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let device_id = parse_device_id(&request.device_id)?;
        let now = current_unix_seconds()?;
        let expires_at = now
            .checked_add(MESSAGE_RETENTION_SECONDS)
            .ok_or_else(|| "system_time_unavailable".to_string())?;
        let sent = applications
            .remove_member(conversation_id, device_id, now, expires_at)
            .await
            .map_err(tool_error)?;
        Ok(Json(membership_result(sent)))
    }

    #[tool(
        name = "change_member_role",
        description = "Submit an encrypted Commit changing one conversation device role."
    )]
    async fn change_member_role(
        &self,
        Parameters(request): Parameters<ChangeMemberRoleRequest>,
    ) -> Result<Json<MembershipResult>, String> {
        self.authorize("change_member_role")?;
        let applications = self
            .applications
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let device_id = parse_device_id(&request.device_id)?;
        let role = parse_role(&request.role)?;
        let now = current_unix_seconds()?;
        let expires_at = now
            .checked_add(MESSAGE_RETENTION_SECONDS)
            .ok_or_else(|| "system_time_unavailable".to_string())?;
        let sent = applications
            .change_role(conversation_id, device_id, role, now, expires_at)
            .await
            .map_err(tool_error)?;
        Ok(Json(membership_result(sent)))
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
            .replay_once(
                conversation_id,
                MAX_PAGE_SIZE as u32,
                current_unix_seconds()?,
            )
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
            .watch_once(conversation_id, current_unix_seconds()?)
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
        "initialize" | "get_identity" | "list_conversations" | "read_messages"
        | "delivery_status" => Ok(()),
        "create_conversation"
        | "create_invitation"
        | "create_join_proof"
        | "add_member"
        | "accept_welcome"
        | "remove_member"
        | "change_member_role"
        | "send_message"
        | "sync_messages"
        | "set_auto_delivery"
        | "watch_messages"
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

fn parse_device_id(value: &str) -> Result<DeviceId, String> {
    decode_hex(value)
        .map(DeviceId::from_bytes)
        .map_err(|_| "invalid_device_id".to_string())
}

fn parse_routing_id(value: &str) -> Result<RoutingId, String> {
    decode_hex(value)
        .map(RoutingId::from_bytes)
        .map_err(|_| "invalid_routing_id".to_string())
}

fn parse_public_key(value: &str) -> Result<Ed25519PublicKey, String> {
    decode_hex(value)
        .map(Ed25519PublicKey::from_bytes)
        .map_err(|_| "invalid_issuer_public_key".to_string())
}

fn parse_role(value: &str) -> Result<ConversationRole, String> {
    match value {
        "administrator" => Ok(ConversationRole::Administrator),
        "member" => Ok(ConversationRole::Member),
        _ => Err("invalid_role".to_string()),
    }
}

fn page_size(value: Option<usize>) -> Result<usize, String> {
    let value = value.unwrap_or(DEFAULT_PAGE_SIZE);
    if (1..=MAX_PAGE_SIZE).contains(&value) {
        Ok(value)
    } else {
        Err("invalid_page_size".to_string())
    }
}

fn message_times() -> Result<(u64, u64, u64), String> {
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
    Ok((milliseconds, seconds, expires_at))
}

fn current_unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system_time_unavailable".to_string())
}

fn conversation_result(summary: ConversationSummary) -> ConversationResult {
    ConversationResult {
        conversation_id: encode_hex(summary.conversation_id.as_bytes()),
        routing_id: encode_hex(summary.routing_id.as_bytes()),
        epoch: summary.epoch,
    }
}

fn membership_result(sent: SentMembership) -> MembershipResult {
    MembershipResult {
        conversation_id: encode_hex(sent.conversation_id.as_bytes()),
        operation_id: encode_hex(sent.operation_id.as_bytes()),
        cursor: sent.cursor,
        welcome: sent.welcome.map(|welcome| encode_hex(&welcome)),
    }
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
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_hex_bytes(
    value: &str,
    maximum_bytes: usize,
    error: &'static str,
) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum_bytes.saturating_mul(2)
        || !value.is_ascii()
    {
        return Err(error.to_string());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            Ok((hex_nibble(pair[0]).map_err(|_| error.to_string())? << 4)
                | hex_nibble(pair[1]).map_err(|_| error.to_string())?)
        })
        .collect()
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
        AuthorizationContext, AuthorizationHook, DeliveryHealth, StdioServer,
        ensure_stdout_safe_diagnostics, local_stdio_authorization,
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
        read_only(AuthorizationContext {
            method: "get_identity",
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
        writable(AuthorizationContext {
            method: "create_invitation",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "accept_welcome",
        })
        .unwrap();
        assert!(writable(AuthorizationContext { method: "unknown" }).is_err());
    }

    #[test]
    fn delivery_status_reads_without_write_but_muting_requires_write() {
        let read_only = local_stdio_authorization(false);
        read_only(AuthorizationContext {
            method: "delivery_status",
        })
        .unwrap();
        assert!(
            read_only(AuthorizationContext {
                method: "set_auto_delivery",
            })
            .is_err()
        );
        local_stdio_authorization(true)(AuthorizationContext {
            method: "set_auto_delivery",
        })
        .unwrap();
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
            DeliveryHealth::default(),
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

        let identity = client
            .call_tool(CallToolRequestParams::new("get_identity"))
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(
            identity["device_id"].as_str().unwrap().len(),
            KonclaveDomainCore::DeviceId::LENGTH * 2
        );
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

    #[tokio::test]
    async fn auto_delivery_starts_muted_and_survives_a_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let health = DeliveryHealth::default();
        health.set_watched_conversations(2);
        health.set_degraded(true);
        let server_state = StdioServer::new(
            open_coordinator(root.path(), "mcp-delivery"),
            None,
            health,
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

        let created = client
            .call_tool(CallToolRequestParams::new("create_conversation"))
            .await
            .unwrap()
            .structured_content
            .unwrap();
        let conversation_id = created["conversation_id"].as_str().unwrap().to_owned();

        let muted = client
            .call_tool(
                CallToolRequestParams::new("delivery_status").with_arguments(
                    json!({"conversation_id": conversation_id})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(muted["auto_delivery_enabled"].as_bool(), Some(false));
        assert_eq!(muted["watched_conversations"].as_u64(), Some(2));
        assert_eq!(muted["delivery_degraded"].as_bool(), Some(true));
        assert_eq!(muted["pending_events"].as_u64(), Some(0));
        assert_eq!(muted["claimed_events"].as_u64(), Some(0));

        let enabled = client
            .call_tool(
                CallToolRequestParams::new("set_auto_delivery").with_arguments(
                    json!({"conversation_id": conversation_id, "enabled": true})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(enabled["auto_delivery_enabled"].as_bool(), Some(true));

        let observed = client
            .call_tool(
                CallToolRequestParams::new("delivery_status").with_arguments(
                    json!({"conversation_id": conversation_id})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(observed["auto_delivery_enabled"].as_bool(), Some(true));

        let remuted = client
            .call_tool(
                CallToolRequestParams::new("set_auto_delivery").with_arguments(
                    json!({"conversation_id": conversation_id, "enabled": false})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert_eq!(remuted["auto_delivery_enabled"].as_bool(), Some(false));

        let global = client
            .call_tool(CallToolRequestParams::new("delivery_status"))
            .await
            .unwrap()
            .structured_content
            .unwrap();
        assert!(global["auto_delivery_enabled"].is_null());

        client.close().await.unwrap();
        server.await.unwrap();
    }
}
