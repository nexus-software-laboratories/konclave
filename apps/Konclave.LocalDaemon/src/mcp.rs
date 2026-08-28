use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::RelayClient;
use KonclaveCryptographicCore::MlsWelcome;
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, DeviceId,
    Ed25519PublicKey, EnvelopeId, MAX_RELAY_PAYLOAD_BYTES, MessageId, PairingId, RoutingId,
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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::application::{ApplicationService, SendApplicationRequest, SentMembership};
use crate::conversation::{
    ConversationCoordinator, ConversationCoordinatorError, ConversationSummary,
    ProcessedApplication,
};
use crate::health::DeliveryHealth;
use crate::pairing_service::{MAX_AUTHORIZATION_WINDOW_SECONDS, PairingService, PairingStatus};
use crate::persistence::pairing::{PairingPhase, PairingRole};
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreatePairingCapabilityRequest {
    requested_role: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RedeemPairingCapabilityRequest {
    capability: String,
}

impl Drop for RedeemPairingCapabilityRequest {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PairingRequest {
    pairing_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AuthorizePairingJoinerRequest {
    pairing_id: String,
    conversation_id: String,
    granted_role: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AuthorizePairingInviterRequest {
    pairing_id: String,
    inviter_device_id: String,
    conversation_id: String,
    granted_role: String,
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
    active_conversation_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ActiveConversationResult {
    active_conversation_id: String,
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
    #[serde(flatten)]
    content: MessageContentResult,
    duplicate: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "content_type", rename_all = "snake_case")]
enum MessageContentResult {
    Text {
        text: String,
    },
    CollaborationPolicyProposal {
        proposal_id: String,
        policy_digest: String,
        replaces_policy_digest: Option<String>,
    },
    CollaborationPolicyResponse {
        proposal_id: String,
        policy_digest: String,
        outcome: &'static str,
    },
    CollaborationPolicyRevocation {
        policy_digest: String,
    },
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

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PairingStatusResult {
    pairing_id: String,
    local_role: String,
    phase: String,
    joiner_device_id: String,
    requested_role: String,
    inviter_device_id: Option<String>,
    granted_role: Option<String>,
    conversation_id: Option<String>,
    authorization_deadline_unix_seconds: u64,
    completion_deadline_unix_seconds: Option<u64>,
}

#[derive(Serialize, schemars::JsonSchema)]
struct PairingCapabilityResult {
    pairing: PairingStatusResult,
    capability: String,
}

impl Drop for PairingCapabilityResult {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PairingSyncResult {
    pairing: PairingStatusResult,
    processed_records: usize,
}

#[derive(Clone)]
pub(crate) struct StdioServer {
    conversations: ConversationCoordinator,
    applications: Option<ApplicationService<RelayClient>>,
    pairings: Option<PairingService<RelayClient>>,
    health: DeliveryHealth,
    authorize: AuthorizationHook,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl StdioServer {
    pub(crate) fn new(
        conversations: ConversationCoordinator,
        applications: Option<ApplicationService<RelayClient>>,
        pairings: Option<PairingService<RelayClient>>,
        health: DeliveryHealth,
        authorize: AuthorizationHook,
    ) -> Self {
        Self {
            conversations,
            applications,
            pairings,
            health,
            authorize,
            tool_router: Self::tool_router(),
        }
    }

    /// Dispatches one local-service operation through the same implementation used
    /// by the MCP adapter.
    ///
    /// The local RPC layer carries a bounded opaque payload. This method is the one
    /// JSON boundary that turns it into the existing typed tool request, invokes the
    /// corresponding handler, and encodes that handler's structured result. A new
    /// operation therefore cannot drift between MCP and local RPC implementations.
    ///
    /// # Errors
    ///
    /// Returns a bounded validation, authorization, domain, task, or encoding code.
    pub(crate) async fn dispatch_json(
        &self,
        operation: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        match operation {
            "get_identity" => {
                Self::require_empty_request(payload)?;
                Self::encode_json(self.get_identity().await?)
            }
            "create_conversation" => {
                Self::require_empty_request(payload)?;
                Self::encode_json(self.create_conversation().await?)
            }
            "list_conversations" => Self::encode_json(
                self.list_conversations(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "send_message" => {
                Self::encode_json(self.send_message(Self::parse_parameters(payload)?).await?)
            }
            "read_messages" => {
                Self::encode_json(self.read_messages(Self::parse_parameters(payload)?).await?)
            }
            "sync_messages" => {
                Self::encode_json(self.sync_messages(Self::parse_parameters(payload)?).await?)
            }
            "watch_messages" => Self::encode_json(
                self.watch_messages(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "create_invitation" => Self::encode_json(
                self.create_invitation(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "create_join_proof" => Self::encode_json(
                self.create_join_proof(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "add_member" => {
                Self::encode_json(self.add_member(Self::parse_parameters(payload)?).await?)
            }
            "accept_welcome" => Self::encode_json(
                self.accept_welcome(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "remove_member" => {
                Self::encode_json(self.remove_member(Self::parse_parameters(payload)?).await?)
            }
            "change_member_role" => Self::encode_json(
                self.change_member_role(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "create_pairing_capability" => Self::encode_json(
                self.create_pairing_capability(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "redeem_pairing_capability" => Self::encode_json(
                self.redeem_pairing_capability(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "get_pairing_status" => Self::encode_json(
                self.get_pairing_status(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "authorize_pairing_joiner" => Self::encode_json(
                self.authorize_pairing_joiner(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "authorize_pairing_inviter" => Self::encode_json(
                self.authorize_pairing_inviter(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "sync_pairing" => {
                Self::encode_json(self.sync_pairing(Self::parse_parameters(payload)?).await?)
            }
            "cancel_pairing" => Self::encode_json(
                self.cancel_pairing(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "set_active_conversation" => Self::encode_json(
                self.set_active_conversation(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "set_auto_delivery" => Self::encode_json(
                self.set_auto_delivery(Self::parse_parameters(payload)?)
                    .await?,
            ),
            "delivery_status" => Self::encode_json(
                self.delivery_status(Self::parse_parameters(payload)?)
                    .await?,
            ),
            _ => Err("unknown_operation".to_string()),
        }
    }

    #[tool(
        name = "set_active_conversation",
        description = "Select one existing conversation for implicit profile operations."
    )]
    async fn set_active_conversation(
        &self,
        Parameters(request): Parameters<ConversationRequest>,
    ) -> Result<Json<ActiveConversationResult>, String> {
        self.authorize("set_active_conversation")?;
        let conversation_id = parse_conversation_id(&request.conversation_id)?;
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.set_active_conversation(conversation_id))
            .await
            .map_err(|_| "task_failed".to_string())?
            .map_err(tool_error)?;
        Ok(Json(ActiveConversationResult {
            active_conversation_id: encode_hex(conversation_id.as_bytes()),
        }))
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

    fn parse_parameters<T: DeserializeOwned>(payload: &[u8]) -> Result<Parameters<T>, String> {
        serde_json::from_slice(payload)
            .map(Parameters)
            .map_err(|_| "invalid_request".to_string())
    }

    fn require_empty_request(payload: &[u8]) -> Result<(), String> {
        let value: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
        match value {
            serde_json::Value::Object(fields) if fields.is_empty() => Ok(()),
            _ => Err("invalid_request".to_string()),
        }
    }

    fn encode_json<T: Serialize>(Json(value): Json<T>) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&value).map_err(|_| "response_encoding_failed".to_string())
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
        description = "Return this profile's public device identifier."
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
        name = "create_pairing_capability",
        description = "Create the one short-lived capability another session needs to start pairing."
    )]
    async fn create_pairing_capability(
        &self,
        Parameters(request): Parameters<CreatePairingCapabilityRequest>,
    ) -> Result<Json<PairingCapabilityResult>, String> {
        self.authorize("create_pairing_capability")?;
        let pairings = self.pairing_service()?;
        let requested_role = parse_role(&request.requested_role)?;
        let now = current_unix_seconds()?;
        let expires_at = now
            .checked_add(MAX_AUTHORIZATION_WINDOW_SECONDS)
            .ok_or_else(|| "system_time_unavailable".to_string())?;
        let created = pairings
            .create_capability(requested_role, expires_at, now)
            .await
            .map_err(tool_error)?;
        let status = pairings
            .status(created.pairing_id)
            .await
            .map_err(tool_error)?;
        Ok(Json(PairingCapabilityResult {
            pairing: pairing_status_result(status),
            capability: created.capability.as_str().to_owned(),
        }))
    }

    #[tool(
        name = "redeem_pairing_capability",
        description = "Open an authorization request from a capability received from another session."
    )]
    async fn redeem_pairing_capability(
        &self,
        Parameters(request): Parameters<RedeemPairingCapabilityRequest>,
    ) -> Result<Json<PairingStatusResult>, String> {
        self.authorize("redeem_pairing_capability")?;
        let status = self
            .pairing_service()?
            .redeem_capability(&request.capability, current_unix_seconds()?)
            .await
            .map_err(tool_error)?;
        Ok(Json(pairing_status_result(status)))
    }

    #[tool(
        name = "get_pairing_status",
        description = "Show the authenticated identities, authorization decision, and progress for one pairing."
    )]
    async fn get_pairing_status(
        &self,
        Parameters(request): Parameters<PairingRequest>,
    ) -> Result<Json<PairingStatusResult>, String> {
        self.authorize("get_pairing_status")?;
        let status = self
            .pairing_service()?
            .status(parse_pairing_id(&request.pairing_id)?)
            .await
            .map_err(tool_error)?;
        Ok(Json(pairing_status_result(status)))
    }

    #[tool(
        name = "authorize_pairing_joiner",
        description = "Approve the requesting device for one conversation and role."
    )]
    async fn authorize_pairing_joiner(
        &self,
        Parameters(request): Parameters<AuthorizePairingJoinerRequest>,
    ) -> Result<Json<PairingStatusResult>, String> {
        self.authorize("authorize_pairing_joiner")?;
        let pairings = self.pairing_service()?;
        let pairing_id = parse_pairing_id(&request.pairing_id)?;
        pairings
            .authorize_joiner(
                pairing_id,
                parse_conversation_id(&request.conversation_id)?,
                parse_role(&request.granted_role)?,
                current_unix_seconds()?,
            )
            .await
            .map_err(tool_error)?;
        Ok(Json(pairing_status_result(
            pairings.status(pairing_id).await.map_err(tool_error)?,
        )))
    }

    #[tool(
        name = "authorize_pairing_inviter",
        description = "Approve the displayed inviter identity, conversation, and granted role."
    )]
    async fn authorize_pairing_inviter(
        &self,
        Parameters(request): Parameters<AuthorizePairingInviterRequest>,
    ) -> Result<Json<PairingStatusResult>, String> {
        self.authorize("authorize_pairing_inviter")?;
        let pairings = self.pairing_service()?;
        let pairing_id = parse_pairing_id(&request.pairing_id)?;
        pairings
            .authorize_inviter(
                pairing_id,
                parse_device_id(&request.inviter_device_id)?,
                parse_conversation_id(&request.conversation_id)?,
                parse_role(&request.granted_role)?,
                current_unix_seconds()?,
            )
            .await
            .map_err(tool_error)?;
        Ok(Json(pairing_status_result(
            pairings.status(pairing_id).await.map_err(tool_error)?,
        )))
    }

    #[tool(
        name = "sync_pairing",
        description = "Process the next available pairing records and return current progress."
    )]
    async fn sync_pairing(
        &self,
        Parameters(request): Parameters<PairingRequest>,
    ) -> Result<Json<PairingSyncResult>, String> {
        self.authorize("sync_pairing")?;
        let pairings = self.pairing_service()?;
        let pairing_id = parse_pairing_id(&request.pairing_id)?;
        let processed_records = pairings
            .replay_once(pairing_id, current_unix_seconds()?)
            .await
            .map_err(tool_error)?;
        Ok(Json(PairingSyncResult {
            pairing: pairing_status_result(pairings.status(pairing_id).await.map_err(tool_error)?),
            processed_records,
        }))
    }

    #[tool(
        name = "cancel_pairing",
        description = "Cancel an active pairing and safely undo membership when required."
    )]
    async fn cancel_pairing(
        &self,
        Parameters(request): Parameters<PairingRequest>,
    ) -> Result<Json<PairingStatusResult>, String> {
        self.authorize("cancel_pairing")?;
        let pairings = self.pairing_service()?;
        let pairing_id = parse_pairing_id(&request.pairing_id)?;
        pairings
            .cancel(pairing_id, current_unix_seconds()?)
            .await
            .map_err(tool_error)?;
        Ok(Json(pairing_status_result(
            pairings.status(pairing_id).await.map_err(tool_error)?,
        )))
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
        let (identifiers, active) = tokio::task::spawn_blocking(move || {
            Ok::<_, crate::conversation::ConversationCoordinatorError>((
                conversations.conversation_ids(after, limit)?,
                conversations.active_conversation_id()?,
            ))
        })
        .await
        .map_err(|_| "task_failed".to_string())?
        .map_err(tool_error)?;
        Ok(Json(ConversationListResult {
            conversation_ids: identifiers
                .into_iter()
                .map(|identifier| encode_hex(identifier.as_bytes()))
                .collect(),
            active_conversation_id: active.map(|identifier| encode_hex(identifier.as_bytes())),
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

    fn pairing_service(&self) -> Result<&PairingService<RelayClient>, String> {
        self.pairings
            .as_ref()
            .ok_or_else(|| "relay_not_configured".to_string())
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
        | "delivery_status" | "get_pairing_status" => Ok(()),
        "create_conversation"
        | "create_pairing_capability"
        | "redeem_pairing_capability"
        | "authorize_pairing_joiner"
        | "authorize_pairing_inviter"
        | "sync_pairing"
        | "cancel_pairing"
        | "create_invitation"
        | "create_join_proof"
        | "add_member"
        | "accept_welcome"
        | "remove_member"
        | "change_member_role"
        | "send_message"
        | "sync_messages"
        | "set_active_conversation"
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

fn parse_pairing_id(value: &str) -> Result<PairingId, String> {
    decode_hex(value)
        .map(PairingId::from_bytes)
        .map_err(|_| "invalid_pairing_id".to_string())
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

fn pairing_status_result(status: PairingStatus) -> PairingStatusResult {
    PairingStatusResult {
        pairing_id: encode_hex(status.pairing_id.as_bytes()),
        local_role: match status.role {
            PairingRole::Joiner => "joiner",
            PairingRole::Inviter => "inviter",
        }
        .to_string(),
        phase: match status.phase {
            PairingPhase::JoinerAwaitingInvitation => "joiner_awaiting_invitation",
            PairingPhase::JoinerAwaitingInviterAuthorization => {
                "joiner_awaiting_inviter_authorization"
            }
            PairingPhase::JoinerAwaitingWelcome => "joiner_awaiting_welcome",
            PairingPhase::InviterAwaitingAuthorization => "inviter_awaiting_authorization",
            PairingPhase::InviterAwaitingJoinProof => "inviter_awaiting_join_proof",
            PairingPhase::InviterAwaitingCompletion => "inviter_awaiting_completion",
            PairingPhase::Compensating => "compensating",
            PairingPhase::Completed => "completed",
            PairingPhase::Cancelled => "cancelled",
        }
        .to_string(),
        joiner_device_id: encode_hex(status.joiner_device_id.as_bytes()),
        requested_role: role_name(status.requested_role).to_string(),
        inviter_device_id: status
            .inviter_device_id
            .map(|identifier| encode_hex(identifier.as_bytes())),
        granted_role: status.granted_role.map(|role| role_name(role).to_string()),
        conversation_id: status
            .conversation_id
            .map(|identifier| encode_hex(identifier.as_bytes())),
        authorization_deadline_unix_seconds: status.authorization_deadline_unix_seconds,
        completion_deadline_unix_seconds: status.completion_deadline_unix_seconds,
    }
}

const fn role_name(role: ConversationRole) -> &'static str {
    match role {
        ConversationRole::Administrator => "administrator",
        ConversationRole::Member => "member",
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
    let content = match message.content() {
        ApplicationContent::Text(text) => MessageContentResult::Text { text: text.clone() },
        ApplicationContent::CollaborationPolicyProposal(proposal) => {
            MessageContentResult::CollaborationPolicyProposal {
                proposal_id: encode_hex(proposal.proposal_id().as_bytes()),
                policy_digest: encode_hex(proposal.policy_digest().as_bytes()),
                replaces_policy_digest: proposal
                    .replaces_policy_digest()
                    .map(|digest| encode_hex(digest.as_bytes())),
            }
        }
        ApplicationContent::CollaborationPolicyResponse(response) => {
            MessageContentResult::CollaborationPolicyResponse {
                proposal_id: encode_hex(response.proposal_id().as_bytes()),
                policy_digest: encode_hex(response.policy_digest().as_bytes()),
                outcome: match response.outcome() {
                    KonclaveDomainCore::CollaborationPolicyResponseOutcome::Accepted => "accepted",
                    KonclaveDomainCore::CollaborationPolicyResponseOutcome::Rejected => "rejected",
                },
            }
        }
        ApplicationContent::CollaborationPolicyRevocation(revocation) => {
            MessageContentResult::CollaborationPolicyRevocation {
                policy_digest: encode_hex(revocation.policy_digest().as_bytes()),
            }
        }
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
        content,
        duplicate,
    })
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
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
        ApplicationContent, ApplicationMessage, CollaborationPolicyDigest,
        CollaborationPolicyProposal, CollaborationPolicyProposalId, CollaborationPolicyResponse,
        CollaborationPolicyResponseOutcome, CollaborationPolicyRevocation, ConversationId,
        ConversationRole, DeviceId, EnvelopeId, MessageId, PairingId, ProtocolVersion,
    };
    use rmcp::model::CallToolRequestParams;
    use rmcp::{ClientHandler, ServiceExt};
    use serde_json::json;

    use super::{
        AuthorizationContext, AuthorizationHook, DeliveryHealth, StdioServer,
        ensure_stdout_safe_diagnostics, local_stdio_authorization, pairing_status_result,
    };
    use crate::conversation::ProcessedApplication;
    use crate::conversation::tests::open_coordinator;
    use crate::pairing_service::PairingStatus;
    use crate::persistence::MessageDirection;
    use crate::persistence::pairing::{PairingPhase, PairingRole};

    #[derive(Clone, Default)]
    struct TestClient;

    impl ClientHandler for TestClient {}

    #[test]
    fn copilot_tool_contract_fixture_matches_the_router() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/local-service/v1/copilot-tools.json"
        ))
        .unwrap();
        let actual = serde_json::to_value(StdioServer::tool_router().list_all()).unwrap();
        assert_eq!(actual, expected);
    }

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
        read_only(AuthorizationContext {
            method: "get_pairing_status",
        })
        .unwrap();
        assert!(
            read_only(AuthorizationContext {
                method: "create_conversation",
            })
            .is_err()
        );
        assert!(
            read_only(AuthorizationContext {
                method: "create_pairing_capability",
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
        writable(AuthorizationContext {
            method: "create_pairing_capability",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "redeem_pairing_capability",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "authorize_pairing_joiner",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "authorize_pairing_inviter",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "sync_pairing",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "cancel_pairing",
        })
        .unwrap();
        writable(AuthorizationContext {
            method: "set_active_conversation",
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
        assert!(
            read_only(AuthorizationContext {
                method: "set_active_conversation",
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

    #[test]
    fn message_results_preserve_typed_policy_exchange_metadata() {
        let proposal_id = CollaborationPolicyProposalId::from_bytes([5; 16]);
        let digest = CollaborationPolicyDigest::from_bytes([6; 32]);
        let replacement = CollaborationPolicyDigest::from_bytes([7; 32]);
        let contents = [
            ApplicationContent::collaboration_policy_proposal(
                CollaborationPolicyProposal::new(proposal_id, digest, vec![1], Some(replacement))
                    .unwrap(),
            ),
            ApplicationContent::CollaborationPolicyResponse(CollaborationPolicyResponse::new(
                proposal_id,
                digest,
                CollaborationPolicyResponseOutcome::Rejected,
            )),
            ApplicationContent::CollaborationPolicyRevocation(CollaborationPolicyRevocation::new(
                digest,
            )),
        ];

        let results = contents.map(|content| {
            let message = ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                MessageId::from_bytes([4; MessageId::LENGTH]),
                1,
                1_700_000_000_000,
                None,
                content,
            )
            .unwrap();
            serde_json::to_value(
                super::message_result(
                    ConversationId::from_bytes([1; ConversationId::LENGTH]),
                    1,
                    EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
                    DeviceId::from_bytes([3; DeviceId::LENGTH]),
                    0,
                    message,
                    "inbound",
                    false,
                )
                .unwrap(),
            )
            .unwrap()
        });

        assert_eq!(results[0]["content_type"], "collaboration_policy_proposal");
        assert_eq!(results[0]["proposal_id"], "05".repeat(16));
        assert_eq!(results[0]["replaces_policy_digest"], "07".repeat(32));
        assert_eq!(results[1]["content_type"], "collaboration_policy_response");
        assert_eq!(results[1]["outcome"], "rejected");
        assert_eq!(
            results[2]["content_type"],
            "collaboration_policy_revocation"
        );
        assert_eq!(results[2]["policy_digest"], "06".repeat(32));
    }

    #[test]
    fn pairing_status_uses_stable_public_names() {
        let result = pairing_status_result(PairingStatus {
            pairing_id: PairingId::from_bytes([1; PairingId::LENGTH]),
            role: PairingRole::Joiner,
            phase: PairingPhase::JoinerAwaitingInviterAuthorization,
            joiner_device_id: DeviceId::from_bytes([2; DeviceId::LENGTH]),
            requested_role: ConversationRole::Member,
            inviter_device_id: Some(DeviceId::from_bytes([3; DeviceId::LENGTH])),
            granted_role: Some(ConversationRole::Administrator),
            conversation_id: Some(ConversationId::from_bytes([4; ConversationId::LENGTH])),
            authorization_deadline_unix_seconds: 10,
            completion_deadline_unix_seconds: None,
        });
        assert_eq!(result.local_role, "joiner");
        assert_eq!(result.phase, "joiner_awaiting_inviter_authorization");
        assert_eq!(result.requested_role, "member");
        assert_eq!(result.granted_role.as_deref(), Some("administrator"));
    }

    #[tokio::test]
    async fn in_memory_client_observes_deterministic_server_identity() {
        let root = tempfile::tempdir().unwrap();
        let server_state = StdioServer::new(
            open_coordinator(root.path(), "mcp-test"),
            None,
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
        assert_eq!(
            listed["active_conversation_id"].as_str(),
            Some(conversation_id)
        );
        let selected = client
            .call_tool(
                CallToolRequestParams::new("set_active_conversation").with_arguments(
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
        assert_eq!(
            selected["active_conversation_id"].as_str(),
            Some(conversation_id)
        );
        let pairing_without_relay = client
            .call_tool(
                CallToolRequestParams::new("create_pairing_capability").with_arguments(
                    json!({"requested_role": "member"})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(pairing_without_relay.is_error, Some(true));

        client.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn creating_a_conversation_enables_delivery_and_muting_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let health = DeliveryHealth::default();
        health.set_watched_conversations(2);
        health.set_degraded(true);
        let server_state = StdioServer::new(
            open_coordinator(root.path(), "mcp-delivery"),
            None,
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
        assert_eq!(muted["auto_delivery_enabled"].as_bool(), Some(true));
        assert_eq!(muted["watched_conversations"].as_u64(), Some(2));
        assert_eq!(muted["delivery_degraded"].as_bool(), Some(true));
        assert_eq!(muted["pending_events"].as_u64(), Some(0));
        assert_eq!(muted["claimed_events"].as_u64(), Some(0));

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

        let reenabled = client
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
        assert_eq!(reenabled["auto_delivery_enabled"].as_bool(), Some(true));

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
