use KonclaveA2AContracts::{InitialGetTaskRequest, InitialSendMessageRequest};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};
use sha2::{Digest as _, Sha256};

use crate::{
    A2AAgentId, A2AContextId, A2ADomainError, A2AMessageId, A2APartIndex, A2ATaskId, A2ATenantId,
};

const TASK_MAPPING_DOMAIN: &[u8] = b"konclave-a2a-task-mapping-v1\0";

/// Deployment-owned route from one published A2A agent to one Konclave target.
#[derive(Clone, PartialEq, Eq)]
pub struct A2AAgentRoute {
    agent_id: A2AAgentId,
    context_id: A2AContextId,
    tenant: Option<A2ATenantId>,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
}

impl A2AAgentRoute {
    /// Creates one explicit A2A-to-Konclave route.
    #[must_use]
    pub const fn new(
        agent_id: A2AAgentId,
        context_id: A2AContextId,
        tenant: Option<A2ATenantId>,
        conversation_id: ConversationId,
        target_device_id: DeviceId,
    ) -> Self {
        Self {
            agent_id,
            context_id,
            tenant,
            conversation_id,
            target_device_id,
        }
    }

    /// Returns the published agent identifier.
    #[must_use]
    pub const fn agent_id(&self) -> &A2AAgentId {
        &self.agent_id
    }

    /// Returns the deployment-owned A2A context.
    #[must_use]
    pub const fn context_id(&self) -> &A2AContextId {
        &self.context_id
    }

    /// Returns the optional deployment-owned tenant.
    #[must_use]
    pub const fn tenant(&self) -> Option<&A2ATenantId> {
        self.tenant.as_ref()
    }

    /// Returns the configured Konclave conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the configured exact Konclave responder.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }
}

/// Pure mapping from one validated A2A message to one Konclave directed request.
pub struct A2ADirectedRequestMapping {
    agent_id: A2AAgentId,
    context_id: A2AContextId,
    tenant: Option<A2ATenantId>,
    source_message_id: A2AMessageId,
    task_id: A2ATaskId,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
    request_message_id: MessageId,
    part_index: A2APartIndex,
    text: String,
    return_immediately: bool,
    history_length: Option<u32>,
}

impl A2ADirectedRequestMapping {
    /// Returns the selected published agent.
    #[must_use]
    pub const fn agent_id(&self) -> &A2AAgentId {
        &self.agent_id
    }

    /// Returns the deployment-owned A2A context.
    #[must_use]
    pub const fn context_id(&self) -> &A2AContextId {
        &self.context_id
    }

    /// Returns the deployment-owned tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> Option<&A2ATenantId> {
        self.tenant.as_ref()
    }

    /// Returns the caller's source message identifier.
    #[must_use]
    pub const fn source_message_id(&self) -> &A2AMessageId {
        &self.source_message_id
    }

    /// Returns the gateway-owned task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &A2ATaskId {
        &self.task_id
    }

    /// Returns the configured Konclave conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the configured exact Konclave responder.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the deterministic Konclave directed-request identifier.
    #[must_use]
    pub const fn request_message_id(&self) -> MessageId {
        self.request_message_id
    }

    /// Returns the source A2A text-part position.
    #[must_use]
    pub const fn part_index(&self) -> A2APartIndex {
        self.part_index
    }

    /// Returns the validated request body.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns whether the caller requested an immediate submitted-task response.
    #[must_use]
    pub const fn return_immediately(&self) -> bool {
        self.return_immediately
    }

    /// Returns the caller's bounded history request.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }
}

/// Task lookup scoped to one published agent.
#[derive(Clone, PartialEq, Eq)]
pub struct A2ATaskLookup {
    agent_id: A2AAgentId,
    task_id: A2ATaskId,
    tenant: Option<A2ATenantId>,
    history_length: Option<u32>,
}

impl A2ATaskLookup {
    /// Returns the selected published agent.
    #[must_use]
    pub const fn agent_id(&self) -> &A2AAgentId {
        &self.agent_id
    }

    /// Returns the exact task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &A2ATaskId {
        &self.task_id
    }

    /// Returns the route tenant.
    #[must_use]
    pub const fn tenant(&self) -> Option<&A2ATenantId> {
        self.tenant.as_ref()
    }

    /// Returns the requested history length.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }
}

/// Maps a validated initial-profile request onto one deployment-selected route.
///
/// Reusing the same source message identifier under the same route reproduces the
/// same A2A task and Konclave message identifiers. A conflicting retry therefore
/// reaches the same durable idempotency key for later storage comparison.
///
/// # Errors
///
/// Returns a typed error when tenant, context, or identifier invariants disagree.
pub fn map_initial_send_message(
    route: &A2AAgentRoute,
    request: InitialSendMessageRequest,
) -> Result<A2ADirectedRequestMapping, A2ADomainError> {
    require_tenant(route, request.tenant())?;
    let context_id = match request.context_id() {
        Some(context) => {
            let context = A2AContextId::parse(context.to_owned())?;
            if context != route.context_id {
                return Err(A2ADomainError::ContextMismatch);
            }
            context
        }
        None => route.context_id.clone(),
    };
    let source_message_id = A2AMessageId::parse(request.message_id().to_owned())?;
    let return_immediately = request.return_immediately();
    let history_length = request.history_length();
    let (task_id, request_message_id) =
        derive_task_mapping(route, &context_id, &source_message_id)?;
    Ok(A2ADirectedRequestMapping {
        agent_id: route.agent_id.clone(),
        context_id,
        tenant: route.tenant.clone(),
        source_message_id,
        task_id,
        conversation_id: route.conversation_id,
        target_device_id: route.target_device_id,
        request_message_id,
        part_index: A2APartIndex::from_position(0)?,
        text: request.into_text(),
        return_immediately,
        history_length,
    })
}

/// Maps a validated `GetTask` request onto one agent-scoped lookup.
///
/// # Errors
///
/// Returns a typed error when tenant or task-identifier invariants disagree.
pub fn map_initial_get_task(
    route: &A2AAgentRoute,
    request: InitialGetTaskRequest,
) -> Result<A2ATaskLookup, A2ADomainError> {
    require_tenant(route, request.tenant())?;
    Ok(A2ATaskLookup {
        agent_id: route.agent_id.clone(),
        task_id: A2ATaskId::parse(request.task_id().to_owned())?,
        tenant: route.tenant.clone(),
        history_length: request.history_length(),
    })
}

fn require_tenant(route: &A2AAgentRoute, request: Option<&str>) -> Result<(), A2ADomainError> {
    if route.tenant.as_ref().map(A2ATenantId::as_str) == request {
        Ok(())
    } else {
        Err(A2ADomainError::TenantMismatch)
    }
}

fn derive_task_mapping(
    route: &A2AAgentRoute,
    context_id: &A2AContextId,
    source_message_id: &A2AMessageId,
) -> Result<(A2ATaskId, MessageId), A2ADomainError> {
    let mut digest = Sha256::new();
    digest.update(TASK_MAPPING_DOMAIN);
    append_component(&mut digest, route.tenant.as_ref().map(A2ATenantId::as_str))?;
    append_component(&mut digest, Some(route.agent_id.as_str()))?;
    append_component(&mut digest, Some(context_id.as_str()))?;
    append_component(&mut digest, Some(source_message_id.as_str()))?;
    digest.update(route.conversation_id.as_bytes());
    digest.update(route.target_device_id.as_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let request_bytes: [u8; MessageId::LENGTH] =
        digest[..MessageId::LENGTH]
            .try_into()
            .map_err(|_| A2ADomainError::InvalidIdentifier {
                kind: "task_mapping",
            })?;
    let request_message_id = MessageId::from_bytes(request_bytes);
    let task_id = A2ATaskId::parse(encode_hex(&request_bytes))?;
    Ok((task_id, request_message_id))
}

fn append_component(digest: &mut Sha256, value: Option<&str>) -> Result<(), A2ADomainError> {
    let value = value.unwrap_or_default().as_bytes();
    let length = u16::try_from(value.len()).map_err(|_| A2ADomainError::InvalidIdentifier {
        kind: "task_mapping",
    })?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
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
