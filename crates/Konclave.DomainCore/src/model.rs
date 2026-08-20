use std::collections::BTreeSet;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ConversationId, CredentialBindingHash, DeviceId, Ed25519PublicKey, Ed25519Signature,
    EnvelopeId, InvitationId, InvitationNonce, KonclaveDomainError, MembershipOperationId,
    MessageId, RoutingId,
};

/// Current Konclave application protocol major version.
pub const APPLICATION_PROTOCOL_MAJOR: u32 = 1;
/// Current Konclave application protocol minor version.
pub const APPLICATION_PROTOCOL_MINOR: u32 = 0;
/// Maximum encoded relay envelope size in protocol v1.
pub const MAX_RELAY_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Maximum opaque payload bytes after reserving relay-envelope framing overhead.
pub const MAX_RELAY_PAYLOAD_BYTES: usize = MAX_RELAY_ENVELOPE_BYTES - 1024;
/// Maximum encoded application message size in protocol v1.
pub const MAX_APPLICATION_MESSAGE_BYTES: usize = 256 * 1024;
/// Maximum UTF-8 byte length for text content in protocol v1.
pub const MAX_TEXT_BODY_BYTES: usize = MAX_APPLICATION_MESSAGE_BYTES - 1024;
/// Maximum active devices in one protocol v1 conversation.
pub const MAX_MEMBERS: usize = 128;
/// Maximum retained invitation identifiers in one membership snapshot.
pub const MAX_CONSUMED_INVITATIONS: usize = 1024;
/// Maximum MLS KeyPackage byte length accepted by a join proof.
pub const MAX_MLS_KEY_PACKAGE_BYTES: usize = 64 * 1024;
/// Maximum number of envelopes returned by one replay page.
pub const MAX_REPLAY_PAGE_SIZE: usize = 100;
/// Maximum encoded replay page size in protocol v1.
pub const MAX_REPLAY_PAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded replay request or acknowledgment size in protocol v1.
pub const MAX_RELAY_CONTROL_MESSAGE_BYTES: usize = 1024;
/// Maximum top-level fields accepted in one protocol v1 Protobuf message.
pub const MAX_PROTOBUF_TOP_LEVEL_FIELDS: usize = 4096;

/// Identifies one version of a Konclave protocol layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    major: u32,
    minor: u32,
}

impl ProtocolVersion {
    /// Creates a version with a positive major component.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::InvalidProtocolMajor`] when `major` is zero.
    pub fn new(major: u32, minor: u32) -> Result<Self, KonclaveDomainError> {
        if major == 0 {
            return Err(KonclaveDomainError::InvalidProtocolMajor);
        }
        Ok(Self { major, minor })
    }

    /// Returns the current application protocol version.
    #[must_use]
    pub const fn application_v1() -> Self {
        Self {
            major: APPLICATION_PROTOCOL_MAJOR,
            minor: APPLICATION_PROTOCOL_MINOR,
        }
    }

    /// Returns the major component.
    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Returns the minor component.
    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }
}

/// Application authorization assigned to a conversation member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConversationRole {
    Administrator,
    Member,
}

/// Signature algorithm for a public device credential binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    Ed25519,
}

/// Public binding between a device root and a conversation-scoped MLS signature key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCredentialBinding {
    version: ProtocolVersion,
    device_id: DeviceId,
    conversation_id: ConversationId,
    signature_scheme: SignatureScheme,
    device_root_public_key: Ed25519PublicKey,
    conversation_signature_public_key: Ed25519PublicKey,
    device_binding_signature: Ed25519Signature,
}

impl DeviceCredentialBinding {
    /// Creates a validated public credential binding.
    #[must_use]
    pub const fn new(
        version: ProtocolVersion,
        device_id: DeviceId,
        conversation_id: ConversationId,
        signature_scheme: SignatureScheme,
        device_root_public_key: Ed25519PublicKey,
        conversation_signature_public_key: Ed25519PublicKey,
        device_binding_signature: Ed25519Signature,
    ) -> Self {
        Self {
            version,
            device_id,
            conversation_id,
            signature_scheme,
            device_root_public_key,
            conversation_signature_public_key,
            device_binding_signature,
        }
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the bound device identity.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the conversation for which the signature key is authorized.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the signature algorithm.
    #[must_use]
    pub const fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    /// Returns the device root public key.
    #[must_use]
    pub const fn device_root_public_key(&self) -> Ed25519PublicKey {
        self.device_root_public_key
    }

    /// Returns the conversation-scoped signature public key.
    #[must_use]
    pub const fn conversation_signature_public_key(&self) -> Ed25519PublicKey {
        self.conversation_signature_public_key
    }

    /// Returns the device root signature over the canonical binding.
    #[must_use]
    pub const fn device_binding_signature(&self) -> Ed25519Signature {
        self.device_binding_signature
    }
}

/// Signed, device-bound authorization to request conversation membership.
pub struct Invitation {
    version: ProtocolVersion,
    invitation_id: InvitationId,
    conversation_id: ConversationId,
    routing_id: Option<RoutingId>,
    expected_device_id: DeviceId,
    role: ConversationRole,
    expires_at_unix_seconds: u64,
    nonce: InvitationNonce,
    issuer_device_id: DeviceId,
    issuer_signature: Ed25519Signature,
}

impl Invitation {
    /// Creates an invitation with a positive expiration timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::ZeroValue`] when
    /// `expires_at_unix_seconds` is zero.
    #[allow(
        clippy::too_many_arguments,
        reason = "the signed invitation fields remain explicit and atomic"
    )]
    pub fn new(
        version: ProtocolVersion,
        invitation_id: InvitationId,
        conversation_id: ConversationId,
        routing_id: Option<RoutingId>,
        expected_device_id: DeviceId,
        role: ConversationRole,
        expires_at_unix_seconds: u64,
        nonce: InvitationNonce,
        issuer_device_id: DeviceId,
        issuer_signature: Ed25519Signature,
    ) -> Result<Self, KonclaveDomainError> {
        require_positive(expires_at_unix_seconds, "expires_at_unix_seconds")?;
        Ok(Self {
            version,
            invitation_id,
            conversation_id,
            routing_id,
            expected_device_id,
            role,
            expires_at_unix_seconds,
            nonce,
            issuer_device_id,
            issuer_signature,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the invitation identifier.
    #[must_use]
    pub const fn invitation_id(&self) -> InvitationId {
        self.invitation_id
    }

    /// Returns the authorized conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the opaque relay route authenticated by this invitation.
    #[must_use]
    pub const fn routing_id(&self) -> Option<RoutingId> {
        self.routing_id
    }

    /// Returns the device identity that may redeem the invitation.
    #[must_use]
    pub const fn expected_device_id(&self) -> DeviceId {
        self.expected_device_id
    }

    /// Returns the role granted by the invitation.
    #[must_use]
    pub const fn role(&self) -> ConversationRole {
        self.role
    }

    /// Returns the absolute expiration timestamp.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the invitation nonce.
    #[must_use]
    pub const fn nonce(&self) -> &InvitationNonce {
        &self.nonce
    }

    /// Returns the administrator device that issued the invitation.
    #[must_use]
    pub const fn issuer_device_id(&self) -> DeviceId {
        self.issuer_device_id
    }

    /// Returns the administrator signature over the canonical invitation.
    #[must_use]
    pub const fn issuer_signature(&self) -> Ed25519Signature {
        self.issuer_signature
    }
}

/// Material presented to request an administrator-authorized MLS join.
pub struct JoinProof {
    invitation: Invitation,
    credential: DeviceCredentialBinding,
    mls_key_package: Vec<u8>,
}

impl JoinProof {
    /// Creates a bounded join proof whose credential matches the invitation.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the KeyPackage is empty or exceeds
    /// [`MAX_MLS_KEY_PACKAGE_BYTES`], or when the credential device or conversation
    /// differs from the invitation.
    pub fn new(
        invitation: Invitation,
        credential: DeviceCredentialBinding,
        mls_key_package: Vec<u8>,
    ) -> Result<Self, KonclaveDomainError> {
        require_length_range(
            mls_key_package.len(),
            1,
            MAX_MLS_KEY_PACKAGE_BYTES,
            "mls_key_package",
        )?;
        if invitation.expected_device_id != credential.device_id {
            return Err(KonclaveDomainError::MismatchedInvitedDevice);
        }
        if invitation.conversation_id != credential.conversation_id {
            return Err(KonclaveDomainError::MismatchedInvitedConversation);
        }
        Ok(Self {
            invitation,
            credential,
            mls_key_package,
        })
    }

    /// Returns the invitation.
    #[must_use]
    pub const fn invitation(&self) -> &Invitation {
        &self.invitation
    }

    /// Returns the device credential binding.
    #[must_use]
    pub const fn credential(&self) -> &DeviceCredentialBinding {
        &self.credential
    }

    /// Returns the opaque MLS KeyPackage bytes.
    #[must_use]
    pub fn mls_key_package(&self) -> &[u8] {
        &self.mls_key_package
    }
}

/// One authorized device in a conversation epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    device_id: DeviceId,
    role: ConversationRole,
    joined_epoch: u64,
}

impl Member {
    /// Creates an authorized member record.
    #[must_use]
    pub const fn new(device_id: DeviceId, role: ConversationRole, joined_epoch: u64) -> Self {
        Self {
            device_id,
            role,
            joined_epoch,
        }
    }

    /// Returns the device identifier.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the application role.
    #[must_use]
    pub const fn role(self) -> ConversationRole {
        self.role
    }

    /// Returns the epoch in which the device joined.
    #[must_use]
    pub const fn joined_epoch(self) -> u64 {
        self.joined_epoch
    }
}

/// Application-authorized membership state for one MLS epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationState {
    version: ProtocolVersion,
    conversation_id: ConversationId,
    epoch: u64,
    members: Vec<Member>,
    consumed_invitation_ids: Vec<InvitationId>,
}

impl ConversationState {
    /// Creates a bounded membership snapshot with unique devices and invitations.
    ///
    /// # Errors
    ///
    /// Returns a validation error for empty or oversized membership, duplicate
    /// identifiers, excessive invitation history, future join epochs, or absence of
    /// an administrator.
    pub fn new(
        version: ProtocolVersion,
        conversation_id: ConversationId,
        epoch: u64,
        members: Vec<Member>,
        consumed_invitation_ids: Vec<InvitationId>,
    ) -> Result<Self, KonclaveDomainError> {
        require_length_range(members.len(), 1, MAX_MEMBERS, "members")?;
        require_length_range(
            consumed_invitation_ids.len(),
            0,
            MAX_CONSUMED_INVITATIONS,
            "consumed_invitation_ids",
        )?;
        require_unique(
            members.iter().map(|member| member.device_id),
            "member_device_id",
        )?;
        require_unique(
            consumed_invitation_ids.iter().copied(),
            "consumed_invitation_id",
        )?;
        if let Some(member) = members.iter().find(|member| member.joined_epoch > epoch) {
            return Err(KonclaveDomainError::MemberJoinedAfterStateEpoch {
                joined_epoch: member.joined_epoch,
                state_epoch: epoch,
            });
        }
        if !members
            .iter()
            .any(|member| member.role == ConversationRole::Administrator)
        {
            return Err(KonclaveDomainError::MissingAdministrator);
        }
        Ok(Self {
            version,
            conversation_id,
            epoch,
            members,
            consumed_invitation_ids,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the conversation identifier.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the MLS epoch represented by this state.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the ordered members.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// Returns invitation identifiers consumed in authenticated state.
    #[must_use]
    pub fn consumed_invitation_ids(&self) -> &[InvitationId] {
        &self.consumed_invitation_ids
    }

    /// Returns the current member record for `device_id`, when present.
    #[must_use]
    pub fn member(&self, device_id: DeviceId) -> Option<Member> {
        self.members
            .iter()
            .copied()
            .find(|member| member.device_id == device_id)
    }

    /// Applies one authenticated membership authorization to the next MLS epoch.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the sender is not a current administrator,
    /// the authorization targets another version, conversation, or parent epoch,
    /// the next epoch is not exactly one greater, or the requested member or
    /// invitation transition contradicts current state.
    pub fn apply_membership_authorization(
        &self,
        authenticated_sender: DeviceId,
        authorization: &MembershipAuthorization,
        new_epoch: u64,
    ) -> Result<Self, KonclaveDomainError> {
        if authorization.version != self.version {
            return Err(KonclaveDomainError::MembershipVersionMismatch);
        }
        if authorization.conversation_id != self.conversation_id {
            return Err(KonclaveDomainError::MembershipConversationMismatch);
        }
        if authorization.parent_epoch != self.epoch {
            return Err(KonclaveDomainError::StaleMembershipEpoch);
        }
        if self.epoch.checked_add(1) != Some(new_epoch) {
            return Err(KonclaveDomainError::InvalidMembershipEpochAdvance);
        }
        if self.member(authenticated_sender).map(Member::role)
            != Some(ConversationRole::Administrator)
        {
            return Err(KonclaveDomainError::UnauthorizedMembershipChange);
        }

        let mut members = self.members.clone();
        let mut consumed_invitation_ids = self.consumed_invitation_ids.clone();
        match authorization.change() {
            MembershipChange::Add(add) => {
                if self.member(add.device_id()).is_some() {
                    return Err(KonclaveDomainError::MemberAlreadyExists);
                }
                if consumed_invitation_ids.contains(&add.invitation_id()) {
                    return Err(KonclaveDomainError::InvitationAlreadyConsumed);
                }
                members.push(Member::new(add.device_id(), add.role(), new_epoch));
                consumed_invitation_ids.push(add.invitation_id());
            }
            MembershipChange::Remove(remove) => {
                let index = members
                    .iter()
                    .position(|member| member.device_id == remove.device_id())
                    .ok_or(KonclaveDomainError::MemberNotFound)?;
                if members[index].role == ConversationRole::Administrator
                    && members
                        .iter()
                        .filter(|member| member.role == ConversationRole::Administrator)
                        .count()
                        == 1
                {
                    return Err(KonclaveDomainError::MissingAdministrator);
                }
                members.remove(index);
            }
            MembershipChange::ChangeRole(change) => {
                let administrator_count = members
                    .iter()
                    .filter(|member| member.role == ConversationRole::Administrator)
                    .count();
                let member = members
                    .iter_mut()
                    .find(|member| member.device_id == change.device_id())
                    .ok_or(KonclaveDomainError::MemberNotFound)?;
                if member.role == ConversationRole::Administrator
                    && change.role() != ConversationRole::Administrator
                    && administrator_count == 1
                {
                    return Err(KonclaveDomainError::MissingAdministrator);
                }
                member.role = change.role();
            }
        }

        Self::new(
            self.version,
            self.conversation_id,
            new_epoch,
            members,
            consumed_invitation_ids,
        )
    }
}

/// Application-authorized membership operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipChange {
    Add(AddMember),
    Remove(RemoveMember),
    ChangeRole(ChangeMemberRole),
}

/// Adds one invitation-bound device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddMember {
    device_id: DeviceId,
    role: ConversationRole,
    invitation_id: InvitationId,
    credential_binding_hash: CredentialBindingHash,
}

impl AddMember {
    /// Creates an add-member operation.
    #[must_use]
    pub const fn new(
        device_id: DeviceId,
        role: ConversationRole,
        invitation_id: InvitationId,
        credential_binding_hash: CredentialBindingHash,
    ) -> Self {
        Self {
            device_id,
            role,
            invitation_id,
            credential_binding_hash,
        }
    }

    /// Returns the device being added.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the granted role.
    #[must_use]
    pub const fn role(self) -> ConversationRole {
        self.role
    }

    /// Returns the authorizing invitation.
    #[must_use]
    pub const fn invitation_id(self) -> InvitationId {
        self.invitation_id
    }

    /// Returns the expected credential binding hash.
    #[must_use]
    pub const fn credential_binding_hash(self) -> CredentialBindingHash {
        self.credential_binding_hash
    }
}

/// Removes one device identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoveMember {
    device_id: DeviceId,
}

impl RemoveMember {
    /// Creates a remove-member operation.
    #[must_use]
    pub const fn new(device_id: DeviceId) -> Self {
        Self { device_id }
    }

    /// Returns the removed device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }
}

/// Replaces one member's application role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeMemberRole {
    device_id: DeviceId,
    role: ConversationRole,
}

impl ChangeMemberRole {
    /// Creates a role-change operation.
    #[must_use]
    pub const fn new(device_id: DeviceId, role: ConversationRole) -> Self {
        Self { device_id, role }
    }

    /// Returns the affected device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the replacement role.
    #[must_use]
    pub const fn role(self) -> ConversationRole {
        self.role
    }
}

/// Versioned authorization for one membership transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipAuthorization {
    version: ProtocolVersion,
    conversation_id: ConversationId,
    parent_epoch: u64,
    operation_id: MembershipOperationId,
    change: MembershipChange,
}

impl MembershipAuthorization {
    /// Creates a membership authorization.
    #[must_use]
    pub const fn new(
        version: ProtocolVersion,
        conversation_id: ConversationId,
        parent_epoch: u64,
        operation_id: MembershipOperationId,
        change: MembershipChange,
    ) -> Self {
        Self {
            version,
            conversation_id,
            parent_epoch,
            operation_id,
            change,
        }
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the conversation identifier.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the expected parent MLS epoch.
    #[must_use]
    pub const fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }

    /// Returns the operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> MembershipOperationId {
        self.operation_id
    }

    /// Returns the authorized change.
    #[must_use]
    pub const fn change(&self) -> &MembershipChange {
        &self.change
    }
}

/// Validated application content.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum ApplicationContent {
    Text(String),
}

impl ApplicationContent {
    /// Creates bounded, non-empty UTF-8 text content.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the body is empty or exceeds
    /// [`MAX_TEXT_BODY_BYTES`].
    pub fn text(body: impl Into<String>) -> Result<Self, KonclaveDomainError> {
        let body = body.into();
        if body.is_empty() {
            return Err(KonclaveDomainError::EmptyText { field: "text_body" });
        }
        if body.len() > MAX_TEXT_BODY_BYTES {
            return Err(KonclaveDomainError::TextTooLong {
                field: "text_body",
                maximum: MAX_TEXT_BODY_BYTES,
                actual: body.len(),
            });
        }
        Ok(Self::Text(body))
    }
}

/// Versioned application operation authenticated by MLS.
pub struct ApplicationMessage {
    version: ProtocolVersion,
    message_id: MessageId,
    sender_counter: u64,
    sent_at_unix_milliseconds: u64,
    reply_to: Option<MessageId>,
    content: ApplicationContent,
}

impl ApplicationMessage {
    /// Creates an application message with a positive sender counter.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::ZeroValue`] when `sender_counter` is zero.
    pub fn new(
        version: ProtocolVersion,
        message_id: MessageId,
        sender_counter: u64,
        sent_at_unix_milliseconds: u64,
        reply_to: Option<MessageId>,
        content: ApplicationContent,
    ) -> Result<Self, KonclaveDomainError> {
        require_positive(sender_counter, "sender_counter")?;
        Ok(Self {
            version,
            message_id,
            sender_counter,
            sent_at_unix_milliseconds,
            reply_to,
            content,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the message identifier.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the sender-local monotonic counter.
    #[must_use]
    pub const fn sender_counter(&self) -> u64 {
        self.sender_counter
    }

    /// Returns the sender-provided display timestamp.
    #[must_use]
    pub const fn sent_at_unix_milliseconds(&self) -> u64 {
        self.sent_at_unix_milliseconds
    }

    /// Returns the referenced message, when present.
    #[must_use]
    pub const fn reply_to(&self) -> Option<MessageId> {
        self.reply_to
    }

    /// Returns the validated content.
    #[must_use]
    pub const fn content(&self) -> &ApplicationContent {
        &self.content
    }
}

/// Relay-visible delivery class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryClass {
    KeyPackage,
    Welcome,
    GroupProposal,
    GroupCommit,
    GroupApplication,
}

impl DeliveryClass {
    /// Returns a stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyPackage => "key_package",
            Self::Welcome => "welcome",
            Self::GroupProposal => "group_proposal",
            Self::GroupCommit => "group_commit",
            Self::GroupApplication => "group_application",
        }
    }

    const fn requires_parent_epoch(self) -> bool {
        matches!(self, Self::GroupProposal | Self::GroupCommit)
    }
}

/// Opaque bytes plus allowlisted metadata accepted by a relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayEnvelope {
    version: ProtocolVersion,
    routing_id: RoutingId,
    envelope_id: EnvelopeId,
    delivery_class: DeliveryClass,
    expected_parent_epoch: Option<u64>,
    expires_at_unix_seconds: u64,
    payload: Vec<u8>,
}

impl RelayEnvelope {
    /// Creates a bounded envelope with delivery-class-consistent epoch metadata.
    ///
    /// # Errors
    ///
    /// Returns a validation error for empty or oversized payloads, zero expiration,
    /// or invalid parent-epoch presence.
    #[allow(
        clippy::too_many_arguments,
        reason = "the relay envelope fields remain explicit and atomic"
    )]
    pub fn new(
        version: ProtocolVersion,
        routing_id: RoutingId,
        envelope_id: EnvelopeId,
        delivery_class: DeliveryClass,
        expected_parent_epoch: Option<u64>,
        expires_at_unix_seconds: u64,
        payload: Vec<u8>,
    ) -> Result<Self, KonclaveDomainError> {
        require_length_range(payload.len(), 1, MAX_RELAY_PAYLOAD_BYTES, "relay_payload")?;
        require_positive(expires_at_unix_seconds, "expires_at_unix_seconds")?;
        if delivery_class.requires_parent_epoch() != expected_parent_epoch.is_some() {
            return Err(KonclaveDomainError::InvalidExpectedParentEpoch {
                delivery_class: delivery_class.as_str(),
            });
        }
        Ok(Self {
            version,
            routing_id,
            envelope_id,
            delivery_class,
            expected_parent_epoch,
            expires_at_unix_seconds,
            payload,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the relay routing identifier.
    #[must_use]
    pub const fn routing_id(&self) -> RoutingId {
        self.routing_id
    }

    /// Returns the idempotency identifier.
    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    /// Returns the delivery class.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }

    /// Returns the expected parent epoch for Proposal and Commit classes.
    #[must_use]
    pub const fn expected_parent_epoch(&self) -> Option<u64> {
        self.expected_parent_epoch
    }

    /// Returns the absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the opaque MLS or KeyPackage bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Relay envelope associated with a positive durable cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredRelayEnvelope {
    envelope: RelayEnvelope,
    cursor: u64,
}

impl StoredRelayEnvelope {
    /// Creates a stored envelope.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::ZeroValue`] when `cursor` is zero.
    pub fn new(envelope: RelayEnvelope, cursor: u64) -> Result<Self, KonclaveDomainError> {
        require_positive(cursor, "cursor")?;
        Ok(Self { envelope, cursor })
    }

    /// Returns the accepted envelope.
    #[must_use]
    pub const fn envelope(&self) -> &RelayEnvelope {
        &self.envelope
    }

    /// Returns the durable cursor.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
}

/// Bounded replay request for one route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayRequest {
    routing_id: RoutingId,
    after_cursor: u64,
    limit: u32,
}

impl ReplayRequest {
    /// Creates a replay request with a page size from 1 through
    /// [`MAX_REPLAY_PAGE_SIZE`].
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::OutOfRange`] for an invalid limit.
    pub fn new(
        routing_id: RoutingId,
        after_cursor: u64,
        limit: u32,
    ) -> Result<Self, KonclaveDomainError> {
        require_length_range(limit as usize, 1, MAX_REPLAY_PAGE_SIZE, "replay_limit")?;
        Ok(Self {
            routing_id,
            after_cursor,
            limit,
        })
    }

    /// Returns the route.
    #[must_use]
    pub const fn routing_id(self) -> RoutingId {
        self.routing_id
    }

    /// Returns the last durable cursor already processed.
    #[must_use]
    pub const fn after_cursor(self) -> u64 {
        self.after_cursor
    }

    /// Returns the requested page size.
    #[must_use]
    pub const fn limit(self) -> u32 {
        self.limit
    }
}

/// Ordered, bounded page of stored relay envelopes.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayPage {
    envelopes: Vec<StoredRelayEnvelope>,
    next_cursor: u64,
    has_more: bool,
}

impl ReplayPage {
    /// Creates a replay page with strictly increasing cursors.
    ///
    /// # Errors
    ///
    /// Returns a validation error for excessive page size, non-increasing cursors,
    /// or a `next_cursor` that precedes the final envelope.
    pub fn new(
        envelopes: Vec<StoredRelayEnvelope>,
        next_cursor: u64,
        has_more: bool,
    ) -> Result<Self, KonclaveDomainError> {
        require_length_range(envelopes.len(), 0, MAX_REPLAY_PAGE_SIZE, "replay_envelopes")?;
        if envelopes
            .windows(2)
            .any(|pair| pair[0].cursor >= pair[1].cursor)
            || envelopes
                .last()
                .is_some_and(|envelope| next_cursor < envelope.cursor)
        {
            return Err(KonclaveDomainError::InvalidReplayOrder);
        }
        Ok(Self {
            envelopes,
            next_cursor,
            has_more,
        })
    }

    /// Returns the ordered envelopes.
    #[must_use]
    pub fn envelopes(&self) -> &[StoredRelayEnvelope] {
        &self.envelopes
    }

    /// Returns the cursor to use for the next request.
    #[must_use]
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    /// Returns whether additional envelopes remain.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

/// Acknowledges one contiguous positive cursor for a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcknowledgeRequest {
    routing_id: RoutingId,
    cursor: u64,
}

impl AcknowledgeRequest {
    /// Creates an acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::ZeroValue`] when `cursor` is zero.
    pub fn new(routing_id: RoutingId, cursor: u64) -> Result<Self, KonclaveDomainError> {
        require_positive(cursor, "cursor")?;
        Ok(Self { routing_id, cursor })
    }

    /// Returns the route.
    #[must_use]
    pub const fn routing_id(self) -> RoutingId {
        self.routing_id
    }

    /// Returns the acknowledged cursor.
    #[must_use]
    pub const fn cursor(self) -> u64 {
        self.cursor
    }
}

fn require_positive(value: u64, field: &'static str) -> Result<(), KonclaveDomainError> {
    if value == 0 {
        return Err(KonclaveDomainError::ZeroValue { field });
    }
    Ok(())
}

fn require_length_range(
    actual: usize,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), KonclaveDomainError> {
    if actual < minimum || actual > maximum {
        return Err(KonclaveDomainError::OutOfRange {
            field,
            minimum,
            maximum,
            actual,
        });
    }
    Ok(())
}

fn require_unique<T>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), KonclaveDomainError>
where
    T: Ord,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(KonclaveDomainError::DuplicateIdentifier { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(value: u8) -> [u8; N] {
        [value; N]
    }

    #[test]
    fn conversation_state_requires_unique_members_and_an_administrator() {
        let device = DeviceId::from_bytes(bytes(1));
        let member = Member::new(device, ConversationRole::Member, 0);
        assert_eq!(
            ConversationState::new(
                ProtocolVersion::application_v1(),
                ConversationId::from_bytes(bytes(2)),
                0,
                vec![member],
                vec![],
            )
            .unwrap_err(),
            KonclaveDomainError::MissingAdministrator
        );

        let administrator = Member::new(device, ConversationRole::Administrator, 0);
        assert_eq!(
            ConversationState::new(
                ProtocolVersion::application_v1(),
                ConversationId::from_bytes(bytes(2)),
                0,
                vec![administrator, administrator],
                vec![],
            )
            .unwrap_err(),
            KonclaveDomainError::DuplicateIdentifier {
                field: "member_device_id"
            }
        );
    }

    #[test]
    fn join_proof_requires_the_invited_device() {
        let invited_device = DeviceId::from_bytes(bytes(1));
        let other_device = DeviceId::from_bytes(bytes(2));
        let invitation = Invitation::new(
            ProtocolVersion::application_v1(),
            InvitationId::from_bytes(bytes(3)),
            ConversationId::from_bytes(bytes(4)),
            None,
            invited_device,
            ConversationRole::Member,
            1,
            InvitationNonce::from_bytes(bytes(5)),
            DeviceId::from_bytes(bytes(6)),
            Ed25519Signature::from_bytes(bytes(7)),
        )
        .unwrap();
        let credential = DeviceCredentialBinding::new(
            ProtocolVersion::application_v1(),
            other_device,
            ConversationId::from_bytes(bytes(4)),
            SignatureScheme::Ed25519,
            Ed25519PublicKey::from_bytes(bytes(8)),
            Ed25519PublicKey::from_bytes(bytes(9)),
            Ed25519Signature::from_bytes(bytes(10)),
        );

        assert!(JoinProof::new(invitation, credential, vec![1]).is_err());
    }

    #[test]
    fn conversation_state_rejects_members_from_a_future_epoch() {
        let result = ConversationState::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes(bytes(1)),
            1,
            vec![Member::new(
                DeviceId::from_bytes(bytes(2)),
                ConversationRole::Administrator,
                2,
            )],
            vec![],
        );
        assert_eq!(
            result.unwrap_err(),
            KonclaveDomainError::MemberJoinedAfterStateEpoch {
                joined_epoch: 2,
                state_epoch: 1,
            }
        );
    }

    #[test]
    fn administrator_can_add_an_invited_member() {
        let administrator = DeviceId::from_bytes(bytes(1));
        let added = DeviceId::from_bytes(bytes(2));
        let invitation_id = InvitationId::from_bytes(bytes(3));
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes(bytes(4)),
            1,
            vec![Member::new(
                administrator,
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            state.conversation_id(),
            state.epoch(),
            MembershipOperationId::from_bytes(bytes(5)),
            MembershipChange::Add(AddMember::new(
                added,
                ConversationRole::Member,
                invitation_id,
                CredentialBindingHash::from_bytes(bytes(6)),
            )),
        );

        let next = state
            .apply_membership_authorization(administrator, &authorization, 2)
            .unwrap();

        assert_eq!(
            next.member(added).map(Member::role),
            Some(ConversationRole::Member)
        );
        assert_eq!(next.consumed_invitation_ids(), &[invitation_id]);

        let replay = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            next.conversation_id(),
            next.epoch(),
            MembershipOperationId::from_bytes(bytes(7)),
            MembershipChange::Add(AddMember::new(
                DeviceId::from_bytes(bytes(8)),
                ConversationRole::Member,
                invitation_id,
                CredentialBindingHash::from_bytes(bytes(9)),
            )),
        );
        assert_eq!(
            next.apply_membership_authorization(administrator, &replay, 3)
                .unwrap_err(),
            KonclaveDomainError::InvitationAlreadyConsumed
        );
    }

    #[test]
    fn membership_transition_requires_current_administrator_and_epoch() {
        let administrator = DeviceId::from_bytes(bytes(1));
        let member = DeviceId::from_bytes(bytes(2));
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes(bytes(3)),
            1,
            vec![
                Member::new(administrator, ConversationRole::Administrator, 0),
                Member::new(member, ConversationRole::Member, 1),
            ],
            vec![],
        )
        .unwrap();
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            state.conversation_id(),
            0,
            MembershipOperationId::from_bytes(bytes(4)),
            MembershipChange::Remove(RemoveMember::new(member)),
        );

        assert_eq!(
            state
                .apply_membership_authorization(member, &authorization, 2)
                .unwrap_err(),
            KonclaveDomainError::StaleMembershipEpoch
        );

        let current = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            state.conversation_id(),
            state.epoch(),
            MembershipOperationId::from_bytes(bytes(4)),
            MembershipChange::Remove(RemoveMember::new(member)),
        );
        assert_eq!(
            state
                .apply_membership_authorization(member, &current, 2)
                .unwrap_err(),
            KonclaveDomainError::UnauthorizedMembershipChange
        );
    }

    #[test]
    fn membership_transition_preserves_an_administrator() {
        let administrator = DeviceId::from_bytes(bytes(1));
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes(bytes(2)),
            1,
            vec![Member::new(
                administrator,
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            state.conversation_id(),
            state.epoch(),
            MembershipOperationId::from_bytes(bytes(3)),
            MembershipChange::Remove(RemoveMember::new(administrator)),
        );

        assert_eq!(
            state
                .apply_membership_authorization(administrator, &authorization, 2)
                .unwrap_err(),
            KonclaveDomainError::MissingAdministrator
        );
    }

    #[test]
    fn membership_transition_is_bound_to_version_conversation_and_next_epoch() {
        let administrator = DeviceId::from_bytes(bytes(1));
        let member = DeviceId::from_bytes(bytes(2));
        let conversation_id = ConversationId::from_bytes(bytes(3));
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            1,
            vec![
                Member::new(administrator, ConversationRole::Administrator, 0),
                Member::new(member, ConversationRole::Member, 1),
            ],
            vec![],
        )
        .unwrap();
        let change = MembershipChange::Remove(RemoveMember::new(member));

        let wrong_version = MembershipAuthorization::new(
            ProtocolVersion::new(1, 1).unwrap(),
            conversation_id,
            1,
            MembershipOperationId::from_bytes(bytes(4)),
            change.clone(),
        );
        assert_eq!(
            state
                .apply_membership_authorization(administrator, &wrong_version, 2)
                .unwrap_err(),
            KonclaveDomainError::MembershipVersionMismatch
        );

        let wrong_conversation = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes(bytes(5)),
            1,
            MembershipOperationId::from_bytes(bytes(4)),
            change.clone(),
        );
        assert_eq!(
            state
                .apply_membership_authorization(administrator, &wrong_conversation, 2)
                .unwrap_err(),
            KonclaveDomainError::MembershipConversationMismatch
        );

        let wrong_next_epoch = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            1,
            MembershipOperationId::from_bytes(bytes(4)),
            change,
        );
        assert_eq!(
            state
                .apply_membership_authorization(administrator, &wrong_next_epoch, 3)
                .unwrap_err(),
            KonclaveDomainError::InvalidMembershipEpochAdvance
        );
    }

    #[test]
    fn relay_commit_requires_expected_parent_epoch() {
        let result = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            RoutingId::from_bytes(bytes(1)),
            EnvelopeId::from_bytes(bytes(2)),
            DeliveryClass::GroupCommit,
            None,
            1,
            vec![1],
        );
        assert_eq!(
            result.err(),
            Some(KonclaveDomainError::InvalidExpectedParentEpoch {
                delivery_class: "group_commit"
            })
        );
    }

    #[test]
    fn replay_page_requires_strict_cursor_order() {
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            RoutingId::from_bytes(bytes(1)),
            EnvelopeId::from_bytes(bytes(2)),
            DeliveryClass::GroupApplication,
            None,
            1,
            vec![1],
        )
        .unwrap();
        let first = StoredRelayEnvelope::new(envelope.clone(), 2).unwrap();
        let second = StoredRelayEnvelope::new(envelope, 2).unwrap();
        assert_eq!(
            ReplayPage::new(vec![first, second], 2, false).err(),
            Some(KonclaveDomainError::InvalidReplayOrder)
        );
    }
}
