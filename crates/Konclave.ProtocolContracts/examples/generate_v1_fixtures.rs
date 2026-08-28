use std::fs;
use std::path::PathBuf;

use KonclaveDomainCore::{
    AcknowledgeRequest, AddMember, ApplicationContent, ApplicationMessage,
    CollaborationPolicyBundle, CollaborationPolicyDigest, CollaborationPolicyEffect,
    CollaborationPolicyLimits, CollaborationPolicyProposal, CollaborationPolicyProposalId,
    CollaborationPolicyResponse, CollaborationPolicyResponseOutcome, CollaborationPolicyRevocation,
    CollaborationPolicyStatement, ConversationId, ConversationRole, ConversationState,
    CredentialBindingHash, DeliveryClass, DeviceCredentialBinding, DeviceId, Ed25519PublicKey,
    Ed25519Signature, EnvelopeId, Invitation, InvitationId, InvitationNonce, JoinProof, Member,
    MembershipAuthorization, MembershipChange, MembershipOperationId, MessageId, ProtocolVersion,
    RelayEnvelope, ReplayPage, ReplayRequest, RoutingId, SignatureScheme, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    encode_acknowledge_request, encode_application_message, encode_collaboration_policy_bundle,
    encode_conversation_state, encode_device_credential_binding, encode_invitation,
    encode_join_proof, encode_membership_change, encode_membership_commit_bundle,
    encode_membership_control, encode_relay_envelope, encode_replay_page, encode_replay_request,
    encode_stored_relay_envelope,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("protocol")
        .join("v1");
    fs::create_dir_all(&output)?;

    write(
        &output,
        "application-message.bin",
        encode_application_message(&application_message())?,
    )?;
    let bundle_bytes = encode_collaboration_policy_bundle(&collaboration_policy_bundle())?;
    write(
        &output,
        "collaboration-policy-bundle.bin",
        bundle_bytes.clone(),
    )?;
    write(
        &output,
        "collaboration-policy-proposal-message.bin",
        encode_application_message(&collaboration_policy_proposal_message(bundle_bytes))?,
    )?;
    write(
        &output,
        "collaboration-policy-response-message.bin",
        encode_application_message(&collaboration_policy_response_message())?,
    )?;
    write(
        &output,
        "collaboration-policy-revocation-message.bin",
        encode_application_message(&collaboration_policy_revocation_message())?,
    )?;
    write(
        &output,
        "device-credential-binding.bin",
        encode_device_credential_binding(&credential(1))?,
    )?;
    write(
        &output,
        "invitation.bin",
        encode_invitation(&invitation(1))?,
    )?;
    write(
        &output,
        "route-bound-invitation.bin",
        encode_invitation(&route_bound_invitation(1))?,
    )?;
    write(
        &output,
        "join-proof.bin",
        encode_join_proof(&JoinProof::new(invitation(1), credential(1), vec![10; 32])?)?,
    )?;

    let state = ConversationState::new(
        ProtocolVersion::application_v1(),
        ConversationId::from_bytes([20; 32]),
        2,
        vec![
            Member::new(
                DeviceId::from_bytes([1; 32]),
                ConversationRole::Administrator,
                0,
            ),
            Member::new(DeviceId::from_bytes([2; 32]), ConversationRole::Member, 1),
        ],
        vec![
            InvitationId::from_bytes([21; 16]),
            InvitationId::from_bytes([22; 16]),
        ],
    )?;
    write(
        &output,
        "conversation-state.bin",
        encode_conversation_state(&state)?,
    )?;

    let membership = MembershipAuthorization::new(
        ProtocolVersion::application_v1(),
        ConversationId::from_bytes([30; 32]),
        2,
        MembershipOperationId::from_bytes([31; 16]),
        MembershipChange::Add(AddMember::new(
            DeviceId::from_bytes([32; 32]),
            ConversationRole::Member,
            InvitationId::from_bytes([33; 16]),
            CredentialBindingHash::from_bytes([34; 32]),
        )),
    );
    write(
        &output,
        "membership-change.bin",
        encode_membership_change(&membership)?,
    )?;
    write(
        &output,
        "membership-control.bin",
        encode_membership_control(
            &membership,
            Some(&JoinProof::new(invitation(1), credential(1), vec![10; 32])?),
        )?,
    )?;
    write(
        &output,
        "membership-commit-bundle.bin",
        encode_membership_commit_bundle(&[0x81; 32], &[0x82; 48])?,
    )?;

    let relay = relay_envelope(41);
    write(
        &output,
        "relay-envelope.bin",
        encode_relay_envelope(&relay)?,
    )?;
    let stored = StoredRelayEnvelope::new(relay_envelope(41), 1)?;
    write(
        &output,
        "stored-relay-envelope.bin",
        encode_stored_relay_envelope(&stored)?,
    )?;

    let replay_request = ReplayRequest::new(RoutingId::from_bytes([40; 32]), 0, 100)?;
    write(
        &output,
        "replay-request.bin",
        encode_replay_request(replay_request)?,
    )?;

    let replay_page = ReplayPage::new(
        vec![
            StoredRelayEnvelope::new(relay_envelope(41), 1)?,
            StoredRelayEnvelope::new(relay_envelope(42), 2)?,
        ],
        2,
        false,
    )?;
    write(
        &output,
        "replay-page.bin",
        encode_replay_page(&replay_page)?,
    )?;

    let acknowledgment = AcknowledgeRequest::new(RoutingId::from_bytes([40; 32]), 2)?;
    write(
        &output,
        "acknowledge-request.bin",
        encode_acknowledge_request(acknowledgment)?,
    )?;
    Ok(())
}

fn application_message() -> ApplicationMessage {
    ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([1; 16]),
        1,
        1_700_000_000_000,
        Some(MessageId::from_bytes([2; 16])),
        ApplicationContent::text("hello").expect("fixture text is valid"),
    )
    .expect("fixture message is valid")
}

fn collaboration_policy_proposal_message(canonical_bundle: Vec<u8>) -> ApplicationMessage {
    application_message_with(
        3,
        ApplicationContent::collaboration_policy_proposal(
            CollaborationPolicyProposal::new(
                CollaborationPolicyProposalId::from_bytes([40; 16]),
                collaboration_policy_digest(),
                canonical_bundle,
                Some(CollaborationPolicyDigest::from_bytes([41; 32])),
            )
            .expect("fixture proposal is valid"),
        ),
    )
}

fn collaboration_policy_response_message() -> ApplicationMessage {
    application_message_with(
        4,
        ApplicationContent::CollaborationPolicyResponse(CollaborationPolicyResponse::new(
            CollaborationPolicyProposalId::from_bytes([40; 16]),
            collaboration_policy_digest(),
            CollaborationPolicyResponseOutcome::Accepted,
        )),
    )
}

fn collaboration_policy_revocation_message() -> ApplicationMessage {
    application_message_with(
        5,
        ApplicationContent::CollaborationPolicyRevocation(CollaborationPolicyRevocation::new(
            collaboration_policy_digest(),
        )),
    )
}

fn application_message_with(id: u8, content: ApplicationContent) -> ApplicationMessage {
    ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([id; 16]),
        u64::from(id),
        1_700_000_000_000 + u64::from(id),
        None,
        content,
    )
    .expect("fixture message is valid")
}

fn collaboration_policy_digest() -> CollaborationPolicyDigest {
    CollaborationPolicyDigest::from_bytes([
        0xf8, 0x18, 0x9b, 0x64, 0x71, 0x27, 0xaa, 0x9f, 0xf9, 0xd0, 0x3f, 0x5c, 0x2d, 0x04, 0x8b,
        0xcd, 0x8e, 0xb8, 0x60, 0x06, 0x20, 0xbc, 0x17, 0x96, 0xc4, 0xc6, 0x68, 0xfa, 0x59, 0x90,
        0xeb, 0x2e,
    ])
}

fn collaboration_policy_bundle() -> CollaborationPolicyBundle {
    CollaborationPolicyBundle::new(
        ProtocolVersion::application_v1(),
        "contract-alignment",
        Some("Align the API contract and report decisions.".to_string()),
        vec![
            CollaborationPolicyStatement::new(
                "workspace-write",
                CollaborationPolicyEffect::RequireLocalApproval,
                "workspace.modify",
                Some("workspace.current".to_string()),
            )
            .expect("fixture write statement is valid"),
            CollaborationPolicyStatement::new(
                "conversation-reply",
                CollaborationPolicyEffect::Allow,
                "conversation.reply",
                None,
            )
            .expect("fixture reply statement is valid"),
        ],
        vec![
            "copilot.tool-interception".to_string(),
            "copilot.session-identity".to_string(),
        ],
        CollaborationPolicyLimits::new(None, None, Some(10_000), Some(1))
            .expect("fixture limits are valid"),
    )
    .expect("fixture policy is valid")
}

fn credential(device: u8) -> DeviceCredentialBinding {
    DeviceCredentialBinding::new(
        ProtocolVersion::application_v1(),
        DeviceId::from_bytes([device; 32]),
        ConversationId::from_bytes([6; 32]),
        SignatureScheme::Ed25519,
        Ed25519PublicKey::from_bytes([2; 32]),
        Ed25519PublicKey::from_bytes([3; 32]),
        Ed25519Signature::from_bytes([4; 64]),
    )
}

fn invitation(expected_device: u8) -> Invitation {
    Invitation::new(
        ProtocolVersion::application_v1(),
        InvitationId::from_bytes([5; 16]),
        ConversationId::from_bytes([6; 32]),
        None,
        DeviceId::from_bytes([expected_device; 32]),
        ConversationRole::Member,
        1_800_000_000,
        InvitationNonce::from_bytes([7; 32]),
        DeviceId::from_bytes([8; 32]),
        Ed25519Signature::from_bytes([9; 64]),
    )
    .expect("fixture invitation is valid")
}

fn route_bound_invitation(expected_device: u8) -> Invitation {
    Invitation::new(
        ProtocolVersion::application_v1(),
        InvitationId::from_bytes([5; 16]),
        ConversationId::from_bytes([6; 32]),
        Some(RoutingId::from_bytes([10; 32])),
        DeviceId::from_bytes([expected_device; 32]),
        ConversationRole::Member,
        1_800_000_000,
        InvitationNonce::from_bytes([7; 32]),
        DeviceId::from_bytes([8; 32]),
        Ed25519Signature::from_bytes([9; 64]),
    )
    .expect("route-bound fixture invitation is valid")
}

fn relay_envelope(envelope: u8) -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        RoutingId::from_bytes([40; 32]),
        EnvelopeId::from_bytes([envelope; 16]),
        DeliveryClass::GroupApplication,
        None,
        1_800_000_000,
        vec![42; 32],
    )
    .expect("fixture relay envelope is valid")
}

fn write(
    output: &std::path::Path,
    name: &str,
    bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(output.join(name), bytes)?;
    Ok(())
}
