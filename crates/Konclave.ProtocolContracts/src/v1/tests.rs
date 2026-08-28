use prost::Message;

use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, CollaborationPolicyDigest, CollaborationPolicyProposal,
    CollaborationPolicyProposalId, CollaborationPolicyResponse, CollaborationPolicyResponseOutcome,
    CollaborationPolicyRevocation, KonclaveDomainError, MAX_APPLICATION_MESSAGE_BYTES,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES, MAX_COLLABORATION_POLICY_STATEMENTS, MAX_MEMBERS,
    MAX_PROTOBUF_TOP_LEVEL_FIELDS, MAX_RELAY_ENVELOPE_BYTES, MAX_RELAY_PAYLOAD_BYTES,
    MAX_REPLAY_PAGE_SIZE, MessageId, ProtocolVersion,
};
use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayEnrollmentResponse,
    RelayPrincipalId,
};

use super::{
    decode_acknowledge_request, decode_application_message, decode_collaboration_policy_bundle,
    decode_conversation_state, decode_device_credential_binding, decode_invitation,
    decode_join_proof, decode_membership_change, decode_membership_commit_bundle,
    decode_membership_control, decode_pairing_control, decode_pairing_envelope,
    decode_pairing_invitation, decode_pairing_offer, decode_pairing_welcome,
    decode_relay_enrollment_request, decode_relay_enrollment_response, decode_relay_envelope,
    decode_replay_page, decode_replay_request, decode_stored_relay_envelope,
    encode_acknowledge_request, encode_application_message, encode_collaboration_policy_bundle,
    encode_conversation_state, encode_device_credential_binding, encode_invitation,
    encode_join_proof, encode_membership_change, encode_membership_commit_bundle,
    encode_membership_control, encode_pairing_control, encode_pairing_envelope,
    encode_pairing_invitation, encode_pairing_offer, encode_pairing_welcome,
    encode_relay_enrollment_request, encode_relay_enrollment_response, encode_relay_envelope,
    encode_replay_page, encode_replay_request, encode_stored_relay_envelope,
};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const APPLICATION_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/application-message.bin");
const COLLABORATION_POLICY_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/collaboration-policy-bundle.bin");
const COLLABORATION_POLICY_PROPOSAL_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/collaboration-policy-proposal-message.bin");
const COLLABORATION_POLICY_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/collaboration-policy-response-message.bin");
const COLLABORATION_POLICY_REVOCATION_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/collaboration-policy-revocation-message.bin");
const CREDENTIAL_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/device-credential-binding.bin");
const INVITATION_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/protocol/v1/invitation.bin");
const ROUTE_BOUND_INVITATION_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/route-bound-invitation.bin");
const JOIN_PROOF_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/protocol/v1/join-proof.bin");
const CONVERSATION_STATE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/conversation-state.bin");
const MEMBERSHIP_CHANGE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/membership-change.bin");
const MEMBERSHIP_CONTROL_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/membership-control.bin");
const MEMBERSHIP_COMMIT_BUNDLE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/membership-commit-bundle.bin");
const RELAY_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/protocol/v1/relay-envelope.bin");
const STORED_RELAY_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/stored-relay-envelope.bin");
const REPLAY_REQUEST_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/replay-request.bin");
const REPLAY_PAGE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/replay-page.bin");
const ACKNOWLEDGE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/acknowledge-request.bin");

#[test]
fn enrollment_request_and_response_round_trip() {
    let request = RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([1; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_bytes([2; RelayPrincipalId::LENGTH]),
    );
    let encoded_request = encode_relay_enrollment_request(&request).unwrap();
    assert_eq!(
        decode_relay_enrollment_request(&encoded_request).unwrap(),
        request
    );
    let response = RelayEnrollmentResponse::new(
        request.version(),
        request.request_id(),
        request.principal_id(),
        RelayEnrollmentOutcome::Registered,
    );
    let encoded_response = encode_relay_enrollment_response(&response).unwrap();
    assert_eq!(
        decode_relay_enrollment_response(&encoded_response).unwrap(),
        response
    );
}

#[test]
fn enrollment_contract_rejects_wrong_lengths_and_unknown_outcomes() {
    let malformed = wire::RelayEnrollmentRequest {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        request_id: Some(wire::EnrollmentRequestId {
            value: vec![1; EnrollmentRequestId::LENGTH - 1].into(),
        }),
        principal_id: Some(wire::RelayPrincipalId {
            value: vec![2; RelayPrincipalId::LENGTH].into(),
        }),
    }
    .encode_to_vec();
    assert!(decode_relay_enrollment_request(&malformed).is_err());

    let unknown = wire::RelayEnrollmentResponse {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        request_id: Some(wire::EnrollmentRequestId {
            value: vec![1; EnrollmentRequestId::LENGTH].into(),
        }),
        principal_id: Some(wire::RelayPrincipalId {
            value: vec![2; RelayPrincipalId::LENGTH].into(),
        }),
        outcome: 99,
    }
    .encode_to_vec();
    assert!(matches!(
        decode_relay_enrollment_response(&unknown),
        Err(KonclaveProtocolError::UnsupportedEnum {
            field: "relay_enrollment_outcome",
            value: 99
        })
    ));
}

#[test]
fn immutable_v1_fixtures_round_trip_exactly() {
    assert_eq!(
        encode_application_message(
            &decode_application_message(APPLICATION_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        APPLICATION_FIXTURE
    );
    assert_eq!(
        encode_collaboration_policy_bundle(
            &decode_collaboration_policy_bundle(COLLABORATION_POLICY_FIXTURE)
                .expect("fixture should decode")
        )
        .expect("fixture should encode"),
        COLLABORATION_POLICY_FIXTURE
    );
    for fixture in [
        COLLABORATION_POLICY_PROPOSAL_FIXTURE,
        COLLABORATION_POLICY_RESPONSE_FIXTURE,
        COLLABORATION_POLICY_REVOCATION_FIXTURE,
    ] {
        assert_eq!(
            encode_application_message(
                &decode_application_message(fixture).expect("fixture should decode")
            )
            .expect("fixture should encode"),
            fixture
        );
    }
    assert_eq!(
        encode_device_credential_binding(
            &decode_device_credential_binding(CREDENTIAL_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        CREDENTIAL_FIXTURE
    );
    assert_eq!(
        encode_invitation(&decode_invitation(INVITATION_FIXTURE).expect("fixture should decode"))
            .expect("fixture should encode"),
        INVITATION_FIXTURE
    );
    assert_eq!(
        encode_invitation(
            &decode_invitation(ROUTE_BOUND_INVITATION_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        ROUTE_BOUND_INVITATION_FIXTURE
    );
    assert_eq!(
        encode_join_proof(&decode_join_proof(JOIN_PROOF_FIXTURE).expect("fixture should decode"))
            .expect("fixture should encode"),
        JOIN_PROOF_FIXTURE
    );
    assert_eq!(
        encode_conversation_state(
            &decode_conversation_state(CONVERSATION_STATE_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        CONVERSATION_STATE_FIXTURE
    );
    assert_eq!(
        encode_membership_change(
            &decode_membership_change(MEMBERSHIP_CHANGE_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        MEMBERSHIP_CHANGE_FIXTURE
    );
    let (authorization, proof) =
        decode_membership_control(MEMBERSHIP_CONTROL_FIXTURE).expect("fixture should decode");
    assert_eq!(
        encode_membership_control(&authorization, proof.as_ref()).expect("fixture should encode"),
        MEMBERSHIP_CONTROL_FIXTURE
    );
    let bundle = decode_membership_commit_bundle(MEMBERSHIP_COMMIT_BUNDLE_FIXTURE)
        .expect("fixture should decode");
    assert_eq!(
        encode_membership_commit_bundle(bundle.encrypted_control(), bundle.mls_commit(),)
            .expect("fixture should encode"),
        MEMBERSHIP_COMMIT_BUNDLE_FIXTURE
    );
    assert_eq!(
        encode_relay_envelope(
            &decode_relay_envelope(RELAY_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        RELAY_FIXTURE
    );
    assert_eq!(
        encode_stored_relay_envelope(
            &decode_stored_relay_envelope(STORED_RELAY_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        STORED_RELAY_FIXTURE
    );
    assert_eq!(
        encode_replay_request(
            decode_replay_request(REPLAY_REQUEST_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        REPLAY_REQUEST_FIXTURE
    );
    assert_eq!(
        encode_replay_page(
            &decode_replay_page(REPLAY_PAGE_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        REPLAY_PAGE_FIXTURE
    );
    assert_eq!(
        encode_acknowledge_request(
            decode_acknowledge_request(ACKNOWLEDGE_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        ACKNOWLEDGE_FIXTURE
    );
}

#[test]
fn collaboration_policy_contract_rejects_noncanonical_and_unbounded_input() {
    let unsorted = wire::CollaborationPolicyBundle {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        name: "contract-alignment".to_string(),
        guidance: None,
        statements: vec![
            wire::CollaborationPolicyStatement {
                statement_id: "z-last".to_string(),
                effect: wire::CollaborationPolicyEffect::Allow as i32,
                action: "conversation.reply".to_string(),
                resource: None,
            },
            wire::CollaborationPolicyStatement {
                statement_id: "a-first".to_string(),
                effect: wire::CollaborationPolicyEffect::Deny as i32,
                action: "workspace.modify".to_string(),
                resource: Some("workspace.current".to_string()),
            },
        ],
        required_harness_claims: vec![],
        limits: Some(wire::CollaborationPolicyLimits::default()),
    }
    .encode_to_vec();
    assert_eq!(
        decode_collaboration_policy_bundle(&unsorted).err(),
        Some(KonclaveProtocolError::NonCanonicalEncoding {
            contract: "CollaborationPolicyBundle"
        })
    );

    let unknown_effect = wire::CollaborationPolicyBundle {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        name: "contract-alignment".to_string(),
        guidance: None,
        statements: vec![wire::CollaborationPolicyStatement {
            statement_id: "reply".to_string(),
            effect: 99,
            action: "conversation.reply".to_string(),
            resource: None,
        }],
        required_harness_claims: vec![],
        limits: Some(wire::CollaborationPolicyLimits::default()),
    }
    .encode_to_vec();
    assert!(matches!(
        decode_collaboration_policy_bundle(&unknown_effect),
        Err(KonclaveProtocolError::UnsupportedEnum {
            field: "collaboration_policy_effect",
            value: 99
        })
    ));

    let oversized_count = wire::CollaborationPolicyBundle {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        name: "contract-alignment".to_string(),
        guidance: None,
        statements: (0..=MAX_COLLABORATION_POLICY_STATEMENTS)
            .map(|_| wire::CollaborationPolicyStatement::default())
            .collect(),
        required_harness_claims: vec![],
        limits: Some(wire::CollaborationPolicyLimits::default()),
    }
    .encode_to_vec();
    assert!(matches!(
        decode_collaboration_policy_bundle(&oversized_count),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::OutOfRange {
                field: "collaboration_policy_statements",
                ..
            }
        ))
    ));
}

#[test]
fn membership_control_and_commit_bundle_round_trip_canonical_bytes() {
    let authorization = decode_membership_change(MEMBERSHIP_CHANGE_FIXTURE).unwrap();
    let proof = decode_join_proof(JOIN_PROOF_FIXTURE).unwrap();
    let control = encode_membership_control(&authorization, Some(&proof)).unwrap();
    let (decoded_authorization, decoded_proof) = decode_membership_control(&control).unwrap();
    assert_eq!(
        encode_membership_change(&decoded_authorization).unwrap(),
        MEMBERSHIP_CHANGE_FIXTURE
    );
    assert_eq!(
        encode_join_proof(&decoded_proof.unwrap()).unwrap(),
        JOIN_PROOF_FIXTURE
    );

    let encoded = encode_membership_commit_bundle(&[0x81; 32], &[0x82; 48]).unwrap();
    let decoded = decode_membership_commit_bundle(&encoded).unwrap();
    assert_eq!(decoded.encrypted_control(), &[0x81; 32]);
    assert_eq!(decoded.mls_commit(), &[0x82; 48]);
}

#[test]
fn membership_client_framing_rejects_missing_or_oversized_fields() {
    let missing_control = wire::MembershipControl::default().encode_to_vec();
    assert_eq!(
        decode_membership_control(&missing_control).err(),
        Some(KonclaveProtocolError::MissingField {
            field: "membership_control.membership_change"
        })
    );
    assert_eq!(
        encode_membership_commit_bundle(&[], &[1]).err(),
        Some(KonclaveProtocolError::MissingField {
            field: "membership_commit_bundle.encrypted_control"
        })
    );
    let oversized = vec![1; MAX_RELAY_PAYLOAD_BYTES + 1];
    assert!(matches!(
        encode_membership_commit_bundle(&oversized, &[1]),
        Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "MembershipCommitBundle",
            ..
        })
    ));
    let aggregate_oversized = vec![1; MAX_RELAY_PAYLOAD_BYTES];
    assert!(matches!(
        encode_membership_commit_bundle(&aggregate_oversized, &[1]),
        Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "MembershipCommitBundle",
            ..
        })
    ));
}

#[test]
fn application_decode_rejects_bounds_version_and_missing_content() {
    assert!(matches!(
        decode_application_message(&vec![0; MAX_APPLICATION_MESSAGE_BYTES + 1]),
        Err(KonclaveProtocolError::EncodedMessageTooLarge { .. })
    ));

    let mut message =
        wire::ApplicationMessage::decode(APPLICATION_FIXTURE).expect("fixture wire should decode");
    message.version = Some(wire::ProtocolVersion { major: 2, minor: 0 });
    assert!(matches!(
        decode_application_message(&message.encode_to_vec()),
        Err(KonclaveProtocolError::UnsupportedMajor { actual: 2, .. })
    ));

    message.version = Some(wire::ProtocolVersion { major: 1, minor: 0 });
    message.content = None;
    assert_eq!(
        decode_application_message(&message.encode_to_vec()).err(),
        Some(KonclaveProtocolError::MissingVariant {
            field: "application_message.content"
        })
    );
}

#[test]
fn application_decode_ignores_additive_unknown_fields() {
    let mut extended = APPLICATION_FIXTURE.to_vec();
    extended.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert!(decode_application_message(&extended).is_ok());
}

#[test]
fn application_decode_rejects_top_level_field_count_amplification() {
    let field_bomb = [0x78, 0x00].repeat(MAX_PROTOBUF_TOP_LEVEL_FIELDS + 1);
    assert!(matches!(
        decode_application_message(&field_bomb),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::OutOfRange {
                field: "protobuf_top_level_fields",
                ..
            }
        ))
    ));
}

#[test]
fn collaboration_policy_exchange_application_content_round_trips() {
    let digest = CollaborationPolicyDigest::from_bytes([
        0xf8, 0x18, 0x9b, 0x64, 0x71, 0x27, 0xaa, 0x9f, 0xf9, 0xd0, 0x3f, 0x5c, 0x2d, 0x04, 0x8b,
        0xcd, 0x8e, 0xb8, 0x60, 0x06, 0x20, 0xbc, 0x17, 0x96, 0xc4, 0xc6, 0x68, 0xfa, 0x59, 0x90,
        0xeb, 0x2e,
    ]);
    let proposal_id = CollaborationPolicyProposalId::from_bytes([41; 16]);
    let replacement = CollaborationPolicyDigest::from_bytes([42; 32]);
    let values = [
        ApplicationContent::collaboration_policy_proposal(
            CollaborationPolicyProposal::new(
                proposal_id,
                digest,
                COLLABORATION_POLICY_FIXTURE.to_vec(),
                Some(replacement),
            )
            .unwrap(),
        ),
        ApplicationContent::CollaborationPolicyResponse(CollaborationPolicyResponse::new(
            proposal_id,
            digest,
            CollaborationPolicyResponseOutcome::Accepted,
        )),
        ApplicationContent::CollaborationPolicyRevocation(CollaborationPolicyRevocation::new(
            digest,
        )),
    ];

    for (index, content) in values.into_iter().enumerate() {
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([index as u8 + 50; 16]),
            index as u64 + 1,
            1_700_000_000_000,
            None,
            content,
        )
        .unwrap();
        let encoded = encode_application_message(&message).unwrap();
        let decoded = decode_application_message(&encoded).unwrap();
        assert_eq!(encode_application_message(&decoded).unwrap(), encoded);
    }
}

#[test]
fn collaboration_policy_exchange_rejects_malformed_wire_values() {
    let decode_proposal = |proposal| {
        let mut application = wire::ApplicationMessage::decode(APPLICATION_FIXTURE)
            .expect("fixture wire should decode");
        application.content =
            Some(wire::application_message::Content::CollaborationPolicyProposal(proposal));
        decode_application_message(&application.encode_to_vec())
    };
    let valid_proposal = wire::CollaborationPolicyProposal {
        proposal_id: Some(wire::CollaborationPolicyProposalId {
            value: vec![1; CollaborationPolicyProposalId::LENGTH].into(),
        }),
        policy_digest: Some(wire::CollaborationPolicyDigest {
            value: vec![2; CollaborationPolicyDigest::LENGTH].into(),
        }),
        canonical_bundle: vec![3].into(),
        replaces_policy_digest: None,
    };

    let mut malformed = valid_proposal.clone();
    malformed.proposal_id = Some(wire::CollaborationPolicyProposalId {
        value: vec![1; CollaborationPolicyProposalId::LENGTH - 1].into(),
    });
    assert!(decode_proposal(malformed).is_err());

    let mut malformed = valid_proposal.clone();
    malformed.policy_digest = Some(wire::CollaborationPolicyDigest {
        value: vec![2; CollaborationPolicyDigest::LENGTH - 1].into(),
    });
    assert!(decode_proposal(malformed).is_err());

    let mut malformed = valid_proposal.clone();
    malformed.replaces_policy_digest = Some(wire::CollaborationPolicyDigest {
        value: vec![2; CollaborationPolicyDigest::LENGTH - 1].into(),
    });
    assert!(decode_proposal(malformed).is_err());

    let mut empty = valid_proposal.clone();
    empty.canonical_bundle = Vec::new().into();
    assert!(decode_proposal(empty).is_err());

    let mut oversized = valid_proposal;
    oversized.canonical_bundle = vec![3; MAX_COLLABORATION_POLICY_BUNDLE_BYTES + 1].into();
    assert!(matches!(
        decode_proposal(oversized),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::OutOfRange {
                field: "collaboration_policy_bundle",
                ..
            }
        ))
    ));

    let mut application =
        wire::ApplicationMessage::decode(APPLICATION_FIXTURE).expect("fixture wire should decode");
    application.content = Some(
        wire::application_message::Content::CollaborationPolicyResponse(
            wire::CollaborationPolicyResponse {
                proposal_id: Some(wire::CollaborationPolicyProposalId {
                    value: vec![1; CollaborationPolicyProposalId::LENGTH].into(),
                }),
                policy_digest: Some(wire::CollaborationPolicyDigest {
                    value: vec![2; CollaborationPolicyDigest::LENGTH].into(),
                }),
                outcome: 99,
            },
        ),
    );
    assert_eq!(
        decode_application_message(&application.encode_to_vec()).err(),
        Some(KonclaveProtocolError::UnsupportedEnum {
            field: "collaboration_policy_response_outcome",
            value: 99
        })
    );

    for malformed in [&[0x58, 0x00][..], &[0x5a, 0x02, 0x00][..]] {
        assert!(matches!(
            decode_application_message(malformed),
            Err(KonclaveProtocolError::Decode {
                contract: "ApplicationMessage",
                ..
            })
        ));
    }
}

#[test]
fn invitation_binding_and_wire_shapes_are_validated() {
    let mut proof =
        wire::JoinProof::decode(JOIN_PROOF_FIXTURE).expect("fixture wire should decode");
    let credential = proof
        .credential
        .as_mut()
        .expect("fixture credential should exist");
    credential.device_id = Some(wire::DeviceId {
        value: prost::bytes::Bytes::from_static(&[99; 32]),
    });
    assert_eq!(
        decode_join_proof(&proof.encode_to_vec()).err(),
        Some(KonclaveProtocolError::Domain(
            KonclaveDomainError::MismatchedInvitedDevice
        ))
    );

    let mut proof =
        wire::JoinProof::decode(JOIN_PROOF_FIXTURE).expect("fixture wire should decode");
    let credential = proof
        .credential
        .as_mut()
        .expect("fixture credential should exist");
    credential.conversation_id = Some(wire::ConversationId {
        value: prost::bytes::Bytes::from_static(&[98; 32]),
    });
    assert_eq!(
        decode_join_proof(&proof.encode_to_vec()).err(),
        Some(KonclaveProtocolError::Domain(
            KonclaveDomainError::MismatchedInvitedConversation
        ))
    );

    let mut credential =
        wire::DeviceCredentialBinding::decode(CREDENTIAL_FIXTURE).expect("wire should decode");
    credential.signature_scheme = 99;
    assert_eq!(
        decode_device_credential_binding(&credential.encode_to_vec()).err(),
        Some(KonclaveProtocolError::UnsupportedEnum {
            field: "signature_scheme",
            value: 99
        })
    );

    credential.signature_scheme = wire::SignatureScheme::Ed25519 as i32;
    credential.device_root_public_key = prost::bytes::Bytes::from_static(&[1; 31]);
    assert!(matches!(
        decode_device_credential_binding(&credential.encode_to_vec()),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::InvalidLength {
                field: "ed25519_public_key",
                ..
            }
        ))
    ));
}

#[test]
fn relay_metadata_and_replay_order_are_validated() {
    assert!(matches!(
        decode_relay_envelope(&vec![0; MAX_RELAY_ENVELOPE_BYTES + 1]),
        Err(KonclaveProtocolError::EncodedMessageTooLarge { .. })
    ));

    let mut envelope =
        wire::RelayEnvelope::decode(RELAY_FIXTURE).expect("fixture wire should decode");
    envelope.delivery_class = 99;
    assert_eq!(
        decode_relay_envelope(&envelope.encode_to_vec()).err(),
        Some(KonclaveProtocolError::UnsupportedEnum {
            field: "delivery_class",
            value: 99
        })
    );

    envelope.delivery_class = wire::DeliveryClass::GroupCommit as i32;
    envelope.expected_parent_epoch = None;
    assert!(matches!(
        decode_relay_envelope(&envelope.encode_to_vec()),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::InvalidExpectedParentEpoch { .. }
        ))
    ));

    let mut page = wire::ReplayPage::decode(REPLAY_PAGE_FIXTURE).expect("wire should decode");
    page.envelopes[1].cursor = page.envelopes[0].cursor;
    assert_eq!(
        decode_replay_page(&page.encode_to_vec()).err(),
        Some(KonclaveProtocolError::Domain(
            KonclaveDomainError::InvalidReplayOrder
        ))
    );
}

#[test]
fn repeated_collections_are_bounded_before_message_materialization() {
    let member_bomb = [0x22, 0x00].repeat(MAX_MEMBERS + 1);
    assert!(matches!(
        decode_conversation_state(&member_bomb),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::OutOfRange {
                field: "members",
                ..
            }
        ))
    ));

    let replay_bomb = [0x0a, 0x00].repeat(MAX_REPLAY_PAGE_SIZE + 1);
    assert!(matches!(
        decode_replay_page(&replay_bomb),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::OutOfRange {
                field: "replay_envelopes",
                ..
            }
        ))
    ));

    assert!(matches!(
        decode_conversation_state(&[0x22, 0x80]),
        Err(KonclaveProtocolError::Decode { .. })
    ));
    assert!(matches!(
        decode_conversation_state(&[0x7b, 0x7c]),
        Err(KonclaveProtocolError::Decode { .. })
    ));
}

fn pairing_offer_fixture() -> KonclaveDomainCore::PairingOffer {
    KonclaveDomainCore::PairingOffer::new(
        KonclaveDomainCore::ProtocolVersion::application_v1(),
        KonclaveDomainCore::PairingId::from_bytes([3; KonclaveDomainCore::PairingId::LENGTH]),
        KonclaveDomainCore::DeviceId::from_bytes([4; KonclaveDomainCore::DeviceId::LENGTH]),
        KonclaveDomainCore::Ed25519PublicKey::from_bytes([5; 32]),
        KonclaveDomainCore::ConversationRole::Member,
        1_700_000_000,
        KonclaveDomainCore::PairingContextHash::from_bytes([7; 32]),
        KonclaveDomainCore::Ed25519Signature::from_bytes([6; 64]),
    )
    .unwrap()
}

#[test]
fn pairing_offer_round_trips() {
    let offer = pairing_offer_fixture();
    let decoded = decode_pairing_offer(&encode_pairing_offer(&offer).unwrap()).unwrap();

    assert_eq!(decoded.version(), offer.version());
    assert_eq!(decoded.pairing_id(), offer.pairing_id());
    assert_eq!(decoded.device_id(), offer.device_id());
    assert_eq!(
        decoded.device_root_public_key(),
        offer.device_root_public_key()
    );
    assert_eq!(decoded.requested_role(), offer.requested_role());
    assert_eq!(
        decoded.expires_at_unix_seconds(),
        offer.expires_at_unix_seconds()
    );
    assert_eq!(decoded.context_hash(), offer.context_hash());
    assert_eq!(decoded.device_signature(), offer.device_signature());
}

#[test]
fn pairing_offer_decoding_rejects_malformed_shapes() {
    let mut wire = wire::PairingOffer {
        version: None,
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());

    wire = wire::PairingOffer {
        pairing_id: None,
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());

    // A wrong-length key or signature must fail here rather than reaching verification
    // as a value that only looks like a key.
    wire = wire::PairingOffer {
        device_root_public_key: prost::bytes::Bytes::from_static(&[7; 31]),
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());

    wire = wire::PairingOffer {
        device_signature: prost::bytes::Bytes::from_static(&[7; 63]),
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());

    // Zero is not a role and must not decode as one.
    wire = wire::PairingOffer {
        requested_role: 0,
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());

    // An offer that never expires is not a bounded capability.
    wire = wire::PairingOffer {
        expires_at_unix_seconds: 0,
        ..pairing_offer_wire()
    };
    assert!(decode_pairing_offer(&wire.encode_to_vec()).is_err());
}

fn pairing_offer_wire() -> wire::PairingOffer {
    let encoded = encode_pairing_offer(&pairing_offer_fixture()).unwrap();
    wire::PairingOffer::decode(encoded.as_slice()).unwrap()
}

#[test]
fn pairing_envelopes_round_trip_and_carry_no_epoch() {
    let mut envelope = wire::RelayEnvelope::decode(RELAY_FIXTURE).unwrap();
    envelope.delivery_class = wire::DeliveryClass::Pairing as i32;
    envelope.expected_parent_epoch = None;

    let decoded = decode_relay_envelope(&envelope.encode_to_vec()).unwrap();
    assert_eq!(
        decoded.delivery_class(),
        KonclaveDomainCore::DeliveryClass::Pairing
    );
    assert_eq!(decoded.expected_parent_epoch(), None);
    assert_eq!(decoded.delivery_class().as_str(), "pairing");

    // Pairing happens before the joiner is in any group, so claiming a parent epoch
    // would assert membership in a group that does not include it yet.
    envelope.expected_parent_epoch = Some(1);
    assert!(matches!(
        decode_relay_envelope(&envelope.encode_to_vec()),
        Err(KonclaveProtocolError::Domain(
            KonclaveDomainError::InvalidExpectedParentEpoch { .. }
        ))
    ));
}

fn pairing_envelope_fixture() -> KonclaveDomainCore::PairingEnvelope {
    KonclaveDomainCore::PairingEnvelope::new(
        KonclaveDomainCore::ProtocolVersion::application_v1(),
        KonclaveDomainCore::PairingId::from_bytes([1; 16]),
        KonclaveDomainCore::PairingMessageId::from_bytes([2; 16]),
        KonclaveDomainCore::PairingSenderRole::Inviter,
        KonclaveDomainCore::PairingStage::Welcome,
        Some(KonclaveDomainCore::PairingMessageId::from_bytes([3; 16])),
        1_700_000_000,
        KonclaveDomainCore::PairingNonce::from_bytes([4; 12]),
        vec![5; 32],
    )
    .unwrap()
}

#[test]
fn authenticated_pairing_envelope_round_trips() {
    let envelope = pairing_envelope_fixture();
    let decoded = decode_pairing_envelope(&encode_pairing_envelope(&envelope).unwrap()).unwrap();

    assert_eq!(decoded.version(), envelope.version());
    assert_eq!(decoded.pairing_id(), envelope.pairing_id());
    assert_eq!(decoded.message_id(), envelope.message_id());
    assert_eq!(decoded.sender(), envelope.sender());
    assert_eq!(decoded.stage(), envelope.stage());
    assert_eq!(decoded.in_reply_to(), envelope.in_reply_to());
    assert_eq!(
        decoded.expires_at_unix_seconds(),
        envelope.expires_at_unix_seconds()
    );
    assert_eq!(decoded.nonce(), envelope.nonce());
    assert_eq!(decoded.ciphertext(), envelope.ciphertext());
}

#[test]
fn pairing_envelope_decoding_rejects_invalid_stage_grammar_and_bounds() {
    let wire = pairing_envelope_wire();

    for malformed in [
        wire::PairingEnvelope {
            sender: wire::PairingSenderRole::Joiner as i32,
            ..wire.clone()
        },
        wire::PairingEnvelope {
            in_reply_to: None,
            ..wire.clone()
        },
        wire::PairingEnvelope {
            expires_at_unix_seconds: 0,
            ..wire.clone()
        },
        wire::PairingEnvelope {
            nonce: prost::bytes::Bytes::from_static(&[0; 11]),
            ..wire.clone()
        },
        wire::PairingEnvelope {
            ciphertext: prost::bytes::Bytes::from_static(&[0; 15]),
            ..wire
        },
    ] {
        assert!(decode_pairing_envelope(&malformed.encode_to_vec()).is_err());
    }
}

#[test]
fn cancellation_accepts_either_sender_but_requires_a_reply() {
    for sender in [
        KonclaveDomainCore::PairingSenderRole::Inviter,
        KonclaveDomainCore::PairingSenderRole::Joiner,
    ] {
        assert!(
            KonclaveDomainCore::PairingEnvelope::new(
                KonclaveDomainCore::ProtocolVersion::application_v1(),
                KonclaveDomainCore::PairingId::from_bytes([1; 16]),
                KonclaveDomainCore::PairingMessageId::from_bytes([2; 16]),
                sender,
                KonclaveDomainCore::PairingStage::Cancellation,
                Some(KonclaveDomainCore::PairingMessageId::from_bytes([3; 16])),
                1_700_000_000,
                KonclaveDomainCore::PairingNonce::from_bytes([4; 12]),
                vec![5; 16],
            )
            .is_ok()
        );
    }
    assert!(
        KonclaveDomainCore::PairingEnvelope::new(
            KonclaveDomainCore::ProtocolVersion::application_v1(),
            KonclaveDomainCore::PairingId::from_bytes([1; 16]),
            KonclaveDomainCore::PairingMessageId::from_bytes([2; 16]),
            KonclaveDomainCore::PairingSenderRole::Joiner,
            KonclaveDomainCore::PairingStage::Cancellation,
            None,
            1_700_000_000,
            KonclaveDomainCore::PairingNonce::from_bytes([4; 12]),
            vec![5; 16],
        )
        .is_err()
    );
}

fn pairing_envelope_wire() -> wire::PairingEnvelope {
    let encoded = encode_pairing_envelope(&pairing_envelope_fixture()).unwrap();
    wire::PairingEnvelope::decode(encoded.as_slice()).unwrap()
}

fn pairing_invitation_fixture() -> KonclaveDomainCore::PairingInvitationPayload {
    let version = KonclaveDomainCore::ProtocolVersion::application_v1();
    let conversation_id = KonclaveDomainCore::ConversationId::from_bytes([21; 32]);
    let issuer = KonclaveDomainCore::DeviceId::from_bytes([22; 32]);
    let issuer_key = KonclaveDomainCore::Ed25519PublicKey::from_bytes([23; 32]);
    KonclaveDomainCore::PairingInvitationPayload::new(
        KonclaveDomainCore::Invitation::new(
            version,
            KonclaveDomainCore::InvitationId::from_bytes([24; 16]),
            conversation_id,
            Some(KonclaveDomainCore::RoutingId::from_bytes([25; 32])),
            KonclaveDomainCore::DeviceId::from_bytes([26; 32]),
            KonclaveDomainCore::ConversationRole::Member,
            1_700_000_000,
            KonclaveDomainCore::InvitationNonce::from_bytes([27; 32]),
            issuer,
            KonclaveDomainCore::Ed25519Signature::from_bytes([28; 64]),
        )
        .unwrap(),
        issuer_key,
        vec![KonclaveDomainCore::DeviceCredentialBinding::new(
            version,
            issuer,
            conversation_id,
            KonclaveDomainCore::SignatureScheme::Ed25519,
            issuer_key,
            KonclaveDomainCore::Ed25519PublicKey::from_bytes([29; 32]),
            KonclaveDomainCore::Ed25519Signature::from_bytes([30; 64]),
        )],
    )
    .unwrap()
}

#[test]
fn pairing_stage_payloads_round_trip() {
    let invitation = pairing_invitation_fixture();
    let decoded_invitation =
        decode_pairing_invitation(&encode_pairing_invitation(&invitation).unwrap()).unwrap();
    assert_eq!(
        encode_invitation(decoded_invitation.invitation()).unwrap(),
        encode_invitation(invitation.invitation()).unwrap()
    );
    assert_eq!(
        decoded_invitation.issuer_public_key(),
        invitation.issuer_public_key()
    );
    assert_eq!(
        decoded_invitation.peer_bindings(),
        invitation.peer_bindings()
    );

    let welcome = KonclaveDomainCore::PairingWelcomePayload::new(
        invitation.invitation().conversation_id(),
        b"opaque welcome".to_vec(),
        7,
    )
    .unwrap();
    let decoded_welcome =
        decode_pairing_welcome(&encode_pairing_welcome(&welcome).unwrap()).unwrap();
    assert_eq!(decoded_welcome.conversation_id(), welcome.conversation_id());
    assert_eq!(decoded_welcome.welcome(), welcome.welcome());
    assert_eq!(decoded_welcome.commit_cursor(), welcome.commit_cursor());

    let control = KonclaveDomainCore::PairingControl::new(
        KonclaveDomainCore::ProtocolVersion::application_v1(),
        KonclaveDomainCore::PairingId::from_bytes([31; 16]),
        KonclaveDomainCore::PairingMessageId::from_bytes([32; 16]),
        KonclaveDomainCore::PairingStage::Completion,
        KonclaveDomainCore::PairingMessageId::from_bytes([33; 16]),
        KonclaveDomainCore::DeviceId::from_bytes([34; 32]),
        welcome.conversation_id(),
        KonclaveDomainCore::Ed25519Signature::from_bytes([35; 64]),
    )
    .unwrap();
    assert_eq!(
        decode_pairing_control(&encode_pairing_control(&control).unwrap()).unwrap(),
        control
    );
}

#[test]
fn pairing_stage_payloads_reject_malformed_and_amplified_input() {
    let invitation = pairing_invitation_fixture();
    let encoded = encode_pairing_invitation(&invitation).unwrap();
    let mut wire = wire::PairingInvitationPayload::decode(encoded.as_slice()).unwrap();
    wire.issuer_public_key = prost::bytes::Bytes::from_static(&[0; 31]);
    assert!(decode_pairing_invitation(&wire.encode_to_vec()).is_err());

    let binding = wire.peer_bindings[0].clone();
    wire.peer_bindings = vec![binding; KonclaveDomainCore::MAX_MEMBERS + 1];
    assert!(decode_pairing_invitation(&wire.encode_to_vec()).is_err());

    let empty_welcome = wire::PairingWelcomePayload {
        conversation_id: Some(wire::ConversationId {
            value: prost::bytes::Bytes::from_static(&[1; 32]),
        }),
        welcome: prost::bytes::Bytes::new(),
        commit_cursor: 1,
    };
    assert!(decode_pairing_welcome(&empty_welcome.encode_to_vec()).is_err());

    let invalid_control = wire::PairingControl {
        version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        pairing_id: Some(wire::PairingId {
            value: prost::bytes::Bytes::from_static(&[1; 16]),
        }),
        message_id: Some(wire::PairingMessageId {
            value: prost::bytes::Bytes::from_static(&[2; 16]),
        }),
        stage: wire::PairingStage::Welcome as i32,
        in_reply_to: Some(wire::PairingMessageId {
            value: prost::bytes::Bytes::from_static(&[3; 16]),
        }),
        device_id: Some(wire::DeviceId {
            value: prost::bytes::Bytes::from_static(&[4; 32]),
        }),
        conversation_id: Some(wire::ConversationId {
            value: prost::bytes::Bytes::from_static(&[5; 32]),
        }),
        device_signature: prost::bytes::Bytes::from_static(&[6; 64]),
    };
    assert!(decode_pairing_control(&invalid_control.encode_to_vec()).is_err());
}
