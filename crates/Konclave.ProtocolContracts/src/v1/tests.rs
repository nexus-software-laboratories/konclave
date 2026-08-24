use prost::Message;

use KonclaveDomainCore::{
    KonclaveDomainError, MAX_APPLICATION_MESSAGE_BYTES, MAX_MEMBERS, MAX_PROTOBUF_TOP_LEVEL_FIELDS,
    MAX_RELAY_ENVELOPE_BYTES, MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_SIZE,
};

use super::{
    decode_acknowledge_request, decode_application_message, decode_conversation_state,
    decode_device_credential_binding, decode_invitation, decode_join_proof,
    decode_membership_change, decode_membership_commit_bundle, decode_membership_control,
    decode_pairing_envelope, decode_pairing_offer, decode_relay_envelope, decode_replay_page,
    decode_replay_request, decode_stored_relay_envelope, encode_acknowledge_request,
    encode_application_message, encode_conversation_state, encode_device_credential_binding,
    encode_invitation, encode_join_proof, encode_membership_change,
    encode_membership_commit_bundle, encode_membership_control, encode_pairing_envelope,
    encode_pairing_offer, encode_relay_envelope, encode_replay_page, encode_replay_request,
    encode_stored_relay_envelope,
};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const APPLICATION_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/application-message.bin");
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
fn immutable_v1_fixtures_round_trip_exactly() {
    assert_eq!(
        encode_application_message(
            &decode_application_message(APPLICATION_FIXTURE).expect("fixture should decode")
        )
        .expect("fixture should encode"),
        APPLICATION_FIXTURE
    );
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
