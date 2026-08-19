use prost::Message;

use KonclaveDomainCore::{
    KonclaveDomainError, MAX_APPLICATION_MESSAGE_BYTES, MAX_MEMBERS, MAX_PROTOBUF_TOP_LEVEL_FIELDS,
    MAX_RELAY_ENVELOPE_BYTES, MAX_REPLAY_PAGE_SIZE,
};

use super::{
    decode_acknowledge_request, decode_application_message, decode_conversation_state,
    decode_device_credential_binding, decode_invitation, decode_join_proof,
    decode_membership_change, decode_relay_envelope, decode_replay_page, decode_replay_request,
    decode_stored_relay_envelope, encode_acknowledge_request, encode_application_message,
    encode_conversation_state, encode_device_credential_binding, encode_invitation,
    encode_join_proof, encode_membership_change, encode_relay_envelope, encode_replay_page,
    encode_replay_request, encode_stored_relay_envelope,
};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const APPLICATION_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/application-message.bin");
const CREDENTIAL_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/device-credential-binding.bin");
const INVITATION_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/protocol/v1/invitation.bin");
const JOIN_PROOF_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/protocol/v1/join-proof.bin");
const CONVERSATION_STATE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/conversation-state.bin");
const MEMBERSHIP_CHANGE_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/protocol/v1/membership-change.bin");
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
