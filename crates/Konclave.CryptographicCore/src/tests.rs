use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole,
    DeviceCredentialBinding, Ed25519PublicKey, MembershipAuthorization, MembershipChange,
    MembershipOperationId, MessageId, ProtocolVersion, RemoveMember, SignatureScheme,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_join_proof, encode_application_message, encode_join_proof,
    encode_membership_change,
};

use crate::{
    DeviceIdentity, KonclaveCryptographicError, MlsApplicationMessage, MlsCommit, MlsWelcome,
    verify_device_credential_binding, verify_invitation,
};

fn conversation_id(value: u8) -> ConversationId {
    ConversationId::from_bytes([value; ConversationId::LENGTH])
}

#[test]
fn device_binding_and_invitation_signatures_fail_closed() {
    let issuer = DeviceIdentity::generate().unwrap();
    let recipient = DeviceIdentity::generate().unwrap();
    let material = issuer
        .create_conversation_signing_material(conversation_id(1))
        .unwrap();
    let verified = verify_device_credential_binding(material.binding()).unwrap();
    assert_eq!(verified.binding().device_id(), issuer.device_id());

    let tampered = DeviceCredentialBinding::new(
        ProtocolVersion::application_v1(),
        material.binding().device_id(),
        material.binding().conversation_id(),
        SignatureScheme::Ed25519,
        material.binding().device_root_public_key(),
        Ed25519PublicKey::from_bytes([99; Ed25519PublicKey::LENGTH]),
        material.binding().device_binding_signature(),
    );
    assert_eq!(
        verify_device_credential_binding(&tampered).err(),
        Some(KonclaveCryptographicError::InvalidCredentialBinding)
    );

    let client = issuer
        .create_conversation_client(conversation_id(1))
        .unwrap();
    let replacement = issuer
        .create_conversation_signing_material(conversation_id(1))
        .unwrap();
    assert_eq!(
        client
            .register_verified_binding(
                verify_device_credential_binding(replacement.binding()).unwrap(),
            )
            .unwrap_err(),
        KonclaveCryptographicError::CredentialSigningKeyMismatch
    );

    let invitation = issuer
        .issue_invitation(
            conversation_id(1),
            recipient.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    verify_invitation(&invitation, issuer.public_key(), 99).unwrap();
    recipient
        .verify_invitation(&invitation, issuer.public_key(), 99)
        .unwrap();
    assert_eq!(
        DeviceIdentity::generate()
            .unwrap()
            .verify_invitation(&invitation, issuer.public_key(), 99)
            .unwrap_err(),
        KonclaveCryptographicError::InvitationDeviceMismatch
    );
    assert_eq!(
        verify_invitation(&invitation, issuer.public_key(), 100).unwrap_err(),
        KonclaveCryptographicError::ExpiredInvitation
    );
    assert_eq!(
        verify_invitation(
            &invitation,
            DeviceIdentity::generate().unwrap().public_key(),
            99
        )
        .unwrap_err(),
        KonclaveCryptographicError::InvalidInvitationSignature
    );
}

#[test]
fn mls_add_send_remove_flow_authenticates_sender_and_epochs() {
    let conversation_id = conversation_id(2);
    let alice_identity = DeviceIdentity::generate().unwrap();
    let bob_identity = DeviceIdentity::generate().unwrap();
    let alice_client = alice_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let mut bob_client = bob_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let alice_binding = alice_client.binding().clone();
    bob_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    let mut alice_group = alice_client.create_group().unwrap();

    let invitation = alice_identity
        .issue_invitation(
            conversation_id,
            bob_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let proof = bob_client
        .create_join_proof(&bob_identity, invitation, alice_identity.public_key(), 50)
        .unwrap();
    let add = alice_group.create_add_commit(proof, 50).unwrap();
    let authorization_bytes = encode_membership_change(add.authorization()).unwrap();
    assert!(
        !add.commit()
            .as_bytes()
            .windows(authorization_bytes.len())
            .any(|window| window == authorization_bytes)
    );
    let welcome = MlsWelcome::from_bytes(add.welcome().unwrap().as_bytes()).unwrap();
    alice_group.accept_pending_commit().unwrap();
    let mut bob_group = bob_client.join_group(&welcome).unwrap();
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(bob_group.epoch(), 1);

    let application = ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([7; MessageId::LENGTH]),
        1,
        1_700_000_000_000,
        None,
        ApplicationContent::text("hello").unwrap(),
    )
    .unwrap();
    let application_bytes = encode_application_message(&application).unwrap();
    let ciphertext = alice_group
        .encrypt_application_message(&application_bytes)
        .unwrap();
    assert!(matches!(
        MlsCommit::from_bytes(ciphertext.as_bytes()),
        Err(KonclaveCryptographicError::UnexpectedMlsMessage { .. })
    ));
    let received_ciphertext = MlsApplicationMessage::from_bytes(ciphertext.as_bytes()).unwrap();
    let plaintext = bob_group
        .decrypt_application_message(&received_ciphertext)
        .unwrap();
    assert_eq!(plaintext.authenticated_sender(), alice_identity.device_id());
    let decoded = decode_application_message(plaintext.plaintext()).unwrap();
    assert_eq!(
        decoded.message_id(),
        MessageId::from_bytes([7; MessageId::LENGTH])
    );

    assert_eq!(
        bob_group
            .create_remove_commit(alice_identity.device_id())
            .err(),
        Some(KonclaveCryptographicError::Domain(
            KonclaveDomainCore::KonclaveDomainError::UnauthorizedMembershipChange
        ))
    );

    let removal = alice_group
        .create_remove_commit(bob_identity.device_id())
        .unwrap();
    let removal_commit = MlsCommit::from_bytes(removal.commit().as_bytes()).unwrap();
    let applied = bob_group
        .process_membership_commit(&removal_commit, removal.authorization().clone(), None, 50)
        .unwrap();
    assert_eq!(applied.authenticated_sender(), alice_identity.device_id());
    assert!(applied.removed_self());
    alice_group.accept_pending_commit().unwrap();
    assert_eq!(alice_group.epoch(), 2);
    assert_eq!(bob_group.epoch(), 2);

    let after_removal = alice_group
        .encrypt_application_message(b"after removal")
        .unwrap();
    assert!(
        bob_group
            .decrypt_application_message(&after_removal)
            .is_err()
    );
}

#[test]
fn incoming_commit_must_match_the_exact_authorization() {
    let conversation_id = conversation_id(3);
    let alice_identity = DeviceIdentity::generate().unwrap();
    let bob_identity = DeviceIdentity::generate().unwrap();
    let alice_client = alice_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let mut bob_client = bob_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let alice_binding = alice_client.binding().clone();
    bob_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    let mut alice_group = alice_client.create_group().unwrap();
    let invitation = alice_identity
        .issue_invitation(
            conversation_id,
            bob_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let proof = bob_client
        .create_join_proof(&bob_identity, invitation, alice_identity.public_key(), 50)
        .unwrap();
    let add = alice_group.create_add_commit(proof, 50).unwrap();
    alice_group.accept_pending_commit().unwrap();
    let mut bob_group = bob_client.join_group(add.welcome().unwrap()).unwrap();

    let removal = alice_group
        .create_remove_commit(bob_identity.device_id())
        .unwrap();
    let wrong_authorization = MembershipAuthorization::new(
        ProtocolVersion::application_v1(),
        conversation_id,
        1,
        MembershipOperationId::from_bytes([9; MembershipOperationId::LENGTH]),
        MembershipChange::Remove(RemoveMember::new(bob_identity.device_id())),
    );
    assert!(
        bob_group
            .process_membership_commit(removal.commit(), wrong_authorization, None, 50)
            .is_err()
    );
    assert_eq!(bob_group.epoch(), 1);

    bob_group
        .process_membership_commit(removal.commit(), removal.authorization().clone(), None, 50)
        .unwrap();
}

#[test]
fn existing_member_can_validate_a_later_add_commit() {
    let conversation_id = conversation_id(4);
    let alice_identity = DeviceIdentity::generate().unwrap();
    let bob_identity = DeviceIdentity::generate().unwrap();
    let charlie_identity = DeviceIdentity::generate().unwrap();
    let alice_client = alice_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let mut bob_client = bob_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    let alice_binding = alice_client.binding().clone();
    let bob_binding = bob_client.binding().clone();
    bob_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    let mut alice_group = alice_client.create_group().unwrap();
    let bob_invitation = alice_identity
        .issue_invitation(
            conversation_id,
            bob_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let bob_proof = bob_client
        .create_join_proof(
            &bob_identity,
            bob_invitation,
            alice_identity.public_key(),
            50,
        )
        .unwrap();
    let bob_add = alice_group.create_add_commit(bob_proof, 50).unwrap();
    alice_group.accept_pending_commit().unwrap();
    let mut bob_group = bob_client.join_group(bob_add.welcome().unwrap()).unwrap();

    let mut charlie_client = charlie_identity
        .create_conversation_client(conversation_id)
        .unwrap();
    charlie_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    charlie_client
        .register_verified_binding(verify_device_credential_binding(&bob_binding).unwrap())
        .unwrap();

    let invitation = alice_identity
        .issue_invitation(
            conversation_id,
            charlie_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let charlie_proof = charlie_client
        .create_join_proof(
            &charlie_identity,
            invitation,
            alice_identity.public_key(),
            50,
        )
        .unwrap();
    let charlie_add = alice_group.create_add_commit(charlie_proof, 50).unwrap();
    let proof_bytes = encode_join_proof(charlie_add.join_proof().unwrap()).unwrap();
    let proof_for_bob = decode_join_proof(&proof_bytes).unwrap();
    bob_group
        .process_membership_commit(
            charlie_add.commit(),
            charlie_add.authorization().clone(),
            Some(proof_for_bob),
            50,
        )
        .unwrap();
    alice_group.accept_pending_commit().unwrap();
    let mut charlie_group = charlie_client
        .join_group(charlie_add.welcome().unwrap())
        .unwrap();
    assert_eq!(alice_group.epoch(), 2);
    assert_eq!(bob_group.epoch(), 2);
    assert_eq!(charlie_group.epoch(), 2);

    let role_change = alice_group
        .create_change_role_commit(bob_identity.device_id(), ConversationRole::Administrator)
        .unwrap();
    bob_group
        .process_membership_commit(
            role_change.commit(),
            role_change.authorization().clone(),
            None,
            50,
        )
        .unwrap();
    charlie_group
        .process_membership_commit(
            role_change.commit(),
            role_change.authorization().clone(),
            None,
            50,
        )
        .unwrap();
    alice_group.accept_pending_commit().unwrap();
    assert_eq!(
        alice_group
            .state()
            .member(bob_identity.device_id())
            .map(KonclaveDomainCore::Member::role),
        Some(ConversationRole::Administrator)
    );
    assert_eq!(alice_group.epoch(), 3);
    assert_eq!(bob_group.epoch(), 3);
    assert_eq!(charlie_group.epoch(), 3);
}
