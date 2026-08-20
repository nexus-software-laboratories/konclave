use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeviceCredentialBinding, Ed25519PublicKey, Invitation, InvitationNonce, Member,
    MembershipAuthorization, MembershipChange, MembershipOperationId, MessageId, ProtocolVersion,
    RemoveMember, RoutingId, SignatureScheme,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_join_proof, encode_application_message, encode_join_proof,
    encode_membership_change,
};
use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer};

use crate::{
    ConversationSigningMaterial, DeviceIdentity, KonclaveCryptographicError, MlsApplicationMessage,
    MlsCommit, MlsConversationClient, MlsWelcome, verify_device_credential_binding,
    verify_invitation,
};

fn conversation_id(value: u8) -> ConversationId {
    ConversationId::from_bytes([value; ConversationId::LENGTH])
}

fn routing_id(value: u8) -> RoutingId {
    RoutingId::from_bytes([value; RoutingId::LENGTH])
}

fn sealer(value: u8) -> SecretSealer {
    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([value; 32])).unwrap()
}

#[test]
fn sealed_mls_state_recovers_pending_join_commit_ratchets_and_removal() {
    let directory = tempfile::tempdir().unwrap();
    let conversation_id = conversation_id(9);
    let alice_identity = DeviceIdentity::generate().unwrap();
    let bob_identity = DeviceIdentity::generate().unwrap();

    let alice_material = alice_identity
        .create_conversation_signing_material(conversation_id)
        .unwrap();
    let alice_binding = alice_material.binding().clone();
    let alice_material_blob = alice_material.seal(&sealer(1), b"alice-profile").unwrap();
    let alice_storage_path = directory.path().join("alice.sqlite");
    let alice_storage = SealedSqliteMlsStorage::open(&alice_storage_path, sealer(1)).unwrap();
    let alice_client = MlsConversationClient::with_storage(alice_material, alice_storage).unwrap();
    let mut alice_group = alice_client.create_group().unwrap();

    let bob_material = bob_identity
        .create_conversation_signing_material(conversation_id)
        .unwrap();
    let bob_binding = bob_material.binding().clone();
    let bob_material_blob = bob_material.seal(&sealer(2), b"bob-profile").unwrap();
    let bob_storage_path = directory.path().join("bob.sqlite");
    let bob_storage = SealedSqliteMlsStorage::open(&bob_storage_path, sealer(2)).unwrap();
    let mut bob_client = MlsConversationClient::with_storage(bob_material, bob_storage).unwrap();
    bob_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    let invitation = alice_identity
        .issue_invitation(
            conversation_id,
            routing_id(1),
            bob_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let proof = bob_client
        .create_join_proof(&bob_identity, invitation, alice_identity.public_key(), 50)
        .unwrap();
    let proof_bytes = encode_join_proof(&proof).unwrap();
    let proof_for_alice = decode_join_proof(&proof_bytes).unwrap();
    drop(bob_client);

    let bob_material = ConversationSigningMaterial::open(
        &sealer(2),
        b"bob-profile",
        conversation_id,
        &bob_material_blob,
    )
    .unwrap();
    let bob_storage = SealedSqliteMlsStorage::open(&bob_storage_path, sealer(2)).unwrap();
    let mut bob_client = MlsConversationClient::with_storage(bob_material, bob_storage).unwrap();
    bob_client
        .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
        .unwrap();
    bob_client
        .restore_join_proof(&proof, alice_identity.public_key(), 50)
        .unwrap();

    let orphaned_add = alice_group.create_add_commit(proof_for_alice, 50).unwrap();
    let alice_parent_state = alice_group.state().clone();
    drop(alice_group);

    let alice_material = ConversationSigningMaterial::open(
        &sealer(1),
        b"alice-profile",
        conversation_id,
        &alice_material_blob,
    )
    .unwrap();
    let alice_storage = SealedSqliteMlsStorage::open(&alice_storage_path, sealer(1)).unwrap();
    let alice_client = MlsConversationClient::with_storage(alice_material, alice_storage).unwrap();
    let mut alice_group = alice_client
        .restore_group(
            alice_parent_state.clone(),
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            None,
        )
        .unwrap();
    alice_group.reject_pending_commit().unwrap();
    let add = alice_group
        .create_add_commit(decode_join_proof(&proof_bytes).unwrap(), 50)
        .unwrap();
    let alice_pending_state = add.next_state().clone();
    drop(orphaned_add);
    drop(alice_group);

    let wrong_pending_state = ConversationState::new(
        alice_pending_state.version(),
        alice_pending_state.conversation_id(),
        alice_pending_state.epoch(),
        alice_pending_state
            .members()
            .iter()
            .copied()
            .map(|member| {
                Member::new(
                    member.device_id(),
                    if member.device_id() == bob_identity.device_id() {
                        ConversationRole::Administrator
                    } else {
                        member.role()
                    },
                    member.joined_epoch(),
                )
            })
            .collect(),
        alice_pending_state.consumed_invitation_ids().to_vec(),
    )
    .unwrap();
    let alice_material = ConversationSigningMaterial::open(
        &sealer(1),
        b"alice-profile",
        conversation_id,
        &alice_material_blob,
    )
    .unwrap();
    let alice_storage = SealedSqliteMlsStorage::open(&alice_storage_path, sealer(1)).unwrap();
    let alice_client = MlsConversationClient::with_storage(alice_material, alice_storage).unwrap();
    let mut mismatched_group = alice_client
        .restore_group(
            alice_parent_state.clone(),
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            Some(wrong_pending_state),
        )
        .unwrap();
    assert_eq!(
        mismatched_group.accept_pending_commit().unwrap_err(),
        KonclaveCryptographicError::MembershipAuthorizationMismatch
    );
    drop(mismatched_group);

    let alice_material = ConversationSigningMaterial::open(
        &sealer(1),
        b"alice-profile",
        conversation_id,
        &alice_material_blob,
    )
    .unwrap();
    let alice_storage = SealedSqliteMlsStorage::open(&alice_storage_path, sealer(1)).unwrap();
    let alice_client = MlsConversationClient::with_storage(alice_material, alice_storage).unwrap();
    let mut alice_group = alice_client
        .restore_group(
            alice_parent_state,
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            Some(alice_pending_state),
        )
        .unwrap();
    alice_group.accept_pending_commit().unwrap();
    let bob_group = bob_client.join_group(add.welcome().unwrap()).unwrap();

    let alice_state = alice_group.state().clone();
    let bob_state = bob_group.state().clone();
    drop(alice_group);
    drop(bob_group);

    let alice_material = ConversationSigningMaterial::open(
        &sealer(1),
        b"alice-profile",
        conversation_id,
        &alice_material_blob,
    )
    .unwrap();
    let alice_client = MlsConversationClient::with_storage(
        alice_material,
        SealedSqliteMlsStorage::open(&alice_storage_path, sealer(1)).unwrap(),
    )
    .unwrap();
    let mut alice_group = alice_client
        .restore_group(
            alice_state,
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            None,
        )
        .unwrap();
    let bob_material = ConversationSigningMaterial::open(
        &sealer(2),
        b"bob-profile",
        conversation_id,
        &bob_material_blob,
    )
    .unwrap();
    let bob_client = MlsConversationClient::with_storage(
        bob_material,
        SealedSqliteMlsStorage::open(&bob_storage_path, sealer(2)).unwrap(),
    )
    .unwrap();
    let mut bob_group = bob_client
        .restore_group(
            bob_state,
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            None,
        )
        .unwrap();

    let ciphertext = alice_group
        .encrypt_application_message(b"durable message")
        .unwrap();
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    assert_eq!(
        bob_group
            .decrypt_application_message(&ciphertext)
            .unwrap()
            .plaintext(),
        b"durable message"
    );
    bob_group.persist().unwrap();
    let bob_state = bob_group.state().clone();
    drop(bob_group);

    let bob_material = ConversationSigningMaterial::open(
        &sealer(2),
        b"bob-profile",
        conversation_id,
        &bob_material_blob,
    )
    .unwrap();
    let bob_client = MlsConversationClient::with_storage(
        bob_material,
        SealedSqliteMlsStorage::open(&bob_storage_path, sealer(2)).unwrap(),
    )
    .unwrap();
    let mut bob_group = bob_client
        .restore_group(
            bob_state,
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            None,
        )
        .unwrap();
    assert_eq!(
        bob_group
            .decrypt_application_message(
                &MlsApplicationMessage::from_bytes(&ciphertext_bytes).unwrap(),
            )
            .err(),
        Some(KonclaveCryptographicError::ApplicationMessageAlreadyProcessed)
    );

    let removal = alice_group
        .create_remove_commit(bob_identity.device_id())
        .unwrap();
    bob_group
        .process_membership_commit(removal.commit(), removal.authorization().clone(), None, 60)
        .unwrap();
    alice_group.accept_pending_commit().unwrap();
    let removed_state = bob_group.state().clone();
    drop(bob_group);

    let bob_material = ConversationSigningMaterial::open(
        &sealer(2),
        b"bob-profile",
        conversation_id,
        &bob_material_blob,
    )
    .unwrap();
    let bob_client = MlsConversationClient::with_storage(
        bob_material,
        SealedSqliteMlsStorage::open(&bob_storage_path, sealer(2)).unwrap(),
    )
    .unwrap();
    let mut removed_bob = bob_client
        .restore_group(
            removed_state,
            vec![
                verify_device_credential_binding(&alice_binding).unwrap(),
                verify_device_credential_binding(&bob_binding).unwrap(),
            ],
            None,
        )
        .unwrap();
    let after_removal = alice_group
        .encrypt_application_message(b"after removal")
        .unwrap();
    assert_eq!(
        removed_bob
            .decrypt_application_message(&after_removal)
            .err(),
        Some(KonclaveCryptographicError::RemovedFromConversation)
    );
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
    let sealer =
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([8; 32])).unwrap();
    let sealed = issuer.seal(&sealer, b"default-profile").unwrap();
    let reopened = DeviceIdentity::open(&sealer, b"default-profile", &sealed).unwrap();
    assert_eq!(reopened.device_id(), issuer.device_id());
    assert_eq!(reopened.public_key(), issuer.public_key());
    assert!(DeviceIdentity::open(&sealer, b"other-profile", &sealed).is_err());

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
            routing_id(1),
            recipient.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    verify_invitation(&invitation, issuer.public_key(), 99).unwrap();
    let rerouted = Invitation::new(
        invitation.version(),
        invitation.invitation_id(),
        invitation.conversation_id(),
        Some(routing_id(2)),
        invitation.expected_device_id(),
        invitation.role(),
        invitation.expires_at_unix_seconds(),
        InvitationNonce::from_slice(invitation.nonce().as_bytes()).unwrap(),
        invitation.issuer_device_id(),
        invitation.issuer_signature(),
    )
    .unwrap();
    assert_eq!(
        verify_invitation(&rerouted, issuer.public_key(), 99).unwrap_err(),
        KonclaveCryptographicError::InvalidInvitationSignature
    );
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
            routing_id(1),
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
            routing_id(1),
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
            routing_id(1),
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
            routing_id(1),
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
    let applied = bob_group
        .process_membership_bundle(&charlie_add.encode_bundle().unwrap(), 50)
        .unwrap();
    assert_eq!(applied.authenticated_sender(), alice_identity.device_id());
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
