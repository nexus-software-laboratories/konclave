#[path = "../examples/native_service/authority.rs"]
mod authority;

use authority::{AuthorityError, MAX_CLAIMS, ServiceAuthority, ServiceAuthorization};
use KonclaveClientLibrary::native::{NativeApplicationRequest, StoredApplicationMessage};
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeviceId, EnvelopeId, Member, MessageId, ProtocolVersion,
};

fn local() -> DeviceId {
    DeviceId::from_bytes([1; DeviceId::LENGTH])
}

fn peer() -> DeviceId {
    DeviceId::from_bytes([2; DeviceId::LENGTH])
}

fn conversation() -> ConversationId {
    ConversationId::from_bytes([4; ConversationId::LENGTH])
}

fn state(include_local: bool, include_peer: bool) -> ConversationState {
    let mut members = vec![Member::new(
        DeviceId::from_bytes([3; DeviceId::LENGTH]),
        ConversationRole::Administrator,
        0,
    )];
    if include_local {
        members.push(Member::new(local(), ConversationRole::Member, 0));
    }
    if include_peer {
        members.push(Member::new(peer(), ConversationRole::Member, 0));
    }
    ConversationState::new(
        ProtocolVersion::application_v1(),
        conversation(),
        0,
        members,
        vec![],
    ).unwrap()
}

fn authority() -> ServiceAuthority {
    ServiceAuthority {
        conversation: conversation(),
        device: local(),
        revision: 7,
        enabled: true,
        claims: vec![],
    }
}

fn received_request() -> StoredApplicationMessage {
    StoredApplicationMessage {
        cursor: 1,
        envelope_id: EnvelopeId::from_bytes([8; EnvelopeId::LENGTH]),
        sender: peer(),
        epoch: 0,
        message: ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([5; MessageId::LENGTH]),
            1,
            1,
            None,
            ApplicationContent::directed_request(local(), "synthetic request").unwrap(),
        ).unwrap(),
    }
}

fn outbound(authorization: Option<ServiceAuthorization>) -> NativeApplicationRequest<ServiceAuthorization> {
    NativeApplicationRequest {
        conversation_id: conversation(),
        message_id: MessageId::from_bytes([6; MessageId::LENGTH]),
        content: ApplicationContent::directed_request(peer(), "synthetic outbound").unwrap(),
        reply_to: None,
        authorization,
        sent_at_unix_milliseconds: 1,
        expires_at_unix_seconds: 100,
        policy_operation: false,
    }
}

fn response(authorization: ServiceAuthorization) -> NativeApplicationRequest<ServiceAuthorization> {
    NativeApplicationRequest {
        content: ApplicationContent::text("synthetic response").unwrap(),
        reply_to: Some(received_request().message.message_id()),
        ..outbound(Some(authorization))
    }
}

#[test]
fn finite_new_admission_categories_leave_denied_state_unchanged() {
    enum Failure {
        Disabled,
        OldGrant,
        MissingGrant,
        ForeignConversation,
        RemovedLocal,
        RemovedTarget,
        SelfTarget,
        PolicyOperation,
        UncorrelatedText,
    }
    for (failure, expected) in [
        (Failure::Disabled, AuthorityError::Denied),
        (Failure::OldGrant, AuthorityError::Denied),
        (Failure::MissingGrant, AuthorityError::Denied),
        (Failure::ForeignConversation, AuthorityError::Scope),
        (Failure::RemovedLocal, AuthorityError::Denied),
        (Failure::RemovedTarget, AuthorityError::Scope),
        (Failure::SelfTarget, AuthorityError::Scope),
        (Failure::PolicyOperation, AuthorityError::Unsupported),
        (Failure::UncorrelatedText, AuthorityError::Unsupported),
    ] {
        let mut current = authority();
        let mut membership = state(true, true);
        let mut request = outbound(Some(ServiceAuthorization { revision: 7, claim: None }));
        match failure {
            Failure::Disabled => current.enabled = false,
            Failure::OldGrant => request.authorization.as_mut().unwrap().revision = 6,
            Failure::MissingGrant => request.authorization = None,
            Failure::ForeignConversation => request.conversation_id =
                ConversationId::from_bytes([9; ConversationId::LENGTH]),
            Failure::RemovedLocal => membership = state(false, true),
            Failure::RemovedTarget => membership = state(true, false),
            Failure::SelfTarget => request.content =
                ApplicationContent::directed_request(local(), "synthetic self target").unwrap(),
            Failure::PolicyOperation => request.policy_operation = true,
            Failure::UncorrelatedText => request.content = ApplicationContent::text("synthetic text").unwrap(),
        }
        assert_eq!(
            current.reserve(&membership, &request, EnvelopeId::from_bytes([9; EnvelopeId::LENGTH])),
            Err(expected)
        );
        assert!(current.claims.is_empty());
    }
    let mut current = authority();
    assert_eq!(
        current.reserve(
            &state(true, true),
            &outbound(Some(ServiceAuthorization { revision: 7, claim: None })),
            EnvelopeId::from_bytes([9; EnvelopeId::LENGTH])
        ),
        Ok(())
    );
}

#[test]
fn exact_live_claim_is_consumed_once_and_retains_original_terminal_identity() {
    let mut current = authority();
    let membership = state(true, true);
    let grant = current.claim(&membership, &received_request(), [1; 16]).unwrap();
    let request = response(grant);
    let envelope = EnvelopeId::from_bytes([9; EnvelopeId::LENGTH]);
    current.reserve(&membership, &request, envelope).unwrap();
    let committed = current.claims[0].response.unwrap();
    assert!(committed.message == request.message_id);
    assert!(committed.envelope == envelope);
    let mut competitor = response(grant);
    competitor.message_id = MessageId::from_bytes([7; MessageId::LENGTH]);
    assert_eq!(current.reserve(&membership, &competitor, envelope), Err(AuthorityError::Claim));
    assert!(current.claims[0].response == Some(committed));
    assert!(matches!(
        current.claim(&membership, &received_request(), [2; 16]),
        Err(AuthorityError::Claim)
    ));
    current.set_enabled(false).unwrap();
    assert!(current.claims[0].response == Some(committed));
    assert_eq!(current.reserve(&membership, &request, envelope), Err(AuthorityError::Denied));
}

#[test]
fn revocation_and_exact_claim_scope_are_revalidated_at_new_reservation() {
    enum Failure { Revoked, OldRevision, WrongClaim, WrongReply, RemovedRequester }
    for (failure, expected) in [
        (Failure::Revoked, AuthorityError::Denied),
        (Failure::OldRevision, AuthorityError::Denied),
        (Failure::WrongClaim, AuthorityError::Claim),
        (Failure::WrongReply, AuthorityError::Claim),
        (Failure::RemovedRequester, AuthorityError::Claim),
    ] {
        let mut current = authority();
        let mut membership = state(true, true);
        let grant = current.claim(&membership, &received_request(), [1; 16]).unwrap();
        let mut request = response(grant);
        match failure {
            Failure::Revoked => current.set_enabled(false).unwrap(),
            Failure::OldRevision => { current.set_enabled(true).unwrap(); }
            Failure::WrongClaim => request.authorization.as_mut().unwrap().claim = Some([2; 16]),
            Failure::WrongReply => request.reply_to = Some(MessageId::from_bytes([9; MessageId::LENGTH])),
            Failure::RemovedRequester => membership = state(true, false),
        }
        assert_eq!(
            current.reserve(&membership, &request, EnvelopeId::from_bytes([9; EnvelopeId::LENGTH])),
            Err(expected)
        );
        assert!(current.claims[0].response.is_none());
    }
}

#[test]
fn claim_identity_and_capacity_fail_closed_without_replacing_prior_claims() {
    let mut current = authority();
    let membership = state(true, true);
    assert!(matches!(
        current.claim(&membership, &received_request(), [0; 16]),
        Err(AuthorityError::Claim)
    ));
    for identifier in 1..=MAX_CLAIMS {
        let mut message = received_request();
        message.message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([identifier as u8; MessageId::LENGTH]),
            identifier as u64,
            1,
            None,
            ApplicationContent::directed_request(local(), "synthetic bounded request").unwrap(),
        ).unwrap();
        current.claim(&membership, &message, [identifier as u8; 16]).unwrap();
    }

    #[test]
    fn claim_rejects_nonrequest_and_wrong_authenticated_delivery_scope() {
        enum Failure { Text, WrongTarget, LocalSender, RemovedSender, WrongEpoch, Reply }
        for (failure, expected) in [
            (Failure::Text, AuthorityError::Unsupported),
            (Failure::WrongTarget, AuthorityError::Scope),
            (Failure::LocalSender, AuthorityError::Scope),
            (Failure::RemovedSender, AuthorityError::Scope),
            (Failure::WrongEpoch, AuthorityError::Scope),
            (Failure::Reply, AuthorityError::Scope),
        ] {
            let mut current = authority();
            let mut message = received_request();
            let mut membership = state(true, true);
            match failure {
                Failure::Text => message.message = ApplicationMessage::new(
                    ProtocolVersion::application_v1(), message.message.message_id(), 1, 1, None,
                    ApplicationContent::text("synthetic nonrequest").unwrap(),
                ).unwrap(),
                Failure::WrongTarget => message.message = ApplicationMessage::new(
                    ProtocolVersion::application_v1(), message.message.message_id(), 1, 1, None,
                    ApplicationContent::directed_request(peer(), "synthetic wrong target").unwrap(),
                ).unwrap(),
                Failure::LocalSender => message.sender = local(),
                Failure::RemovedSender => membership = state(true, false),
                Failure::WrongEpoch => message.epoch = 1,
                Failure::Reply => message.message = ApplicationMessage::new(
                    ProtocolVersion::application_v1(), message.message.message_id(), 1, 1,
                    Some(MessageId::from_bytes([9; MessageId::LENGTH])),
                    ApplicationContent::directed_request(local(), "synthetic nested request").unwrap(),
                ).unwrap(),
            }
            assert!(matches!(
                current.claim(&membership, &message, [1; 16]),
                Err(error) if error == expected
            ));
            assert!(current.claims.is_empty());
        }
    }
    let mut extra = received_request();
    extra.message = ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([99; MessageId::LENGTH]), 99, 1, None,
        ApplicationContent::directed_request(local(), "synthetic extra request").unwrap(),
    ).unwrap();
    assert!(matches!(
        current.claim(&membership, &extra, [99; 16]),
        Err(AuthorityError::Capacity)
    ));
    assert_eq!(current.claims.len(), MAX_CLAIMS);
    current.revision = u64::MAX;
    assert_eq!(current.set_enabled(false), Err(AuthorityError::Capacity));
    assert!(current.enabled);
    assert_eq!(current.revision, u64::MAX);
}
