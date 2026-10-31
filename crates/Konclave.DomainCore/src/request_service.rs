use crate::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeviceId,
};

/// Immutable endpoint identities for one private requester/operator channel.
///
/// This is an authorization contract, not a routing label or work permission.
/// Callers must authenticate it through invitation and MLS state before use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestServiceChannel {
    conversation_id: ConversationId,
    operator_device_id: DeviceId,
    requester_device_id: DeviceId,
}

/// Finite refusals at the request-service authorization boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestServiceError {
    #[error("request-service endpoints must be distinct")]
    IdenticalEndpoints,
    #[error("request-service conversation does not match")]
    ConversationMismatch,
    #[error("request-service operator must remain the sole administrator")]
    InvalidOperator,
    #[error("request-service requester must remain an ordinary member")]
    InvalidRequester,
    #[error("request-service channel cannot contain another member")]
    ForeignMember,
    #[error("request-service sender is not an active endpoint")]
    SenderNotMember,
    #[error("only the requester may initiate a request-service request")]
    OperatorCannotRequest,
    #[error("request-service request must target its operator")]
    InvalidTarget,
    #[error("request-service channels do not permit unsolicited text")]
    UnsolicitedText,
    #[error("only the operator may answer a request-service request")]
    RequesterCannotReply,
    #[error("request-service reply has no authenticated original request")]
    MissingRequest,
    #[error("request-service reply does not match its original request")]
    InvalidReply,
    #[error("request-service channel does not permit this internal operation")]
    UnsupportedOperation,
}

/// Authenticated original request selected from the same channel's durable history.
///
/// The caller must verify MLS sender identity and completed history before supplying
/// this evidence. This pure view does not prove custody, storage or one-use claims.
pub struct RequestServiceRequest<'a> {
    pub conversation_id: ConversationId,
    pub authenticated_sender: DeviceId,
    pub message: &'a ApplicationMessage,
}

impl RequestServiceChannel {
    /// Creates an exact channel contract without granting membership or work.
    ///
    /// # Errors
    ///
    /// Rejects a requester that is also the operator.
    pub fn new(
        conversation_id: ConversationId,
        operator_device_id: DeviceId,
        requester_device_id: DeviceId,
    ) -> Result<Self, RequestServiceError> {
        if operator_device_id == requester_device_id {
            return Err(RequestServiceError::IdenticalEndpoints);
        }
        Ok(Self {
            conversation_id,
            operator_device_id,
            requester_device_id,
        })
    }

    /// Returns the exact conversation covered by the contract.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the sole endpoint allowed to answer requests.
    #[must_use]
    pub const fn operator_device_id(self) -> DeviceId {
        self.operator_device_id
    }

    /// Returns the sole endpoint allowed to initiate requests.
    #[must_use]
    pub const fn requester_device_id(self) -> DeviceId {
        self.requester_device_id
    }

    /// Checks current or proposed authenticated membership.
    ///
    /// The operator-only state is valid before enrollment and after revocation.
    /// Joining a requester or rekeying never changes the immutable endpoints.
    ///
    /// # Errors
    ///
    /// Rejects a different conversation, changed endpoint roles or any third member.
    pub fn validate_membership(self, state: &ConversationState) -> Result<(), RequestServiceError> {
        if state.conversation_id() != self.conversation_id {
            return Err(RequestServiceError::ConversationMismatch);
        }
        if state
            .member(self.operator_device_id)
            .map(|member| member.role())
            != Some(ConversationRole::Administrator)
        {
            return Err(RequestServiceError::InvalidOperator);
        }
        for member in state.members() {
            if member.device_id() == self.operator_device_id {
                continue;
            }
            if member.device_id() != self.requester_device_id {
                return Err(RequestServiceError::ForeignMember);
            }
            if member.role() != ConversationRole::Member {
                return Err(RequestServiceError::InvalidRequester);
            }
        }
        Ok(())
    }

    /// Checks one authenticated application operation independently of its transport.
    ///
    /// Policy exchange remains administrative data, not a task message. Reply
    /// admission also requires the caller's atomic one-response reservation and
    /// current local work/reply authority; this function does not grant either.
    ///
    /// # Errors
    ///
    /// Rejects inactive or foreign senders, reverse requests, unsolicited text,
    /// cross-channel or incorrect replies and internal pairing operations.
    pub fn validate_application(
        self,
        state: &ConversationState,
        authenticated_sender: DeviceId,
        content: &ApplicationContent,
        reply_to: Option<crate::MessageId>,
        original: Option<RequestServiceRequest<'_>>,
    ) -> Result<(), RequestServiceError> {
        self.validate_membership(state)?;
        if state.member(authenticated_sender).is_none() {
            return Err(RequestServiceError::SenderNotMember);
        }
        match content {
            ApplicationContent::DirectedRequest(request) => {
                if authenticated_sender != self.requester_device_id {
                    return Err(RequestServiceError::OperatorCannotRequest);
                }
                if request.target_device_id() != self.operator_device_id {
                    return Err(RequestServiceError::InvalidTarget);
                }
            }
            ApplicationContent::Text(_) => {
                if reply_to.is_none() {
                    return Err(RequestServiceError::UnsolicitedText);
                }
                if authenticated_sender != self.operator_device_id {
                    return Err(RequestServiceError::RequesterCannotReply);
                }
                if state.member(self.requester_device_id).is_none() {
                    return Err(RequestServiceError::SenderNotMember);
                }
                let original = original.ok_or(RequestServiceError::MissingRequest)?;
                if original.conversation_id != self.conversation_id
                    || original.authenticated_sender != self.requester_device_id
                    || Some(original.message.message_id()) != reply_to
                {
                    return Err(RequestServiceError::InvalidReply);
                }
                let ApplicationContent::DirectedRequest(request) = original.message.content()
                else {
                    return Err(RequestServiceError::InvalidReply);
                };
                if request.target_device_id() != self.operator_device_id {
                    return Err(RequestServiceError::InvalidReply);
                }
            }
            ApplicationContent::CollaborationPolicyProposal(_)
            | ApplicationContent::CollaborationPolicyResponse(_)
            | ApplicationContent::CollaborationPolicyRevocation(_) => {}
            ApplicationContent::RepeatPairingRequest(_)
            | ApplicationContent::RepeatPairingResponse(_) => {
                return Err(RequestServiceError::UnsupportedOperation);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Member, MessageId, ProtocolVersion, RepeatPairingOperationId, RepeatPairingRequest,
    };

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    fn channel() -> RequestServiceChannel {
        RequestServiceChannel::new(ConversationId::from_bytes([1; 32]), device(2), device(3))
            .unwrap()
    }

    fn state(members: Vec<Member>) -> ConversationState {
        ConversationState::new(
            ProtocolVersion::application_v1(),
            channel().conversation_id(),
            1,
            members,
            vec![],
        )
        .unwrap()
    }

    fn active() -> ConversationState {
        state(vec![
            Member::new(device(2), ConversationRole::Administrator, 0),
            Member::new(device(3), ConversationRole::Member, 1),
        ])
    }

    fn request(target: DeviceId) -> ApplicationMessage {
        ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([4; 16]),
            1,
            1,
            None,
            ApplicationContent::directed_request(target, "fixture request").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn request_service_snapshot_preserves_contract_and_rejects_membership_escape() {
        use crate::{
            AddMember, ChangeMemberRole, CredentialBindingHash, InvitationId,
            MembershipAuthorization, MembershipChange, MembershipOperationId, RemoveMember,
        };

        let channel = channel();
        let initial = ConversationState::new_with_request_service(
            ProtocolVersion::application_v1(),
            channel.conversation_id(),
            1,
            active().members().to_vec(),
            vec![],
            Some(channel),
        )
        .unwrap();
        let authorization = |change| {
            MembershipAuthorization::new(
                initial.version(),
                initial.conversation_id(),
                initial.epoch(),
                MembershipOperationId::from_bytes([5; 16]),
                change,
            )
        };
        for change in [
            MembershipChange::Add(AddMember::new(
                device(9),
                ConversationRole::Member,
                InvitationId::from_bytes([6; 16]),
                CredentialBindingHash::from_bytes([7; 32]),
            )),
            MembershipChange::ChangeRole(ChangeMemberRole::new(
                device(3),
                ConversationRole::Administrator,
            )),
        ] {
            assert!(
                initial
                    .apply_membership_authorization(device(2), &authorization(change), 2)
                    .is_err()
            );
        }
        let revoked = initial
            .apply_membership_authorization(
                device(2),
                &authorization(MembershipChange::Remove(RemoveMember::new(device(3)))),
                2,
            )
            .unwrap();
        assert_eq!(revoked.request_service(), Some(channel));
        assert_eq!(revoked.members().len(), 1);
        let restored = revoked
            .apply_membership_authorization(
                device(2),
                &MembershipAuthorization::new(
                    revoked.version(),
                    revoked.conversation_id(),
                    revoked.epoch(),
                    MembershipOperationId::from_bytes([8; 16]),
                    MembershipChange::Add(AddMember::new(
                        device(3),
                        ConversationRole::Member,
                        InvitationId::from_bytes([9; 16]),
                        CredentialBindingHash::from_bytes([7; 32]),
                    )),
                ),
                3,
            )
            .unwrap();
        assert_eq!(restored.request_service(), Some(channel));
        assert_eq!(
            restored.member(device(3)).unwrap().role(),
            ConversationRole::Member
        );
    }

    #[test]
    fn membership_rejects_role_changes_and_third_members() {
        let operator = Member::new(device(2), ConversationRole::Administrator, 0);
        for (members, expected) in [
            (vec![operator], Ok(())),
            (active().members().to_vec(), Ok(())),
            (
                vec![
                    operator,
                    Member::new(device(3), ConversationRole::Administrator, 1),
                ],
                Err(RequestServiceError::InvalidRequester),
            ),
            (
                vec![
                    operator,
                    Member::new(device(5), ConversationRole::Member, 1),
                ],
                Err(RequestServiceError::ForeignMember),
            ),
            (
                vec![
                    Member::new(device(2), ConversationRole::Member, 0),
                    Member::new(device(3), ConversationRole::Administrator, 1),
                ],
                Err(RequestServiceError::InvalidOperator),
            ),
        ] {
            assert_eq!(channel().validate_membership(&state(members)), expected);
        }
        assert_eq!(
            RequestServiceChannel::new(channel().conversation_id(), device(2), device(2)),
            Err(RequestServiceError::IdenticalEndpoints)
        );
        let other =
            RequestServiceChannel::new(ConversationId::from_bytes([9; 32]), device(2), device(3))
                .unwrap();
        assert_eq!(
            other.validate_membership(&active()),
            Err(RequestServiceError::ConversationMismatch)
        );
    }

    #[test]
    fn request_direction_is_not_a_prompt_convention() {
        for (sender, target, expected) in [
            (device(3), device(2), Ok(())),
            (
                device(2),
                device(3),
                Err(RequestServiceError::OperatorCannotRequest),
            ),
            (
                device(3),
                device(5),
                Err(RequestServiceError::InvalidTarget),
            ),
            (
                device(5),
                device(2),
                Err(RequestServiceError::SenderNotMember),
            ),
        ] {
            assert_eq!(
                channel().validate_application(
                    &active(),
                    sender,
                    request(target).content(),
                    None,
                    None,
                ),
                expected
            );
        }
    }

    #[test]
    fn reply_requires_exact_authenticated_original_request() {
        let request = request(device(2));
        let reply = ApplicationContent::text("fixture reply").unwrap();
        for (sender, conversation, original_sender, reference, expected) in [
            (
                device(2),
                channel().conversation_id(),
                device(3),
                request.message_id(),
                Ok(()),
            ),
            (
                device(3),
                channel().conversation_id(),
                device(3),
                request.message_id(),
                Err(RequestServiceError::RequesterCannotReply),
            ),
            (
                device(2),
                ConversationId::from_bytes([9; 32]),
                device(3),
                request.message_id(),
                Err(RequestServiceError::InvalidReply),
            ),
            (
                device(2),
                channel().conversation_id(),
                device(5),
                request.message_id(),
                Err(RequestServiceError::InvalidReply),
            ),
            (
                device(2),
                channel().conversation_id(),
                device(3),
                MessageId::from_bytes([9; 16]),
                Err(RequestServiceError::InvalidReply),
            ),
        ] {
            assert_eq!(
                channel().validate_application(
                    &active(),
                    sender,
                    &reply,
                    Some(reference),
                    Some(RequestServiceRequest {
                        conversation_id: conversation,
                        authenticated_sender: original_sender,
                        message: &request,
                    }),
                ),
                expected
            );
        }
        assert_eq!(
            channel().validate_application(&active(), device(2), &reply, None, None),
            Err(RequestServiceError::UnsolicitedText)
        );
        assert_eq!(
            channel().validate_application(
                &active(),
                device(2),
                &reply,
                Some(request.message_id()),
                None,
            ),
            Err(RequestServiceError::MissingRequest)
        );
    }

    #[test]
    fn reply_cannot_reclassify_text_or_another_target_as_original_request() {
        let reply = ApplicationContent::text("fixture reply").unwrap();
        for content in [
            ApplicationContent::text("not a request").unwrap(),
            ApplicationContent::directed_request(device(5), "wrong target").unwrap(),
        ] {
            let original = ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                MessageId::from_bytes([4; 16]),
                1,
                1,
                None,
                content,
            )
            .unwrap();
            assert_eq!(
                channel().validate_application(
                    &active(),
                    device(2),
                    &reply,
                    Some(original.message_id()),
                    Some(RequestServiceRequest {
                        conversation_id: channel().conversation_id(),
                        authenticated_sender: device(3),
                        message: &original,
                    }),
                ),
                Err(RequestServiceError::InvalidReply)
            );
        }
    }

    #[test]
    fn removed_requester_and_internal_pairing_cannot_bypass_direction() {
        let revoked = state(vec![Member::new(
            device(2),
            ConversationRole::Administrator,
            0,
        )]);
        let original = request(device(2));
        assert_eq!(
            channel().validate_application(&revoked, device(3), original.content(), None, None,),
            Err(RequestServiceError::SenderNotMember)
        );
        let content = ApplicationContent::repeat_pairing_request(
            RepeatPairingRequest::new(
                RepeatPairingOperationId::from_bytes([1; 16]),
                device(3),
                ConversationId::from_bytes([9; 32]),
                10,
            )
            .unwrap(),
        );
        assert_eq!(
            channel().validate_application(&active(), device(2), &content, None, None),
            Err(RequestServiceError::UnsupportedOperation)
        );
    }
}
