//! Pure authority decisions for the bounded native-service journal.
//!
//! The durable adapter must load, evaluate and persist this state together with
//! its immutable reservation/response intent under the same current owner.
//! These decisions alone do not prove ownership, authentication or atomicity.

use KonclaveClientLibrary::native::{NativeApplicationRequest, StoredApplicationMessage};
use KonclaveDomainCore::{
    ApplicationContent, ConversationId, ConversationState, DeviceId, EnvelopeId, MessageId,
};

/// Retained claims are never pruned or recycled by this bounded example.
pub const MAX_CLAIMS: usize = 16;

/// Explicit locally issued authority, not a value derived from peer content.
#[derive(Clone, Copy)]
pub struct ServiceAuthorization {
    /// Exact current local policy generation.
    pub revision: u64,
    /// Exact locally issued request-handling identity, only for a response.
    pub claim: Option<[u8; 16]>,
}

/// Immutable response identity recorded when a live claim is consumed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommittedResponse {
    /// Immutable terminal response identity.
    pub message: MessageId,
    /// Immutable terminal relay identity.
    pub envelope: EnvelopeId,
}

/// One authenticated request's retained live or terminal handling claim.
#[derive(Clone, Copy)]
pub struct HandlingClaim {
    /// Host-issued, nonzero claim identity.
    pub id: [u8; 16],
    /// Authenticated request selected by this endpoint.
    pub request: MessageId,
    /// Authenticated remote request sender.
    pub requester: DeviceId,
    /// Terminal identity; a consumed claim never becomes live again.
    pub response: Option<CommittedResponse>,
}

/// Host policy and bounded handling state belonging to one native scope.
#[derive(Clone)]
pub struct ServiceAuthority {
    /// Exact provisioned native scope.
    pub conversation: ConversationId,
    /// Exact independently provisioned endpoint identity.
    pub device: DeviceId,
    /// Monotonic policy generation invalidating earlier admission grants.
    pub revision: u64,
    /// Host policy switch, independent of native membership.
    pub enabled: bool,
    /// Retained live and terminal claims, bounded by `MAX_CLAIMS`.
    pub claims: Vec<HandlingClaim>,
}

/// Finite authority failures with no payload-bearing diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// Local authority or current membership does not permit new admission.
    #[error("native service authority denied admission")]
    Denied,
    /// Authenticated evidence belongs to another operation scope.
    #[error("native service authority scope mismatch")]
    Scope,
    /// This example does not implement the requested operation.
    #[error("native service operation is unsupported")]
    Unsupported,
    /// No exact unused claim authorizes this response.
    #[error("native service handling claim is unavailable")]
    Claim,
    /// Retained state or policy generation cannot grow further.
    #[error("native service authority capacity exhausted")]
    Capacity,
}

impl ServiceAuthority {
    fn current(&self, state: &ConversationState) -> Result<(), AuthorityError> {
        if state.conversation_id() != self.conversation {
            return Err(AuthorityError::Scope);
        }
        if !self.enabled || state.member(self.device).is_none() {
            return Err(AuthorityError::Denied);
        }
        if self.claims.len() > MAX_CLAIMS {
            return Err(AuthorityError::Capacity);
        }
        Ok(())
    }

    /// Evaluates new admission and consumes only the exact live response claim.
    ///
    /// The caller commits this mutation with the complete original response
    /// intent and counter reservation, or discards the entire decoded snapshot.
    ///
    /// # Errors
    /// Rejects stale authority, membership/scope mismatch, unsupported operations,
    /// or a missing, mismatched or consumed response claim before mutation.
    pub fn reserve(
        &mut self,
        state: &ConversationState,
        request: &NativeApplicationRequest<ServiceAuthorization>,
        envelope: EnvelopeId,
    ) -> Result<(), AuthorityError> {
        self.current(state)?;
        if request.conversation_id != self.conversation {
            return Err(AuthorityError::Scope);
        }
        let authorization = request.authorization.ok_or(AuthorityError::Denied)?;
        if authorization.revision != self.revision {
            return Err(AuthorityError::Denied);
        }
        if request.policy_operation {
            return Err(AuthorityError::Unsupported);
        }
        match (&request.content, request.reply_to, authorization.claim) {
            (ApplicationContent::DirectedRequest(directed), None, None) => {
                if directed.target_device_id() == self.device
                    || state.member(directed.target_device_id()).is_none()
                {
                    return Err(AuthorityError::Scope);
                }
                Ok(())
            }
            (ApplicationContent::Text(_), Some(reply), Some(claim_id)) => {
                let claim = self
                    .claims
                    .iter_mut()
                    .find(|claim| claim.id == claim_id)
                    .ok_or(AuthorityError::Claim)?;
                if claim.request != reply
                    || claim.response.is_some()
                    || state.member(claim.requester).is_none()
                {
                    return Err(AuthorityError::Claim);
                }
                claim.response = Some(CommittedResponse {
                    message: request.message_id,
                    envelope,
                });
                Ok(())
            }
            _ => Err(AuthorityError::Unsupported),
        }
    }

    /// Claims one durably completed, authenticated request addressed to this device.
    ///
    /// # Errors
    /// Rejects inactive authority, wrong recipient/sender/epoch, duplicate or zero
    /// claim identities, and exhausted retained capacity. The durable caller must
    /// prove the supplied message is complete within the same scoped transaction.
    pub fn claim(
        &mut self,
        state: &ConversationState,
        message: &StoredApplicationMessage,
        claim_id: [u8; 16],
    ) -> Result<ServiceAuthorization, AuthorityError> {
        self.current(state)?;
        let ApplicationContent::DirectedRequest(request) = message.message.content() else {
            return Err(AuthorityError::Unsupported);
        };
        if request.target_device_id() != self.device
            || message.sender == self.device
            || state.member(message.sender).is_none()
            || message.message.reply_to().is_some()
            || message.epoch != state.epoch()
        {
            return Err(AuthorityError::Scope);
        }
        if claim_id == [0; 16]
            || self.claims.iter().any(|claim| {
                claim.id == claim_id || claim.request == message.message.message_id()
            })
        {
            return Err(AuthorityError::Claim);
        }
        if self.claims.len() == MAX_CLAIMS {
            return Err(AuthorityError::Capacity);
        }
        self.claims.push(HandlingClaim {
            id: claim_id,
            request: message.message.message_id(),
            requester: message.sender,
            response: None,
        });
        Ok(ServiceAuthorization {
            revision: self.revision,
            claim: Some(claim_id),
        })
    }

    /// Changes local policy without reviving or replacing any consumed claim.
    ///
    /// # Errors
    /// Returns capacity exhaustion without mutation if the generation cannot advance.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), AuthorityError> {
        let revision = self.revision.checked_add(1).ok_or(AuthorityError::Capacity)?;
        self.revision = revision;
        self.enabled = enabled;
        Ok(())
    }
}
