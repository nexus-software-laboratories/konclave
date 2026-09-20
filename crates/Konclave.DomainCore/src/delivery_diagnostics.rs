use thiserror::Error;

/// Authenticated local preparation or submission evidence for one outbound message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundDeliveryObservation {
    /// Authenticated local content exists, but an envelope is not ready.
    Prepared,
    /// The sealed envelope is ready, with no observed relay acceptance.
    Ready,
    /// An authenticated cursor observation proves relay acceptance.
    RelayAccepted,
    /// The sealed envelope's expiry and local terminal state have been verified.
    Expired,
    /// Authenticated membership state terminalized this outbound operation.
    Removed,
}

/// Authenticated local notification evidence, not evidence of model execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalDeliveryObservation {
    /// No notification remains within the retained local journal.
    NotRetained,
    /// The notification is waiting for an eligible local consumer.
    Pending,
    /// A consumer claimed the notification; acceptance is not yet recorded.
    Claimed,
    /// The local harness acknowledged the notification.
    Acknowledged,
    /// Local policy suppressed this notification.
    Suppressed,
}

/// Authenticated handling evidence for a directed request targeting this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestHandlingObservation {
    /// No handling outcome has been recorded.
    NotRecorded,
    /// A handling claim exists with this recorded expiry.
    ///
    /// Expiry alone does not establish whether its owning consumer is still live.
    Claimed {
        /// Positive Unix-millisecond expiry from the authenticated claim.
        expires_at_unix_milliseconds: u64,
    },
    /// One response was reserved atomically, not necessarily submitted or delivered.
    ResponseReserved,
    /// Handling completed without reserving a response.
    CompletedWithoutResponse,
}

/// Verified local facts selected by the persistence boundary for one message.
///
/// The caller authenticates the profile, record context, source and cursor before
/// constructing an observation. Unsealed reservations and hidden internal messages
/// are not evidence that an externally inspectable message was committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDeliveryObservation {
    /// No externally inspectable authenticated message was observed locally.
    NotObserved,
    /// Local outbound evidence.
    Outbound(OutboundDeliveryObservation),
    /// Inbound content is sealed but contiguous local completion is not observed.
    InboundPrepared,
    /// Inbound completion and any retained notification/handling have been verified.
    Inbound {
        /// Retained local notification evidence.
        notification: LocalDeliveryObservation,
        /// Recorded handling for an exact locally targeted directed request.
        handling: RequestHandlingObservation,
    },
}

/// Finite body-free status for an authenticated local diagnostic.
///
/// No status proves remote harness acceptance or remote execution. In particular,
/// relay acceptance and a local response reservation are different milestones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDeliveryStatus {
    /// No authenticated inspectable local record was observed.
    NotObserved,
    /// Outbound content is prepared but its envelope is not ready.
    OutboundPrepared,
    /// A sealed outbound envelope is awaiting observed relay acceptance.
    AwaitingRelayAcceptance,
    /// An authenticated receipt proves relay acceptance only.
    RelayAccepted,
    /// The local outbound operation expired without observed acceptance.
    OutboundExpired,
    /// Authenticated membership removal stopped the local outbound operation.
    OutboundRemoved,
    /// Inbound content is sealed but local completion is not observed.
    InboundPrepared,
    /// Inbound completion is verified; its notification is no longer retained.
    PersistedInbound,
    /// The notification is waiting for local harness delivery.
    AwaitingHarnessDelivery,
    /// The notification is claimed, without recorded harness acknowledgment.
    ClaimedForDelivery,
    /// The harness acknowledged the notification, not necessarily a model turn.
    AcknowledgedByHarness,
    /// The notification was suppressed by local delivery policy.
    DeliverySuppressed,
    /// A handling claim has a future recorded expiry; consumer liveness is unknown.
    RequestClaimRecorded,
    /// The recorded handling expiry has elapsed; this is not a retry authorization.
    RequestClaimExpired,
    /// One response effect is reserved, without a delivery claim.
    ResponseReserved,
    /// The local handling attempt ended without a response effect.
    CompletedWithoutResponse,
}

impl MessageDeliveryStatus {
    /// Returns the fixed local diagnostic code without content or identifiers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotObserved => "not_observed",
            Self::OutboundPrepared => "outbound_prepared",
            Self::AwaitingRelayAcceptance => "awaiting_relay_acceptance",
            Self::RelayAccepted => "relay_accepted",
            Self::OutboundExpired => "outbound_expired",
            Self::OutboundRemoved => "outbound_removed",
            Self::InboundPrepared => "inbound_prepared",
            Self::PersistedInbound => "persisted_inbound",
            Self::AwaitingHarnessDelivery => "awaiting_harness_delivery",
            Self::ClaimedForDelivery => "claimed_for_delivery",
            Self::AcknowledgedByHarness => "acknowledged_by_harness",
            Self::DeliverySuppressed => "delivery_suppressed",
            Self::RequestClaimRecorded => "request_claim_recorded",
            Self::RequestClaimExpired => "request_claim_expired",
            Self::ResponseReserved => "response_reserved",
            Self::CompletedWithoutResponse => "completed_without_response",
        }
    }
}

/// Invalid authenticated evidence supplied to the diagnostic classifier.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeliveryDiagnosticError {
    /// A recorded claim must contain a positive expiry.
    #[error("delivery diagnostic claim expiry is invalid")]
    InvalidClaimExpiry,
}

/// Projects verified local evidence into a body-free status without side effects.
///
/// Handling evidence is more specific than notification delivery. A notification
/// acknowledgment never independently proves a response or a completed model turn.
/// The caller supplies the clock; this function performs no I/O or allocation.
///
/// # Errors
///
/// Returns [`DeliveryDiagnosticError::InvalidClaimExpiry`] for a zero claim expiry.
pub const fn classify_message_delivery(
    observation: MessageDeliveryObservation,
    now_unix_milliseconds: u64,
) -> Result<MessageDeliveryStatus, DeliveryDiagnosticError> {
    let status = match observation {
        MessageDeliveryObservation::NotObserved => MessageDeliveryStatus::NotObserved,
        MessageDeliveryObservation::Outbound(outbound) => match outbound {
            OutboundDeliveryObservation::Prepared => MessageDeliveryStatus::OutboundPrepared,
            OutboundDeliveryObservation::Ready => MessageDeliveryStatus::AwaitingRelayAcceptance,
            OutboundDeliveryObservation::RelayAccepted => MessageDeliveryStatus::RelayAccepted,
            OutboundDeliveryObservation::Expired => MessageDeliveryStatus::OutboundExpired,
            OutboundDeliveryObservation::Removed => MessageDeliveryStatus::OutboundRemoved,
        },
        MessageDeliveryObservation::InboundPrepared => MessageDeliveryStatus::InboundPrepared,
        MessageDeliveryObservation::Inbound {
            notification,
            handling,
        } => match handling {
            RequestHandlingObservation::Claimed {
                expires_at_unix_milliseconds: 0,
            } => return Err(DeliveryDiagnosticError::InvalidClaimExpiry),
            RequestHandlingObservation::Claimed {
                expires_at_unix_milliseconds,
            } => {
                if expires_at_unix_milliseconds <= now_unix_milliseconds {
                    MessageDeliveryStatus::RequestClaimExpired
                } else {
                    MessageDeliveryStatus::RequestClaimRecorded
                }
            }
            RequestHandlingObservation::ResponseReserved => MessageDeliveryStatus::ResponseReserved,
            RequestHandlingObservation::CompletedWithoutResponse => {
                MessageDeliveryStatus::CompletedWithoutResponse
            }
            RequestHandlingObservation::NotRecorded => match notification {
                LocalDeliveryObservation::NotRetained => MessageDeliveryStatus::PersistedInbound,
                LocalDeliveryObservation::Pending => MessageDeliveryStatus::AwaitingHarnessDelivery,
                LocalDeliveryObservation::Claimed => MessageDeliveryStatus::ClaimedForDelivery,
                LocalDeliveryObservation::Acknowledged => {
                    MessageDeliveryStatus::AcknowledgedByHarness
                }
                LocalDeliveryObservation::Suppressed => MessageDeliveryStatus::DeliverySuppressed,
            },
        },
    };
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_local_record_and_notification_has_an_exact_projection() {
        let cases = [
            (MessageDeliveryObservation::NotObserved, "not_observed"),
            (
                MessageDeliveryObservation::Outbound(OutboundDeliveryObservation::Prepared),
                "outbound_prepared",
            ),
            (
                MessageDeliveryObservation::Outbound(OutboundDeliveryObservation::Ready),
                "awaiting_relay_acceptance",
            ),
            (
                MessageDeliveryObservation::Outbound(OutboundDeliveryObservation::RelayAccepted),
                "relay_accepted",
            ),
            (
                MessageDeliveryObservation::Outbound(OutboundDeliveryObservation::Expired),
                "outbound_expired",
            ),
            (
                MessageDeliveryObservation::Outbound(OutboundDeliveryObservation::Removed),
                "outbound_removed",
            ),
            (
                MessageDeliveryObservation::InboundPrepared,
                "inbound_prepared",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                classify_message_delivery(input, 100).unwrap().as_str(),
                expected
            );
        }
        for (notification, expected) in [
            (LocalDeliveryObservation::NotRetained, "persisted_inbound"),
            (
                LocalDeliveryObservation::Pending,
                "awaiting_harness_delivery",
            ),
            (LocalDeliveryObservation::Claimed, "claimed_for_delivery"),
            (
                LocalDeliveryObservation::Acknowledged,
                "acknowledged_by_harness",
            ),
            (LocalDeliveryObservation::Suppressed, "delivery_suppressed"),
        ] {
            assert_eq!(
                classify_message_delivery(
                    MessageDeliveryObservation::Inbound {
                        notification,
                        handling: RequestHandlingObservation::NotRecorded,
                    },
                    100,
                )
                .unwrap()
                .as_str(),
                expected
            );
        }
    }

    #[test]
    fn handling_evidence_is_not_inferred_from_notification_state() {
        for notification in [
            LocalDeliveryObservation::NotRetained,
            LocalDeliveryObservation::Pending,
            LocalDeliveryObservation::Claimed,
            LocalDeliveryObservation::Acknowledged,
            LocalDeliveryObservation::Suppressed,
        ] {
            for (handling, expected) in [
                (
                    RequestHandlingObservation::ResponseReserved,
                    MessageDeliveryStatus::ResponseReserved,
                ),
                (
                    RequestHandlingObservation::CompletedWithoutResponse,
                    MessageDeliveryStatus::CompletedWithoutResponse,
                ),
            ] {
                assert_eq!(
                    classify_message_delivery(
                        MessageDeliveryObservation::Inbound {
                            notification,
                            handling,
                        },
                        100,
                    ),
                    Ok(expected)
                );
            }
        }
    }

    #[test]
    fn claim_expiry_has_an_exact_boundary_without_liveness_or_retry_authority() {
        for (expiry, now, expected) in [
            (101, 100, MessageDeliveryStatus::RequestClaimRecorded),
            (100, 100, MessageDeliveryStatus::RequestClaimExpired),
            (99, 100, MessageDeliveryStatus::RequestClaimExpired),
            (
                u64::MAX,
                u64::MAX - 1,
                MessageDeliveryStatus::RequestClaimRecorded,
            ),
            (
                u64::MAX,
                u64::MAX,
                MessageDeliveryStatus::RequestClaimExpired,
            ),
        ] {
            assert_eq!(
                classify_message_delivery(
                    MessageDeliveryObservation::Inbound {
                        notification: LocalDeliveryObservation::Claimed,
                        handling: RequestHandlingObservation::Claimed {
                            expires_at_unix_milliseconds: expiry,
                        },
                    },
                    now,
                ),
                Ok(expected)
            );
        }
        assert_eq!(
            classify_message_delivery(
                MessageDeliveryObservation::Inbound {
                    notification: LocalDeliveryObservation::Claimed,
                    handling: RequestHandlingObservation::Claimed {
                        expires_at_unix_milliseconds: 0,
                    },
                },
                100,
            ),
            Err(DeliveryDiagnosticError::InvalidClaimExpiry)
        );
    }
}
