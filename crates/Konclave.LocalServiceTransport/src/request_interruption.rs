use crate::LocalServiceErrorCode;

/// Why an authenticated request can no longer proceed on its original connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRequestInterruption {
    /// The caller explicitly requested cancellation.
    Caller,
    /// The caller's request deadline elapsed.
    Deadline,
    /// The service is shutting down.
    Shutdown,
    /// A current authorization projection rejects the bound grant.
    AuthorizationLost,
    /// No current verified authorization projection is available.
    AuthorizationUnavailable,
    /// The bound profile's supervised runtime is no longer available.
    ProfileUnavailable,
}

impl LocalRequestInterruption {
    /// Returns the existing RPC code for this interruption without fabricating a denial.
    pub const fn error_code(self) -> LocalServiceErrorCode {
        match self {
            Self::Caller => LocalServiceErrorCode::Cancelled,
            Self::Deadline => LocalServiceErrorCode::DeadlineExceeded,
            Self::Shutdown => LocalServiceErrorCode::ProfileUnavailable,
            Self::AuthorizationLost => LocalServiceErrorCode::NotAuthorized,
            Self::AuthorizationUnavailable | Self::ProfileUnavailable => {
                LocalServiceErrorCode::ReconciliationPending
            }
        }
    }
}

/// Whether a handler might already have produced an externally visible effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRequestExecutionState {
    /// The operation handler has not started.
    BeforeExecution,
    /// The operation handler may have started and must not be dispatched again.
    Executing,
    /// The actual terminal outcome has been recorded.
    Settled,
}

/// How an interruption affects a request's replay and outcome ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRequestInterruptionAction {
    /// Record a terminal cancellation without invoking the operation handler.
    Cancel(LocalServiceErrorCode),
    /// Preserve exact request binding until a freshly authorized replay can resume it.
    AwaitAuthorization,
    /// Let the existing execution reconcile its actual outcome without redispatch.
    ReconcileExecution,
    /// Keep the already-recorded terminal outcome unchanged.
    PreserveOutcome,
}

/// Resolves interruption policy without granting authority or performing effects.
///
/// `BeforeExecution` must only be supplied when the handler has not started.
/// `AwaitAuthorization` never permits execution on the interrupted connection:
/// replay must pass fresh authorization and retain the exact principal, identifier,
/// operation, and payload binding.
pub const fn resolve_local_request_interruption(
    state: LocalRequestExecutionState,
    reason: LocalRequestInterruption,
) -> LocalRequestInterruptionAction {
    match state {
        LocalRequestExecutionState::BeforeExecution => match reason {
            LocalRequestInterruption::AuthorizationUnavailable
            | LocalRequestInterruption::ProfileUnavailable => {
                LocalRequestInterruptionAction::AwaitAuthorization
            }
            reason => LocalRequestInterruptionAction::Cancel(reason.error_code()),
        },
        LocalRequestExecutionState::Executing => LocalRequestInterruptionAction::ReconcileExecution,
        LocalRequestExecutionState::Settled => LocalRequestInterruptionAction::PreserveOutcome,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalRequestExecutionState, LocalRequestInterruption, LocalRequestInterruptionAction,
        resolve_local_request_interruption,
    };
    use crate::LocalServiceErrorCode;

    #[test]
    fn every_interruption_preserves_its_finite_error_category() {
        for (reason, code) in [
            (
                LocalRequestInterruption::Caller,
                LocalServiceErrorCode::Cancelled,
            ),
            (
                LocalRequestInterruption::Deadline,
                LocalServiceErrorCode::DeadlineExceeded,
            ),
            (
                LocalRequestInterruption::Shutdown,
                LocalServiceErrorCode::ProfileUnavailable,
            ),
            (
                LocalRequestInterruption::AuthorizationLost,
                LocalServiceErrorCode::NotAuthorized,
            ),
            (
                LocalRequestInterruption::AuthorizationUnavailable,
                LocalServiceErrorCode::ReconciliationPending,
            ),
            (
                LocalRequestInterruption::ProfileUnavailable,
                LocalServiceErrorCode::ReconciliationPending,
            ),
        ] {
            assert_eq!(reason.error_code(), code, "{reason:?}");
        }
    }

    #[test]
    fn all_execution_and_interruption_pairs_preserve_replay_safety() {
        for reason in [
            LocalRequestInterruption::Caller,
            LocalRequestInterruption::Deadline,
            LocalRequestInterruption::Shutdown,
            LocalRequestInterruption::AuthorizationLost,
            LocalRequestInterruption::AuthorizationUnavailable,
            LocalRequestInterruption::ProfileUnavailable,
        ] {
            let before_execution = if matches!(
                reason,
                LocalRequestInterruption::AuthorizationUnavailable
                    | LocalRequestInterruption::ProfileUnavailable
            ) {
                LocalRequestInterruptionAction::AwaitAuthorization
            } else {
                LocalRequestInterruptionAction::Cancel(reason.error_code())
            };
            for (state, expected) in [
                (
                    LocalRequestExecutionState::BeforeExecution,
                    before_execution,
                ),
                (
                    LocalRequestExecutionState::Executing,
                    LocalRequestInterruptionAction::ReconcileExecution,
                ),
                (
                    LocalRequestExecutionState::Settled,
                    LocalRequestInterruptionAction::PreserveOutcome,
                ),
            ] {
                assert_eq!(
                    resolve_local_request_interruption(state, reason),
                    expected,
                    "{state:?} / {reason:?}",
                );
            }
        }
    }
}
