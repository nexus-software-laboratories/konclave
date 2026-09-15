#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationReloadState {
    Active,
    FailedClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationReloadEvent {
    SnapshotVerified,
    ObservationFailed,
    WorkerFailed,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationReloadTransition {
    Publish { next: AuthorizationReloadState },
    FailClosed { next: AuthorizationReloadState },
    StopService,
    StopCleanly,
}

pub(crate) const fn resolve_authorization_reload_transition(
    _state: AuthorizationReloadState,
    event: AuthorizationReloadEvent,
) -> AuthorizationReloadTransition {
    match event {
        AuthorizationReloadEvent::SnapshotVerified => AuthorizationReloadTransition::Publish {
            next: AuthorizationReloadState::Active,
        },
        AuthorizationReloadEvent::ObservationFailed => AuthorizationReloadTransition::FailClosed {
            next: AuthorizationReloadState::FailedClosed,
        },
        AuthorizationReloadEvent::WorkerFailed => AuthorizationReloadTransition::StopService,
        AuthorizationReloadEvent::Shutdown => AuthorizationReloadTransition::StopCleanly,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationReloadEvent, AuthorizationReloadState, AuthorizationReloadTransition,
        resolve_authorization_reload_transition,
    };

    #[test]
    fn reload_transition_table_is_exhaustive() {
        let cases = [
            (
                AuthorizationReloadState::Active,
                AuthorizationReloadEvent::SnapshotVerified,
                AuthorizationReloadTransition::Publish {
                    next: AuthorizationReloadState::Active,
                },
            ),
            (
                AuthorizationReloadState::FailedClosed,
                AuthorizationReloadEvent::SnapshotVerified,
                AuthorizationReloadTransition::Publish {
                    next: AuthorizationReloadState::Active,
                },
            ),
            (
                AuthorizationReloadState::Active,
                AuthorizationReloadEvent::ObservationFailed,
                AuthorizationReloadTransition::FailClosed {
                    next: AuthorizationReloadState::FailedClosed,
                },
            ),
            (
                AuthorizationReloadState::FailedClosed,
                AuthorizationReloadEvent::ObservationFailed,
                AuthorizationReloadTransition::FailClosed {
                    next: AuthorizationReloadState::FailedClosed,
                },
            ),
            (
                AuthorizationReloadState::Active,
                AuthorizationReloadEvent::WorkerFailed,
                AuthorizationReloadTransition::StopService,
            ),
            (
                AuthorizationReloadState::FailedClosed,
                AuthorizationReloadEvent::WorkerFailed,
                AuthorizationReloadTransition::StopService,
            ),
            (
                AuthorizationReloadState::Active,
                AuthorizationReloadEvent::Shutdown,
                AuthorizationReloadTransition::StopCleanly,
            ),
            (
                AuthorizationReloadState::FailedClosed,
                AuthorizationReloadEvent::Shutdown,
                AuthorizationReloadTransition::StopCleanly,
            ),
        ];

        for (state, event, expected) in cases {
            assert_eq!(
                resolve_authorization_reload_transition(state, event),
                expected
            );
        }
    }
}
