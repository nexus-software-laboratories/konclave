#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationState {
    SourceActive,
    RegistrationPrepared,
    DestinationActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationEvent {
    Apply,
    RegistrationAccepted,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationAction {
    PrepareRegistration,
    RegisterDestination,
    CommitDestination,
    ClearPreparation,
    Complete,
    Reject,
}

pub(crate) const fn resolve_relay_migration_action(
    state: RelayMigrationState,
    event: RelayMigrationEvent,
) -> RelayMigrationAction {
    match (state, event) {
        (RelayMigrationState::SourceActive, RelayMigrationEvent::Apply) => {
            RelayMigrationAction::PrepareRegistration
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::Apply) => {
            RelayMigrationAction::RegisterDestination
        }
        (RelayMigrationState::DestinationActive, RelayMigrationEvent::Apply)
        | (RelayMigrationState::SourceActive, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::Complete
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::RegistrationAccepted) => {
            RelayMigrationAction::CommitDestination
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::ClearPreparation
        }
        (
            RelayMigrationState::SourceActive | RelayMigrationState::DestinationActive,
            RelayMigrationEvent::RegistrationAccepted,
        )
        | (RelayMigrationState::DestinationActive, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RelayMigrationAction, RelayMigrationEvent, RelayMigrationState,
        resolve_relay_migration_action,
    };

    #[test]
    fn relay_migration_transition_table_is_exhaustive() {
        let cases = [
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::PrepareRegistration,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::RegisterDestination,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::Complete,
            ),
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::CommitDestination,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::Complete,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::ClearPreparation,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::Reject,
            ),
        ];

        for (state, event, expected) in cases {
            assert_eq!(resolve_relay_migration_action(state, event), expected);
        }
    }
}
