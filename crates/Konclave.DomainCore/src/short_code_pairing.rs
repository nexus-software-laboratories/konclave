use crate::KonclaveDomainError;

/// Maximum numeric value represented by a six-digit short authentication string.
pub const MAX_SHORT_CODE_PAIRING_SAS: u32 = 999_999;

/// Six-digit transcript authentication string displayed at both endpoints.
///
/// This type intentionally omits `Debug`; SAS values must not enter diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortCodePairingSas(u32);

impl ShortCodePairingSas {
    /// Validates one six-digit numeric SAS.
    ///
    /// # Errors
    ///
    /// Returns an out-of-range error for values above six decimal digits.
    pub fn new(value: u32) -> Result<Self, KonclaveDomainError> {
        if value > MAX_SHORT_CODE_PAIRING_SAS {
            return Err(KonclaveDomainError::OutOfRange {
                field: "short_code_pairing_sas",
                minimum: 0,
                maximum: MAX_SHORT_CODE_PAIRING_SAS as usize,
                actual: value as usize,
            });
        }
        Ok(Self(value))
    }

    /// Returns the zero-padded six-digit display text.
    #[must_use]
    pub fn to_text(self) -> String {
        format!("{:06}", self.0)
    }

    /// Returns the numeric value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Durable state of two independent short-code pairing confirmations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeConfirmationState {
    /// Neither endpoint confirmation has authenticated.
    AwaitingBoth,
    /// Peer confirmation authenticated before the local operator confirmed.
    AwaitingLocal,
    /// The local operator confirmed before peer confirmation authenticated.
    AwaitingPeer,
    /// Both independent confirmations authenticated before the deadline.
    Confirmed,
    /// The attempt was explicitly cancelled and cannot be confirmed.
    Cancelled,
}

/// Authenticated event applied to short-code confirmation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeConfirmationEvent {
    /// The local operator confirmed the exact displayed transcript.
    LocalConfirmed,
    /// The peer's session-authenticated confirmation was received.
    PeerConfirmed,
    /// The attempt was explicitly cancelled.
    Cancelled,
}

/// Applies one idempotent confirmation event before the common deadline.
///
/// # Errors
///
/// Returns expiry before any non-cancellation transition at the deadline, or an
/// invalid-transition error when confirmation is attempted after cancellation.
pub fn transition_short_code_confirmation(
    state: ShortCodeConfirmationState,
    event: ShortCodeConfirmationEvent,
    now_unix_seconds: u64,
    deadline_unix_seconds: u64,
) -> Result<ShortCodeConfirmationState, KonclaveDomainError> {
    if event == ShortCodeConfirmationEvent::Cancelled {
        return Ok(ShortCodeConfirmationState::Cancelled);
    }
    if state == ShortCodeConfirmationState::Cancelled {
        return Err(KonclaveDomainError::InvalidShortCodePairingTransition);
    }
    if now_unix_seconds >= deadline_unix_seconds {
        return Err(KonclaveDomainError::ShortCodePairingExpired);
    }
    Ok(match (state, event) {
        (ShortCodeConfirmationState::AwaitingBoth, ShortCodeConfirmationEvent::LocalConfirmed) => {
            ShortCodeConfirmationState::AwaitingPeer
        }
        (ShortCodeConfirmationState::AwaitingBoth, ShortCodeConfirmationEvent::PeerConfirmed) => {
            ShortCodeConfirmationState::AwaitingLocal
        }
        (ShortCodeConfirmationState::AwaitingLocal, ShortCodeConfirmationEvent::LocalConfirmed)
        | (ShortCodeConfirmationState::AwaitingPeer, ShortCodeConfirmationEvent::PeerConfirmed) => {
            ShortCodeConfirmationState::Confirmed
        }
        (ShortCodeConfirmationState::AwaitingLocal, ShortCodeConfirmationEvent::PeerConfirmed)
        | (ShortCodeConfirmationState::AwaitingPeer, ShortCodeConfirmationEvent::LocalConfirmed)
        | (ShortCodeConfirmationState::Confirmed, _)
        | (ShortCodeConfirmationState::AwaitingBoth, ShortCodeConfirmationEvent::Cancelled)
        | (ShortCodeConfirmationState::AwaitingLocal, ShortCodeConfirmationEvent::Cancelled)
        | (ShortCodeConfirmationState::AwaitingPeer, ShortCodeConfirmationEvent::Cancelled)
        | (ShortCodeConfirmationState::Cancelled, _) => state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_six_digits_and_bounded() {
        assert_eq!(ShortCodePairingSas::new(42).unwrap().to_text(), "000042");
        assert!(ShortCodePairingSas::new(1_000_000).is_err());
    }

    #[test]
    fn confirmation_transition_table_covers_order_replay_expiry_and_cancellation() {
        use ShortCodeConfirmationEvent as Event;
        use ShortCodeConfirmationState as State;

        let cases = [
            (
                State::AwaitingBoth,
                Event::LocalConfirmed,
                Ok(State::AwaitingPeer),
            ),
            (
                State::AwaitingBoth,
                Event::PeerConfirmed,
                Ok(State::AwaitingLocal),
            ),
            (
                State::AwaitingPeer,
                Event::PeerConfirmed,
                Ok(State::Confirmed),
            ),
            (
                State::AwaitingLocal,
                Event::LocalConfirmed,
                Ok(State::Confirmed),
            ),
            (
                State::AwaitingPeer,
                Event::LocalConfirmed,
                Ok(State::AwaitingPeer),
            ),
            (
                State::AwaitingLocal,
                Event::PeerConfirmed,
                Ok(State::AwaitingLocal),
            ),
            (
                State::Confirmed,
                Event::LocalConfirmed,
                Ok(State::Confirmed),
            ),
            (State::Confirmed, Event::PeerConfirmed, Ok(State::Confirmed)),
            (State::AwaitingBoth, Event::Cancelled, Ok(State::Cancelled)),
            (State::Confirmed, Event::Cancelled, Ok(State::Cancelled)),
            (
                State::Cancelled,
                Event::LocalConfirmed,
                Err(KonclaveDomainError::InvalidShortCodePairingTransition),
            ),
        ];
        for (state, event, expected) in cases {
            assert_eq!(
                transition_short_code_confirmation(state, event, 9, 10),
                expected
            );
        }
        assert_eq!(
            transition_short_code_confirmation(State::AwaitingBoth, Event::LocalConfirmed, 10, 10),
            Err(KonclaveDomainError::ShortCodePairingExpired)
        );
        assert_eq!(
            transition_short_code_confirmation(State::Cancelled, Event::Cancelled, 10, 10),
            Ok(State::Cancelled)
        );
    }
}
