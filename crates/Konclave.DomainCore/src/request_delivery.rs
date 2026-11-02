use thiserror::Error;

/// Largest admission cutoff representable exactly by supported JSON clients.
pub const MAX_REQUEST_ADMISSION_UNIX_MILLISECONDS: u64 = 9_007_199_254_740_991;

/// An immutable request admission cutoff, not a work or lease deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestAdmissionExpiry(u64);

impl RequestAdmissionExpiry {
    /// Validates a nonzero, exactly representable Unix millisecond cutoff.
    ///
    /// # Errors
    ///
    /// Returns [`RequestDeliveryError::InvalidExpiry`] for zero or an oversized value.
    pub fn new(unix_milliseconds: u64) -> Result<Self, RequestDeliveryError> {
        if unix_milliseconds == 0 || unix_milliseconds > MAX_REQUEST_ADMISSION_UNIX_MILLISECONDS {
            return Err(RequestDeliveryError::InvalidExpiry);
        }
        Ok(Self(unix_milliseconds))
    }

    /// Returns the authenticated sender's cutoff in Unix milliseconds.
    #[must_use]
    pub const fn unix_milliseconds(self) -> u64 {
        self.0
    }

    /// Checks the receiver's current clock; equality is already expired.
    ///
    /// Call before enqueue and again at admission. Once admitted, the cutoff does
    /// not cancel work, invalidate replies, or extend any local authorization.
    #[must_use]
    pub const fn is_expired(self, now_unix_milliseconds: u64) -> bool {
        now_unix_milliseconds >= self.0
    }
}

/// Authority-free observations of one exact directed request.
///
/// These values describe delivery, not task success or permission to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDeliveryOutcome {
    /// The receiver admitted the request under current local authorization.
    Admitted,
    /// The receiver durably reserved the request's one terminal response.
    Responded,
    /// The cutoff passed before admission.
    ExpiredBeforeAdmission,
    /// Handling ended without a response; arbitrary external effects may have occurred.
    EndedWithoutResponse,
}

impl RequestDeliveryOutcome {
    /// Stable nonzero representation for the encrypted receipt.
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::Admitted => 1,
            Self::Responded => 2,
            Self::ExpiredBeforeAdmission => 3,
            Self::EndedWithoutResponse => 4,
        }
    }

    /// Rejects absent and unknown receipt outcomes rather than interpreting defaults.
    ///
    /// # Errors
    ///
    /// Returns [`RequestDeliveryError::UnknownOutcome`] for an unsupported value.
    pub fn from_wire(value: u32) -> Result<Self, RequestDeliveryError> {
        match value {
            1 => Ok(Self::Admitted),
            2 => Ok(Self::Responded),
            3 => Ok(Self::ExpiredBeforeAdmission),
            4 => Ok(Self::EndedWithoutResponse),
            _ => Err(RequestDeliveryError::UnknownOutcome),
        }
    }
}

/// Finite delivery-contract errors without peer bodies or local secrets.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RequestDeliveryError {
    /// The supplied cutoff cannot be represented by every supported client.
    #[error("request admission expiry is invalid")]
    InvalidExpiry,
    /// An encrypted receipt has no recognized outcome.
    #[error("request delivery outcome is unsupported")]
    UnknownOutcome,
    /// Two authenticated observations contradict an already observed terminal result.
    #[error("request delivery outcome conflicts with existing delivery state")]
    ConflictingOutcome,
}

/// Folds authenticated observations without a task registry or arrival-order trust.
///
/// `None` means no receipt has been observed. The caller must first bind each receipt
/// to the exact outbound request, conversation and authenticated target. A terminal
/// receipt may precede its admission receipt, but no receipt can reopen a terminal
/// result. Absence of a receipt is unknown, never evidence of expiry or completion.
///
/// # Errors
///
/// Returns [`RequestDeliveryError::ConflictingOutcome`] for contradictory terminal
/// outcomes or an expiry observation after observed admission.
pub fn observe_request_delivery(
    current: Option<RequestDeliveryOutcome>,
    observed: RequestDeliveryOutcome,
) -> Result<RequestDeliveryOutcome, RequestDeliveryError> {
    use RequestDeliveryOutcome::{Admitted, ExpiredBeforeAdmission};

    match (current, observed) {
        (None, _) => Ok(observed),
        (Some(existing), incoming) if existing == incoming => Ok(existing),
        (Some(Admitted), ExpiredBeforeAdmission) => Err(RequestDeliveryError::ConflictingOutcome),
        (Some(Admitted), _) => Ok(observed),
        (Some(existing), Admitted) => Ok(existing),
        (Some(_), _) => Err(RequestDeliveryError::ConflictingOutcome),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_cutoff_is_exclusive_and_never_uses_a_relative_budget() {
        let expiry = RequestAdmissionExpiry::new(1_000).unwrap();
        assert!(!expiry.is_expired(999));
        assert!(expiry.is_expired(1_000));
        assert!(expiry.is_expired(1_001));
        assert!(expiry.is_expired(u64::MAX));
        for value in [0, MAX_REQUEST_ADMISSION_UNIX_MILLISECONDS + 1, u64::MAX] {
            assert_eq!(
                RequestAdmissionExpiry::new(value),
                Err(RequestDeliveryError::InvalidExpiry)
            );
        }
        for value in [1, MAX_REQUEST_ADMISSION_UNIX_MILLISECONDS] {
            assert_eq!(
                RequestAdmissionExpiry::new(value).unwrap().unix_milliseconds(),
                value
            );
        }
    }

    #[test]
    fn every_wire_outcome_is_explicit_and_unknown_values_fail_closed() {
        for outcome in [
            RequestDeliveryOutcome::Admitted,
            RequestDeliveryOutcome::Responded,
            RequestDeliveryOutcome::ExpiredBeforeAdmission,
            RequestDeliveryOutcome::EndedWithoutResponse,
        ] {
            assert_eq!(
                RequestDeliveryOutcome::from_wire(outcome.wire_value()),
                Ok(outcome)
            );
        }
        for value in [0, 5, u32::MAX] {
            assert_eq!(
                RequestDeliveryOutcome::from_wire(value),
                Err(RequestDeliveryError::UnknownOutcome)
            );
        }
    }

    #[test]
    fn all_observation_pairs_preserve_terminal_results() {
        use RequestDeliveryOutcome::{
            Admitted, EndedWithoutResponse, ExpiredBeforeAdmission, Responded,
        };
        let outcomes = [
            Admitted,
            Responded,
            ExpiredBeforeAdmission,
            EndedWithoutResponse,
        ];
        let conflict = Err(RequestDeliveryError::ConflictingOutcome);
        let expected = [
            [
                Ok(Admitted),
                Ok(Responded),
                conflict,
                Ok(EndedWithoutResponse),
            ],
            [Ok(Responded), Ok(Responded), conflict, conflict],
            [
                Ok(ExpiredBeforeAdmission),
                conflict,
                Ok(ExpiredBeforeAdmission),
                conflict,
            ],
            [
                Ok(EndedWithoutResponse),
                conflict,
                conflict,
                Ok(EndedWithoutResponse),
            ],
        ];
        for (row, current) in outcomes.into_iter().enumerate() {
            for (column, observed) in outcomes.into_iter().enumerate() {
                assert_eq!(
                    observe_request_delivery(Some(current), observed),
                    expected[row][column],
                    "{current:?} then {observed:?}"
                );
            }
            assert_eq!(observe_request_delivery(None, current), Ok(current));
        }
    }
}
