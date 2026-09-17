#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identifiers;
mod pairing_rendezvous;
mod repository;
mod service;
mod short_code_pairing;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use error::RelayError;
pub use identifiers::RelayPrincipalId;
pub use pairing_rendezvous::{
    MAX_ACTIVE_PAIRING_RENDEZVOUS, MAX_ACTIVE_PAIRING_RENDEZVOUS_PER_PRINCIPAL,
    PairingRendezvousPublishDecision, PairingRendezvousTakeDecision, StoredPairingRendezvous,
    decide_pairing_rendezvous_publish, decide_pairing_rendezvous_take,
};
pub use repository::{
    EncodedReplayPage, PairingRendezvousPublishOutcome, PairingRendezvousRepository,
    RelayPrincipalRegistry, RelayRepository, ShortCodeAttemptMessageOutcome,
    ShortCodeAttemptPublishOutcome, ShortCodePairingRepository, SubmitResult,
};
pub use service::{
    DynamicRelayAuthorizer, RelayAuthorizer, RelayClock, RelayPermission, RelayService,
    SystemRelayClock,
};
pub use short_code_pairing::{
    MAX_ACTIVE_SHORT_CODE_ATTEMPTS, MAX_ACTIVE_SHORT_CODE_ATTEMPTS_PER_CREATOR,
    MAX_SHORT_CODE_CLAIMS_PER_LOCATOR_WINDOW, MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW,
    SHORT_CODE_ATTEMPT_LIFETIME_SECONDS, SHORT_CODE_CLAIM_WINDOW_SECONDS,
    ShortCodeCapabilityDecision, ShortCodeClaimDecision, ShortCodeMessageDecision,
    ShortCodePublishDecision, StoredShortCodeAttempt, authorize_short_code_cancel,
    authorize_short_code_read, decide_short_code_capability_take, decide_short_code_claim,
    decide_short_code_message, decide_short_code_publish,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRelayRepository;
