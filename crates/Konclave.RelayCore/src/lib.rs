#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identifiers;
mod pairing_rendezvous;
mod repository;
mod service;
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
    RelayPrincipalRegistry, RelayRepository, SubmitResult,
};
pub use service::{
    DynamicRelayAuthorizer, RelayAuthorizer, RelayClock, RelayPermission, RelayService,
    SystemRelayClock,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRelayRepository;
