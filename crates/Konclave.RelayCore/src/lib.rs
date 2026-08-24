#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identifiers;
mod repository;
mod service;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use error::RelayError;
pub use identifiers::RelayPrincipalId;
pub use repository::{EncodedReplayPage, RelayPrincipalRegistry, RelayRepository, SubmitResult};
pub use service::{
    DynamicRelayAuthorizer, RelayAuthorizer, RelayClock, RelayPermission, RelayService,
    SystemRelayClock,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRelayRepository;
