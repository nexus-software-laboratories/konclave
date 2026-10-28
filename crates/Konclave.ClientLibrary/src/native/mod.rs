//! Durable native conversation processing over explicit host-owned journals.
//!
//! The caller is a trusted cryptographic endpoint, not an RPC adapter. Hold one
//! exclusive endpoint operation lease while constructing and using a processor.
//! Journal and MLS adapters must fence every mutation against that same owner.
//! A process mutex alone does not provide ownership across service replicas.

mod journal;
mod processor;

#[cfg(test)]
mod tests;

pub use journal::*;
pub use processor::*;
