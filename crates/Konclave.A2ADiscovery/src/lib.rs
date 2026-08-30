#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod catalog;
mod error;
mod model;
mod oasf;
mod source;

pub use catalog::{
    FileA2AAgentCatalog, MAX_A2A_AGENT_CATALOG_BYTES, MAX_A2A_AGENT_CATALOG_ENTRIES,
};
pub use error::A2ADiscoveryError;
pub use model::{
    A2ADiscoveryAction, A2ADiscoveryAuthorizationDecision, A2ADiscoveryAuthorizer,
    CompiledA2AAgentPublication,
};
pub use oasf::{
    OASF_LANGUAGE_GENERATION_SKILL, OASF_RELEASE_COMMIT, OASF_SCHEMA_VERSION, OasfAgentRecord,
};
pub use source::{
    MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES, MAX_OASF_AUTHOR_BYTES, MAX_OASF_AUTHORS,
    MAX_OASF_SKILLS, compile_a2a_agent_publication_file, compile_a2a_agent_publication_source,
};
