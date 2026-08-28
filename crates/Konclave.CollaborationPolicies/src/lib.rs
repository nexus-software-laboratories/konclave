#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod catalog;
mod error;
mod file;
mod source;

pub use catalog::FileCollaborationPolicyCatalog;
pub use error::CollaborationPolicySourceError;
pub use source::{
    CompiledCollaborationPolicy, MAX_COLLABORATION_POLICY_SOURCE_BYTES,
    compile_collaboration_policy_file, compile_collaboration_policy_source,
    create_collaboration_policy_source_file, write_compiled_collaboration_policy_file,
};
