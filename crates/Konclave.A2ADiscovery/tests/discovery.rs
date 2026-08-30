use std::cell::RefCell;
use std::path::Path;

use KonclaveA2AContracts::InitialA2AInterfaceEnvironment;
use KonclaveA2ADiscovery::{
    A2ADiscoveryAction, A2ADiscoveryAuthorizationDecision, A2ADiscoveryAuthorizer,
    A2ADiscoveryError, FileA2AAgentCatalog, MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES,
    OASF_LANGUAGE_GENERATION_SKILL, OASF_RELEASE_COMMIT, OASF_SCHEMA_VERSION,
    compile_a2a_agent_publication_source,
};
use KonclaveA2ADomain::A2AAgentId;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn publication(id: &str, publicly_discoverable: bool, extended: bool, oasf: bool) -> Vec<u8> {
    let extended_skills = if extended {
        vec![json!({
            "id": "private-contract-review",
            "name": "Private contract review",
            "description": "Reviews deployment-scoped contract details.",
            "tags": ["contracts", "private"]
        })]
    } else {
        vec![]
    };
    let oasf = oasf.then(|| {
        json!({
            "authors": ["Konclave Maintainers <maintainers@example.com>"],
            "createdAt": "2026-08-30T00:00:00Z",
            "skills": [OASF_LANGUAGE_GENERATION_SKILL]
        })
    });
    serde_json::to_vec(&json!({
        "apiVersion": "konclave.dev/v1",
        "kind": "A2AAgentPublication",
        "metadata": {
            "name": id
        },
        "spec": {
            "publicWellKnown": publicly_discoverable,
            "name": "Contract agent",
            "description": "Coordinates one bounded text contract request.",
            "version": "1.0.0",
            "interfaces": [{
                "url": "https://agent.example.com/a2a/v1",
                "tenant": "tenant-a"
            }],
            "authentication": {
                "type": "bearer",
                "name": "bearer",
                "bearerFormat": "JWT"
            },
            "skills": [{
                "id": "contract-review",
                "name": "Contract review",
                "description": "Reviews one text contract and returns one response.",
                "tags": ["contracts", "text"]
            }],
            "extendedSkills": extended_skills,
            "oasf": oasf
        }
    }))
    .unwrap()
}

fn write_publication(root: &Path, file_name: &str, id: &str, public: bool) {
    std::fs::write(root.join(file_name), publication(id, public, true, true)).unwrap();
}

#[test]
fn source_generates_compatible_public_extended_and_oasf_views() {
    assert_eq!(OASF_SCHEMA_VERSION, "1.1.0");
    assert_eq!(
        OASF_RELEASE_COMMIT,
        "f510be0d4b5878ac8f86c64ffd6cd7132733c03e"
    );
    let compiled = compile_a2a_agent_publication_source(
        &publication("agent-a", false, true, true),
        InitialA2AInterfaceEnvironment::Production,
    )
    .unwrap();
    assert_eq!(compiled.id().as_str(), "agent-a");
    assert!(!compiled.publicly_discoverable());
    assert_eq!(compiled.card().skills().len(), 1);
    assert!(compiled.card().extended_agent_card());
    assert_eq!(compiled.extended_card().unwrap().skills().len(), 2);

    let oasf = compiled.oasf_record().unwrap();
    let record: Value = serde_json::from_slice(oasf.bytes()).unwrap();
    assert_eq!(record["schema_version"], OASF_SCHEMA_VERSION);
    assert_eq!(record["skills"][0]["name"], OASF_LANGUAGE_GENERATION_SKILL);
    assert!(record.get("locators").is_none());
    assert_eq!(
        record["modules"][0]["artifact"]["size"],
        u64::try_from(oasf.agent_card_size()).unwrap()
    );
    let digest = record["modules"][0]["artifact"]["digest"].as_str().unwrap();
    assert!(digest.starts_with("sha256:"));
    assert_eq!(digest.len(), 71);
    assert_eq!(
        record["modules"][0]["artifact"]["json"]["skills"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let embedded_card = serde_json::to_vec(&record["modules"][0]["artifact"]["json"]).unwrap();
    assert_eq!(embedded_card.len(), oasf.agent_card_size());
    assert_eq!(
        format!("sha256:{}", hex(oasf.agent_card_digest())),
        record["modules"][0]["artifact"]["digest"]
    );
    assert_eq!(
        hex(oasf.agent_card_digest()),
        "3f5741dcbdfd05a742184d5e9e6d1b3c65d14982b826345cd1b559b427458294"
    );
    assert_eq!(
        hex(&Sha256::digest(oasf.bytes()).into()),
        "0fa68bc7d750b07f794b43fa6d226f78fe5a33054fd0a26866d13fdd5a8cc15d"
    );

    let repeated = compile_a2a_agent_publication_source(
        &publication("agent-a", false, true, true),
        InitialA2AInterfaceEnvironment::Production,
    )
    .unwrap();
    assert_eq!(
        repeated.oasf_record().unwrap().bytes(),
        compiled.oasf_record().unwrap().bytes()
    );
}

#[test]
fn production_requires_authentication_and_unauthenticated_development_is_loopback_only() {
    let mut source: Value =
        serde_json::from_slice(&publication("agent-a", false, false, false)).unwrap();
    source["spec"]
        .as_object_mut()
        .unwrap()
        .remove("authentication");
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&source).unwrap(),
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::AuthenticationRequired)
    );
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&source).unwrap(),
            InitialA2AInterfaceEnvironment::LoopbackDevelopment
        )
        .err(),
        Some(A2ADiscoveryError::UnauthenticatedInterface)
    );

    source["spec"]["interfaces"][0]["url"] = json!("http://127.0.0.1:8080/a2a/v1");
    source["spec"]["interfaces"][0]
        .as_object_mut()
        .unwrap()
        .remove("tenant");
    let compiled = compile_a2a_agent_publication_source(
        &serde_json::to_vec(&source).unwrap(),
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    assert!(compiled.card().security().is_none());
    assert_eq!(compiled.card().interfaces()[0].tenant(), None);

    let mut mtls: Value =
        serde_json::from_slice(&publication("agent-a", false, false, false)).unwrap();
    mtls["spec"]["authentication"] = json!({
        "type": "mutualTls",
        "name": "mutual-tls"
    });
    let compiled = compile_a2a_agent_publication_source(
        &serde_json::to_vec(&mtls).unwrap(),
        InitialA2AInterfaceEnvironment::Production,
    )
    .unwrap();
    assert_eq!(compiled.card().security().unwrap().name(), "mutual-tls");
}

#[test]
fn source_rejects_unbounded_unknown_duplicate_and_false_oasf_claims() {
    assert_eq!(
        compile_a2a_agent_publication_source(
            &vec![b' '; MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES + 1],
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::DocumentTooLarge {
            document: "publication",
            maximum: MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES,
        })
    );

    let mut unknown: Value =
        serde_json::from_slice(&publication("agent-a", false, false, false)).unwrap();
    unknown["spec"]["unknown"] = json!(true);
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&unknown).unwrap(),
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::InvalidJson {
            document: "publication"
        })
    );

    let mut duplicate: Value =
        serde_json::from_slice(&publication("agent-a", false, true, false)).unwrap();
    duplicate["spec"]["extendedSkills"][0]["id"] = json!("contract-review");
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&duplicate).unwrap(),
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::InvalidAgentCard)
    );

    let mut false_taxonomy: Value =
        serde_json::from_slice(&publication("agent-a", false, false, true)).unwrap();
    false_taxonomy["spec"]["oasf"]["skills"][0] = json!("contract_review");
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&false_taxonomy).unwrap(),
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::InvalidOasfProjection)
    );

    let mut invalid_time: Value =
        serde_json::from_slice(&publication("agent-a", false, false, true)).unwrap();
    invalid_time["spec"]["oasf"]["createdAt"] = json!("2026-02-30T00:00:00Z");
    assert_eq!(
        compile_a2a_agent_publication_source(
            &serde_json::to_vec(&invalid_time).unwrap(),
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::InvalidOasfProjection)
    );
}

#[test]
fn file_catalog_is_explicit_eager_and_private_by_default() {
    let root = tempfile::tempdir().unwrap();
    write_publication(root.path(), "private.json", "agent-a", false);
    write_publication(root.path(), "public.json", "agent-b", true);
    write_publication(root.path(), "unlisted.json", "agent-c", true);
    let catalog_path = root.path().join("catalog.json");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "entries": [
                {"name": "agent-b", "source": "public.json"},
                {"name": "agent-a", "source": "private.json"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let catalog =
        FileA2AAgentCatalog::open(&catalog_path, InitialA2AInterfaceEnvironment::Production)
            .unwrap();
    let private = A2AAgentId::parse("agent-a").unwrap();
    let public = A2AAgentId::parse("agent-b").unwrap();
    let absent = A2AAgentId::parse("agent-c").unwrap();
    assert!(catalog.public_card(&private).is_none());
    assert!(catalog.public_card(&absent).is_none());
    assert!(catalog.public_card(&public).is_some());

    let allow = RecordingAuthorizer::new(A2ADiscoveryAuthorizationDecision::Allow);
    assert_eq!(
        catalog
            .list(&allow)
            .unwrap()
            .iter()
            .map(A2AAgentId::as_str)
            .collect::<Vec<_>>(),
        ["agent-a", "agent-b"]
    );
    assert_eq!(
        catalog
            .private_card(&private, &allow)
            .unwrap()
            .skills()
            .len(),
        1
    );
    assert_eq!(
        catalog
            .extended_card(&private, &allow)
            .unwrap()
            .skills()
            .len(),
        2
    );
    assert!(catalog.oasf_record(&private, &allow).is_ok());
}

#[test]
fn authorization_runs_before_private_lookup_and_never_falls_back() {
    let root = tempfile::tempdir().unwrap();
    write_publication(root.path(), "agent.json", "agent-a", false);
    let catalog_path = root.path().join("catalog.json");
    std::fs::write(
        &catalog_path,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-a","source":"agent.json"}]}"#,
    )
    .unwrap();
    let catalog =
        FileA2AAgentCatalog::open(&catalog_path, InitialA2AInterfaceEnvironment::Production)
            .unwrap();
    let existing = A2AAgentId::parse("agent-a").unwrap();
    let missing = A2AAgentId::parse("agent-z").unwrap();
    let deny = RecordingAuthorizer::new(A2ADiscoveryAuthorizationDecision::Deny);
    assert_eq!(
        catalog.private_card(&existing, &deny).err(),
        Some(A2ADiscoveryError::Unauthorized)
    );
    assert_eq!(
        catalog.private_card(&missing, &deny).err(),
        Some(A2ADiscoveryError::Unauthorized)
    );
    assert_eq!(
        deny.calls.borrow().as_slice(),
        [
            (
                A2ADiscoveryAction::ReadPrivateCard,
                Some("agent-a".to_owned())
            ),
            (
                A2ADiscoveryAction::ReadPrivateCard,
                Some("agent-z".to_owned())
            )
        ]
    );

    let unavailable = RecordingAuthorizer::new(A2ADiscoveryAuthorizationDecision::Unavailable);
    assert_eq!(
        catalog.list(&unavailable).err(),
        Some(A2ADiscoveryError::AuthorizationUnavailable)
    );
    let allow = RecordingAuthorizer::new(A2ADiscoveryAuthorizationDecision::Allow);
    assert_eq!(
        catalog.private_card(&missing, &allow).err(),
        Some(A2ADiscoveryError::PublicationNotFound)
    );
}

#[test]
fn catalog_rejects_unsafe_duplicate_mismatched_and_invalid_sources() {
    let root = tempfile::tempdir().unwrap();
    write_publication(root.path(), "agent.json", "agent-a", false);
    write_publication(root.path(), "other.json", "agent-b", false);

    let duplicate_source = root.path().join("duplicate-source.json");
    std::fs::write(
        &duplicate_source,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-a","source":"agent.json"},{"name":"agent-b","source":"agent.json"}]}"#,
    )
    .unwrap();
    assert_eq!(
        FileA2AAgentCatalog::open(
            &duplicate_source,
            InitialA2AInterfaceEnvironment::Production
        )
        .err(),
        Some(A2ADiscoveryError::DuplicateCatalogEntry { field: "source" })
    );

    write_publication(root.path(), "duplicate-name.json", "agent-a", false);
    let duplicate_name = root.path().join("duplicate-name-catalog.json");
    std::fs::write(
        &duplicate_name,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-a","source":"agent.json"},{"name":"agent-a","source":"duplicate-name.json"}]}"#,
    )
    .unwrap();
    assert_eq!(
        FileA2AAgentCatalog::open(&duplicate_name, InitialA2AInterfaceEnvironment::Production)
            .err(),
        Some(A2ADiscoveryError::DuplicateCatalogEntry { field: "name" })
    );

    let mismatch = root.path().join("mismatch.json");
    std::fs::write(
        &mismatch,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-b","source":"agent.json"}]}"#,
    )
    .unwrap();
    assert_eq!(
        FileA2AAgentCatalog::open(&mismatch, InitialA2AInterfaceEnvironment::Production).err(),
        Some(A2ADiscoveryError::CatalogNameMismatch)
    );

    let unsafe_path = root.path().join("unsafe.json");
    std::fs::write(
        &unsafe_path,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-a","source":"../agent.json"}]}"#,
    )
    .unwrap();
    assert_eq!(
        FileA2AAgentCatalog::open(&unsafe_path, InitialA2AInterfaceEnvironment::Production).err(),
        Some(A2ADiscoveryError::UnsafeCatalogPath)
    );

    let invalid = root.path().join("invalid.json");
    std::fs::write(&invalid, br#"{"apiVersion":"wrong"}"#).unwrap();
    let invalid_catalog = root.path().join("invalid-catalog.json");
    std::fs::write(
        &invalid_catalog,
        br#"{"schemaVersion":1,"entries":[{"name":"agent-a","source":"invalid.json"}]}"#,
    )
    .unwrap();
    assert!(
        FileA2AAgentCatalog::open(&invalid_catalog, InitialA2AInterfaceEnvironment::Production)
            .is_err()
    );
}

#[test]
fn repository_examples_compile_through_private_catalog_discovery() {
    let catalog_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../a2a/examples/catalog.json");
    let catalog =
        FileA2AAgentCatalog::open(&catalog_path, InitialA2AInterfaceEnvironment::Production)
            .unwrap();
    let agent_id = A2AAgentId::parse("contract-agent").unwrap();
    assert!(catalog.public_card(&agent_id).is_none());
    let allow = RecordingAuthorizer::new(A2ADiscoveryAuthorizationDecision::Allow);
    assert_eq!(
        catalog.private_card(&agent_id, &allow).unwrap().name(),
        "Contract agent"
    );
    assert!(catalog.extended_card(&agent_id, &allow).is_ok());
    assert!(catalog.oasf_record(&agent_id, &allow).is_ok());
}

struct RecordingAuthorizer {
    decision: A2ADiscoveryAuthorizationDecision,
    calls: RefCell<Vec<(A2ADiscoveryAction, Option<String>)>>,
}

impl RecordingAuthorizer {
    fn new(decision: A2ADiscoveryAuthorizationDecision) -> Self {
        Self {
            decision,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl A2ADiscoveryAuthorizer for RecordingAuthorizer {
    fn authorize(
        &self,
        action: A2ADiscoveryAction,
        agent_id: Option<&A2AAgentId>,
    ) -> A2ADiscoveryAuthorizationDecision {
        self.calls.borrow_mut().push((
            action,
            agent_id.map(|agent_id| agent_id.as_str().to_owned()),
        ));
        self.decision
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}
