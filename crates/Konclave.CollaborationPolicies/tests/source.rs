use KonclaveCollaborationPolicies::{
    CollaborationPolicySourceError, MAX_COLLABORATION_POLICY_SOURCE_BYTES,
    compile_collaboration_policy_file, compile_collaboration_policy_source,
    create_collaboration_policy_source_file, write_compiled_collaboration_policy_file,
};
use KonclaveDomainCore::{CollaborationPolicyEffect, CollaborationPolicyLimits};

fn source(guidance: &str, limits: &str) -> Vec<u8> {
    format!(
        r#"{{
  "apiVersion": "konclave.dev/v1",
  "kind": "CollaborationPolicy",
  "metadata": {{ "name": "contract-alignment" }},
  "spec": {{
    "guidance": "{guidance}",
    "statements": [
      {{
        "id": "workspace-write",
        "effect": "require_local_approval",
        "action": "workspace.modify",
        "resource": "workspace.current"
      }},
      {{
        "id": "conversation-reply",
        "effect": "allow",
        "action": "conversation.reply"
      }}
    ],
    "requiredHarnessClaims": [
      "copilot.tool-interception",
      "copilot.session-identity"
    ],
    "limits": {limits}
  }}
}}"#
    )
    .into_bytes()
}

#[test]
fn source_compiles_to_canonical_bundle_and_digest() {
    let compiled = compile_collaboration_policy_source(
        &source(
            "Align the API contract.",
            r#"{
              "durationMilliseconds": null,
              "turns": null,
              "tokens": 10000,
              "concurrentRequests": 1
            }"#,
        ),
        CollaborationPolicyLimits::default(),
    )
    .unwrap();

    assert_eq!(compiled.bundle().name(), "contract-alignment");
    assert_eq!(
        compiled.bundle().statements()[0].statement_id(),
        "conversation-reply"
    );
    assert_eq!(
        compiled.bundle().statements()[0].effect(),
        CollaborationPolicyEffect::Allow
    );
    assert_eq!(
        compiled.bundle().required_harness_claims(),
        ["copilot.session-identity", "copilot.tool-interception"]
    );
    assert_eq!(compiled.bundle().limits().duration_milliseconds(), None);
    assert_eq!(compiled.bundle().limits().tokens(), Some(10_000));
    assert_eq!(compiled.digest().as_bytes().len(), 32);
    assert!(!compiled.canonical_bytes().is_empty());
}

#[test]
fn source_distinguishes_inherited_unlimited_and_finite_limits() {
    let defaults =
        CollaborationPolicyLimits::new(Some(60_000), Some(20), Some(50_000), Some(2)).unwrap();
    let inherited =
        compile_collaboration_policy_source(&source("Inherited limits.", "{}"), defaults).unwrap();
    assert_eq!(
        inherited.bundle().limits().duration_milliseconds(),
        Some(60_000)
    );
    assert_eq!(inherited.bundle().limits().turns(), Some(20));

    let overridden = compile_collaboration_policy_source(
        &source(
            "Overridden limits.",
            r#"{
              "durationMilliseconds": null,
              "turns": 5,
              "tokens": null,
              "concurrentRequests": 1
            }"#,
        ),
        defaults,
    )
    .unwrap();
    assert_eq!(overridden.bundle().limits().duration_milliseconds(), None);
    assert_eq!(overridden.bundle().limits().turns(), Some(5));
    assert_eq!(overridden.bundle().limits().tokens(), None);
    assert_eq!(overridden.bundle().limits().concurrent_requests(), Some(1));
}

#[test]
fn source_rejects_unknown_structure_bounds_and_zero_limits() {
    for invalid in [
        br#"{"apiVersion":"unknown","kind":"CollaborationPolicy","metadata":{"name":"x"},"spec":{}}"#
            .as_slice(),
        br#"{"apiVersion":"konclave.dev/v1","kind":"Unknown","metadata":{"name":"x"},"spec":{}}"#
            .as_slice(),
        br#"{"apiVersion":"konclave.dev/v1","kind":"CollaborationPolicy","metadata":{"name":"x","extra":true},"spec":{}}"#
            .as_slice(),
    ] {
        assert!(compile_collaboration_policy_source(
            invalid,
            CollaborationPolicyLimits::default()
        )
        .is_err());
    }

    let zero = compile_collaboration_policy_source(
        &source("Zero is invalid.", r#"{ "turns": 0 }"#),
        CollaborationPolicyLimits::default(),
    );
    assert!(matches!(
        zero,
        Err(CollaborationPolicySourceError::Domain(_))
    ));

    assert_eq!(
        compile_collaboration_policy_source(
            &vec![b' '; MAX_COLLABORATION_POLICY_SOURCE_BYTES + 1],
            CollaborationPolicyLimits::default()
        )
        .err(),
        Some(CollaborationPolicySourceError::DocumentTooLarge {
            document: "source",
            maximum: MAX_COLLABORATION_POLICY_SOURCE_BYTES
        })
    );

    let statements = (0..=256)
        .map(|index| {
            serde_json::json!({
                "id": format!("statement-{index}"),
                "effect": "allow",
                "action": "conversation.reply"
            })
        })
        .collect::<Vec<_>>();
    let amplified = serde_json::to_vec(&serde_json::json!({
        "apiVersion": "konclave.dev/v1",
        "kind": "CollaborationPolicy",
        "metadata": { "name": "contract-alignment" },
        "spec": {
            "statements": statements
        }
    }))
    .unwrap();
    assert_eq!(
        compile_collaboration_policy_source(&amplified, CollaborationPolicyLimits::default()).err(),
        Some(CollaborationPolicySourceError::InvalidJson { document: "source" })
    );
}

#[test]
fn same_name_with_different_content_has_a_different_digest() {
    let first = compile_collaboration_policy_source(
        &source("First guidance.", "{}"),
        CollaborationPolicyLimits::default(),
    )
    .unwrap();
    let second = compile_collaboration_policy_source(
        &source("Second guidance.", "{}"),
        CollaborationPolicyLimits::default(),
    )
    .unwrap();
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn source_and_bundle_files_use_exclusive_creation() {
    let root = tempfile::tempdir().unwrap();
    let source_path = root.path().join("policy.json");
    create_collaboration_policy_source_file(&source_path, "contract-alignment").unwrap();
    assert!(create_collaboration_policy_source_file(&source_path, "contract-alignment").is_err());

    let compiled =
        compile_collaboration_policy_file(&source_path, CollaborationPolicyLimits::default())
            .unwrap();
    let bundle_path = root.path().join("policy.bin");
    write_compiled_collaboration_policy_file(&bundle_path, &compiled).unwrap();
    assert_eq!(
        std::fs::read(&bundle_path).unwrap(),
        compiled.canonical_bytes()
    );
    assert!(write_compiled_collaboration_policy_file(&bundle_path, &compiled).is_err());
}

#[test]
fn schema_boundary_fixtures_match_compiler_behavior() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy/test-fixtures");
    let accepted = compile_collaboration_policy_file(
        &root.join("source-boundaries.json"),
        CollaborationPolicyLimits::default(),
    )
    .unwrap();
    assert_eq!(accepted.bundle().statements()[0].resource(), None);
    assert_eq!(accepted.bundle().limits().turns(), Some(u64::MAX));
    assert_eq!(
        accepted.bundle().limits().concurrent_requests(),
        Some(u32::MAX)
    );
    assert_eq!(
        compile_collaboration_policy_file(
            &root.join("source-overflow.json"),
            CollaborationPolicyLimits::default()
        )
        .err(),
        Some(CollaborationPolicySourceError::InvalidJson { document: "source" })
    );
}
