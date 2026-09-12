use std::collections::HashMap;

use KonclaveA2AContracts::wire::{
    AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentProvider, AgentSkill,
    GetExtendedAgentCardRequest, HttpAuthSecurityScheme, MutualTlsSecurityScheme,
    OAuth2SecurityScheme, SecurityRequirement, SecurityScheme, StringList, security_scheme,
};
use KonclaveA2AContracts::{
    A2A_EXTENDED_AGENT_CARD_PATH, A2A_HTTP_JSON_BINDING, A2A_KONCLAVE_PROTECTED_DESCRIPTION,
    A2A_KONCLAVE_PROTECTED_DOWNGRADE_POLICY, A2A_KONCLAVE_PROTECTED_EXTENSION_URI,
    A2A_KONCLAVE_PROTECTED_GATEWAY_VISIBILITY, A2A_KONCLAVE_PROTECTED_PAYLOAD_PROTECTION,
    A2A_KONCLAVE_PROTECTED_PROFILE, A2A_KONCLAVE_PROTECTED_TRANSPORT, A2A_PROTOCOL_VERSION,
    A2A_TEXT_MEDIA_TYPE, A2A_WELL_KNOWN_AGENT_CARD_PATH, A2AContractError,
    InitialA2AAgentSecurityKind, InitialA2AInterfaceEnvironment, InitialA2ANegotiatedTrust,
    InitialA2ATrustRequirement, MAX_A2A_AGENT_CARD_INTERFACES, MAX_A2A_ENCODED_AGENT_CARD_BYTES,
    decode_initial_agent_card_json, decode_initial_agent_card_protobuf,
    decode_initial_get_extended_agent_card_json, decode_initial_get_extended_agent_card_protobuf,
    validate_initial_agent_card,
};
use prost::Message as _;

fn card() -> AgentCard {
    AgentCard {
        name: "Contract agent".to_owned(),
        description: "Coordinates one bounded text contract request.".to_owned(),
        supported_interfaces: vec![AgentInterface {
            url: "https://agent.example.com/a2a/v1".to_owned(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_owned(),
            tenant: "tenant-a".to_owned(),
            protocol_version: A2A_PROTOCOL_VERSION.to_owned(),
        }],
        provider: None,
        version: "1.0.0".to_owned(),
        documentation_url: None,
        capabilities: Some(AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: vec![],
            extended_agent_card: Some(true),
        }),
        security_schemes: HashMap::from([(
            "bearer".to_owned(),
            SecurityScheme {
                scheme: Some(security_scheme::Scheme::HttpAuthSecurityScheme(
                    HttpAuthSecurityScheme {
                        description: String::new(),
                        scheme: "Bearer".to_owned(),
                        bearer_format: "JWT".to_owned(),
                    },
                )),
            },
        )]),
        security_requirements: vec![SecurityRequirement {
            schemes: HashMap::from([("bearer".to_owned(), StringList { list: vec![] })]),
        }],
        default_input_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
        default_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
        skills: vec![AgentSkill {
            id: "contract-review".to_owned(),
            name: "Contract review".to_owned(),
            description: "Reviews one text contract and returns one response.".to_owned(),
            tags: vec!["contracts".to_owned(), "text".to_owned()],
            examples: vec![],
            input_modes: vec![],
            output_modes: vec![],
            security_requirements: vec![],
        }],
        signatures: vec![],
        icon_url: None,
    }
}

fn protected_extension(required: bool, relay_endpoint: &str) -> AgentExtension {
    AgentExtension {
        uri: A2A_KONCLAVE_PROTECTED_EXTENSION_URI.to_owned(),
        description: A2A_KONCLAVE_PROTECTED_DESCRIPTION.to_owned(),
        required,
        params: Some(pbjson_types::Struct {
            fields: HashMap::from([string_parameter("relayEndpoint", relay_endpoint)]),
        }),
    }
}

fn string_parameter(name: &str, value: &str) -> (String, pbjson_types::Value) {
    (
        name.to_owned(),
        pbjson_types::Value {
            kind: Some(pbjson_types::value::Kind::StringValue(value.to_owned())),
        },
    )
}

#[test]
fn agent_card_protobuf_and_protojson_narrow_to_the_initial_profile() {
    assert_eq!(
        A2A_WELL_KNOWN_AGENT_CARD_PATH,
        "/.well-known/agent-card.json"
    );
    assert_eq!(A2A_EXTENDED_AGENT_CARD_PATH, "/extendedAgentCard");
    let wire = card();
    let validated = decode_initial_agent_card_protobuf(
        &wire.encode_to_vec(),
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(validated.name(), "Contract agent");
    assert_eq!(validated.version(), "1.0.0");
    assert!(validated.streaming());
    assert!(validated.extended_agent_card());
    assert_eq!(validated.interfaces().len(), 1);
    assert_eq!(validated.skills()[0].id(), "contract-review");
    let security = validated.security().unwrap();
    assert_eq!(security.kind(), InitialA2AAgentSecurityKind::Bearer);
    assert_eq!(security.bearer_format(), Some("JWT"));

    let json = validated.deterministic_json().unwrap();
    assert_eq!(json, validated.deterministic_json().unwrap());
    let from_json = decode_initial_agent_card_json(
        &json,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(from_json.name(), validated.name());
    assert_eq!(from_json.skills()[0].tags(), validated.skills()[0].tags());

    let duplicate_name = String::from_utf8(json)
        .unwrap()
        .replacen('{', r#"{"name":"shadow","#, 1);
    assert_eq!(
        decode_initial_agent_card_json(
            duplicate_name.as_bytes(),
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .err(),
        Some(A2AContractError::MalformedEncoding)
    );
}

#[test]
fn protected_profile_negotiation_is_exact_and_never_falls_back() {
    let mut optional = card();
    optional.capabilities.as_mut().unwrap().extensions =
        vec![protected_extension(false, "https://relay.example.com/")];
    let optional = validate_initial_agent_card(
        optional,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    let profile = optional.protected_profile().unwrap();
    assert!(!profile.required());
    assert_eq!(profile.relay_endpoint(), "https://relay.example.com/");
    assert_eq!(profile.profile(), A2A_KONCLAVE_PROTECTED_PROFILE);
    assert_eq!(profile.transport(), A2A_KONCLAVE_PROTECTED_TRANSPORT);
    assert_eq!(
        profile.payload_protection(),
        A2A_KONCLAVE_PROTECTED_PAYLOAD_PROTECTION
    );
    assert_eq!(
        profile.gateway_visibility(),
        A2A_KONCLAVE_PROTECTED_GATEWAY_VISIBILITY
    );
    assert_eq!(
        profile.downgrade_policy(),
        A2A_KONCLAVE_PROTECTED_DOWNGRADE_POLICY
    );
    assert!(matches!(
        optional
            .negotiate_trust(InitialA2ATrustRequirement::AllowStandardBridge)
            .unwrap(),
        InitialA2ANegotiatedTrust::StandardBridge
    ));
    assert!(matches!(
        optional
            .negotiate_trust(InitialA2ATrustRequirement::RequireKonclaveProtected)
            .unwrap(),
        InitialA2ANegotiatedTrust::KonclaveProtected(_)
    ));
    let json = optional.deterministic_json().unwrap();
    assert_eq!(json, optional.deterministic_json().unwrap());
    let round_tripped = decode_initial_agent_card_json(
        &json,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        round_tripped.protected_profile().unwrap().relay_endpoint(),
        "https://relay.example.com/"
    );

    let mut required = card();
    required.capabilities.as_mut().unwrap().extensions =
        vec![protected_extension(true, "https://relay.example.com/")];
    let required = validate_initial_agent_card(
        required,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        required
            .negotiate_trust(InitialA2ATrustRequirement::AllowStandardBridge)
            .err(),
        Some(A2AContractError::RequiredExtensionUnsupported)
    );
    assert!(matches!(
        required
            .negotiate_trust(InitialA2ATrustRequirement::RequireKonclaveProtected)
            .unwrap(),
        InitialA2ANegotiatedTrust::KonclaveProtected(_)
    ));
    assert_eq!(
        validate_initial_agent_card(
            card(),
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .unwrap()
        .negotiate_trust(InitialA2ATrustRequirement::RequireKonclaveProtected)
        .err(),
        Some(A2AContractError::RequiredExtensionUnsupported)
    );
}

#[test]
fn protected_profile_rejects_unknown_claims_and_insecure_endpoints() {
    let invalid_extensions = [
        AgentExtension {
            uri: "https://example.com/unknown".to_owned(),
            ..protected_extension(false, "https://relay.example.com/")
        },
        AgentExtension {
            params: None,
            ..protected_extension(false, "https://relay.example.com/")
        },
        protected_extension(false, "http://relay.example.com/"),
    ];
    for extension in invalid_extensions {
        let mut invalid = card();
        invalid.capabilities.as_mut().unwrap().extensions = vec![extension];
        assert!(
            validate_initial_agent_card(
                invalid,
                InitialA2AInterfaceEnvironment::Production,
                Some("tenant-a")
            )
            .is_err()
        );
    }

    let mut changed_claim = card();
    let mut extension = protected_extension(false, "https://relay.example.com/");
    extension.params.as_mut().unwrap().fields.insert(
        "gatewayVisibility".to_owned(),
        string_parameter("ignored", "application-plaintext").1,
    );
    changed_claim.capabilities.as_mut().unwrap().extensions = vec![extension];
    assert!(matches!(
        validate_initial_agent_card(
            changed_claim,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        ),
        Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.extension.params"
        })
    ));

    let mut loopback = card();
    loopback.capabilities.as_mut().unwrap().extensions =
        vec![protected_extension(false, "http://127.0.0.1:8080/")];
    assert!(
        validate_initial_agent_card(
            loopback,
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
            Some("tenant-a")
        )
        .is_ok()
    );
}

#[test]
fn agent_card_accepts_mtls_and_rejects_unsupported_or_inconsistent_security() {
    let mut mtls = card();
    mtls.security_schemes = HashMap::from([(
        "mutual-tls".to_owned(),
        SecurityScheme {
            scheme: Some(security_scheme::Scheme::MtlsSecurityScheme(
                MutualTlsSecurityScheme {
                    description: String::new(),
                },
            )),
        },
    )]);
    mtls.security_requirements = vec![SecurityRequirement {
        schemes: HashMap::from([("mutual-tls".to_owned(), StringList { list: vec![] })]),
    }];
    let validated = validate_initial_agent_card(
        mtls,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        validated.security().unwrap().kind(),
        InitialA2AAgentSecurityKind::MutualTls
    );

    let mut mixed_case_bearer = card();
    let security_scheme::Scheme::HttpAuthSecurityScheme(scheme) = mixed_case_bearer
        .security_schemes
        .get_mut("bearer")
        .unwrap()
        .scheme
        .as_mut()
        .unwrap()
    else {
        panic!("test card must use HTTP authentication");
    };
    scheme.scheme = "bEaReR".to_owned();
    let validated = validate_initial_agent_card(
        mixed_case_bearer,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        validated.security().unwrap().kind(),
        InitialA2AAgentSecurityKind::Bearer
    );

    let mut oauth = card();
    oauth.security_schemes = HashMap::from([(
        "oauth".to_owned(),
        SecurityScheme {
            scheme: Some(security_scheme::Scheme::Oauth2SecurityScheme(
                OAuth2SecurityScheme {
                    description: String::new(),
                    flows: None,
                    oauth2_metadata_url: "https://identity.example.com".to_owned(),
                },
            )),
        },
    )]);
    assert!(matches!(
        validate_initial_agent_card(
            oauth,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        ),
        Err(A2AContractError::UnsupportedField {
            field: "agent_card.security_scheme"
        })
    ));

    let mut wrong_requirement = card();
    wrong_requirement.security_requirements[0].schemes =
        HashMap::from([("other".to_owned(), StringList { list: vec![] })]);
    assert!(
        validate_initial_agent_card(
            wrong_requirement,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .is_err()
    );

    let mut scoped_requirement = card();
    scoped_requirement.security_requirements[0]
        .schemes
        .get_mut("bearer")
        .unwrap()
        .list = vec!["write".to_owned()];
    assert!(
        validate_initial_agent_card(
            scoped_requirement,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .is_err()
    );
}

#[test]
fn agent_card_rejects_unbounded_duplicate_or_sensitive_metadata() {
    assert_eq!(
        decode_initial_agent_card_json(
            &vec![b' '; MAX_A2A_ENCODED_AGENT_CARD_BYTES + 1],
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .err(),
        Some(A2AContractError::EncodedMessageTooLarge {
            maximum: MAX_A2A_ENCODED_AGENT_CARD_BYTES,
            actual: MAX_A2A_ENCODED_AGENT_CARD_BYTES + 1,
        })
    );

    let mut duplicate_skill = card();
    duplicate_skill
        .skills
        .push(duplicate_skill.skills[0].clone());
    assert!(matches!(
        validate_initial_agent_card(
            duplicate_skill,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        ),
        Err(A2AContractError::DuplicateValue {
            field: "agent_card.skill.id"
        })
    ));

    let mut duplicate_tag = card();
    duplicate_tag.skills[0].tags.push("text".to_owned());
    assert!(matches!(
        validate_initial_agent_card(
            duplicate_tag,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        ),
        Err(A2AContractError::DuplicateValue {
            field: "agent_card.skill.tag"
        })
    ));

    let mut too_many_interfaces = card();
    too_many_interfaces.supported_interfaces = vec![
        too_many_interfaces.supported_interfaces[0]
            .clone();
        MAX_A2A_AGENT_CARD_INTERFACES + 1
    ];
    assert!(matches!(
        validate_initial_agent_card(
            too_many_interfaces,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        ),
        Err(A2AContractError::OutOfRange {
            field: "agent_card.supported_interfaces"
        })
    ));

    let mut provider = card();
    provider.provider = Some(AgentProvider {
        url: "https://provider.example.com".to_owned(),
        organization: "Provider".to_owned(),
    });
    assert!(
        validate_initial_agent_card(
            provider,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .is_err()
    );

    assert_eq!(
        validate_initial_agent_card(
            card(),
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-b")
        )
        .err(),
        Some(A2AContractError::TenantMismatch)
    );
}

#[test]
fn extended_agent_card_request_is_tenant_bound_in_both_encodings() {
    let request = GetExtendedAgentCardRequest {
        tenant: "tenant-a".to_owned(),
    };
    let protobuf =
        decode_initial_get_extended_agent_card_protobuf(&request.encode_to_vec(), Some("tenant-a"))
            .unwrap();
    assert_eq!(protobuf.tenant(), Some("tenant-a"));
    let json = decode_initial_get_extended_agent_card_json(
        &serde_json::to_vec(&request).unwrap(),
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(json.tenant(), protobuf.tenant());
    assert_eq!(
        decode_initial_get_extended_agent_card_protobuf(&request.encode_to_vec(), Some("tenant-b"))
            .err(),
        Some(A2AContractError::TenantMismatch)
    );
}
