use std::collections::HashMap;

use KonclaveA2AContracts::wire::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill,
    GetExtendedAgentCardRequest, HttpAuthSecurityScheme, MutualTlsSecurityScheme,
    OAuth2SecurityScheme, SecurityRequirement, SecurityScheme, StringList, security_scheme,
};
use KonclaveA2AContracts::{
    A2A_EXTENDED_AGENT_CARD_PATH, A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE,
    A2A_WELL_KNOWN_AGENT_CARD_PATH, A2AContractError, InitialA2AAgentSecurityKind,
    InitialA2AInterfaceEnvironment, MAX_A2A_AGENT_CARD_INTERFACES,
    MAX_A2A_ENCODED_AGENT_CARD_BYTES, decode_initial_agent_card_json,
    decode_initial_agent_card_protobuf, decode_initial_get_extended_agent_card_json,
    decode_initial_get_extended_agent_card_protobuf, validate_initial_agent_card,
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
            streaming: Some(false),
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

    let mut streaming = card();
    streaming.capabilities.as_mut().unwrap().streaming = Some(true);
    assert!(
        validate_initial_agent_card(
            streaming,
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
