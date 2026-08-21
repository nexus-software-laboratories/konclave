use std::path::Path;
use std::process::Stdio;

use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

#[derive(Clone, Default)]
struct TestClient;

impl ClientHandler for TestClient {}

struct TestRelay {
    _directory: TempDir,
    endpoint: String,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
}

impl TestRelay {
    async fn start(token: [u8; RelayPrincipalId::LENGTH]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let access_path = directory.path().join("access.json");
        let principal = RelayPrincipalId::from_access_token(&token);
        std::fs::write(
            &access_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "principals": [{
                    "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                    "grants": [{
                        "route": "*",
                        "permissions": ["send", "replay", "acknowledge"]
                    }]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application =
            RelayApplication::connect(&directory.path().join("relay.sqlite"), access.clone())
                .await
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(
                    HttpState::new("daemon-e2e", application),
                    access,
                    shutdown_rx.clone(),
                ),
            )
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        });
        Self {
            _directory: directory,
            endpoint: format!("http://{address}"),
            shutdown,
            server,
        }
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        timeout(Duration::from_secs(2), self.server)
            .await
            .unwrap()
            .unwrap();
    }

    fn assert_opaque(&self, sentinels: &[&[u8]]) {
        for entry in std::fs::read_dir(self._directory.path()).unwrap() {
            let path = entry.unwrap().path();
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("relay.sqlite"))
            {
                continue;
            }
            let bytes = std::fs::read(path).unwrap();
            for sentinel in sentinels {
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|window| window == *sentinel)
                );
            }
        }
    }
}

async fn connect_daemon(
    profile_root: &Path,
    profile_id: &str,
    wrapping_key_file: &Path,
    relay_endpoint: &str,
    relay_credential_file: &Path,
) -> RunningService<RoleClient, TestClient> {
    let profile_root = profile_root.to_path_buf();
    let profile_id = profile_id.to_string();
    let wrapping_key_file = wrapping_key_file.to_path_buf();
    let relay_endpoint = relay_endpoint.to_string();
    let relay_credential_file = relay_credential_file.to_path_buf();
    let transport = TokioChildProcess::new(
        Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon")).configure(move |command| {
            command
                .env("KONCLAVE_PROFILE_ROOT", profile_root)
                .env("KONCLAVE_PROFILE_ID", profile_id)
                .env("KONCLAVE_WRAPPING_KEY_FILE", wrapping_key_file)
                .env("KONCLAVE_RELAY_ENDPOINT", relay_endpoint)
                .env("KONCLAVE_RELAY_CREDENTIAL_FILE", relay_credential_file)
                .env("KONCLAVE_MCP_ALLOW_WRITE", "true")
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
        }),
    )
    .unwrap();
    TestClient.serve(transport).await.unwrap()
}

async fn call(
    client: &RunningService<RoleClient, TestClient>,
    name: &str,
    arguments: Value,
) -> rmcp::model::CallToolResult {
    let parameters = match arguments.as_object() {
        Some(arguments) => {
            CallToolRequestParams::new(name.to_string()).with_arguments(arguments.clone())
        }
        None => CallToolRequestParams::new(name.to_string()),
    };
    client.call_tool(parameters).await.unwrap()
}

fn structured(result: rmcp::model::CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{:?}", result.content);
    result.structured_content.unwrap()
}

#[tokio::test]
async fn two_daemons_join_exchange_reconnect_replay_and_remove() {
    let directory = tempfile::tempdir().unwrap();
    let profile_root = directory.path().join("profiles");
    let wrapping_key_file = directory.path().join("wrapping.key");
    let relay_credential_file = directory.path().join("relay.credential");
    let token = [7_u8; RelayPrincipalId::LENGTH];
    std::fs::write(&wrapping_key_file, [5_u8; 32]).unwrap();
    std::fs::write(
        &relay_credential_file,
        format!("{}\n", URL_SAFE_NO_PAD.encode(token)),
    )
    .unwrap();
    let relay = TestRelay::start(token).await;
    let mut alice = connect_daemon(
        &profile_root,
        "alice",
        &wrapping_key_file,
        &relay.endpoint,
        &relay_credential_file,
    )
    .await;
    let mut bob = connect_daemon(
        &profile_root,
        "bob",
        &wrapping_key_file,
        &relay.endpoint,
        &relay_credential_file,
    )
    .await;

    let bob_identity = structured(call(&bob, "get_identity", Value::Null).await);
    let created = structured(call(&alice, "create_conversation", Value::Null).await);
    let conversation_id = created["conversation_id"].as_str().unwrap();
    let invitation = structured(
        call(
            &alice,
            "create_invitation",
            json!({
                "conversation_id": conversation_id,
                "expected_device_id": bob_identity["device_id"],
                "role": "member"
            }),
        )
        .await,
    );
    let proof = structured(
        call(
            &bob,
            "create_join_proof",
            json!({
                "invitation": invitation["invitation"],
                "routing_id": invitation["routing_id"],
                "issuer_public_key": invitation["issuer_public_key"],
                "peer_bindings": invitation["peer_bindings"]
            }),
        )
        .await,
    );
    let added = structured(
        call(
            &alice,
            "add_member",
            json!({
                "conversation_id": conversation_id,
                "join_proof": proof["join_proof"]
            }),
        )
        .await,
    );
    let joined = structured(
        call(
            &bob,
            "accept_welcome",
            json!({
                "conversation_id": conversation_id,
                "welcome": added["welcome"],
                "cursor": added["cursor"]
            }),
        )
        .await,
    );
    assert_eq!(joined["epoch"], 1);

    structured(
        call(
            &alice,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    let sent = structured(
        call(
            &alice,
            "send_message",
            json!({
                "conversation_id": conversation_id,
                "message_id": "01010101010101010101010101010101",
                "text": "hello from alice"
            }),
        )
        .await,
    );
    assert_eq!(sent["cursor"], 2);
    let bob_messages = structured(
        call(
            &bob,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    assert_eq!(bob_messages["messages"][0]["text"], "hello from alice");

    let reply = structured(
        call(
            &bob,
            "send_message",
            json!({
                "conversation_id": conversation_id,
                "message_id": "02020202020202020202020202020202",
                "text": "hello from bob"
            }),
        )
        .await,
    );
    assert_eq!(reply["cursor"], 3);
    let alice_messages = structured(
        call(
            &alice,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    assert!(
        alice_messages["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["text"] == "hello from bob")
    );

    bob.close().await.unwrap();
    structured(
        call(
            &alice,
            "send_message",
            json!({
                "conversation_id": conversation_id,
                "message_id": "03030303030303030303030303030303",
                "text": "missed while offline"
            }),
        )
        .await,
    );
    bob = connect_daemon(
        &profile_root,
        "bob",
        &wrapping_key_file,
        &relay.endpoint,
        &relay_credential_file,
    )
    .await;
    let replayed = structured(
        call(
            &bob,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    assert!(
        replayed["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["text"] == "missed while offline")
    );
    let duplicate = structured(
        call(
            &bob,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    assert!(duplicate["messages"].as_array().unwrap().is_empty());

    let removed = structured(
        call(
            &alice,
            "remove_member",
            json!({
                "conversation_id": conversation_id,
                "device_id": bob_identity["device_id"]
            }),
        )
        .await,
    );
    assert_eq!(removed["cursor"], 5);
    structured(
        call(
            &bob,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    structured(
        call(
            &alice,
            "sync_messages",
            json!({"conversation_id": conversation_id}),
        )
        .await,
    );
    let post_removal = structured(
        call(
            &alice,
            "send_message",
            json!({
                "conversation_id": conversation_id,
                "message_id": "04040404040404040404040404040404",
                "text": "post-removal secret"
            }),
        )
        .await,
    );
    assert_eq!(post_removal["cursor"], 6);
    let undecryptable = call(
        &bob,
        "sync_messages",
        json!({"conversation_id": conversation_id}),
    )
    .await;
    assert_eq!(undecryptable.is_error, Some(true));
    let denied = call(
        &bob,
        "send_message",
        json!({
            "conversation_id": conversation_id,
            "message_id": "05050505050505050505050505050505",
            "text": "must be denied"
        }),
    )
    .await;
    assert_eq!(denied.is_error, Some(true));

    bob.close().await.unwrap();
    alice.close().await.unwrap();
    relay.assert_opaque(&[
        b"hello from alice",
        b"hello from bob",
        b"missed while offline",
        b"post-removal secret",
    ]);
    relay.stop().await;
}
