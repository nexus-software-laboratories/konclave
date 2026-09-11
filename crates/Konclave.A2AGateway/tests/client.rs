mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use KonclaveA2AContracts::InitialA2AInterfaceEnvironment;
use KonclaveA2AContracts::wire::{Task, TaskState, TaskStatus};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2ADomain::{A2AAgentId, A2ATaskId, A2ATaskState, A2ATenantId};
use KonclaveA2AGateway::{
    A2AAgentCardFetchOutcome, A2ABearerCredential, A2AGatewayError, A2AGatewayWaitConfig,
    A2AHttpClientConfig, A2AHttpConfig, A2AHttpJsonClient, A2AHttpState, StaticBearerAccess,
    a2a_router, fetch_public_agent_card,
};
use KonclaveA2ATaskStore::{A2ATaskKey, A2ATaskStore, A2ATaskTransition};
use axum::Router;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::routing::{get, post};
use futures_util::StreamExt as _;
use serde_json::{Value, json};

use common::{
    CompletingSubmitter, PUBLICATION, RecordingSubmitter, TestClock,
    application_with_publication, artifact, request, request_with_message_id, store,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn outbound_client_round_trips_server_tasks_cards_and_etags() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let publication = local_publication(address, true, false);
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let application = application_with_publication(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
        store.clone(),
        Arc::new(CompletingSubmitter { store }),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let client = A2AHttpJsonClient::new(
        application.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::default(),
    )
    .unwrap();
    let access = StaticBearerAccess::new([A2ABearerCredential::parse(TOKEN).unwrap()]).unwrap();
    let state = A2AHttpState::new(application, Arc::new(access), A2AHttpConfig::default()).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, a2a_router(state)).await.unwrap();
    });

    let task = client
        .send_message(request("request", false, 1))
        .await
        .unwrap();
    let task_id = A2ATaskId::parse(task.task_id().to_owned()).unwrap();
    assert_eq!(
        client.get_task(&task_id, Some(0)).await.unwrap().task_id(),
        task.task_id()
    );
    assert_eq!(
        client
            .get_extended_agent_card(InitialA2AInterfaceEnvironment::LoopbackDevelopment)
            .await
            .unwrap()
            .skills()
            .len(),
        2
    );
    let list = client.list_tasks(Some(50), None).await.unwrap();
    assert_eq!(list.as_wire().tasks.len(), 1);
    assert!(list.as_wire().tasks[0].history.is_empty());

    let mut stream = client
        .send_streaming_message(request_with_message_id(
            "message-stream",
            "request",
            true,
            1,
        ))
        .await
        .unwrap();
    let streamed = stream.next().await.unwrap().unwrap();
    assert!(streamed.state() == KonclaveA2AContracts::wire::TaskState::Completed);
    assert!(stream.next().await.is_none());
    let streamed_task_id = A2ATaskId::parse(streamed.task_id().to_owned()).unwrap();
    assert_eq!(
        client.subscribe_to_task(&streamed_task_id).await.err(),
        Some(A2AGatewayError::Remote {
            status: 400,
            reason: Some("UNSUPPORTED_OPERATION".to_owned())
        })
    );

    let discovery_url = format!("http://{address}/.well-known/agent-card.json");
    let (etag, card_name) = match fetch_public_agent_card(
        &discovery_url,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
        Some("tenant-a"),
        None,
        A2AHttpClientConfig::default(),
    )
    .await
    .unwrap()
    {
        A2AAgentCardFetchOutcome::Modified {
            card,
            etag,
            cache_control,
        } => {
            assert_eq!(cache_control.as_deref(), Some("public, max-age=3600"));
            (etag.unwrap(), card.name().to_owned())
        }

        #[tokio::test]
        async fn outbound_client_gets_artifacts_and_lists_them_only_when_requested() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let publication = local_publication(address, false, false);
            let root = tempfile::tempdir().unwrap();
            let store = store(&root);
            let application = application_with_publication(
                &publication,
                InitialA2AInterfaceEnvironment::LoopbackDevelopment,
                store.clone(),
                Arc::new(RecordingSubmitter::default()),
                Arc::new(TestClock::new(100)),
                A2AGatewayWaitConfig::default(),
            );
            let client = A2AHttpJsonClient::new(
                application.card(),
                Some(A2ABearerCredential::parse(TOKEN).unwrap()),
                A2AHttpClientConfig::default(),
            )
            .unwrap();
            let access = StaticBearerAccess::new([A2ABearerCredential::parse(TOKEN).unwrap()]).unwrap();
            let state =
                A2AHttpState::new(application.clone(), Arc::new(access), A2AHttpConfig::default()).unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, a2a_router(state)).await.unwrap();
            });

            let task = client
                .send_message(request("request", true, 0))
                .await
                .unwrap();
            let task_id = A2ATaskId::parse(task.task_id().to_owned()).unwrap();
            let key = A2ATaskKey::new(
                A2AAgentId::parse("contract-agent").unwrap(),
                Some(A2ATenantId::parse("tenant-a").unwrap()),
                task_id.clone(),
            );
            store
                .transition_task(A2ATaskTransition::new(
                    key.clone(),
                    0,
                    A2ATaskState::Working,
                    None,
                    110,
                ))
                .unwrap();
            application.publish_artifact(&task_id, artifact()).await.unwrap();
            store
                .transition_task(A2ATaskTransition::new(
                    key,
                    1,
                    A2ATaskState::Completed,
                    None,
                    120,
                ))
                .unwrap();

            assert_eq!(
                client
                    .get_task(&task_id, Some(0))
                    .await
                    .unwrap()
                    .as_wire()
                    .artifacts
                    .len(),
                1
            );
            assert!(
                client
                    .list_tasks(Some(50), None)
                    .await
                    .unwrap()
                    .as_wire()
                    .tasks[0]
                    .artifacts
                    .is_empty()
            );
            assert_eq!(
                client
                    .list_tasks_with_artifacts(Some(50), None, true)
                    .await
                    .unwrap()
                    .as_wire()
                    .tasks[0]
                    .artifacts
                    .len(),
                1
            );

            server.abort();
            let _ = server.await;
        }
        A2AAgentCardFetchOutcome::NotModified => panic!("first fetch must return a card"),
    };
    assert_eq!(card_name, "Contract agent");
    assert!(matches!(
        fetch_public_agent_card(
            &discovery_url,
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
            Some("tenant-a"),
            Some(&etag),
            A2AHttpClientConfig::default(),
        )
        .await
        .unwrap(),
        A2AAgentCardFetchOutcome::NotModified
    ));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn outbound_client_does_not_follow_redirects_with_credentials() {
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let target_hits = Arc::clone(&hits);
    let target = tokio::spawn(async move {
        let router = Router::new().route(
            "/hit",
            get(move || {
                let hits = Arc::clone(&target_hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        );
        axum::serve(target_listener, router).await.unwrap();
    });

    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_address = redirect_listener.local_addr().unwrap();
    let location = format!("http://{target_address}/hit");
    let redirect = tokio::spawn(async move {
        let router = Router::new().route(
            "/tenant-a/tasks/{id}",
            get(move || {
                let location = location.clone();
                async move { (StatusCode::FOUND, [(LOCATION, location)]) }
            }),
        );
        axum::serve(redirect_listener, router).await.unwrap();
    });
    let publication = local_publication(redirect_address, false, false);
    let compiled = compile_a2a_agent_publication_source(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let client = A2AHttpJsonClient::new(
        compiled.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::default(),
    )
    .unwrap();
    let task_id = A2ATaskId::parse("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(
        client.get_task(&task_id, None).await.err(),
        Some(A2AGatewayError::Remote {
            status: 302,
            reason: None
        })
    );
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    redirect.abort();
    target.abort();
    let _ = redirect.await;
    let _ = target.await;
}

#[tokio::test]
async fn outbound_client_bounds_responses_and_rejects_wrong_auth_profile() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let router = Router::new().route(
            "/tenant-a/tasks/{id}",
            get(|| async {
                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "application/a2a+json")],
                    "x".repeat(1_024),
                )
            }),
        );
        axum::serve(listener, router).await.unwrap();
    });
    let publication = local_publication(address, false, false);
    let compiled = compile_a2a_agent_publication_source(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let client = A2AHttpJsonClient::new(
        compiled.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::new(std::time::Duration::from_secs(1), 128).unwrap(),
    )
    .unwrap();
    let task_id = A2ATaskId::parse("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(
        client.get_task(&task_id, None).await.err(),
        Some(A2AGatewayError::Contract)
    );
    server.abort();
    let _ = server.await;

    let mtls = local_publication(address, false, true);
    let compiled = compile_a2a_agent_publication_source(
        &mtls,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    assert_eq!(
        A2AHttpJsonClient::new(compiled.card(), None, A2AHttpClientConfig::default()).err(),
        Some(A2AGatewayError::UnsupportedAuthentication)
    );
}

#[tokio::test]
async fn outbound_stream_rejects_wrong_media_type_and_non_task_first_event() {
    let wrong_media_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wrong_media_address = wrong_media_listener.local_addr().unwrap();
    let wrong_media_server = tokio::spawn(async move {
        let router = Router::new().route(
            "/tenant-a/message:stream",
            post(|| async {
                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "application/a2a+json")],
                    "{}",
                )
            }),
        );
        axum::serve(wrong_media_listener, router).await.unwrap();
    });
    let publication = local_publication(wrong_media_address, false, false);
    let compiled = compile_a2a_agent_publication_source(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let client = A2AHttpJsonClient::new(
        compiled.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::default(),
    )
    .unwrap();
    assert_eq!(
        client
            .send_streaming_message(request("request", true, 0))
            .await
            .err(),
        Some(A2AGatewayError::Contract)
    );
    wrong_media_server.abort();
    let _ = wrong_media_server.await;

    let status_first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let status_first_address = status_first_listener.local_addr().unwrap();
    let status_first_server = tokio::spawn(async move {
        let router = Router::new().route(
            "/tenant-a/message:stream",
            post(|| async {
                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "text/event-stream")],
                    "data: {\"statusUpdate\":{\"taskId\":\"00112233445566778899aabbccddeeff\",\"contextId\":\"context-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\",\"timestamp\":\"1970-01-01T00:00:01Z\"}}}\n\n",
                )
            }),
        );
        axum::serve(status_first_listener, router).await.unwrap();
    });
    let publication = local_publication(status_first_address, false, false);
    let compiled = compile_a2a_agent_publication_source(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let client = A2AHttpJsonClient::new(
        compiled.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::default(),
    )
    .unwrap();
    let mut stream = client
        .send_streaming_message(request("request", true, 0))
        .await
        .unwrap();
    assert_eq!(
        stream.next().await.unwrap().err(),
        Some(A2AGatewayError::Contract)
    );
    status_first_server.abort();
    let _ = status_first_server.await;
}

#[tokio::test]
async fn outbound_client_rejects_mismatched_tasks_and_unsolicited_not_modified() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let wrong_task = serde_json::to_vec(&Task {
        id: "ffffffffffffffffffffffffffffffff".to_owned(),
        context_id: "context-1".to_owned(),
        status: Some(TaskStatus {
            state: TaskState::Submitted as i32,
            message: None,
            timestamp: Some(pbjson_types::Timestamp {
                seconds: 1,
                nanos: 0,
            }),
        }),
        artifacts: vec![],
        history: vec![],
        metadata: None,
    })
    .unwrap();
    let server = tokio::spawn(async move {
        let router = Router::new()
            .route(
                "/tenant-a/tasks/{id}",
                get(move || {
                    let wrong_task = wrong_task.clone();
                    async move {
                        (
                            StatusCode::OK,
                            [(CONTENT_TYPE, "application/a2a+json")],
                            wrong_task,
                        )
                    }
                }),
            )
            .route(
                "/.well-known/agent-card.json",
                get(|| async { StatusCode::NOT_MODIFIED }),
            );
        axum::serve(listener, router).await.unwrap();
    });
    let publication = local_publication(address, true, false);
    let compiled = compile_a2a_agent_publication_source(
        &publication,
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let client = A2AHttpJsonClient::new(
        compiled.card(),
        Some(A2ABearerCredential::parse(TOKEN).unwrap()),
        A2AHttpClientConfig::default(),
    )
    .unwrap();
    let requested = A2ATaskId::parse("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(
        client.get_task(&requested, None).await.err(),
        Some(A2AGatewayError::Contract)
    );
    assert_eq!(
        fetch_public_agent_card(
            &format!("http://{address}/.well-known/agent-card.json"),
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
            Some("tenant-a"),
            None,
            A2AHttpClientConfig::default(),
        )
        .await
        .err(),
        Some(A2AGatewayError::Contract)
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn public_discovery_rejects_preferred_origin_substitution() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut publication: Value =
        serde_json::from_slice(&local_publication(address, true, false)).unwrap();
    publication["spec"]["interfaces"][0]["url"] = json!("http://127.0.0.1:9/");
    let compiled = compile_a2a_agent_publication_source(
        &serde_json::to_vec(&publication).unwrap(),
        InitialA2AInterfaceEnvironment::LoopbackDevelopment,
    )
    .unwrap();
    let card = compiled.card().deterministic_json().unwrap();
    let server = tokio::spawn(async move {
        let router = Router::new().route(
            "/.well-known/agent-card.json",
            get(move || {
                let card = card.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(CONTENT_TYPE, "application/a2a+json")],
                        card,
                    )
                }
            }),
        );
        axum::serve(listener, router).await.unwrap();
    });
    assert_eq!(
        fetch_public_agent_card(
            &format!("http://{address}/.well-known/agent-card.json"),
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
            Some("tenant-a"),
            None,
            A2AHttpClientConfig::default(),
        )
        .await
        .err(),
        Some(A2AGatewayError::Contract)
    );
    server.abort();
    let _ = server.await;
}

fn local_publication(
    address: std::net::SocketAddr,
    publicly_discoverable: bool,
    mutual_tls: bool,
) -> Vec<u8> {
    let mut publication: Value = serde_json::from_slice(PUBLICATION).unwrap();
    publication["spec"]["publicWellKnown"] = json!(publicly_discoverable);
    publication["spec"]["interfaces"][0]["url"] = json!(format!("http://{address}/"));
    if mutual_tls {
        publication["spec"]["authentication"] = json!({
            "type": "mutualTls",
            "name": "mutual-tls"
        });
    }
    serde_json::to_vec(&publication).unwrap()
}
