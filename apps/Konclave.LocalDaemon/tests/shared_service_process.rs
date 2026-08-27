#![cfg(unix)]

mod support;

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use KonclaveClientLibrary::{
    RELAY_INSTALLATION_CONFIG_FILE, RelayEndpoint, RelayEnrollmentCredential,
    RelayEnrollmentSourceConfig, RelayInstallationConfig,
};
use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, HarnessKind,
    LOCAL_SERVICE_INSTALLATION_FILE, LocalServiceEndpoint, LocalServiceIdentitySource,
    LocalServiceInstallation, LocalServiceProfileCustody, ProfileAuthorization, ServiceProfileId,
};
use KonclaveSecretStorage::{
    create_or_verify_owner_protected_file, ensure_owner_protected_directory,
};
use tokio::time::timeout;
use zeroize::Zeroizing;

use support::TestRelay;
use support::shared_service::{
    SessionConnectionRequest, SharedServiceProcess, complete_pairing, connect,
    connect_with_session_identity, identity, rpc, rpc_with_request_id,
};

const CLIENT_COUNT: u8 = 20;

fn adapter_key_id() -> AdapterKeyId {
    AdapterKeyId::from_bytes([7_u8; AdapterKeyId::LENGTH])
}

fn adapter_key_version() -> AdapterKeyVersion {
    AdapterKeyVersion::new(1).unwrap()
}

fn write_seed(path: &Path, seed: &LocalServiceSigningSeed) {
    let mut bytes = Zeroizing::new(Vec::new());
    seed.write_to(&mut *bytes).unwrap();
    create_or_verify_owner_protected_file(path, bytes.as_slice()).unwrap();
}

fn process_children(process_id: u32) -> String {
    std::fs::read_to_string(format!("/proc/{process_id}/task/{process_id}/children"))
        .unwrap_or_default()
}

fn process_resident_kibibytes(process_id: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{process_id}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_clients_share_one_process_and_recover_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let service_root = root.path().join("service");
    let profile_root = root.path().join("profiles");
    let key_root = root.path().join("profile-keys");
    for directory in [&service_root, &profile_root, &key_root] {
        ensure_owner_protected_directory(directory).unwrap();
    }
    let enrollment_token = [11_u8; RelayEnrollmentCredential::LENGTH];
    let relay = TestRelay::start_enrollment(enrollment_token, "shared-service-process").await;
    let enrollment_source = service_root.join("enrollment.credential");
    let relay_installation = RelayInstallationConfig::new(
        RelayEndpoint::parse(relay.endpoint()).unwrap(),
        RelayEnrollmentSourceConfig::ExternalFile {
            path: enrollment_source,
        },
    )
    .unwrap();
    relay_installation
        .create_external_credential(&RelayEnrollmentCredential::from_bytes(enrollment_token))
        .unwrap();
    create_or_verify_owner_protected_file(
        &profile_root.join(RELAY_INSTALLATION_CONFIG_FILE),
        &relay_installation.encode().unwrap(),
    )
    .unwrap();

    let service_seed = LocalServiceSigningSeed::generate().unwrap();
    let service_identity = LocalServiceIdentity::from_signing_seed(&service_seed).unwrap();
    let service_seed_path = service_root.join("service.key");
    write_seed(&service_seed_path, &service_seed);
    let adapter_seed = LocalServiceSigningSeed::generate().unwrap();
    let adapter_identity = LocalServiceIdentity::from_signing_seed(&adapter_seed).unwrap();
    let endpoint =
        LocalServiceEndpoint::parse(service_root.join("service.sock").to_str().unwrap()).unwrap();

    for index in 0..CLIENT_COUNT {
        let profile = format!("session-load-{index:02}");
        create_or_verify_owner_protected_file(
            &key_root.join(format!("{profile}.key")),
            &[index.saturating_add(1); 32],
        )
        .unwrap();
    }
    let installation = LocalServiceInstallation::new(
        endpoint.clone(),
        profile_root.clone(),
        service_identity.public_key(),
        LocalServiceIdentitySource::ExternalFile(service_seed_path),
        LocalServiceProfileCustody::ExternalDirectory(key_root),
        KonclaveLocalServiceTransport::AuthorizationPolicy::account_trusted(),
        vec![
            KonclaveLocalServiceTransport::InstalledIssuerRegistration::new(
                adapter_key_id(),
                adapter_key_version(),
                AdapterRegistration::new(
                    adapter_identity.public_key(),
                    HarnessKind::Copilot,
                    ProfileAuthorization::Namespace(ServiceProfileId::parse("session").unwrap()),
                ),
            ),
        ],
    )
    .unwrap();
    let mut encoded = Vec::new();
    installation.write_to(&mut encoded).unwrap();
    let config = service_root.join(LOCAL_SERVICE_INSTALLATION_FILE);
    create_or_verify_owner_protected_file(&config, &encoded).unwrap();

    let service = SharedServiceProcess::start(
        Path::new(env!("CARGO_BIN_EXE_KonclaveLocalService")),
        &config,
    );
    let process_id = service.id();
    let mut clients = Vec::new();
    let mut delivery_clients = Vec::new();
    let mut identities = Vec::new();
    for index in 0..CLIENT_COUNT {
        let profile = format!("session-load-{index:02}");
        let mut client = connect(
            &endpoint,
            service_identity.public_key(),
            &adapter_identity,
            adapter_key_id(),
            adapter_key_version(),
            &profile,
            index.saturating_add(1),
        )
        .await;
        identities.push(identity(&mut client).await);
        clients.push(client);
        let mut delivery = connect(
            &endpoint,
            service_identity.public_key(),
            &adapter_identity,
            adapter_key_id(),
            adapter_key_version(),
            &profile,
            index.saturating_add(101),
        )
        .await;
        let claimed = rpc(
            &mut delivery,
            "delivery.claim",
            serde_json::json!({"maxEvents": 16, "waitMilliseconds": 0}),
        )
        .await;
        assert_eq!(claimed["events"].as_array().unwrap().len(), 0);
        delivery_clients.push(delivery);
    }

    assert_eq!(clients.len(), usize::from(CLIENT_COUNT));
    assert_eq!(delivery_clients.len(), usize::from(CLIENT_COUNT));
    assert_eq!(
        identities.iter().collect::<HashSet<_>>().len(),
        usize::from(CLIENT_COUNT)
    );
    assert!(process_children(process_id).trim().is_empty());
    assert!(
        std::fs::read_dir(format!("/proc/{process_id}/fd"))
            .unwrap()
            .count()
            < 256
    );
    assert!(process_resident_kibibytes(process_id) < 512 * 1024);
    assert_eq!(
        std::fs::read_dir(&profile_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().join("profile.sqlite").is_file())
            .count(),
        usize::from(CLIENT_COUNT)
    );

    let (first_two, _) = clients.split_at_mut(2);
    let (first_slice, second_slice) = first_two.split_at_mut(1);
    let (_pairing_id, conversation_id) =
        complete_pairing(&mut first_slice[0], &mut second_slice[0]).await;
    drop(clients.remove(1));
    drop(delivery_clients.remove(1));
    let first_text = "shared service offline delivery";
    rpc(
        &mut clients[0],
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": "11".repeat(16),
            "text": first_text
        }),
    )
    .await;
    let mut second = connect(
        &endpoint,
        service_identity.public_key(),
        &adapter_identity,
        adapter_key_id(),
        adapter_key_version(),
        "session-load-01",
        99,
    )
    .await;
    timeout(Duration::from_secs(10), async {
        loop {
            rpc(
                &mut second,
                "sync_messages",
                serde_json::json!({"conversation_id": conversation_id}),
            )
            .await;
            let history = rpc(
                &mut second,
                "read_messages",
                serde_json::json!({"conversation_id": conversation_id, "limit": 100}),
            )
            .await;
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == first_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("offline message was not replayed");
    let reply_text = "shared service exact reply";
    rpc(
        &mut second,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": "22".repeat(16),
            "reply_to_message_id": "11".repeat(16),
            "text": reply_text
        }),
    )
    .await;
    timeout(Duration::from_secs(10), async {
        loop {
            rpc(
                &mut clients[0],
                "sync_messages",
                serde_json::json!({"conversation_id": conversation_id}),
            )
            .await;
            let history = rpc(
                &mut clients[0],
                "read_messages",
                serde_json::json!({"conversation_id": conversation_id, "limit": 100}),
            )
            .await;
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == reply_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("reply did not reach the first profile");
    relay.assert_opaque(&[first_text.as_bytes(), reply_text.as_bytes()]);
    clients.push(second);

    drop(clients.remove(0));
    drop(delivery_clients.remove(0));
    let mut reconnected = connect(
        &endpoint,
        service_identity.public_key(),
        &adapter_identity,
        adapter_key_id(),
        adapter_key_version(),
        "session-load-00",
        100,
    )
    .await;
    assert_eq!(identity(&mut reconnected).await, identities[0]);
    clients.push(reconnected);
    let recovery_session_identity = LocalServiceIdentity::generate().unwrap();
    let recovery_request_id = [0x5a; 16];
    let mut durable_request = connect_with_session_identity(SessionConnectionRequest {
        endpoint: &endpoint,
        service_key: service_identity.public_key(),
        issuer_identity: &adapter_identity,
        issuer_key_id: adapter_key_id(),
        issuer_key_version: adapter_key_version(),
        profile: "session-load-00",
        instance: 102,
        session_identity: &recovery_session_identity,
    })
    .await;
    let created_before_restart = rpc_with_request_id(
        &mut durable_request,
        recovery_request_id,
        "create_conversation",
        serde_json::json!({}),
    )
    .await;
    drop(durable_request);
    drop(clients);
    drop(delivery_clients);
    service.shutdown().await;

    let restarted = SharedServiceProcess::start(
        Path::new(env!("CARGO_BIN_EXE_KonclaveLocalService")),
        &config,
    );
    let mut recovered = connect_with_session_identity(SessionConnectionRequest {
        endpoint: &endpoint,
        service_key: service_identity.public_key(),
        issuer_identity: &adapter_identity,
        issuer_key_id: adapter_key_id(),
        issuer_key_version: adapter_key_version(),
        profile: "session-load-00",
        instance: 103,
        session_identity: &recovery_session_identity,
    })
    .await;
    assert_eq!(identity(&mut recovered).await, identities[0]);
    let recovered_outcome = rpc_with_request_id(
        &mut recovered,
        recovery_request_id,
        "create_conversation",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(recovered_outcome, created_before_restart);
    drop(recovered);
    restarted.shutdown().await;
    relay.stop().await;
}
