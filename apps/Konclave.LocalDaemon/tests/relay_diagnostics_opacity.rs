//! Proves an exchange leaves no application plaintext in diagnostics or storage.
//!
//! The relay is untrusted infrastructure and the daemon legitimately holds plaintext,
//! so both are checked: the relay must never be able to see a message, and the daemon
//! must never write one where an operator or log shipper would collect it.
//!
//! This suite installs a process-global tracing subscriber, so it lives in its own
//! test binary rather than sharing one with the other end-to-end suites.

#![cfg(unix)]

mod support;

use std::sync::{Arc, Mutex};

use support::{AdapterHost, DaemonFixture, join_conversation};
use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;

/// Text that must never appear anywhere except inside sealed storage.
const FIRST_SECRET: &str = "konclave-plaintext-sentinel-alpha";
const SECOND_SECRET: &str = "konclave-plaintext-sentinel-beta";

/// A tracing writer that keeps everything the relay emits in memory.
#[derive(Clone, Default)]
struct CapturedDiagnostics(Arc<Mutex<Vec<u8>>>);

impl CapturedDiagnostics {
    fn contents(&self) -> String {
        self.0
            .lock()
            .map(|captured| String::from_utf8_lossy(&captured).into_owned())
            .unwrap_or_default()
    }
}

impl std::io::Write for CapturedDiagnostics {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut captured) = self.0.lock() {
            captured.extend_from_slice(buffer);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedDiagnostics {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn an_exchange_leaves_no_plaintext_in_diagnostics_or_storage() {
    let captured = CapturedDiagnostics::default();
    // Only the relay and the server stack it runs on are in scope. This process also
    // hosts the sending MCP client, which holds plaintext legitimately, so capturing
    // everything would assert something untrue about the relay.
    //
    // TRACE keeps the assertion honest: a field that only appears at a verbose level
    // is still a field that a deployment can be configured to emit.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(captured.clone())
                .with_ansi(false)
                .with_filter(
                    tracing_subscriber::filter::Targets::new()
                        .with_target("KonclaveCommunityRelay", tracing::Level::TRACE)
                        .with_target("KonclaveRelayCore", tracing::Level::TRACE)
                        .with_target("axum", tracing::Level::TRACE)
                        .with_target("hyper", tracing::Level::TRACE)
                        .with_target("hyper_util", tracing::Level::TRACE)
                        .with_target("tower", tracing::Level::TRACE)
                        .with_target("tower_http", tracing::Level::TRACE)
                        .with_target("tungstenite", tracing::Level::TRACE)
                        .with_target("tokio_tungstenite", tracing::Level::TRACE),
                ),
        )
        .init();

    let fixture = DaemonFixture::start("opacity").await;
    let bob_host = AdapterHost::new("bob", 41, 41);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;
    alice
        .send(&conversation_id, &"2a".repeat(16), FIRST_SECRET)
        .await;
    assert!(
        !bob_session.claim(4, 15_000).await.is_empty(),
        "the exchange must actually happen before opacity means anything"
    );
    bob.send(&conversation_id, &"2b".repeat(16), SECOND_SECRET)
        .await;
    alice
        .require(
            "sync_messages",
            serde_json::json!({"conversation_id": conversation_id}),
        )
        .await;

    let alice_diagnostics = alice.diagnostics();
    let bob_diagnostics = bob.diagnostics();
    bob.close().await;
    alice.close().await;

    let relay_diagnostics = captured.contents();
    assert!(
        !alice_diagnostics.is_empty() && !bob_diagnostics.is_empty(),
        "each daemon must have emitted something, or this asserts nothing"
    );
    assert!(
        !relay_diagnostics.is_empty(),
        "the relay must have emitted something, or this asserts nothing"
    );

    for (source, text) in [
        ("relay tracing", relay_diagnostics),
        ("alice diagnostics", alice_diagnostics),
        ("bob diagnostics", bob_diagnostics),
    ] {
        for secret in [FIRST_SECRET, SECOND_SECRET] {
            assert!(
                !text.contains(secret),
                "{source} disclosed application plaintext"
            );
        }
        assert!(
            !text.contains(&conversation_id),
            "{source} disclosed a conversation identifier"
        );
    }

    fixture
        .relay()
        .assert_opaque(&[FIRST_SECRET.as_bytes(), SECOND_SECRET.as_bytes()]);
    fixture.stop().await;
}
