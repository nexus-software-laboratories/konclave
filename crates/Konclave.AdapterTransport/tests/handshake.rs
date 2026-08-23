//! Exercises the full handshake over a real duplex channel.
//!
//! ADR 0005 requires wrong-capability, wrong-profile, replayed-proof, and stalled-peer
//! rejection. These run both sides against each other so a change that breaks the
//! agreement fails here rather than against a live adapter.

use KonclaveAdapterTransport::{
    ADAPTER_PROTOCOL_VERSION, AdapterTransportError, ChallengeSource, HandshakeMessage,
    LaunchCapability, MAX_PREAUTH_FRAME_BYTES, SequentialChallenges, complete_adapter_handshake,
    complete_daemon_handshake, encode_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROFILE: &str = "alice";
const CONSUMER: &str = "01HQ8Z3K";

fn capability(seed: u8) -> LaunchCapability {
    LaunchCapability::from_bytes([seed; LaunchCapability::LENGTH])
}

#[tokio::test]
async fn both_sides_authenticate_and_agree_on_profile_and_consumer() {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    let adapter = tokio::spawn(async move {
        complete_adapter_handshake(
            &mut adapter_side,
            PROFILE,
            CONSUMER,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
    });

    let daemon = complete_daemon_handshake(
        &mut daemon_side,
        PROFILE,
        &capability(9),
        &mut SequentialChallenges::new(),
    )
    .await
    .unwrap();

    let adapter = adapter.await.unwrap().unwrap();
    assert_eq!(daemon.profile(), PROFILE);
    assert_eq!(daemon.consumer(), CONSUMER);
    assert_eq!(adapter.profile(), PROFILE);
    assert_eq!(adapter.consumer(), CONSUMER);
}

#[tokio::test]
async fn an_adapter_holding_a_different_capability_is_rejected_by_both_sides() {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    let adapter = tokio::spawn(async move {
        complete_adapter_handshake(
            &mut adapter_side,
            PROFILE,
            CONSUMER,
            &capability(8),
            &mut SequentialChallenges::new(),
        )
        .await
    });

    let daemon = complete_daemon_handshake(
        &mut daemon_side,
        PROFILE,
        &capability(9),
        &mut SequentialChallenges::new(),
    )
    .await;

    assert!(matches!(
        adapter.await.unwrap().unwrap_err(),
        AdapterTransportError::UnauthenticPeer
    ));
    assert!(daemon.is_err());
}

#[tokio::test]
async fn a_daemon_answering_for_another_profile_is_rejected() {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    let adapter = tokio::spawn(async move {
        complete_adapter_handshake(
            &mut adapter_side,
            PROFILE,
            CONSUMER,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
    });

    let _ = complete_daemon_handshake(
        &mut daemon_side,
        "bob",
        &capability(9),
        &mut SequentialChallenges::new(),
    )
    .await;

    assert_eq!(
        adapter.await.unwrap().unwrap_err(),
        AdapterTransportError::ProfileMismatch
    );
}

#[tokio::test]
async fn a_replayed_daemon_proof_does_not_authenticate_a_second_channel() {
    let captured = capture_daemon_auth().await;
    let HandshakeMessage::DaemonAuth { proof, .. } = captured else {
        panic!("expected a daemon authentication message");
    };

    // A second channel issues a different adapter challenge, so a proof captured from
    // the first transcript must not verify even though the capability is identical.
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);
    let mut challenges = SequentialChallenges::new();
    let _ = challenges.next_challenge().unwrap();

    let adapter = tokio::spawn(async move {
        complete_adapter_handshake(
            &mut adapter_side,
            PROFILE,
            CONSUMER,
            &capability(9),
            &mut challenges,
        )
        .await
    });

    let hello = read_frame(&mut daemon_side).await;
    assert!(matches!(hello, HandshakeMessage::AdapterHello { .. }));
    write_frame(
        &mut daemon_side,
        &HandshakeMessage::DaemonAuth {
            profile: PROFILE.to_string(),
            challenge: match hello {
                HandshakeMessage::AdapterHello { challenge, .. } => challenge,
                _ => unreachable!(),
            },
            proof,
        },
    )
    .await;

    assert_eq!(
        adapter.await.unwrap().unwrap_err(),
        AdapterTransportError::UnauthenticPeer
    );
}

#[tokio::test]
async fn an_oversized_preauth_frame_is_rejected_before_it_is_read() {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let declared = u32::try_from(MAX_PREAUTH_FRAME_BYTES + 1).unwrap();
        let _ = adapter_side.write_all(&declared.to_be_bytes()).await;
        let _ = adapter_side.flush().await;
        // The oversized body is never sent; the peer must fail on the header alone.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    assert_eq!(
        complete_daemon_handshake(
            &mut daemon_side,
            PROFILE,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
        .unwrap_err(),
        AdapterTransportError::FrameTooLarge
    );
}

#[tokio::test]
async fn a_message_arriving_out_of_order_is_rejected() {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        write_frame(
            &mut adapter_side,
            &HandshakeMessage::AdapterAuth { proof: [0_u8; 32] },
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    assert_eq!(
        complete_daemon_handshake(
            &mut daemon_side,
            PROFILE,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
        .unwrap_err(),
        AdapterTransportError::UnexpectedMessage
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_never_speaks_is_bounded_by_the_handshake_timeout() {
    let (mut daemon_side, adapter_side) = tokio::io::duplex(4096);
    // Holding the peer end open without writing keeps the read pending rather than
    // returning end-of-file, which is the stall the timeout exists to bound.
    let _held = adapter_side;

    assert_eq!(
        complete_daemon_handshake(
            &mut daemon_side,
            PROFILE,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
        .unwrap_err(),
        AdapterTransportError::HandshakeTimeout
    );
}

#[tokio::test]
async fn a_closed_channel_fails_instead_of_hanging() {
    let (mut daemon_side, adapter_side) = tokio::io::duplex(4096);
    drop(adapter_side);

    assert_eq!(
        complete_daemon_handshake(
            &mut daemon_side,
            PROFILE,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
        .unwrap_err(),
        AdapterTransportError::ChannelClosed
    );
}

async fn capture_daemon_auth() -> HandshakeMessage {
    let (mut daemon_side, mut adapter_side) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let _ = complete_daemon_handshake(
            &mut daemon_side,
            PROFILE,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await;
    });

    write_frame(
        &mut adapter_side,
        &HandshakeMessage::AdapterHello {
            version: ADAPTER_PROTOCOL_VERSION,
            consumer: CONSUMER.to_string(),
            challenge: KonclaveAdapterTransport::AuthChallenge::from_bytes({
                let mut challenge = [0_u8; 32];
                challenge[..8].copy_from_slice(&1_u64.to_be_bytes());
                challenge
            }),
        },
    )
    .await;
    read_frame(&mut adapter_side).await
}

async fn read_frame<S>(stream: &mut S) -> HandshakeMessage
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.unwrap();
    HandshakeMessage::decode(&payload).unwrap()
}

async fn write_frame<S>(stream: &mut S, message: &HandshakeMessage)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let frame = encode_frame(&message.encode(), MAX_PREAUTH_FRAME_BYTES).unwrap();
    stream.write_all(&frame).await.unwrap();
    stream.flush().await.unwrap();
}
