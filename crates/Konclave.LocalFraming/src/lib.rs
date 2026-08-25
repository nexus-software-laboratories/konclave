#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Bounded length-prefixed framing for Konclave's local channels.
//!
//! Both the adapter rendezvous channel and the shared local service protocol move
//! self-describing payloads over a stream that carries no message boundaries. The
//! framing rule is identical for both and carries no protocol vocabulary, so it lives
//! here once instead of being restated by every local channel.
//!
//! A caller supplies the limit that applies to the current stage. Declaring the bound
//! at the call site is what lets an unauthenticated stage stay far below an
//! authenticated one while both share this code.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes carried by a frame length header.
pub const FRAME_HEADER_LENGTH: usize = 4;

/// Stable failures produced while framing or deframing a local channel payload.
///
/// The set is deliberately closed and exhaustive over the framing failure space, so
/// a channel that maps these onto its own protocol errors fails to compile rather
/// than silently collapsing a new failure into an existing code.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum FrameError {
    /// A frame declared or carried more bytes than its stage permits.
    #[error("frame exceeds its bound")]
    TooLarge,

    /// A frame declared zero bytes, so it carries no message.
    #[error("frame is malformed")]
    Malformed,

    /// The channel ended before the frame completed.
    #[error("channel closed")]
    Closed,
}

/// Reads a declared frame length and rejects it before any buffer is reserved.
///
/// Validating the declared length against the applicable limit first is what stops a
/// peer from causing a large allocation with a four-byte header it never satisfies.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] when the declared length exceeds `limit` and
/// [`FrameError::Malformed`] when it is zero.
pub fn decode_frame_length(
    header: [u8; FRAME_HEADER_LENGTH],
    limit: usize,
) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(FrameError::Malformed);
    }
    if declared > limit {
        return Err(FrameError::TooLarge);
    }
    Ok(declared)
}

/// Prefixes a payload with its length header.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] when the payload exceeds `limit` and
/// [`FrameError::Malformed`] when it is empty.
pub fn encode_frame(payload: &[u8], limit: usize) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Malformed);
    }
    if payload.len() > limit {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LENGTH + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Reads one length-prefixed frame, refusing a declared length above `limit`.
///
/// # Errors
///
/// Returns [`FrameError::Closed`] when the peer stops, [`FrameError::TooLarge`] when
/// the declared length exceeds `limit`, or [`FrameError::Malformed`] for a zero
/// length.
pub async fn read_frame<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, FrameError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| FrameError::Closed)?;
    let length = decode_frame_length(header, limit)?;
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| FrameError::Closed)?;
    Ok(payload)
}

/// Writes one length-prefixed frame, refusing a payload above `limit`.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] when the payload exceeds `limit` or
/// [`FrameError::Closed`] when the peer stops.
pub async fn write_frame<S>(stream: &mut S, payload: &[u8], limit: usize) -> Result<(), FrameError>
where
    S: AsyncWrite + Unpin,
{
    let frame = encode_frame(payload, limit)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|_| FrameError::Closed)?;
    stream.flush().await.map_err(|_| FrameError::Closed)
}

#[cfg(test)]
mod tests {
    use super::{FRAME_HEADER_LENGTH, FrameError, decode_frame_length, encode_frame, read_frame};

    #[test]
    fn a_frame_declares_its_exact_payload_length() {
        let frame = encode_frame(b"payload", 64).unwrap();
        assert_eq!(frame.len(), FRAME_HEADER_LENGTH + 7);
        let mut header = [0_u8; FRAME_HEADER_LENGTH];
        header.copy_from_slice(&frame[..FRAME_HEADER_LENGTH]);
        assert_eq!(decode_frame_length(header, 64).unwrap(), 7);
    }

    #[test]
    fn an_empty_or_oversized_payload_is_refused() {
        assert_eq!(encode_frame(&[], 64).unwrap_err(), FrameError::Malformed);
        assert_eq!(
            encode_frame(&[0_u8; 65], 64).unwrap_err(),
            FrameError::TooLarge
        );
    }

    #[test]
    fn a_declared_length_is_checked_before_any_buffer_is_reserved() {
        assert_eq!(
            decode_frame_length(u32::MAX.to_be_bytes(), 1_024).unwrap_err(),
            FrameError::TooLarge
        );
        assert_eq!(
            decode_frame_length(0_u32.to_be_bytes(), 1_024).unwrap_err(),
            FrameError::Malformed
        );
    }

    #[tokio::test]
    async fn a_truncated_frame_reports_a_closed_channel() {
        let mut stream = &b"\x00\x00\x00\x08short"[..];
        assert_eq!(
            read_frame(&mut stream, 1_024).await.unwrap_err(),
            FrameError::Closed
        );
    }

    #[tokio::test]
    async fn a_frame_round_trips_over_a_stream() {
        let frame = encode_frame(b"local", 1_024).unwrap();
        let mut stream = &frame[..];
        assert_eq!(read_frame(&mut stream, 1_024).await.unwrap(), b"local");
    }
}
