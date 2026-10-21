use KonclaveLocalServiceTransport::{LocalServiceRequest, LocalServiceTransportError, read_request};
use tokio::io::AsyncRead;
use tokio::sync::watch;

/// Reads one bounded request while the connection's existing authority remains valid.
///
/// Control-channel closure, shutdown, revoked authority, and peer closure end the
/// connection. Other frame errors remain visible to the connection owner.
pub(crate) async fn read_authorized_request<S, T, Authorized>(
    stream: &mut S,
    stop: &mut watch::Receiver<bool>,
    authorization_changes: &mut watch::Receiver<T>,
    mut authorized: Authorized,
) -> Result<Option<LocalServiceRequest>, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
    T: Send + Sync,
    Authorized: FnMut() -> bool,
{
    if *stop.borrow() || !authorized() {
        return Ok(None);
    }
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(None);
                }
            }
            changed = authorization_changes.changed() => {
                if changed.is_err() || !authorized() {
                    return Ok(None);
                }
            }
            result = read_request(stream) => {
                return match result {
                    Ok(request) => Ok(Some(request)),
                    Err(LocalServiceTransportError::ChannelClosed) => Ok(None),
                    Err(error) => Err(error),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::{Future, poll_fn};
    use std::io;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    use KonclaveLocalServiceTransport::{MAX_RPC_FRAME_BYTES, OperationName, RequestId, write_request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf, duplex};

    use super::*;

    struct ObservedRead {
        stream: DuplexStream,
        consumed: Rc<Cell<usize>>,
    }

    impl AsyncRead for ObservedRead {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let reader = self.get_mut();
            let before = buffer.filled().len();
            let result = Pin::new(&mut reader.stream).poll_read(context, buffer);
            reader
                .consumed
                .set(reader.consumed.get() + buffer.filled().len() - before);
            result
        }
    }

    fn request(identifier: u8) -> LocalServiceRequest {
        LocalServiceRequest::new(
            RequestId::from_bytes([identifier; 16]),
            OperationName::parse("service.status").unwrap(),
            b"{}".to_vec(),
        )
        .unwrap()
    }

    async fn encoded_request(request: &LocalServiceRequest) -> Vec<u8> {
        let (mut writer, mut reader) = duplex(1024);
        write_request(&mut writer, request).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut frame = Vec::new();
        reader.read_to_end(&mut frame).await.unwrap();
        frame
    }

    async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
        assert!(
            poll_fn(|context| Poll::Ready(future.as_mut().poll(context)))
                .await
                .is_pending()
        );
    }

    #[tokio::test]
    async fn unrelated_updates_preserve_every_partial_header_and_payload() {
        let expected = request(1);
        let frame = encoded_request(&expected).await;
        let following = request(2);
        let following_frame = encoded_request(&following).await;
        for split in 1..frame.len() {
            let (mut writer, stream) = duplex(1024);
            let consumed = Rc::new(Cell::new(0));
            let mut reader = ObservedRead {
                stream,
                consumed: Rc::clone(&consumed),
            };
            let (stop_tx, mut stop) = watch::channel(false);
            let (authorization_tx, mut authorization_changes) = watch::channel(0_u64);
            let checks = Cell::new(0);
            {
                let reading = read_authorized_request(
                    &mut reader,
                    &mut stop,
                    &mut authorization_changes,
                    || {
                        checks.set(checks.get() + 1);
                        true
                    },
                );
                tokio::pin!(reading);
                writer.write_all(&frame[..split]).await.unwrap();
                assert_pending(reading.as_mut()).await;
                assert_eq!(consumed.get(), split);
                for generation in 1..=3 {
                    authorization_tx.send(generation).unwrap();
                    assert_pending(reading.as_mut()).await;
                    assert_eq!(checks.get(), generation + 1);
                    assert_eq!(consumed.get(), split);
                }
                stop_tx.send(false).unwrap();
                assert_pending(reading.as_mut()).await;
                writer.write_all(&frame[split..]).await.unwrap();
                writer.write_all(&following_frame).await.unwrap();
                writer.shutdown().await.unwrap();
                assert_eq!(reading.await.unwrap(), Some(expected.clone()));
            }
            assert_eq!(read_request(&mut reader).await.unwrap(), following);
        }
    }

    #[derive(Clone, Copy)]
    enum Termination {
        Revocation,
        Shutdown,
        AuthorizationWatchClosed,
        ShutdownWatchClosed,
    }

    #[tokio::test]
    async fn authority_loss_and_shutdown_interrupt_partial_reads() {
        let frame = encoded_request(&request(1)).await;
        for termination in [
            Termination::Revocation,
            Termination::Shutdown,
            Termination::AuthorizationWatchClosed,
            Termination::ShutdownWatchClosed,
        ] {
            for split in [1, 3, frame.len() - 1] {
                let (mut writer, mut reader) = duplex(1024);
                let (stop_tx, mut stop) = watch::channel(false);
                let (authorization_tx, mut authorization_changes) = watch::channel(true);
                let authority = authorization_changes.clone();
                let reading = read_authorized_request(
                    &mut reader,
                    &mut stop,
                    &mut authorization_changes,
                    || *authority.borrow(),
                );
                tokio::pin!(reading);
                writer.write_all(&frame[..split]).await.unwrap();
                assert_pending(reading.as_mut()).await;
                match termination {
                    Termination::Revocation => authorization_tx.send(false).unwrap(),
                    Termination::Shutdown => stop_tx.send(true).unwrap(),
                    Termination::AuthorizationWatchClosed => drop(authorization_tx),
                    Termination::ShutdownWatchClosed => drop(stop_tx),
                }
                assert_eq!(reading.await.unwrap(), None);
            }
        }
    }

    #[tokio::test]
    async fn inactive_initial_authority_never_accepts_a_buffered_request() {
        let frame = encoded_request(&request(1)).await;
        for (stopping, authorized) in [(false, false), (true, false), (true, true)] {
            let (mut writer, mut reader) = duplex(1024);
            writer.write_all(&frame).await.unwrap();
            let (_stop_tx, mut stop) = watch::channel(stopping);
            let (_authorization_tx, mut authorization_changes) = watch::channel(());
            assert_eq!(
                read_authorized_request(
                    &mut reader,
                    &mut stop,
                    &mut authorization_changes,
                    || authorized,
                )
                .await
                .unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn malformed_and_oversized_frames_fail_closed() {
        let oversized = u32::try_from(MAX_RPC_FRAME_BYTES)
            .unwrap()
            .checked_add(1)
            .unwrap();
        for (header, expected) in [
            ([0_u8; 4], LocalServiceTransportError::MalformedFrame),
            (
                oversized.to_be_bytes(),
                LocalServiceTransportError::FrameTooLarge,
            ),
        ] {
            let (mut writer, mut reader) = duplex(1024);
            writer.write_all(&header).await.unwrap();
            let (_stop_tx, mut stop) = watch::channel(false);
            let (_authorization_tx, mut authorization_changes) = watch::channel(());
            assert_eq!(
                read_authorized_request(
                    &mut reader,
                    &mut stop,
                    &mut authorization_changes,
                    || true,
                )
                .await
                .unwrap_err(),
                expected
            );
        }
    }
}
