use std::error::Error;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::task::JoinSet;

const WORKER_CAPACITY: usize = 32;

type Completion = Result<(), NativeWorkerError>;

struct WorkerState {
    closing: bool,
    tasks: JoinSet<Completion>,
}

/// Owns bounded synchronous native work even when its requesting future is dropped.
///
/// Captured operation admission and submission guards stay with the actual worker.
/// The profile owner must call `shutdown` before releasing its persistence owner.
#[derive(Clone)]
pub(crate) struct NativeWorkers {
    state: Arc<Mutex<WorkerState>>,
    capacity: Arc<Semaphore>,
}

impl NativeWorkers {
    pub(crate) fn new() -> Self {
        Self::with_capacity(WORKER_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(WorkerState {
                closing: false,
                tasks: JoinSet::new(),
            })),
            capacity: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Returns operation failures separately from worker lifecycle failures.
    ///
    /// An error whose requester disappeared remains owned until reaped by the next
    /// operation or shutdown. Error values must be safe for normal error reporting.
    pub(crate) async fn run<R, E, F>(&self, operation: F) -> Result<Result<R, E>, NativeWorkerError>
    where
        R: Send + 'static,
        E: Error + Send + Sync + 'static,
        F: FnOnce() -> Result<R, E> + Send + 'static,
    {
        let permit = Arc::clone(&self.capacity)
            .acquire_owned()
            .await
            .map_err(|_| NativeWorkerError::Closed)?;
        let (completed, result) = oneshot::channel();
        {
            let mut state = self.state.lock().await;
            if state.closing {
                return Err(NativeWorkerError::Closed);
            }
            while let Some(joined) = state.tasks.try_join_next() {
                joined.map_err(|_| NativeWorkerError::Task)??;
            }
            state.tasks.spawn_blocking(move || {
                let _permit = permit;
                match completed.send(operation()) {
                    Ok(()) | Err(Ok(_)) => Ok(()),
                    Err(Err(error)) => Err(NativeWorkerError::UnobservedOperation(Box::new(error))),
                }
            });
        }
        result.await.map_err(|_| NativeWorkerError::Task)
    }

    /// Stops admission and joins every owned worker, including cancelled requests.
    ///
    /// The state lock deliberately spans joining: no operation can enqueue work
    /// after closing. Workers never need this lock to finish.
    pub(crate) async fn shutdown(&self) -> Result<(), NativeWorkerError> {
        let mut state = self.state.lock().await;
        state.closing = true;
        self.capacity.close();
        let mut failure = None;
        while let Some(joined) = state.tasks.join_next().await {
            let outcome = joined
                .map_err(|_| NativeWorkerError::Task)
                .and_then(|result| result);
            if let Err(error) = outcome {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum NativeWorkerError {
    #[error("native worker admission is closed")]
    Closed,
    #[error("native worker failed")]
    Task,
    #[error("cancelled native operation failed")]
    UnobservedOperation(#[source] Box<dyn Error + Send + Sync>),
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    use super::*;

    #[derive(Debug, Error)]
    #[error("synthetic native operation failure")]
    struct OperationFailure;

    struct CapturedGuard(Arc<AtomicBool>);

    impl Drop for CapturedGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn operation_results_and_failures_remain_distinct_from_worker_failures() {
        let workers = NativeWorkers::new();
        assert_eq!(
            workers
                .run(|| Ok::<_, OperationFailure>(7))
                .await
                .unwrap()
                .unwrap(),
            7
        );
        assert!(matches!(
            workers.run(|| Err::<(), _>(OperationFailure)).await,
            Ok(Err(OperationFailure))
        ));
        workers.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn closing_is_shared_and_rejects_work_before_the_callback_runs() {
        let workers = NativeWorkers::new();
        let clone = workers.clone();
        workers.shutdown().await.unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&called);
        assert!(matches!(
            clone
                .run(move || {
                    observed.store(true, Ordering::SeqCst);
                    Ok::<_, OperationFailure>(())
                })
                .await,
            Err(NativeWorkerError::Closed)
        ));
        assert!(!called.load(Ordering::SeqCst));
        clone.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_request_retains_its_worker_and_captured_guard_until_shutdown_joins() {
        let workers = NativeWorkers::with_capacity(1);
        let worker_owner = workers.clone();
        let (entered, running) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let held = Arc::new(AtomicBool::new(true));
        let guard = CapturedGuard(Arc::clone(&held));
        let request = tokio::spawn(async move {
            worker_owner
                .run(move || {
                    let _guard = guard;
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                    observed.store(true, Ordering::SeqCst);
                    Ok::<_, OperationFailure>(())
                })
                .await
        });
        running.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(held.load(Ordering::SeqCst));
        let shutdown = workers.shutdown();
        tokio::pin!(shutdown);
        poll_fn(|context| {
            assert!(shutdown.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!finished.load(Ordering::SeqCst));
        assert!(held.load(Ordering::SeqCst));
        release.send(()).unwrap();
        shutdown.await.unwrap();
        assert!(finished.load(Ordering::SeqCst));
        assert!(!held.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn saturated_capacity_cannot_start_a_second_callback_before_release() {
        let workers = NativeWorkers::with_capacity(1);
        let worker_owner = workers.clone();
        let (entered, running) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let first = tokio::spawn(async move {
            worker_owner
                .run(move || {
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                    Ok::<_, OperationFailure>(())
                })
                .await
        });
        running.await.unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&called);
        let second = workers.run(move || {
            observed.store(true, Ordering::SeqCst);
            Ok::<_, OperationFailure>(())
        });
        tokio::pin!(second);
        poll_fn(|context| {
            assert!(second.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!called.load(Ordering::SeqCst));
        release.send(()).unwrap();
        first.await.unwrap().unwrap().unwrap();
        second.await.unwrap().unwrap();
        assert!(called.load(Ordering::SeqCst));
        workers.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn panic_is_reported_to_the_request_and_observed_again_when_joined() {
        let workers = NativeWorkers::new();
        assert!(matches!(
            workers
                .run(|| -> Result<(), OperationFailure> { panic!("synthetic worker panic") })
                .await,
            Err(NativeWorkerError::Task)
        ));
        assert!(matches!(
            workers.shutdown().await,
            Err(NativeWorkerError::Task)
        ));
    }

    #[tokio::test]
    async fn abandoned_operation_error_is_not_lost_when_the_request_is_cancelled() {
        let workers = NativeWorkers::new();
        let worker_owner = workers.clone();
        let (entered, running) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let request = tokio::spawn(async move {
            worker_owner
                .run(move || {
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                    Err::<(), _>(OperationFailure)
                })
                .await
        });
        running.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        assert!(matches!(
            workers.shutdown().await,
            Err(NativeWorkerError::UnobservedOperation(_))
        ));
    }
}
