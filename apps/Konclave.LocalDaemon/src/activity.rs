use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::watch;
use tokio::time::timeout;

/// One profile's operation admission gate.
///
/// ADR 0008 keeps a profile open while a pairing operation or a relay recovery
/// operation requires it. Counting those operations is not enough on its own: an
/// evicting service that merely observes zero can still race an operation that starts
/// immediately afterwards. Admission and closing are therefore one atomic transition
/// over the same state. Once the gate is closing, no operation is ever admitted
/// again, and a closer drains only the operations that were already admitted.
#[derive(Clone)]
pub(crate) struct ProfileActivity {
    state: Arc<watch::Sender<ActivityState>>,
}

/// The gate state every admission and close decision is made against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActivityState {
    closing: bool,
    in_flight: usize,
}

/// Why an operation could not be admitted or drained.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ProfileActivityError {
    #[error("the profile is closing and admits no further operations")]
    Closing,
    #[error("profile operations did not drain before the close deadline")]
    DrainTimeout,
}

impl Default for ProfileActivity {
    fn default() -> Self {
        Self {
            state: Arc::new(watch::Sender::new(ActivityState {
                closing: false,
                in_flight: 0,
            })),
        }
    }
}

impl ProfileActivity {
    /// Admits one operation unless the profile is closing.
    ///
    /// The check and the count increment happen in one atomic transition, so an
    /// admitted operation is always visible to a concurrent closer and a denied one
    /// never begins.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileActivityError::Closing`] once the gate is closing.
    pub(crate) fn try_begin(&self) -> Result<ProfileActivityGuard, ProfileActivityError> {
        let mut admitted = false;
        self.state.send_if_modified(|state| {
            if state.closing {
                return false;
            }
            state.in_flight += 1;
            admitted = true;
            true
        });
        if !admitted {
            return Err(ProfileActivityError::Closing);
        }
        Ok(ProfileActivityGuard {
            state: Arc::clone(&self.state),
        })
    }

    /// Returns how many operations are in flight.
    pub(crate) fn in_flight(&self) -> usize {
        self.state.borrow().in_flight
    }

    /// Reports whether the gate has stopped admitting operations.
    pub(crate) fn is_closing(&self) -> bool {
        self.state.borrow().closing
    }

    /// Waits until the gate stops admitting operations.
    pub(crate) async fn wait_closing(&self) {
        let mut closing = self.state.subscribe();
        // The sender lives in this gate, so a receive failure is not reachable while
        // a caller still holds it.
        let _ = closing.wait_for(|state| state.closing).await;
    }

    /// Closes the gate only when no operation is in flight.
    ///
    /// This is the transition an eviction uses: it either wins outright, leaving no
    /// operation that could be closed underneath, or it loses to a running operation
    /// and the profile is retained.
    pub(crate) fn try_begin_closing(&self) -> bool {
        let mut closing = false;
        self.state.send_if_modified(|state| {
            if state.in_flight > 0 {
                return false;
            }
            closing = true;
            if state.closing {
                return false;
            }
            state.closing = true;
            true
        });
        closing
    }

    /// Stops admitting operations regardless of what is already running.
    ///
    /// This is the transition a coordinated shutdown uses. Already-admitted
    /// operations still have to drain before the profile's stores may be dropped.
    pub(crate) fn begin_closing(&self) {
        self.state.send_if_modified(|state| {
            if state.closing {
                return false;
            }
            state.closing = true;
            true
        });
    }

    /// Waits for every admitted operation to finish, within a bounded deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileActivityError::DrainTimeout`] when operations are still
    /// running at the deadline, which the caller must report rather than closing the
    /// profile underneath them silently.
    pub(crate) async fn wait_drained(
        &self,
        deadline: Duration,
    ) -> Result<(), ProfileActivityError> {
        let mut drained = self.state.subscribe();
        timeout(deadline, drained.wait_for(|state| state.in_flight == 0))
            .await
            .map_err(|_| ProfileActivityError::DrainTimeout)?
            // The sender lives in this gate, so it outlives every waiter.
            .map_err(|_| ProfileActivityError::DrainTimeout)?;
        Ok(())
    }
}

/// Keeps one operation admitted for exactly as long as it runs.
#[derive(Debug)]
pub(crate) struct ProfileActivityGuard {
    state: Arc<watch::Sender<ActivityState>>,
}

impl Drop for ProfileActivityGuard {
    fn drop(&mut self) {
        // A cancelled operation drops its guard from a `select!` branch or while
        // unwinding, so the count must never depend on the operation finishing.
        self.state.send_if_modified(|state| {
            state.in_flight = state.in_flight.saturating_sub(1);
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{ProfileActivity, ProfileActivityError};
    use std::time::Duration;

    #[test]
    fn an_operation_is_counted_only_while_its_guard_lives() {
        let activity = ProfileActivity::default();
        assert_eq!(activity.in_flight(), 0);

        let first = activity.try_begin().unwrap();
        let second = activity.try_begin().unwrap();
        assert_eq!(activity.in_flight(), 2);

        drop(second);
        assert_eq!(activity.in_flight(), 1);
        drop(first);
        assert_eq!(activity.in_flight(), 0);
    }

    #[test]
    fn every_clone_observes_the_same_operations() {
        let activity = ProfileActivity::default();
        let observer = activity.clone();
        let running = activity.try_begin().unwrap();

        assert_eq!(observer.in_flight(), 1);
        drop(running);
        assert_eq!(observer.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_running_operation_defeats_a_conditional_close() {
        let activity = ProfileActivity::default();
        let running = activity.try_begin().unwrap();

        assert!(!activity.try_begin_closing());
        assert!(!activity.is_closing());
        // Losing the race leaves the gate open for further work.
        let concurrent = activity.try_begin().unwrap();

        drop((running, concurrent));
        assert!(activity.try_begin_closing());
    }

    #[tokio::test]
    async fn a_closing_gate_admits_nothing_further() {
        let activity = ProfileActivity::default();
        assert!(activity.try_begin_closing());

        assert_eq!(
            activity.try_begin().unwrap_err(),
            ProfileActivityError::Closing
        );
        assert!(activity.is_closing());
        activity.wait_drained(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn an_unconditional_close_denies_admission_and_waits_for_the_drain() {
        let activity = ProfileActivity::default();
        let running = activity.try_begin().unwrap();

        activity.begin_closing();

        // The already-admitted operation keeps running, and no new one joins it.
        assert_eq!(
            activity.try_begin().unwrap_err(),
            ProfileActivityError::Closing
        );
        assert_eq!(activity.in_flight(), 1);
        // One poll is enough to prove the close has not completed.
        assert_eq!(
            activity.wait_drained(Duration::ZERO).await.unwrap_err(),
            ProfileActivityError::DrainTimeout
        );

        drop(running);
        activity.wait_drained(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn a_stuck_operation_fails_the_drain_explicitly() {
        let activity = ProfileActivity::default();
        let _stuck = activity.try_begin().unwrap();
        activity.begin_closing();

        assert_eq!(
            activity.wait_drained(Duration::from_millis(10)).await,
            Err(ProfileActivityError::DrainTimeout)
        );
    }
}
