use std::error::Error;
use std::fmt;
use std::sync::Arc;

use tokio::sync::watch;

/// Typed context identifies the failed worker without formatting its error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileComponent {
    RelayWatch,
    Pairing,
    Attachment,
}

impl ProfileComponent {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RelayWatch => "relay_watch",
            Self::Pairing => "pairing",
            Self::Attachment => "attachment",
        }
    }
}

impl fmt::Display for ProfileComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One immutable task-set failure shared with its owner and attached clients.
///
/// Formatting is deliberately opaque; only the explicit cause accessor exposes
/// operator detail that may contain paths, endpoints, or other private context.
#[derive(Clone)]
pub(crate) struct ProfileFailure {
    cause: Arc<anyhow::Error>,
}

impl ProfileFailure {
    /// Retains the original typed error without copying its operator detail.
    pub(crate) fn new(cause: anyhow::Error) -> Self {
        Self {
            cause: Arc::new(cause),
        }
    }

    /// Exposes operator detail only for explicit inspection or typed classification.
    pub(crate) fn cause(&self) -> &anyhow::Error {
        &self.cause
    }
}

impl fmt::Debug for ProfileFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileFailure")
    }
}

impl fmt::Display for ProfileFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the profile task set failed")
    }
}

impl Error for ProfileFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref().as_ref())
    }
}

impl PartialEq for ProfileFailure {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cause, &other.cause)
    }
}

impl Eq for ProfileFailure {}

/// A terminal snapshot retains its failure until every observer releases it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProfileRunState {
    Running,
    Stopped,
    Failed(ProfileFailure),
    Unavailable,
}

/// A lost publisher cannot leave a running snapshot usable indefinitely.
pub(crate) fn observed_run_state(state: &watch::Receiver<ProfileRunState>) -> ProfileRunState {
    let owner_lost = state.has_changed().is_err();
    let snapshot = state.borrow().clone();
    if owner_lost && !snapshot.is_terminal() {
        ProfileRunState::Unavailable
    } else {
        snapshot
    }
}

impl ProfileRunState {
    pub(crate) fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// Completes on a terminal snapshot or loss of the owning state publisher.
///
/// Nonterminal notifications retain the same waiting future; callers may pin this
/// alongside a cancellation-safe request reader without restarting that reader.
pub(crate) async fn wait_for_profile_stop(mut state: watch::Receiver<ProfileRunState>) {
    loop {
        if state.borrow_and_update().is_terminal() {
            return;
        }
        if state.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use tokio::sync::watch;

    use super::{
        ProfileComponent, ProfileFailure, ProfileRunState, observed_run_state,
        wait_for_profile_stop,
    };

    fn failure() -> ProfileFailure {
        ProfileFailure::new(
            anyhow::Error::new(io::Error::from(io::ErrorKind::PermissionDenied))
                .context("private operator context"),
        )
    }

    #[test]
    fn every_run_state_has_an_explicit_terminal_decision() {
        for (state, terminal) in [
            (ProfileRunState::Running, false),
            (ProfileRunState::Stopped, true),
            (ProfileRunState::Failed(failure()), true),
            (ProfileRunState::Unavailable, true),
        ] {
            assert_eq!(state.is_terminal(), terminal);
        }
    }

    #[test]
    fn component_origins_are_finite_and_survive_error_context() {
        for (component, expected) in [
            (ProfileComponent::RelayWatch, "relay_watch"),
            (ProfileComponent::Pairing, "pairing"),
            (ProfileComponent::Attachment, "attachment"),
        ] {
            let failure =
                ProfileFailure::new(anyhow::anyhow!("private operator context").context(component));
            assert_eq!(
                failure
                    .cause()
                    .downcast_ref::<ProfileComponent>()
                    .unwrap()
                    .as_str(),
                expected
            );
            assert_eq!(component.to_string(), expected);
        }
    }

    #[test]
    fn failure_snapshots_preserve_the_original_typed_cause_and_identity() {
        let original = failure();
        let snapshot = original.clone();
        assert_eq!(original, snapshot);
        assert_ne!(original, failure());
        assert!(std::ptr::eq(original.cause(), snapshot.cause()));
        assert_eq!(
            snapshot.cause().downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );

        let returned = anyhow::Error::new(original);
        assert!(
            returned
                .chain()
                .any(|cause| cause.downcast_ref::<io::Error>().is_some())
        );
    }

    #[test]
    fn ordinary_failure_formatting_never_exposes_the_retained_detail() {
        let failure = failure();
        assert_eq!(format!("{failure}"), "the profile task set failed");
        assert_eq!(format!("{failure:?}"), "ProfileFailure");
        assert_eq!(
            format!("{:?}", ProfileRunState::Failed(failure)),
            "Failed(ProfileFailure)"
        );
    }

    #[test]
    fn existing_terminal_snapshots_complete_without_another_notification() {
        for state in [
            ProfileRunState::Stopped,
            ProfileRunState::Failed(failure()),
            ProfileRunState::Unavailable,
        ] {
            let (_publisher, receiver) = watch::channel(state);
            let mut stopped = pin!(wait_for_profile_stop(receiver));
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(stopped.as_mut().poll(&mut context), Poll::Ready(()));
        }
    }

    #[test]
    fn nonterminal_notifications_do_not_finish_or_replace_the_waiter() {
        for terminal in [
            ProfileRunState::Stopped,
            ProfileRunState::Failed(failure()),
            ProfileRunState::Unavailable,
        ] {
            let (publisher, receiver) = watch::channel(ProfileRunState::Running);
            let mut stopped = pin!(wait_for_profile_stop(receiver));
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(stopped.as_mut().poll(&mut context), Poll::Pending);
            publisher.send_replace(ProfileRunState::Running);
            assert_eq!(stopped.as_mut().poll(&mut context), Poll::Pending);
            publisher.send_replace(terminal);
            assert_eq!(stopped.as_mut().poll(&mut context), Poll::Ready(()));
        }
    }

    #[test]
    fn losing_the_state_owner_is_terminal_even_without_a_final_snapshot() {
        let (publisher, receiver) = watch::channel(ProfileRunState::Running);
        let mut stopped = pin!(wait_for_profile_stop(receiver));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(stopped.as_mut().poll(&mut context), Poll::Pending);
        drop(publisher);
        assert_eq!(stopped.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn lost_publishers_preserve_terminal_causes_but_never_report_running() {
        for (state, expected) in [
            (ProfileRunState::Running, ProfileRunState::Unavailable),
            (ProfileRunState::Stopped, ProfileRunState::Stopped),
            (ProfileRunState::Unavailable, ProfileRunState::Unavailable),
        ] {
            let (publisher, receiver) = watch::channel(state.clone());
            assert_eq!(observed_run_state(&receiver), state);
            drop(publisher);
            assert_eq!(observed_run_state(&receiver), expected);
        }

        let state = ProfileRunState::Failed(failure());
        let (publisher, receiver) = watch::channel(state.clone());
        drop(publisher);
        assert_eq!(observed_run_state(&receiver), state);
    }
}
