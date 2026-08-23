use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Shared delivery health reported to an adapter.
///
/// The watch supervisor owns the truth and the adapter channel only reads it, so
/// status never becomes a second source of truth that can disagree with the
/// supervisor about what is actually being watched.
#[derive(Clone, Default)]
pub(crate) struct DeliveryHealth {
    watched_conversations: Arc<AtomicU32>,
    degraded: Arc<AtomicBool>,
}

impl DeliveryHealth {
    /// Records how many conversations currently have a live watch worker.
    pub(crate) fn set_watched_conversations(&self, count: usize) {
        self.watched_conversations
            .store(u32::try_from(count).unwrap_or(u32::MAX), Ordering::Relaxed);
    }

    /// Returns the current watched-conversation count.
    pub(crate) fn watched_conversations(&self) -> u32 {
        self.watched_conversations.load(Ordering::Relaxed)
    }

    /// Records whether delivery is currently backpressured or reconnecting.
    pub(crate) fn set_degraded(&self, degraded: bool) {
        self.degraded.store(degraded, Ordering::Relaxed);
    }

    /// Returns whether delivery is currently degraded.
    pub(crate) fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::DeliveryHealth;

    #[test]
    fn health_is_shared_between_clones() {
        let supervisor = DeliveryHealth::default();
        let reader = supervisor.clone();

        assert_eq!(reader.watched_conversations(), 0);
        assert!(!reader.is_degraded());

        supervisor.set_watched_conversations(3);
        supervisor.set_degraded(true);

        assert_eq!(reader.watched_conversations(), 3);
        assert!(reader.is_degraded());
    }

    #[test]
    fn an_implausible_count_saturates_rather_than_wrapping() {
        let health = DeliveryHealth::default();
        health.set_watched_conversations(usize::MAX);
        assert_eq!(health.watched_conversations(), u32::MAX);
    }
}
