/// Supplies the current wall clock so expiry boundaries are deterministic in tests.
pub(crate) trait UnixClock: Send + Sync {
    fn now_unix_milliseconds(&self) -> u64;
}

/// The production wall clock.
pub(crate) struct SystemUnixClock;

impl UnixClock for SystemUnixClock {
    fn now_unix_milliseconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}
