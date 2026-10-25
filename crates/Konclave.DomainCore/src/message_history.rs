use thiserror::Error;

/// Maximum returned messages or authenticated candidate records in one history page.
pub const MAX_MESSAGE_PAGE_SIZE: usize = 100;

/// Durable cursor order, independent of sender-provided display timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageHistoryOrder {
    /// Oldest cursor first.
    Ascending,
    /// Newest cursor first.
    Descending,
}

impl TryFrom<&str> for MessageHistoryOrder {
    type Error = MessageHistoryQueryError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "asc" => Ok(Self::Ascending),
            "desc" => Ok(Self::Descending),
            _ => Err(MessageHistoryQueryError::InvalidOrder),
        }
    }
}

/// Finite input or progress failures without message content.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MessageHistoryQueryError {
    /// Only the canonical ascending and descending order names are accepted.
    #[error("history order must be asc or desc")]
    InvalidOrder,
    /// The requested result count exceeds the bounded history page.
    #[error("history page size is invalid")]
    InvalidPageSize,
    /// Cursor bounds must fit signed storage integers and form a nonempty interval.
    #[error("history cursor bounds are invalid")]
    InvalidCursorBounds,
    /// The inclusive timestamp lower bound exceeds the exclusive upper bound.
    #[error("history timestamp range is reversed")]
    InvalidTimeRange,
    /// An authenticated candidate is outside the requested exclusive cursor bounds.
    #[error("history candidate cursor is outside the requested bounds")]
    CursorOutOfBounds,
    /// Scanned cursors must make strict progress in the requested order.
    #[error("history candidate cursors are not strictly ordered")]
    CursorOrderViolation,
    /// More candidates cannot be reported without a scanned cursor to resume from.
    #[error("history continuation is missing its scanned cursor")]
    MissingContinuationCursor,
}

/// Validated local-history bounds and allocation-free filtering decisions.
///
/// Timestamps are authenticated sender metadata, not ordering or authorization
/// evidence. Signed filter instants allow ranges before the Unix epoch without
/// changing the unsigned timestamp carried by an application message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHistoryQuery {
    order: MessageHistoryOrder,
    after_cursor: u64,
    before_cursor: Option<u64>,
    since_unix_milliseconds: Option<i64>,
    until_unix_milliseconds: Option<i64>,
    limit: usize,
}

impl MessageHistoryQuery {
    /// Validates exclusive cursor bounds, a half-open timestamp range, and page size.
    ///
    /// Equal timestamp bounds describe an empty range. Absent bounds are unbounded.
    ///
    /// # Errors
    ///
    /// Returns a finite page-size, cursor-bound, or reversed timestamp-range error.
    pub fn new(
        order: MessageHistoryOrder,
        after_cursor: u64,
        before_cursor: Option<u64>,
        since_unix_milliseconds: Option<i64>,
        until_unix_milliseconds: Option<i64>,
        limit: usize,
    ) -> Result<Self, MessageHistoryQueryError> {
        if !(1..=MAX_MESSAGE_PAGE_SIZE).contains(&limit) {
            return Err(MessageHistoryQueryError::InvalidPageSize);
        }
        if i64::try_from(after_cursor).is_err()
            || before_cursor.is_some_and(|before| {
                i64::try_from(before).is_err() || before <= after_cursor
            })
        {
            return Err(MessageHistoryQueryError::InvalidCursorBounds);
        }
        if since_unix_milliseconds
            .zip(until_unix_milliseconds)
            .is_some_and(|(since, until)| since > until)
        {
            return Err(MessageHistoryQueryError::InvalidTimeRange);
        }
        Ok(Self {
            order,
            after_cursor,
            before_cursor,
            since_unix_milliseconds,
            until_unix_milliseconds,
            limit,
        })
    }

    /// Returns the requested durable cursor order.
    #[must_use]
    pub const fn order(self) -> MessageHistoryOrder {
        self.order
    }

    /// Returns the exclusive lower cursor bound.
    #[must_use]
    pub const fn after_cursor(self) -> u64 {
        self.after_cursor
    }

    /// Returns the optional exclusive upper cursor bound.
    #[must_use]
    pub const fn before_cursor(self) -> Option<u64> {
        self.before_cursor
    }

    /// Returns the maximum number of matching messages to return.
    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }

    /// Bounds authenticated scanning, even when a timestamp range matches no rows.
    ///
    /// Unfiltered pages need only their result limit; filtered pages may inspect the
    /// full bounded candidate page. A storage implementation may look ahead one
    /// opaque identifier to determine whether more candidates exist.
    #[must_use]
    pub const fn scan_limit(self) -> usize {
        if self.since_unix_milliseconds.is_some() || self.until_unix_milliseconds.is_some() {
            MAX_MESSAGE_PAGE_SIZE
        } else {
            self.limit
        }
    }

    /// Tests an authenticated sender timestamp without inferring cursor order.
    #[must_use]
    pub fn matches_timestamp(self, sent_at_unix_milliseconds: u64) -> bool {
        let timestamp = i128::from(sent_at_unix_milliseconds);
        self.since_unix_milliseconds
            .is_none_or(|since| timestamp >= i128::from(since))
            && self
                .until_unix_milliseconds
                .is_none_or(|until| timestamp < i128::from(until))
    }

    /// Verifies a candidate's bounds and strict progress from the prior scanned row.
    ///
    /// # Errors
    ///
    /// Rejects out-of-bounds cursors, duplicates, and movement against cursor order.
    pub fn validate_cursor(
        self,
        cursor: u64,
        previous_scanned_cursor: Option<u64>,
    ) -> Result<(), MessageHistoryQueryError> {
        if !self.contains_cursor(cursor)
            || previous_scanned_cursor.is_some_and(|previous| !self.contains_cursor(previous))
        {
            return Err(MessageHistoryQueryError::CursorOutOfBounds);
        }
        if previous_scanned_cursor.is_some_and(|previous| match self.order {
            MessageHistoryOrder::Ascending => cursor <= previous,
            MessageHistoryOrder::Descending => cursor >= previous,
        }) {
            return Err(MessageHistoryQueryError::CursorOrderViolation);
        }
        Ok(())
    }

    /// Returns the last scanned cursor when more candidates remain.
    ///
    /// The caller supplies the last authenticated candidate, not the last match.
    /// An empty filtered page can therefore still make resumable progress.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-bounds cursor or more-results evidence without any scan.
    pub fn continuation_cursor(
        self,
        last_scanned_cursor: Option<u64>,
        has_more: bool,
    ) -> Result<Option<u64>, MessageHistoryQueryError> {
        if let Some(cursor) = last_scanned_cursor {
            self.validate_cursor(cursor, None)?;
        }
        match (has_more, last_scanned_cursor) {
            (true, None) => Err(MessageHistoryQueryError::MissingContinuationCursor),
            (true, Some(cursor)) => Ok(Some(cursor)),
            (false, _) => Ok(None),
        }
    }

    fn contains_cursor(self, cursor: u64) -> bool {
        i64::try_from(cursor).is_ok()
            && cursor > self.after_cursor
            && self.before_cursor.is_none_or(|before| cursor < before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(order: MessageHistoryOrder) -> MessageHistoryQuery {
        MessageHistoryQuery::new(order, 2, Some(10), Some(20), Some(40), 3).unwrap()
    }

    #[test]
    fn canonical_orders_reject_unknown_values() {
        for (value, expected) in [
            ("asc", Ok(MessageHistoryOrder::Ascending)),
            ("desc", Ok(MessageHistoryOrder::Descending)),
            ("ASC", Err(MessageHistoryQueryError::InvalidOrder)),
            ("", Err(MessageHistoryQueryError::InvalidOrder)),
            ("timestamp", Err(MessageHistoryQueryError::InvalidOrder)),
        ] {
            assert_eq!(MessageHistoryOrder::try_from(value), expected);
        }
    }

    #[test]
    fn query_bounds_have_finite_validation_errors() {
        for (after, before, since, until, limit, expected) in [
            (0, None, None, None, 0, MessageHistoryQueryError::InvalidPageSize),
            (0, None, None, None, 101, MessageHistoryQueryError::InvalidPageSize),
            (u64::MAX, None, None, None, 1, MessageHistoryQueryError::InvalidCursorBounds),
            (0, Some(u64::MAX), None, None, 1, MessageHistoryQueryError::InvalidCursorBounds),
            (0, Some(0), None, None, 1, MessageHistoryQueryError::InvalidCursorBounds),
            (4, Some(4), None, None, 1, MessageHistoryQueryError::InvalidCursorBounds),
            (4, Some(3), None, None, 1, MessageHistoryQueryError::InvalidCursorBounds),
            (0, None, Some(2), Some(1), 1, MessageHistoryQueryError::InvalidTimeRange),
        ] {
            for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
                assert_eq!(
                    MessageHistoryQuery::new(order, after, before, since, until, limit),
                    Err(expected)
                );
            }
        }
    }

    #[test]
    fn scan_and_result_budgets_preserve_legacy_unfiltered_work() {
        for limit in [1, 10, MAX_MESSAGE_PAGE_SIZE] {
            for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
                let unfiltered = MessageHistoryQuery::new(order, 0, None, None, None, limit).unwrap();
                assert_eq!(unfiltered.limit(), limit);
                assert_eq!(unfiltered.scan_limit(), limit);
                assert_eq!(unfiltered.order(), order);
                assert_eq!(unfiltered.after_cursor(), 0);
                assert_eq!(unfiltered.before_cursor(), None);
                for (since, until) in [(Some(0), None), (None, Some(40)), (Some(20), Some(40))] {
                    let filtered =
                        MessageHistoryQuery::new(order, 0, None, since, until, limit).unwrap();
                    assert_eq!(filtered.scan_limit(), MAX_MESSAGE_PAGE_SIZE);
                    assert_eq!(filtered.limit(), limit);
                }
            }
        }
    }

    #[test]
    fn cursor_storage_bounds_are_checked_at_the_exact_integer_boundary() {
        let maximum_cursor = u64::try_from(i64::MAX).unwrap();
        for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
            assert!(
                MessageHistoryQuery::new(order, maximum_cursor, None, None, None, 1).is_ok()
            );
            assert!(
                MessageHistoryQuery::new(order, 0, Some(maximum_cursor), None, None, 1).is_ok()
            );
            for (after, before) in [
                (maximum_cursor + 1, None),
                (0, Some(maximum_cursor + 1)),
            ] {
                assert_eq!(
                    MessageHistoryQuery::new(order, after, before, None, None, 1),
                    Err(MessageHistoryQueryError::InvalidCursorBounds)
                );
            }
        }
    }

    #[test]
    fn timestamp_filters_are_half_open_and_do_not_define_order() {
        for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
            let query = query(order);
            for (timestamp, matches) in [(40, false), (20, true), (0, false), (39, true), (19, false)] {
                assert_eq!(query.matches_timestamp(timestamp), matches);
            }
            assert!(!query.matches_timestamp(u64::MAX));
        }
    }

    #[test]
    fn timestamp_ranges_handle_empty_negative_and_full_unsigned_instants() {
        for (since, until, timestamp, matches) in [
            (None, None, u64::MAX, true),
            (Some(-1), None, 0, true),
            (None, Some(-1), 0, false),
            (Some(20), Some(20), 20, false),
            (Some(i64::MAX), None, u64::MAX, true),
            (None, Some(i64::MAX), u64::MAX, false),
        ] {
            let query =
                MessageHistoryQuery::new(MessageHistoryOrder::Ascending, 0, None, since, until, 1)
                    .unwrap();
            assert_eq!(query.matches_timestamp(timestamp), matches);
        }
    }

    #[test]
    fn cursor_bounds_and_strict_order_prevent_repeated_or_reversed_progress() {
        for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
            let query = query(order);
            for cursor in [0, 2, 10, u64::MAX] {
                assert_eq!(
                    query.validate_cursor(cursor, None),
                    Err(MessageHistoryQueryError::CursorOutOfBounds)
                );
            }
            assert_eq!(query.validate_cursor(5, None), Ok(()));
            assert_eq!(
                query.validate_cursor(5, Some(5)),
                Err(MessageHistoryQueryError::CursorOrderViolation)
            );
            assert_eq!(
                query.validate_cursor(5, Some(2)),
                Err(MessageHistoryQueryError::CursorOutOfBounds)
            );
            let (previous, next) = match order {
                MessageHistoryOrder::Ascending => (4, 5),
                MessageHistoryOrder::Descending => (5, 4),
            };
            assert_eq!(query.validate_cursor(next, Some(previous)), Ok(()));
            assert_eq!(
                query.validate_cursor(previous, Some(next)),
                Err(MessageHistoryQueryError::CursorOrderViolation)
            );
        }
    }

    #[test]
    fn continuation_uses_scanned_progress_even_without_any_timestamp_matches() {
        for order in [MessageHistoryOrder::Ascending, MessageHistoryOrder::Descending] {
            let query = query(order);
            let cursors = match order {
                MessageHistoryOrder::Ascending => [3, 4, 5],
                MessageHistoryOrder::Descending => [9, 8, 7],
            };
            let mut last_scanned = None;
            for cursor in cursors {
                query.validate_cursor(cursor, last_scanned).unwrap();
                assert!(!query.matches_timestamp(100));
                last_scanned = Some(cursor);
            }
            assert_eq!(
                query.continuation_cursor(last_scanned, true),
                Ok(last_scanned)
            );
            assert_eq!(query.continuation_cursor(last_scanned, false), Ok(None));
            assert_eq!(query.continuation_cursor(None, false), Ok(None));
            assert_eq!(
                query.continuation_cursor(None, true),
                Err(MessageHistoryQueryError::MissingContinuationCursor)
            );
            assert_eq!(
                query.continuation_cursor(Some(10), false),
                Err(MessageHistoryQueryError::CursorOutOfBounds)
            );
        }
    }
}
