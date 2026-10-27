use KonclaveA2ADomain::A2ATaskState;

use crate::{
    A2ATaskRecord, A2ATaskStoreError, A2ATaskTransition, A2ATerminalReason, StoredA2ATaskStatus,
};

/// Decision made from the task observed inside the adapter's write transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A2ATaskTransitionPlan {
    /// Return the original task without rewriting its timestamp or querying pruned evidence.
    Existing,
    /// Apply the transition without completion evidence.
    Apply,
    /// Apply only after observing an Agent message or complete artifact for this exact task.
    RequireCompletionEvidence,
}

impl A2ATaskTransitionPlan {
    /// Checks transaction-observed completion evidence before publishing a new transition.
    ///
    /// The adapter must read evidence for the same task inside the transaction that
    /// selected its current generation. A caller-supplied claim is not evidence.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTransition` when completion requires evidence and none exists.
    pub fn validate_completion_evidence(
        self,
        has_completion_evidence: bool,
    ) -> Result<(), A2ATaskStoreError> {
        if self == Self::RequireCompletionEvidence && !has_completion_evidence {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        Ok(())
    }
}

/// Identifies the terminal states supported by the initial task-store profile.
#[must_use]
pub const fn a2a_task_state_is_terminal(state: A2ATaskState) -> bool {
    matches!(
        state,
        A2ATaskState::Completed
            | A2ATaskState::Failed
            | A2ATaskState::Canceled
            | A2ATaskState::Rejected
    )
}

/// Tests a new state change, excluding exact retry reconciliation.
#[must_use]
pub const fn a2a_task_state_transition_is_allowed(
    previous: A2ATaskState,
    next: A2ATaskState,
) -> bool {
    match previous {
        A2ATaskState::Submitted => matches!(
            next,
            A2ATaskState::Working
                | A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        A2ATaskState::Working => matches!(
            next,
            A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        _ => false,
    }
}

/// Checks whether a persisted status has the reason required by its state.
#[must_use]
pub fn a2a_task_status_reason_is_valid(
    state: A2ATaskState,
    reason: Option<&A2ATerminalReason>,
) -> bool {
    match state {
        A2ATaskState::Submitted | A2ATaskState::Working | A2ATaskState::Completed => {
            reason.is_none()
        }
        A2ATaskState::Failed | A2ATaskState::Canceled | A2ATaskState::Rejected => reason.is_some(),
        A2ATaskState::InputRequired | A2ATaskState::AuthRequired => false,
    }
}

/// Reconciles an exact retry before validating a new transition.
///
/// The adapter must obtain `current` under the same write transaction as any
/// completion-evidence read and subsequent mutation. `Existing` preserves the
/// original timestamp, including when terminal payloads have been pruned.
///
/// # Errors
///
/// Returns `Conflict` for a different task or stale conflicting generation, and
/// `InvalidTransition` for an unsupported state path, reason, or regressing timestamp.
pub fn plan_a2a_task_transition(
    current: &A2ATaskRecord,
    transition: &A2ATaskTransition,
) -> Result<A2ATaskTransitionPlan, A2ATaskStoreError> {
    if current.key() != transition.key() {
        return Err(A2ATaskStoreError::Conflict);
    }
    if current.generation() != transition.expected_generation() {
        if transition
            .expected_generation()
            .checked_add(1)
            .is_some_and(|generation| generation == current.generation())
            && current.state() == transition.state()
            && current.terminal_reason().map(A2ATerminalReason::as_str)
                == transition.terminal_reason().map(A2ATerminalReason::as_str)
        {
            return Ok(A2ATaskTransitionPlan::Existing);
        }
        return Err(A2ATaskStoreError::Conflict);
    }
    if !a2a_task_state_transition_is_allowed(current.state(), transition.state())
        || !a2a_task_status_reason_is_valid(transition.state(), transition.terminal_reason())
        || transition.occurred_at_unix_milliseconds() < current.updated_at_unix_milliseconds()
    {
        return Err(A2ATaskStoreError::InvalidTransition);
    }
    Ok(if transition.state() == A2ATaskState::Completed {
        A2ATaskTransitionPlan::RequireCompletionEvidence
    } else {
        A2ATaskTransitionPlan::Apply
    })
}

/// Validates the bounded durable state shape, including retention deadlines.
///
/// This does not replace immutable-identity, context-binding, or status-history
/// verification. The adapter supplies the deadlines observed with the task row.
///
/// # Errors
///
/// Returns `CorruptData` for an unsupported state, generation, reason, or retention shape.
#[allow(
    clippy::too_many_arguments,
    reason = "the complete durable task-state shape remains explicit"
)]
pub fn validate_a2a_task_shape(
    state: A2ATaskState,
    generation: u64,
    updated_at: u64,
    terminal_at: Option<u64>,
    terminal_reason: Option<&A2ATerminalReason>,
    content_pruned: bool,
    content_expires_at: Option<u64>,
    tombstone_expires_at: Option<u64>,
) -> Result<(), A2ATaskStoreError> {
    let terminal = a2a_task_state_is_terminal(state);
    if generation > 2
        || (terminal
            && (terminal_at != Some(updated_at)
                || content_expires_at.is_none()
                || tombstone_expires_at.is_none()
                || terminal_at > content_expires_at
                || content_expires_at > tombstone_expires_at))
        || (!terminal
            && (terminal_at.is_some()
                || terminal_reason.is_some()
                || content_pruned
                || content_expires_at.is_some()
                || tombstone_expires_at.is_some()))
        || !a2a_task_status_reason_is_valid(state, terminal_reason)
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

/// Verifies a complete, generation-ordered history from the same snapshot as `task`.
///
/// Adapters must bound the read to four rows: the profile permits at most three,
/// and an extra row must remain detectable instead of being silently truncated.
///
/// # Errors
///
/// Returns `CorruptData` for missing, extra, reordered, regressing, or substituted statuses.
pub fn validate_a2a_task_status_history(
    task: &A2ATaskRecord,
    statuses: &[StoredA2ATaskStatus],
) -> Result<(), A2ATaskStoreError> {
    let expected_length = task
        .generation()
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(A2ATaskStoreError::CorruptData)?;
    if statuses.len() != expected_length || statuses.is_empty() || statuses.len() > 3 {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let mut previous_state = None;
    let mut previous_time = 0;
    for (index, status) in statuses.iter().enumerate() {
        if status.generation()
            != u64::try_from(index).map_err(|_| A2ATaskStoreError::CorruptData)?
            || status.occurred_at_unix_milliseconds() < previous_time
            || (index == 0
                && (status.state() != A2ATaskState::Submitted
                    || status.terminal_reason().is_some()
                    || status.occurred_at_unix_milliseconds()
                        != task.created_at_unix_milliseconds()))
            || !a2a_task_status_reason_is_valid(status.state(), status.terminal_reason())
            || previous_state.is_some_and(|previous| {
                !a2a_task_state_transition_is_allowed(previous, status.state())
            })
        {
            return Err(A2ATaskStoreError::CorruptData);
        }
        previous_state = Some(status.state());
        previous_time = status.occurred_at_unix_milliseconds();
    }
    let last = statuses.last().ok_or(A2ATaskStoreError::CorruptData)?;
    if last.state() != task.state()
        || last.generation() != task.generation()
        || last.occurred_at_unix_milliseconds() != task.updated_at_unix_milliseconds()
        || last.terminal_reason().map(A2ATerminalReason::as_str)
            != task.terminal_reason().map(A2ATerminalReason::as_str)
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::A2ATaskKey;
    use KonclaveA2ADomain::{A2AAgentId, A2AContextId, A2AMessageId, A2ATaskId, A2ATenantId};
    use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};

    const STATES: [A2ATaskState; 8] = [
        A2ATaskState::Submitted,
        A2ATaskState::Working,
        A2ATaskState::Completed,
        A2ATaskState::Failed,
        A2ATaskState::Canceled,
        A2ATaskState::InputRequired,
        A2ATaskState::AuthRequired,
        A2ATaskState::Rejected,
    ];
    const ALLOWED: [[bool; 8]; 8] = [
        [false, true, true, true, true, false, false, true],
        [false, false, true, true, true, false, false, true],
        [false; 8],
        [false; 8],
        [false; 8],
        [false; 8],
        [false; 8],
        [false; 8],
    ];

    fn task(
        state: A2ATaskState,
        generation: u64,
        reason: Option<&str>,
        updated_at: u64,
    ) -> A2ATaskRecord {
        A2ATaskRecord::new(
            A2ATaskKey::new(
                A2AAgentId::parse("agent-a").unwrap(),
                Some(A2ATenantId::parse("tenant-a").unwrap()),
                A2ATaskId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            ),
            A2AContextId::parse("context-a").unwrap(),
            A2AMessageId::parse("source-a").unwrap(),
            ConversationId::from_bytes([4; ConversationId::LENGTH]),
            DeviceId::from_bytes([5; DeviceId::LENGTH]),
            MessageId::from_bytes([6; MessageId::LENGTH]),
            [0; 32],
            [0; 32],
            Some("request".to_string()),
            false,
            None,
            state,
            generation,
            100,
            updated_at,
            a2a_task_state_is_terminal(state).then_some(updated_at),
            reason.map(|value| A2ATerminalReason::parse(value).unwrap()),
            false,
        )
    }

    fn status(
        generation: u64,
        state: A2ATaskState,
        reason: Option<&str>,
        occurred_at: u64,
    ) -> StoredA2ATaskStatus {
        StoredA2ATaskStatus::new(
            generation,
            state,
            reason.map(|value| A2ATerminalReason::parse(value).unwrap()),
            occurred_at,
        )
    }

    #[test]
    fn state_paths_terminal_states_and_reason_categories_are_exhaustive() {
        for (previous_index, previous) in STATES.into_iter().enumerate() {
            for (next_index, next) in STATES.into_iter().enumerate() {
                assert_eq!(
                    a2a_task_state_transition_is_allowed(previous, next),
                    ALLOWED[previous_index][next_index]
                );
            }
            assert_eq!(
                a2a_task_state_is_terminal(previous),
                [false, false, true, true, true, false, false, true][previous_index]
            );
            let reason = A2ATerminalReason::parse("failed").unwrap();
            for (present, expected) in [
                (false, [true, true, true, false, false, false, false, false]),
                (true, [false, false, false, true, true, false, false, true]),
            ] {
                assert_eq!(
                    a2a_task_status_reason_is_valid(previous, present.then_some(&reason)),
                    expected[previous_index]
                );
            }
        }
    }

    #[test]
    fn new_transition_plans_cover_every_state_reason_time_and_evidence_category() {
        for (previous_index, previous) in STATES.into_iter().enumerate() {
            let current = task(previous, 1, None, 110);
            for (next_index, next) in STATES.into_iter().enumerate() {
                for reason_present in [false, true] {
                    for occurred_at in [109, 110, 111] {
                        let transition = A2ATaskTransition::new(
                            current.key().clone(),
                            1,
                            next,
                            reason_present.then(|| A2ATerminalReason::parse("failed").unwrap()),
                            occurred_at,
                        );
                        let reason_valid = match next_index {
                            0..=2 => !reason_present,
                            3 | 4 | 7 => reason_present,
                            _ => false,
                        };
                        let valid = ALLOWED[previous_index][next_index]
                            && reason_valid
                            && occurred_at >= 110;
                        let result = plan_a2a_task_transition(&current, &transition);
                        if !valid {
                            assert_eq!(result, Err(A2ATaskStoreError::InvalidTransition));
                            continue;
                        }
                        let plan = result.unwrap();
                        assert_eq!(
                            plan,
                            if next == A2ATaskState::Completed {
                                A2ATaskTransitionPlan::RequireCompletionEvidence
                            } else {
                                A2ATaskTransitionPlan::Apply
                            }
                        );
                        for evidence in [false, true] {
                            assert_eq!(
                                plan.validate_completion_evidence(evidence),
                                if next == A2ATaskState::Completed && !evidence {
                                    Err(A2ATaskStoreError::InvalidTransition)
                                } else {
                                    Ok(())
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exact_retries_precede_terminal_time_and_completion_evidence_validation() {
        for state in [
            A2ATaskState::Working,
            A2ATaskState::Completed,
            A2ATaskState::Failed,
            A2ATaskState::Canceled,
            A2ATaskState::Rejected,
        ] {
            let reason = matches!(
                state,
                A2ATaskState::Failed | A2ATaskState::Canceled | A2ATaskState::Rejected
            )
            .then_some("failed");
            let current = task(state, 1, reason, 110);
            for retry_time in [0, 100, 110, u64::MAX] {
                let retry = A2ATaskTransition::new(
                    current.key().clone(),
                    0,
                    state,
                    reason.map(|value| A2ATerminalReason::parse(value).unwrap()),
                    retry_time,
                );
                let plan = plan_a2a_task_transition(&current, &retry).unwrap();
                assert_eq!(plan, A2ATaskTransitionPlan::Existing);
                assert_eq!(plan.validate_completion_evidence(false), Ok(()));
                assert_eq!(current.updated_at_unix_milliseconds(), 110);
            }
        }
    }

    #[test]
    fn stale_conflicts_do_not_alias_generations_states_reasons_or_scopes() {
        let current = task(A2ATaskState::Failed, 2, Some("failed"), 120);
        for expected_generation in [0, 1, 3, u64::MAX] {
            for state in STATES {
                for reason in [None, Some("failed"), Some("different")] {
                    let transition = A2ATaskTransition::new(
                        current.key().clone(),
                        expected_generation,
                        state,
                        reason.map(|value| A2ATerminalReason::parse(value).unwrap()),
                        120,
                    );
                    assert_eq!(
                        plan_a2a_task_transition(&current, &transition),
                        if expected_generation == 1
                            && state == A2ATaskState::Failed
                            && reason == Some("failed")
                        {
                            Ok(A2ATaskTransitionPlan::Existing)
                        } else {
                            Err(A2ATaskStoreError::Conflict)
                        }
                    );
                }
            }
        }
        for key in [
            A2ATaskKey::new(
                A2AAgentId::parse("other-agent").unwrap(),
                current.key().tenant().cloned(),
                current.key().task_id().clone(),
            ),
            A2ATaskKey::new(
                current.key().agent_id().clone(),
                Some(A2ATenantId::parse("other-tenant").unwrap()),
                current.key().task_id().clone(),
            ),
            A2ATaskKey::new(
                current.key().agent_id().clone(),
                None,
                current.key().task_id().clone(),
            ),
            A2ATaskKey::new(
                current.key().agent_id().clone(),
                current.key().tenant().cloned(),
                A2ATaskId::parse("fedcba9876543210fedcba9876543210").unwrap(),
            ),
        ] {
            let transition = A2ATaskTransition::new(
                key,
                1,
                A2ATaskState::Failed,
                Some(A2ATerminalReason::parse("failed").unwrap()),
                120,
            );
            assert_eq!(
                plan_a2a_task_transition(&current, &transition),
                Err(A2ATaskStoreError::Conflict)
            );
        }
    }

    #[test]
    fn durable_shapes_cover_generation_reason_pruning_and_deadline_categories() {
        for (state_index, state) in STATES.into_iter().enumerate() {
            let terminal = [false, false, true, true, true, false, false, true][state_index];
            for generation in [0, 1, 2, 3, u64::MAX] {
                for reason_present in [false, true] {
                    let reason =
                        reason_present.then(|| A2ATerminalReason::parse("failed").unwrap());
                    for content_pruned in [false, true] {
                        for terminal_at in [None, Some(99), Some(100), Some(101)] {
                            for content_expiry in [None, Some(99), Some(100), Some(110)] {
                                for tombstone_expiry in [None, Some(99), Some(100), Some(120)] {
                                    let reason_valid = match state_index {
                                        0..=2 => !reason_present,
                                        3 | 4 | 7 => reason_present,
                                        _ => false,
                                    };
                                    let retention_valid = if terminal {
                                        terminal_at == Some(100)
                                            && content_expiry.is_some_and(|value| value >= 100)
                                            && tombstone_expiry.is_some_and(|value| {
                                                content_expiry
                                                    .is_some_and(|content| content <= value)
                                            })
                                    } else {
                                        terminal_at.is_none()
                                            && content_expiry.is_none()
                                            && tombstone_expiry.is_none()
                                            && !content_pruned
                                    };
                                    assert_eq!(
                                        validate_a2a_task_shape(
                                            state,
                                            generation,
                                            100,
                                            terminal_at,
                                            reason.as_ref(),
                                            content_pruned,
                                            content_expiry,
                                            tombstone_expiry,
                                        ),
                                        if generation <= 2 && reason_valid && retention_valid {
                                            Ok(())
                                        } else {
                                            Err(A2ATaskStoreError::CorruptData)
                                        }
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn complete_histories_bind_initial_status_order_time_reason_and_projection() {
        for (state, reason) in [
            (A2ATaskState::Completed, None),
            (A2ATaskState::Failed, Some("failed")),
            (A2ATaskState::Rejected, Some("rejected")),
            (A2ATaskState::Canceled, Some("canceled")),
        ] {
            for with_working in [false, true] {
                let generation = if with_working { 2 } else { 1 };
                let current = task(state, generation, reason, 120);
                let mut statuses = vec![status(0, A2ATaskState::Submitted, None, 100)];
                if with_working {
                    statuses.push(status(1, A2ATaskState::Working, None, 110));
                }
                statuses.push(status(generation, state, reason, 120));
                assert_eq!(
                    validate_a2a_task_status_history(&current, &statuses),
                    Ok(())
                );
                for replacement in [
                    status(1, A2ATaskState::Submitted, None, 100),
                    status(0, A2ATaskState::Working, None, 100),
                    status(0, A2ATaskState::Submitted, Some("failed"), 100),
                    status(0, A2ATaskState::Submitted, None, 99),
                ] {
                    statuses[0] = replacement;
                    assert_eq!(
                        validate_a2a_task_status_history(&current, &statuses),
                        Err(A2ATaskStoreError::CorruptData)
                    );
                }
                statuses[0] = status(0, A2ATaskState::Submitted, None, 100);
                for replacement in [
                    status(generation + 1, state, reason, 120),
                    status(generation, state, reason, 119),
                    status(generation, state, Some("different"), 120),
                    status(generation, A2ATaskState::Working, None, 120),
                    status(generation, A2ATaskState::InputRequired, None, 120),
                    status(generation, state, reason, 99),
                ] {
                    statuses[generation as usize] = replacement;
                    assert_eq!(
                        validate_a2a_task_status_history(&current, &statuses),
                        Err(A2ATaskStoreError::CorruptData)
                    );
                }
            }
        }
        let current = task(A2ATaskState::Working, 1, None, 110);
        for statuses in [
            vec![],
            vec![status(0, A2ATaskState::Submitted, None, 100)],
            vec![
                status(0, A2ATaskState::Submitted, None, 100),
                status(1, A2ATaskState::Working, None, 110),
                status(2, A2ATaskState::Completed, None, 120),
            ],
        ] {
            assert_eq!(
                validate_a2a_task_status_history(&current, &statuses),
                Err(A2ATaskStoreError::CorruptData)
            );
        }
        let overflow = task(A2ATaskState::Completed, u64::MAX, None, 120);
        assert_eq!(
            validate_a2a_task_status_history(&overflow, &[]),
            Err(A2ATaskStoreError::CorruptData)
        );
    }
}
