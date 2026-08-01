//! Connect-transaction step records for the UI (F3).
//!
//! Mirrors the §6 stage sequence into a serializable per-step state list:
//! an attempt starts from a fresh all-pending record, each `set_stage`
//! advance completes the previous step with its elapsed time and marks the
//! new one current, a failure marks the in-flight step failed (never
//! completed), and success completes them all. Pure, timing injected.

use serde::Serialize;
use tono_core::connection::ConnectStage;

use crate::tono::commands;

/// Serializable step state (`tonoConnectProgress.steps[].state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StepState {
    Pending,
    Current,
    Completed,
    Failed,
}

/// One step of the connect transaction as the UI shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepRecord {
    pub key: &'static str,
    pub label: &'static str,
    pub state: StepState,
    pub elapsed_ms: Option<u64>,
}

/// The 8 §6 stages as fresh steps: all pending except the first, which is
/// current at attempt start (FSM `begin_connect` lands on `Preparing`).
pub fn initial_steps() -> Vec<StepRecord> {
    ConnectStage::ALL
        .iter()
        .enumerate()
        .map(|(index, stage)| StepRecord {
            key: commands::stage_key(*stage),
            label: stage.label(),
            state: if index == 0 {
                StepState::Current
            } else {
                StepState::Pending
            },
            elapsed_ms: None,
        })
        .collect()
}

/// Advance the record to `stage`: the step currently marked current is
/// completed with `elapsed_ms` (its wall time as current), and `stage`
/// becomes the new current. Advancing past the end is a no-op; advancing
/// to a stage already passed leaves the record untouched (stale guard).
pub fn advance(steps: &mut [StepRecord], stage: ConnectStage, elapsed_ms: u64) {
    let key = commands::stage_key(stage);
    let Some(current) = steps.iter().position(|step| step.state == StepState::Current) else {
        return;
    };
    let Some(target) = steps.iter().position(|step| step.key == key) else {
        return;
    };
    if target <= current {
        return;
    }
    steps[current].state = StepState::Completed;
    steps[current].elapsed_ms = Some(elapsed_ms);
    steps[target].state = StepState::Current;
}

/// Mark the in-flight step failed (F3: a failed step is never rewritten as
/// completed afterwards).
pub fn fail_current(steps: &mut [StepRecord], elapsed_ms: u64) {
    if let Some(current) = steps.iter_mut().find(|step| step.state == StepState::Current) {
        current.state = StepState::Failed;
        current.elapsed_ms = Some(elapsed_ms);
    }
}

/// Success: every step completed; the in-flight one gets its final elapsed.
pub fn complete_all(steps: &mut [StepRecord], elapsed_ms: u64) {
    for step in steps.iter_mut() {
        if step.state == StepState::Current {
            step.elapsed_ms = Some(elapsed_ms);
        }
        if step.state != StepState::Failed {
            step.state = StepState::Completed;
        }
    }
}

/// Sum of recorded step durations (the total connect time we can account
/// for); `None` when nothing has been measured yet.
pub fn total_elapsed_ms(steps: &[StepRecord]) -> Option<u64> {
    let mut total = 0_u64;
    let mut any = false;
    for step in steps {
        if let Some(elapsed) = step.elapsed_ms {
            total += elapsed;
            any = true;
        }
    }
    any.then_some(total)
}

#[cfg(test)]
mod tests {
    use super::{StepState, advance, complete_all, fail_current, initial_steps, total_elapsed_ms};
    use tono_core::connection::ConnectStage;

    #[test]
    fn initial_record_is_first_current_rest_pending() {
        let steps = initial_steps();
        assert_eq!(steps.len(), ConnectStage::ALL.len());
        assert_eq!(steps[0].key, "preparing");
        assert_eq!(steps[0].state, StepState::Current);
        assert!(steps[1..].iter().all(|step| step.state == StepState::Pending));
        // The cloud-policy stage is part of the record (Build 28).
        assert!(steps.iter().any(|step| step.key == "applyingCloudPolicy"));
    }

    #[test]
    fn advance_completes_previous_with_elapsed_and_marks_current() {
        let mut steps = initial_steps();
        advance(&mut steps, ConnectStage::PreparingService, 120);
        assert_eq!(steps[0].state, StepState::Completed);
        assert_eq!(steps[0].elapsed_ms, Some(120));
        assert_eq!(steps[1].state, StepState::Current);
        assert_eq!(steps[1].elapsed_ms, None);
        advance(&mut steps, ConnectStage::StartingKillSwitch, 80);
        assert_eq!(steps[1].state, StepState::Completed);
        assert_eq!(steps[1].elapsed_ms, Some(80));
        assert_eq!(steps[2].state, StepState::Current);
        assert_eq!(total_elapsed_ms(&steps), Some(200));
    }

    #[test]
    fn advance_is_monotonic_and_stale_safe() {
        let mut steps = initial_steps();
        advance(&mut steps, ConnectStage::PreparingService, 10);
        // Going backwards or re-advancing the same stage does nothing.
        advance(&mut steps, ConnectStage::Preparing, 999);
        assert_eq!(steps[0].state, StepState::Completed);
        assert_eq!(steps[1].state, StepState::Current);
        advance(&mut steps, ConnectStage::PreparingService, 999);
        assert_eq!(steps[1].state, StepState::Current);
        assert_eq!(steps[1].elapsed_ms, None);
    }

    #[test]
    fn failed_step_is_never_rewritten_as_completed() {
        let mut steps = initial_steps();
        advance(&mut steps, ConnectStage::PreparingService, 50);
        advance(&mut steps, ConnectStage::StartingKillSwitch, 60);
        fail_current(&mut steps, 70);
        assert_eq!(steps[2].state, StepState::Failed);
        assert_eq!(steps[2].elapsed_ms, Some(70));
        // complete_all (or a late advance) must not resurrect the failure.
        complete_all(&mut steps, 999);
        assert_eq!(steps[2].state, StepState::Failed);
        advance(&mut steps, ConnectStage::StartingTunnel, 999);
        assert_eq!(steps[2].state, StepState::Failed);
        assert!(steps[3..].iter().all(|step| step.state != StepState::Failed));
    }

    #[test]
    fn new_attempt_resets_the_record() {
        let mut steps = initial_steps();
        fail_current(&mut steps, 42);
        let steps = initial_steps();
        assert_eq!(steps[0].state, StepState::Current);
        assert!(steps[1..].iter().all(|step| step.state == StepState::Pending));
        assert_eq!(total_elapsed_ms(&steps), None);
    }

    #[test]
    fn complete_all_marks_everything_completed() {
        let mut steps = initial_steps();
        advance(&mut steps, ConnectStage::PreparingService, 10);
        complete_all(&mut steps, 20);
        assert!(steps.iter().all(|step| step.state == StepState::Completed));
        assert_eq!(total_elapsed_ms(&steps), Some(30));
    }
}
