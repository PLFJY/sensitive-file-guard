use std::time::Duration;

/// Leave enough time for the deny response to reach Endpoint Security even
/// when the machine is briefly under load.
pub const SAFETY_MARGIN: Duration = Duration::from_secs(1);
/// A prompt with no useful human-response window is denied without dispatching
/// any UI work.
pub const MIN_INTERACTIVE_BUDGET: Duration = Duration::from_secs(2);
/// Product prompts never consume an arbitrarily long per-event ES deadline.
pub const PRODUCT_MAX_PROMPT_CAP: Duration = Duration::from_secs(45);

pub trait DeadlineClock {
    fn now_ticks(&self) -> u64;
    fn ticks_to_duration(&self, ticks: u64) -> Duration;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsufficientDeadline {
    pub remaining: Duration,
    pub effective: Duration,
}

impl std::fmt::Display for InsufficientDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Endpoint Security deadline is too short for interactive authorization (remaining {:?}, usable {:?}, minimum {:?})",
            self.remaining, self.effective, MIN_INTERACTIVE_BUDGET
        )
    }
}

impl std::error::Error for InsufficientDeadline {}

pub fn interactive_budget(
    clock: &impl DeadlineClock,
    deadline_ticks: u64,
) -> Result<Duration, InsufficientDeadline> {
    let remaining_ticks = deadline_ticks.saturating_sub(clock.now_ticks());
    let remaining = clock.ticks_to_duration(remaining_ticks);
    let usable = remaining.saturating_sub(SAFETY_MARGIN);
    let effective = usable.min(PRODUCT_MAX_PROMPT_CAP);
    if effective <= MIN_INTERACTIVE_BUDGET {
        return Err(InsufficientDeadline {
            remaining,
            effective,
        });
    }
    Ok(effective)
}

#[cfg(target_os = "macos")]
pub(crate) struct DarwinClock;

#[cfg(target_os = "macos")]
impl DeadlineClock for DarwinClock {
    fn now_ticks(&self) -> u64 {
        // SAFETY: the bridge directly returns mach_absolute_time().
        unsafe { guard_mach_absolute_time() }
    }

    fn ticks_to_duration(&self, ticks: u64) -> Duration {
        // SAFETY: conversion has no pointer arguments or retained state.
        Duration::from_nanos(unsafe { guard_mach_ticks_to_nanos(ticks) })
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_mach_absolute_time() -> u64;
    fn guard_mach_ticks_to_nanos(ticks: u64) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClock {
        now: u64,
    }

    impl DeadlineClock for FakeClock {
        fn now_ticks(&self) -> u64 {
            self.now
        }

        fn ticks_to_duration(&self, ticks: u64) -> Duration {
            Duration::from_secs(ticks)
        }
    }

    #[test]
    fn ample_deadline_is_limited_by_product_cap() {
        let budget = interactive_budget(&FakeClock { now: 10 }, 130).unwrap();
        assert_eq!(budget, PRODUCT_MAX_PROMPT_CAP);
    }

    #[test]
    fn shorter_deadline_keeps_safety_margin() {
        let budget = interactive_budget(&FakeClock { now: 10 }, 20).unwrap();
        assert_eq!(budget, Duration::from_secs(9));
    }

    #[test]
    fn insufficient_deadline_fails_closed() {
        let error = interactive_budget(&FakeClock { now: 10 }, 13).unwrap_err();
        assert_eq!(error.remaining, Duration::from_secs(3));
        assert_eq!(error.effective, MIN_INTERACTIVE_BUDGET);
    }
}
