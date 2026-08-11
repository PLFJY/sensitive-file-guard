//! Shared, GTK-free lifecycle for interactive daemon authorizations.
//!
//! The daemon's pending list is a discovery stream, not the lifecycle of a
//! desktop dialog. In particular, a request can disappear while a Polkit
//! authorization is still in flight. This controller deliberately keeps the
//! active request until the UI reports a terminal result.

use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PromptKind {
    Migration,
    SshRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PromptKey {
    pub kind: PromptKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptState {
    AwaitingChoice,
    Authorizing,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPrompt {
    pub key: PromptKey,
    /// The daemon's opaque request ID used by the resolver.
    pub request_id: String,
    pub title: String,
    pub details: String,
    pub allow_label: String,
    pub block_label: String,
}

#[derive(Debug, Default)]
pub struct PendingDialogController {
    active: Option<(PendingPrompt, PromptState)>,
    queue: VecDeque<PendingPrompt>,
    known: HashSet<PromptKey>,
}

impl PendingDialogController {
    /// Add freshly discovered requests. Existing and active keys are ignored;
    /// the daemon remains the source of truth for request metadata.
    pub fn reconcile<I>(&mut self, prompts: I)
    where
        I: IntoIterator<Item = PendingPrompt>,
    {
        for prompt in prompts {
            if self.known.insert(prompt.key.clone()) {
                self.queue.push_back(prompt);
            }
        }
    }

    /// Reconcile a complete, successful daemon snapshot. Queued requests that
    /// disappeared before display are dropped, while the active request is
    /// deliberately retained even when it is absent from the snapshot.
    pub fn reconcile_snapshot<I>(&mut self, prompts: I)
    where
        I: IntoIterator<Item = PendingPrompt>,
    {
        let prompts = prompts.into_iter().collect::<Vec<_>>();
        let present = prompts
            .iter()
            .map(|prompt| &prompt.key)
            .collect::<HashSet<_>>();
        self.queue.retain(|prompt| present.contains(&prompt.key));
        let active_key = self.active.as_ref().map(|(prompt, _)| prompt.key.clone());
        let queued_keys = self
            .queue
            .iter()
            .map(|prompt| prompt.key.clone())
            .collect::<HashSet<_>>();
        self.known
            .retain(|key| active_key.as_ref() == Some(key) || queued_keys.contains(key));
        self.reconcile(prompts);
    }

    /// Start the next request if no dialog is active. The active request is
    /// retained independently of future `reconcile` calls.
    pub fn activate_next(&mut self) -> Option<PendingPrompt> {
        if self.active.is_some() {
            return None;
        }
        let prompt = self.queue.pop_front()?;
        self.active = Some((prompt.clone(), PromptState::AwaitingChoice));
        Some(prompt)
    }

    pub fn active(&self) -> Option<(&PendingPrompt, PromptState)> {
        self.active.as_ref().map(|(prompt, state)| (prompt, *state))
    }

    /// Whether no prompt remains active or queued after a terminal prompt is
    /// released. This is used by the transient confirmation client to decide
    /// whether its host window can exit.
    pub fn is_empty(&self) -> bool {
        self.active.is_none() && self.queue.is_empty()
    }

    pub fn begin_authorization(&mut self) -> bool {
        match self.active.as_mut() {
            Some((_, state)) if *state == PromptState::AwaitingChoice => {
                *state = PromptState::Authorizing;
                true
            }
            _ => false,
        }
    }

    /// Return to the choice state after a failed Allow authorization. The
    /// request remains active and is never re-enqueued by a refresh.
    pub fn retry(&mut self) -> bool {
        match self.active.as_mut() {
            Some((_, state)) if *state == PromptState::Authorizing => {
                *state = PromptState::AwaitingChoice;
                true
            }
            _ => false,
        }
    }

    /// Complete the active request exactly once. Its key remains known until
    /// the GTK dialog is closed and released, so a refresh cannot enqueue a
    /// duplicate in the short terminal transition.
    pub fn finish(&mut self) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|(_, state)| *state == PromptState::Terminal)
        {
            return false;
        }
        let Some((prompt, _)) = self.active.take() else {
            return false;
        };
        self.active = Some((prompt, PromptState::Terminal));
        true
    }

    /// Remove the terminal item and make the next queued item eligible for
    /// display. This is called only after the GTK dialog has been closed.
    pub fn release_terminal(&mut self) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|(_, state)| *state == PromptState::Terminal)
        {
            if let Some((prompt, _)) = self.active.take() {
                self.known.remove(&prompt.key);
            }
            return true;
        }
        false
    }

    #[cfg(test)]
    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(kind: PromptKind, key: &str, id: &str) -> PendingPrompt {
        PendingPrompt {
            key: PromptKey {
                kind,
                value: key.into(),
            },
            request_id: id.into(),
            title: "title".into(),
            details: "details".into(),
            allow_label: "Allow".into(),
            block_label: "Block".into(),
        }
    }

    #[test]
    fn duplicate_refresh_does_not_duplicate_dialog() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([prompt(PromptKind::SshRead, "ssh:1", "1")]);
        controller.reconcile([prompt(PromptKind::SshRead, "ssh:1", "1")]);
        assert_eq!(controller.queued_len(), 1);
        assert!(controller.activate_next().is_some());
        controller.reconcile([prompt(PromptKind::SshRead, "ssh:1", "1")]);
        assert!(controller.active().is_some());
        assert_eq!(controller.queued_len(), 0);
    }

    #[test]
    fn only_one_active_item_and_next_is_queued() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([
            prompt(PromptKind::Migration, "migration:1", "1"),
            prompt(PromptKind::SshRead, "ssh:2", "2"),
        ]);
        assert_eq!(controller.queued_len(), 2);
        assert_eq!(controller.activate_next().unwrap().request_id, "1");
        assert_eq!(controller.queued_len(), 1);
        assert!(controller.activate_next().is_none());
    }

    #[test]
    fn authorizing_survives_empty_refresh_and_can_retry() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([prompt(PromptKind::Migration, "migration:1", "1")]);
        controller.activate_next();
        assert!(controller.begin_authorization());
        assert!(!controller.begin_authorization());
        controller.reconcile_snapshot(std::iter::empty());
        assert_eq!(controller.active().unwrap().1, PromptState::Authorizing);
        assert!(controller.retry());
        assert_eq!(controller.active().unwrap().1, PromptState::AwaitingChoice);
    }

    #[test]
    fn undisplayed_request_removed_by_successful_snapshot() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([prompt(PromptKind::SshRead, "ssh:1", "1")]);
        controller.reconcile_snapshot(std::iter::empty());
        assert_eq!(controller.queued_len(), 0);
        assert!(controller.activate_next().is_none());
    }

    #[test]
    fn terminal_release_shows_next_and_finish_is_once() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([
            prompt(PromptKind::SshRead, "ssh:1", "1"),
            prompt(PromptKind::SshRead, "ssh:2", "2"),
        ]);
        controller.activate_next();
        assert!(controller.begin_authorization());
        assert!(controller.finish());
        assert!(!controller.finish());
        assert!(controller.release_terminal());
        assert_eq!(controller.activate_next().unwrap().request_id, "2");
    }

    #[test]
    fn empty_after_last_terminal_prompt_is_releasable() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([prompt(PromptKind::SshRead, "ssh:1", "1")]);
        controller.activate_next();
        assert!(controller.begin_authorization());
        assert!(controller.finish());
        assert!(!controller.is_empty());
        assert!(controller.release_terminal());
        assert!(controller.is_empty());
    }

    #[test]
    fn migration_and_ssh_keys_are_not_cross_deduplicated() {
        let mut controller = PendingDialogController::default();
        controller.reconcile([
            prompt(PromptKind::Migration, "same", "migration"),
            prompt(PromptKind::SshRead, "same", "ssh"),
        ]);
        assert_eq!(controller.queued_len(), 2);
    }
}
