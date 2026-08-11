use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use guard_core::identity::{AncestorSummary, ProcessStableId};

pub const DEFAULT_GRAPH_MAX_ENTRIES: usize = 4096;
pub const DEFAULT_GRAPH_MAX_AGE: Duration = Duration::from_secs(10 * 60);
pub const MAX_ANCESTOR_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditProcessKey {
    pub pid: u32,
    pub pidversion: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCodeIdentity {
    pub valid: bool,
    pub platform_binary: bool,
    pub flags: u32,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableSnapshot {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub owner_uid: u32,
    pub mode: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacProcessFacts {
    pub key: AuditProcessKey,
    pub uid: u32,
    pub gid: u32,
    /// Microseconds since the Unix epoch from `es_process_t.start_time`.
    pub start_time_us: u64,
    pub executable: ExecutableSnapshot,
    pub code: MacCodeIdentity,
    pub parent: Option<AuditProcessKey>,
    pub responsible: Option<AuditProcessKey>,
}

impl MacProcessFacts {
    pub fn stable_id(&self) -> ProcessStableId {
        ProcessStableId {
            pid: self.key.pid,
            start_time: self.start_time_us,
            exe: self.executable.path.clone(),
            exe_dev: self.executable.dev,
            exe_ino: self.executable.ino,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.key.pid > 0, "missing process PID");
        anyhow::ensure!(self.start_time_us > 0, "missing process start time");
        anyhow::ensure!(
            self.executable.path.is_absolute(),
            "executable path is not absolute"
        );
        anyhow::ensure!(
            self.executable.dev != 0 && self.executable.ino != 0,
            "missing executable file identity"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct GraphEntry {
    facts: MacProcessFacts,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct MacProcessGraph {
    entries: HashMap<AuditProcessKey, GraphEntry>,
    current_by_pid: HashMap<u32, AuditProcessKey>,
    max_entries: usize,
    max_age: Duration,
}

impl Default for MacProcessGraph {
    fn default() -> Self {
        Self::new(DEFAULT_GRAPH_MAX_ENTRIES, DEFAULT_GRAPH_MAX_AGE)
    }
}

impl MacProcessGraph {
    pub fn new(max_entries: usize, max_age: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            current_by_pid: HashMap::new(),
            max_entries: max_entries.max(1),
            max_age,
        }
    }

    pub fn observe(&mut self, facts: MacProcessFacts, now: Instant) -> anyhow::Result<()> {
        facts.validate()?;
        if let Some(existing) = self.entries.get(&facts.key) {
            anyhow::ensure!(
                existing.facts.stable_id() == facts.stable_id() && existing.facts.uid == facts.uid,
                "same audit process key changed stable identity"
            );
        }
        self.current_by_pid.insert(facts.key.pid, facts.key);
        self.entries.insert(
            facts.key,
            GraphEntry {
                facts,
                last_seen: now,
            },
        );
        self.evict(now);
        Ok(())
    }

    pub fn remove_terminal(&mut self, key: AuditProcessKey) {
        self.entries.remove(&key);
        if self.current_by_pid.get(&key.pid) == Some(&key) {
            self.current_by_pid.remove(&key.pid);
        }
    }

    pub fn current(&self, pid: u32) -> Option<&MacProcessFacts> {
        self.current_by_pid
            .get(&pid)
            .and_then(|key| self.entries.get(key))
            .map(|entry| &entry.facts)
    }

    pub fn is_live_instance(&self, identity: &ProcessStableId) -> bool {
        self.current(identity.pid)
            .is_some_and(|facts| facts.stable_id() == *identity)
    }

    pub fn ancestors(
        &self,
        key: AuditProcessKey,
        now: Instant,
    ) -> anyhow::Result<Vec<AncestorSummary>> {
        let current = self
            .entries
            .get(&key)
            .filter(|entry| now.saturating_duration_since(entry.last_seen) <= self.max_age)
            .ok_or_else(|| anyhow::anyhow!("process graph entry is missing or stale"))?;
        let mut parent = current.facts.parent;
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        while let Some(parent_key) = parent {
            anyhow::ensure!(
                seen.insert(parent_key),
                "process graph contains an ancestry cycle"
            );
            anyhow::ensure!(
                result.len() < MAX_ANCESTOR_DEPTH,
                "process ancestry exceeds the bounded depth"
            );
            let entry = self
                .entries
                .get(&parent_key)
                .filter(|entry| now.saturating_duration_since(entry.last_seen) <= self.max_age)
                .ok_or_else(|| {
                    anyhow::anyhow!("required parent graph entry is missing or stale")
                })?;
            let stable = entry.facts.stable_id();
            result.push(AncestorSummary {
                pid: stable.pid,
                start_time: stable.start_time,
                exe: stable.exe,
                exe_dev: stable.exe_dev,
                exe_ino: stable.exe_ino,
            });
            parent = entry.facts.parent;
        }
        Ok(result)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict(&mut self, now: Instant) {
        let stale = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                (now.saturating_duration_since(entry.last_seen) > self.max_age).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in stale {
            self.remove_terminal(key);
        }
        while self.entries.len() > self.max_entries {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.remove_terminal(oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        pid: u32,
        version: u32,
        start: u64,
        parent: Option<AuditProcessKey>,
    ) -> MacProcessFacts {
        MacProcessFacts {
            key: AuditProcessKey {
                pid,
                pidversion: version,
            },
            uid: 501,
            gid: 20,
            start_time_us: start,
            executable: ExecutableSnapshot {
                path: PathBuf::from(format!("/Applications/Test.app/Contents/MacOS/test-{pid}")),
                dev: 1,
                ino: u64::from(pid),
                owner_uid: 501,
                mode: 0o100755,
                size: 10,
                mtime_ns: 1,
                ctime_ns: 1,
            },
            code: MacCodeIdentity {
                valid: true,
                platform_binary: false,
                flags: 0,
                team_id: Some("TEAM".to_owned()),
                signing_id: Some("signing".to_owned()),
                cdhash: [0; 20],
            },
            parent,
            responsible: None,
        }
    }

    #[test]
    fn valid_graph_returns_stable_ancestry() {
        let now = Instant::now();
        let mut graph = MacProcessGraph::default();
        let root = facts(10, 1, 100, None);
        let child = facts(11, 1, 101, Some(root.key));
        graph.observe(root.clone(), now).unwrap();
        graph.observe(child.clone(), now).unwrap();
        let ancestors = graph.ancestors(child.key, now).unwrap();
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors[0].pid, root.key.pid);
        assert_eq!(ancestors[0].start_time, root.start_time_us);
    }

    #[test]
    fn missing_parent_fails_closed() {
        let now = Instant::now();
        let mut graph = MacProcessGraph::default();
        let child = facts(
            11,
            1,
            101,
            Some(AuditProcessKey {
                pid: 10,
                pidversion: 1,
            }),
        );
        graph.observe(child.clone(), now).unwrap();
        assert!(graph.ancestors(child.key, now).is_err());
    }

    #[test]
    fn pid_reuse_does_not_match_old_stable_identity() {
        let now = Instant::now();
        let mut graph = MacProcessGraph::default();
        let old = facts(10, 1, 100, None);
        let new = facts(10, 2, 200, None);
        graph.observe(old.clone(), now).unwrap();
        graph.observe(new.clone(), now).unwrap();
        assert!(!graph.is_live_instance(&old.stable_id()));
        assert!(graph.is_live_instance(&new.stable_id()));
    }

    #[test]
    fn same_audit_key_cannot_change_start_time() {
        let now = Instant::now();
        let mut graph = MacProcessGraph::default();
        let first = facts(10, 1, 100, None);
        let changed = facts(10, 1, 200, None);
        graph.observe(first, now).unwrap();
        assert!(graph.observe(changed, now).is_err());
    }

    #[test]
    fn graph_removes_terminal_and_bounds_stale_entries() {
        let now = Instant::now();
        let mut graph = MacProcessGraph::new(2, Duration::from_secs(1));
        let first = facts(10, 1, 100, None);
        graph.observe(first.clone(), now).unwrap();
        graph.remove_terminal(first.key);
        assert!(graph.is_empty());
        graph.observe(facts(11, 1, 101, None), now).unwrap();
        graph
            .observe(facts(12, 1, 102, None), now + Duration::from_secs(2))
            .unwrap();
        assert_eq!(graph.len(), 1);
    }
}
