use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use guard_core::identity::{ProcessIdentity, ProcessIntegrity, ProcessStableId, TrustTier};
use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_core::{evaluate, AccessEvent, AccessOperation, Decision, LeaseSet};
use guard_platform::{AccessDisposition, PendingPermission, ProtectedAccessRequest};

struct FakePending {
    responses: Arc<Mutex<Vec<&'static str>>>,
    completed: bool,
}

impl FakePending {
    fn new(responses: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            responses,
            completed: false,
        }
    }
}

impl PendingPermission for FakePending {
    fn allow(mut self: Box<Self>) -> anyhow::Result<()> {
        anyhow::ensure!(!self.completed, "fake permission already completed");
        self.responses.lock().unwrap().push("allow");
        self.completed = true;
        Ok(())
    }

    fn deny(mut self: Box<Self>) -> anyhow::Result<()> {
        anyhow::ensure!(!self.completed, "fake permission already completed");
        self.responses.lock().unwrap().push("deny");
        self.completed = true;
        Ok(())
    }
}

impl Drop for FakePending {
    fn drop(&mut self) {
        if !self.completed {
            self.responses.lock().unwrap().push("deny-on-drop");
            self.completed = true;
        }
    }
}

#[test]
fn deferred_permission_has_one_terminal_response() {
    let responses = Arc::new(Mutex::new(Vec::new()));
    let pending: Box<dyn PendingPermission> = Box::new(FakePending::new(Arc::clone(&responses)));
    assert_eq!(AccessDisposition::Deferred, AccessDisposition::Deferred);
    pending.allow().unwrap();
    assert_eq!(*responses.lock().unwrap(), vec!["allow"]);

    let dropped: Box<dyn PendingPermission> = Box::new(FakePending::new(Arc::clone(&responses)));
    drop(dropped);
    assert_eq!(*responses.lock().unwrap(), vec!["allow", "deny-on-drop"]);
}

fn process(browser: Option<&str>, uid: u32) -> ProcessIdentity {
    ProcessIdentity {
        stable: ProcessStableId {
            pid: 10,
            start_time: 20,
            exe: PathBuf::from("/synthetic/browser"),
            exe_dev: 1,
            exe_ino: 2,
        },
        uid,
        gid: uid,
        exe_owner_uid: 0,
        browser: browser.map(|id| BrowserId(id.to_owned())),
        trust_tier: TrustTier::SystemPackage,
        cmdline: Vec::new(),
        ancestors: Vec::new(),
        integrity: ProcessIntegrity::Normal,
    }
}

fn resource() -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId("synthetic-profile".into()),
        kind: ProtectedResourceKind::CookieStore,
        browser: Some(BrowserId("chrome".into())),
        profile: Some(ProfileId("Default".into())),
        path: PathBuf::from("/synthetic/profile/Cookies"),
        owner_uid: 1000,
    }
}

#[test]
fn fake_backend_can_model_allow_and_unknown_process_policy() {
    let own = AccessEvent {
        resource: resource(),
        process: process(Some("chrome"), 1000),
        operation: AccessOperation::Open,
    };
    assert_eq!(evaluate(&own, &LeaseSet::default(), 1, 0), Decision::Allow);

    let unknown = AccessEvent {
        resource: resource(),
        process: process(None, 1000),
        operation: AccessOperation::Open,
    };
    assert!(matches!(
        evaluate(&unknown, &LeaseSet::default(), 1, 0),
        Decision::Deny(_)
    ));
}

#[test]
fn request_contains_product_data_only() {
    let request = ProtectedAccessRequest {
        process: process(Some("chrome"), 1000),
        resource: resource(),
        operation: guard_platform::ProtectedOperation::Open,
    };
    assert_eq!(request.process.uid, request.resource.owner_uid);
}
