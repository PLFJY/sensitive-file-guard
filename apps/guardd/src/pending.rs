//! Linux composition aliases for the portable pending authorization runtime.

pub use guard_runtime::{
    MigrationEnqueueResult as EnqueueResult, PendingMigrationInfo, PendingMigrationStore,
    PendingSshReadInfo, PendingSshReadStore, SshEnqueueResult,
};
