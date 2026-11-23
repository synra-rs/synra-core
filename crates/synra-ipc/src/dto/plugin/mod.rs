//! Plugins: what is installed, what is available, and what installing one reports.

mod audit;
mod catalog;
mod install;
mod registry;
mod snapshot;
mod sync;

pub use audit::AuditEntryDto;
pub use catalog::{CatalogItem, CatalogQuery, CatalogSort};
pub use install::{
    InstallPreviewDto, InstallReport, InstallSourceDto, RemoveOptionsDto, RemoveReport,
};
pub use registry::RegistryProblem;
pub use snapshot::{PluginHealthDto, PluginSnapshot, PublisherDto, UpdateInfo};
pub use sync::{SyncFailure, SyncPlanDto, SyncReport, SyncTarget};
