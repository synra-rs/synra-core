//! Plugins: what is installed, what is available, and what installing one reports.

mod snapshot;
mod catalog;
mod install;
mod sync;
mod audit;

pub use snapshot::{PluginHealthDto, PluginSnapshot, PublisherDto, UpdateInfo};
pub use catalog::{CatalogItem, CatalogQuery, CatalogSort};
pub use install::{InstallPreviewDto, InstallReport, InstallSourceDto, RemoveOptionsDto, RemoveReport};
pub use sync::{SyncFailure, SyncPlanDto, SyncReport, SyncTarget};
pub use audit::AuditEntryDto;
