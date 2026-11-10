use rusqlite::params;

use crate::records::{PluginActionRow, PluginGrantRow, PluginRow, RowError};

use super::{DbError, SynraDb};

mod actions;
mod grants;
mod state;
