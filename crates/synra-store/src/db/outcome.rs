//! How a migration outcome reads in a log line.

use core::fmt;

use super::schema::MigrationOutcome;
impl fmt::Display for MigrationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}
