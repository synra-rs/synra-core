//! The metrics module's tests.

use super::*;

fn key(name: &str) -> SeriesKey {
    SeriesKey::new(name, Vec::<(String, String)>::new())
}

fn labelled(name: &str, pairs: &[(&str, &str)]) -> SeriesKey {
    SeriesKey::new(
        name,
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

mod series;
mod histograms;
mod snapshots;
