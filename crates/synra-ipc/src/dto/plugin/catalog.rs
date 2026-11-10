use serde::{Deserialize, Serialize};
use synra_protocol::PluginId;

/// A plugin in the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogItem {
    /// The plugin's identifier.
    pub plugin_id: PluginId,
    /// Its name.
    pub title: String,
    /// Its description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The version on offer.
    pub version: String,
    /// Who published it.
    pub publisher: String,
    /// How many capabilities it asks for.
    ///
    /// A count rather than the list: the catalogue response is a search result, and a search result that carried
    /// every plugin's full permission list would be the largest thing on the wire for the least read part of it.
    pub capability_count: usize,
    /// Whether it is already installed.
    pub installed: bool,
}

/// How a catalogue result set is ordered.
///
/// ★ Only the two the search endpoint can honour: npm's index returns relevance, and the rest of the design's sorts
/// (downloads, updated) are numbers the search response does not carry. A `sort` value this build cannot perform is not
/// offered rather than silently ignored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CatalogSort {
    /// The registry's own order, which for an npm index is relevance.
    #[default]
    Relevance,
    /// By name, for a list a person is scanning.
    Name,
}

/// What to search the catalogue for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogQuery {
    /// The search text.
    pub query: String,
    /// Which registry, when the user has more than one configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The most results to return. The kernel clamps this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// How many results to skip, for paging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// The order to return them in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<CatalogSort>,
}
