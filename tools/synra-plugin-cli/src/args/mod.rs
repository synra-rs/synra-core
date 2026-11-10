//! The command surface: what an author types, and what it means.
//!
//! # Why this is a type
//!
//! The plugin author's command line is a contract with someone who is not reading this repository. The failures it
//! produces are the ones they read first — a missing flag, an unknown subcommand, a directory that does not exist — so
//! every one of those is decidable from the arguments alone and worth being tested rather than discovered by whoever
//! types the command wrong.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::template::TemplateKind;

/// The plugin author's tool.
#[derive(Debug, Parser)]
#[command(
    name = "synra-plugin",
    version,
    about = "Scaffold, verify and package a Synra plugin",
    long_about = "Works against a plugin's directory: scaffolds one from a template and checks one before it reaches \
                  a user. Every check it makes is one the kernel also makes at install time, moved earlier so the \
                  author can still act on it.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// The subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// What the author asked for.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a new plugin.
    New(NewArgs),
    /// Build a plugin's artifacts.
    Build(BuildArgs),
    /// Check a plugin before publishing it.
    Verify(VerifyArgs),
    /// Sign a plugin with a publisher's key.
    Sign(SignArgs),
    /// Pack a plugin into an npm-compatible `.tgz` for a registry.
    Pack(PackArgs),
    /// Check the files a static bucket would serve, without uploading them.
    Publish(PublishArgs),
    /// Upload a static package with a command the author provides.
    Upload(UploadArgs),
}

/// Options for `build`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// The plugin's directory.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,

    /// Print the commands without running them.
    #[arg(long)]
    pub dry_run: bool,
}

/// Options for `sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The plugin's directory.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,

    /// The signing key: 32 bytes of hex.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Generate a key, print it, and write the public half to `public-key.txt`.
    ///
    /// For an author who has never published: a tool that hid the key would be one whose keys they cannot back up, and
    /// a publisher who loses theirs cannot ship an update to a plugin users already trust.
    #[arg(long)]
    pub generate_key: bool,

    /// Check an existing signature instead of making one.
    #[arg(long, value_name = "PATH")]
    pub verify: Option<PathBuf>,
}

/// Options for `pack`.
#[derive(Debug, Args)]
pub struct PackArgs {
    /// The plugin's directory, as it stands after `build` and `sign`.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,

    /// Where the archive goes. Defaults to `<dir>/dist/<id>-<version>.tgz`.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// The registry this package is intended for. Checked for shape only; nothing is uploaded.
    #[arg(long, value_name = "URL")]
    pub registry: Option<String>,

    /// Also write a static index for a bucket, with tarball URLs under this base.
    ///
    /// The index goes beside the tarball as `<plugin id>.json`, which is the path a `static:` registry reads. Without a
    /// value the index names the tarball relatively, and the client resolves it against the index's own URL.
    #[arg(long, value_name = "URL", num_args = 0..=1, default_missing_value = "")]
    pub index: Option<String>,

    /// Print the target without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

/// Options for `publish`.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// The static index to check: the `.json` `pack --index` wrote.
    #[arg(long, value_name = "FILE")]
    pub index: PathBuf,

    /// The public base URL, when the index names tarballs absolutely. The local path is the URL minus this prefix.
    #[arg(long, value_name = "URL")]
    pub base: Option<String>,

    /// Also fetch the index and tarballs from `--base` and compare them with the local files.
    #[arg(long)]
    pub verify: bool,
}

/// Options for `upload`.
#[derive(Debug, Args)]
pub struct UploadArgs {
    /// The static index to publish: the `.json` `pack --index` wrote.
    #[arg(long, value_name = "FILE")]
    pub index: PathBuf,

    /// The public base URL the files are addressed under.
    #[arg(long, value_name = "URL")]
    pub base: String,

    /// The upload command, with `{file}` and `{url}` placeholders. Split on spaces; no shell.
    #[arg(long, value_name = "TEMPLATE")]
    pub command: String,

    /// Print the commands without running them.
    #[arg(long)]
    pub dry_run: bool,

    /// Read the bucket back after a successful upload and compare it with the local files.
    #[arg(long)]
    pub verify: bool,
}

/// Options for `new`.
#[derive(Debug, Args)]
pub struct NewArgs {
    /// The plugin's id, such as `@your-scope/my-plugin`.
    ///
    /// Validated the same way the kernel validates it at install, so a scaffold cannot produce a plugin that cannot
    /// install — and the id is in every path and capability string, so finding out later means a rename.
    pub plugin_id: String,

    /// The version.
    #[arg(long, value_name = "VERSION", default_value = "0.1.0")]
    pub version: String,

    /// The name shown to a person.
    #[arg(long, value_name = "TITLE")]
    pub title: Option<String>,

    /// Which template.
    #[arg(long, value_enum, default_value_t = TemplateKind::Headless)]
    pub template: TemplateKind,

    /// Where to write it.
    ///
    /// Defaults to a directory named after the plugin's wire slug, which is the name its artifact uses everywhere
    /// else — the registry, the cache, the log.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Print what would be written without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

impl NewArgs {
    /// The title, defaulting to the plugin's name part.
    ///
    /// Derived from the id rather than required, because an author who typed `@scope/my-plugin` has already said what
    /// it is called and being asked again is friction at the moment they are least invested.
    #[must_use]
    pub fn title(&self) -> String {
        self.title.clone().unwrap_or_else(|| {
            self.plugin_id
                .rsplit_once('/')
                .map_or_else(|| self.plugin_id.clone(), |(_, name)| name.to_owned())
        })
    }
}

/// Options for `verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The plugin's directory.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,

    /// Print one JSON value instead of prose.
    #[arg(long)]
    pub json: bool,

    /// Print the findings without the suggestions.
    #[arg(long)]
    pub brief: bool,
}

#[cfg(test)]
mod tests;
