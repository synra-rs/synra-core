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
    /// The index goes beside the tarball as `<plugin id>.json`, which is the path a `static:` registry reads.
    #[arg(long, value_name = "URL")]
    pub index: Option<String>,

    /// Print the target without writing it.
    #[arg(long)]
    pub dry_run: bool,
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
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parsed(args: &[&str]) -> Cli {
        parse(args).expect("parses")
    }

    #[test]
    fn the_parser_is_internally_consistent() {
        // `clap`'s own check: two flags with one long name, a subcommand with an undocumented required argument, and
        // so on. A build failure rather than something an author finds.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_documented_command_exists() {
        // The design document's list, as an executable statement. `publish` and `dev` are documented and not
        // implemented — see the crate docs for why a version of them that only printed what it would do would be worse
        // than one that says it is not implemented.
        for args in [
            vec!["synra-plugin", "new", "@scope/plugin"],
            vec!["synra-plugin", "build"],
            vec!["synra-plugin", "verify"],
            vec!["synra-plugin", "sign", "--generate-key"],
        ] {
            assert!(parse(&args).is_ok(), "{args:?} should parse");
        }
    }

    #[test]
    fn an_unimplemented_command_is_refused_rather_than_silently_absent() {
        // `publish` and `dev` need a registry client and a running host, and a stub that printed "would publish" would
        // be worse than an absent one: it exits zero. `clap`'s "unrecognized subcommand" is the honest answer.
        for command in ["publish", "dev"] {
            let error = parse(&["synra-plugin", command]).expect_err("not implemented");
            assert!(
                error.to_string().contains("unrecognized"),
                "{command}: {error}"
            );
        }
    }

    // ── new ───────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn new_needs_a_plugin_id() {
        assert!(parse(&["synra-plugin", "new"]).is_err());
    }

    #[test]
    fn new_defaults_to_the_headless_template_and_the_current_directory() {
        let Command::New(args) = parsed(&["synra-plugin", "new", "@scope/plugin"]).command else {
            panic!("expected new");
        };
        assert_eq!(args.template, TemplateKind::Headless);
        assert_eq!(args.dir, None);
        assert_eq!(args.version, "0.1.0");
        assert!(!args.dry_run);
    }

    #[test]
    fn new_accepts_every_template_by_name() {
        for (word, kind) in [
            ("headless", TemplateKind::Headless),
            ("ui", TemplateKind::Ui),
            ("hybrid", TemplateKind::Hybrid),
        ] {
            let Command::New(args) =
                parsed(&["synra-plugin", "new", "@scope/plugin", "--template", word]).command
            else {
                panic!("expected new");
            };
            assert_eq!(args.template, kind, "{word}");
        }
    }

    #[test]
    fn an_unknown_template_is_refused() {
        // A typo that fell back to a default would scaffold the wrong shape, and the author would find out at `verify`
        // — or at install.
        assert!(parse(&["synra-plugin", "new", "@scope/p", "--template", "server"]).is_err());
    }

    #[test]
    fn the_title_defaults_to_the_name_part_of_the_id() {
        // An author who typed `@scope/my-plugin` has already said what it is called, and being asked again is friction
        // at the moment they are least invested.
        let Command::New(args) = parsed(&["synra-plugin", "new", "@scope/my-plugin"]).command else {
            panic!("expected new");
        };
        assert_eq!(args.title(), "my-plugin");

        let Command::New(args) =
            parsed(&["synra-plugin", "new", "@scope/my-plugin", "--title", "My Plugin"]).command
        else {
            panic!("expected new");
        };
        assert_eq!(args.title(), "My Plugin");
    }

    #[test]
    fn a_title_is_derived_even_from_an_id_with_no_scope() {
        // The id validator refuses this, and `title()` must not panic on the way to that refusal.
        let Command::New(args) = parsed(&["synra-plugin", "new", "plugin"]).command else {
            panic!("expected new");
        };
        assert_eq!(args.title(), "plugin");
    }

    #[test]
    fn new_can_be_pointed_at_a_directory_and_a_dry_run() {
        let Command::New(args) =
            parsed(&["synra-plugin", "new", "@scope/p", "--dir", "/tmp/p", "--dry-run"]).command
        else {
            panic!("expected new");
        };
        assert_eq!(args.dir, Some(PathBuf::from("/tmp/p")));
        assert!(args.dry_run);
    }

    // ── verify ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_defaults_to_the_current_directory_and_prose() {
        let Command::Verify(args) = parsed(&["synra-plugin", "verify"]).command else {
            panic!("expected verify");
        };
        assert_eq!(args.dir, PathBuf::from("."));
        assert!(!args.json);
        assert!(!args.brief);
    }

    #[test]
    fn verify_can_be_pointed_and_asked_for_json() {
        let Command::Verify(args) =
            parsed(&["synra-plugin", "verify", "--dir", "/tmp/p", "--json"]).command
        else {
            panic!("expected verify");
        };
        assert_eq!(args.dir, PathBuf::from("/tmp/p"));
        assert!(args.json);
    }
}