//! Uploading a static package with a command the author already uses.
//!
//! # Why a template rather than a bucket client
//!
//! Because every author's upload path is different — `aws s3 cp`, `rclone copy`, `gsutil`, a deploy script — and the
//! credentials for it are theirs, not this tool's. What this command owns is the two values an author keeps getting wrong:
//! which local file, and which URL the index says it lives at. Those come from the index, not from a human's memory.
//!
//! # The boundary
//!
//! The template is split on whitespace and each token is substituted; **no shell runs**. `{file}` and `{url}` become single
//! arguments even when a path contains a space, so a plugin id cannot turn into a second command. The author still decides
//! which program runs and with which flags — this is their tool, invoked with the values this tool computed.

use std::path::{Path, PathBuf};

use crate::run::Outcome;

/// One file to upload, and the URL the index says it is at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadStep {
    /// The local file.
    pub file: PathBuf,
    /// Where it belongs.
    pub url: String,
}

/// Uploads every file an index names, refusing to start when the plan is not sound.
pub fn upload_plugin(args: &crate::args::UploadArgs) -> Outcome {
    match upload(args) {
        Ok(lines) => Outcome::Reported { lines, code: 0, failure: false },
        Err(lines) => Outcome::Reported { lines, code: 1, failure: true },
    }
}

/// The plan and the run, as a list of lines.
fn upload(args: &crate::args::UploadArgs) -> Result<Vec<String>, Vec<String>> {
    let steps = plan(args).map_err(|reason| vec![reason])?;
    let mut lines = vec![format!(
        "{} file(s) for {}",
        steps.len(),
        args.base.trim_end_matches('/')
    )];

    for step in steps {
        let (program, arguments) = expand(&args.command, &step.file, &step.url)?;
        let shown = format!("{program} {}", arguments.join(" "));
        if args.dry_run {
            lines.push(format!("  would run: {shown}"));
            continue;
        }
        match std::process::Command::new(&program).args(&arguments).status() {
            Ok(status) if status.success() => {
                lines.push(format!("  uploaded {} -> {}", step.file.display(), step.url));
            }
            Ok(status) => {
                return Err(vec![
                    lines.join("\n"),
                    format!("  {shown} exited with {status}; nothing after this file was uploaded"),
                ]);
            }
            Err(error) => {
                return Err(vec![lines.join("\n"), format!("  {shown}: {error}")]);
            }
        }
    }

    // ★ Upload success is not publish success: a bucket can accept every PUT and still serve the wrong bytes. The check is
    // the one `publish --verify` already performs, so the two commands cannot disagree about what "published" means.
    // A dry run uploaded nothing, so there is nothing new to read back.
    if args.verify && !args.dry_run {
        let outcome = crate::publish::publish_plugin(&crate::args::PublishArgs {
            index: args.index.clone(),
            base: Some(args.base.clone()),
            verify: true,
        });
        let Outcome::Reported { lines: remote, failure, .. } = outcome else {
            return Err(vec!["the verification produced no report".to_owned()]);
        };
        lines.extend(remote);
        if failure {
            return Err(lines);
        }
    }

    Ok(lines)
}

/// The index, then every tarball it names, in the order the index lists them.
fn plan(args: &crate::args::UploadArgs) -> Result<Vec<UploadStep>, String> {
    let base = args.base.trim().trim_end_matches('/');
    if !(base.starts_with("https://") || base.starts_with("http://")) {
        return Err("--base must start with https:// or http://".to_owned());
    }
    let text = std::fs::read_to_string(&args.index)
        .map_err(|error| format!("{}: {error}", args.index.display()))?;
    let index = synra_registry::parse_static_index(&text)
        .map_err(|error| format!("{}: {error}", args.index.display()))?;
    let directory = args.index.parent().unwrap_or_else(|| Path::new("."));

    let mut steps = vec![UploadStep {
        file: args.index.clone(),
        url: format!("{base}/{}.json", index.document.name),
    }];
    for entry in index.document.versions.values() {
        let file = crate::publish::local_tarball(directory, Some(base), &entry.dist.tarball)?;
        let url = if entry.dist.tarball.starts_with("https://") || entry.dist.tarball.starts_with("http://") {
            entry.dist.tarball.clone()
        }
        else {
            format!("{base}/{}", entry.dist.tarball.trim_start_matches('/'))
        };
        if steps.iter().all(|step| step.file != file) {
            steps.push(UploadStep { file, url });
        }
    }
    Ok(steps)
}

/// Expands a template into a program and its arguments.
///
/// # Errors
///
/// When the template is empty, or does not mention both placeholders — a command that silently uploads every file to one
/// address is worse than one that refuses to start.
fn expand(template: &str, file: &Path, url: &str) -> Result<(String, Vec<String>), Vec<String>> {
    if !template.contains("{file}") || !template.contains("{url}") {
        return Err(vec!["--command must contain both {file} and {url}".to_owned()]);
    }
    let file = file.display().to_string();
    let mut arguments: Vec<String> = template
        .split_whitespace()
        .map(|token| token.replace("{file}", &file).replace("{url}", url))
        .collect();
    if arguments.is_empty() {
        return Err(vec!["--command is empty".to_owned()]);
    }
    let program = arguments.remove(0);
    Ok((program, arguments))
}

#[cfg(test)]
mod tests {
    use super::{expand, plan, upload_plugin};
    use std::path::Path;

    fn manifest(version: &str) -> String {
        serde_json::json!({
            "id": "@acme/hello",
            "version": version,
            "title": "Hello",
            "publisher": { "id": "acme" },
            "sdk": { "min": "1.0.0" },
            "wit": synra_plugin_host::host_world(),
            "capabilities": [{ "cap": "log:*" }],
            "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
        })
        .to_string()
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("synra-upload-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }

    /// Packs a package the way an author would, and returns the index path.
    fn packed(root: &Path, version: &str) -> std::path::PathBuf {
        std::fs::write(root.join("manifest.json"), manifest(version)).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
        let outcome = crate::pack::pack_plugin(&crate::args::PackArgs {
            dir: root.to_path_buf(),
            out: None,
            index: Some(String::new()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let _ = crate::execute::execute(&outcome, false);
        root.join("dist").join("@acme").join("hello.json")
    }

    #[test]
    fn the_plan_uploads_the_index_and_the_tarball_it_names() {
        let root = scratch("plan");
        let index = packed(&root, "1.0.0");

        let steps = plan(&crate::args::UploadArgs {
            index,
            base: "https://bucket.example/plugins".to_owned(),
            command: "aws s3 cp {file} {url}".to_owned(),
            dry_run: true,
            verify: false,
        })
        .expect("a plan");

        assert_eq!(steps.len(), 2);
        assert_eq!(steps.first().expect("the index").url, "https://bucket.example/plugins/@acme/hello.json");
        assert_eq!(
            steps.get(1).expect("the tarball").url,
            "https://bucket.example/plugins/@acme-hello-1.0.0.tgz"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_template_expands_without_a_shell() {
        let file = Path::new("/tmp/a b.tgz");
        let (program, arguments) =
            expand("aws s3 cp --acl public-read {file} {url}", file, "https://x/y.tgz").expect("a command");

        assert_eq!(program, "aws");
        // ★ The path with a space is one argument, not two: substitution happens after the split.
        assert_eq!(
            arguments,
            ["s3", "cp", "--acl", "public-read", "/tmp/a b.tgz", "https://x/y.tgz"]
        );
    }

    #[test]
    fn a_template_without_both_placeholders_is_refused() {
        let refused = expand("aws s3 cp {file} s3://bucket/", Path::new("x.tgz"), "https://x/y.tgz")
            .expect_err("no {url}");
        assert!(refused.first().expect("a line").contains("{url}"), "{refused:?}");
    }

    #[test]
    fn a_dry_run_runs_nothing_and_says_what_it_would_do() {        let root = scratch("dry");
        let index = packed(&root, "1.0.0");

        let outcome = upload_plugin(&crate::args::UploadArgs {
            index,
            base: "https://bucket.example/plugins".to_owned(),
            command: "aws s3 cp {file} {url}".to_owned(),
            dry_run: true,
            verify: false,
        });

        let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
            panic!("expected a report");
        };
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(lines.iter().filter(|line| line.contains("would run")).count(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dry_run_does_not_read_the_bucket_back() {
        // ★ `--dry-run --verify` uploaded nothing, so there is nothing to verify. The address is unreachable on purpose:
        // a dry run that still fetched would fail here.
        let root = scratch("dry-verify");
        let index = packed(&root, "1.0.0");

        let outcome = upload_plugin(&crate::args::UploadArgs {
            index,
            base: "https://127.0.0.1:1/plugins".to_owned(),
            command: "aws s3 cp {file} {url}".to_owned(),
            dry_run: true,
            verify: true,
        });

        let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
            panic!("expected a report");
        };
        assert_eq!(code, 0, "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
