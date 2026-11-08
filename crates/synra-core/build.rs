//! Captures source control metadata for `synra-core` at compile time.

use std::process::Command;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn git(cwd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let git_root = git(&manifest_dir, &["rev-parse", "--show-toplevel"])
        .unwrap_or_else(|| manifest_dir.clone());
    let hash = git(&git_root, &["rev-parse", "HEAD"]).unwrap_or_default();
    let short_hash = hash.chars().take(7).collect::<String>();
    let branch = git(&git_root, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_default();
    let commit_time = git(&git_root, &["log", "-1", "--format=%cI"]).unwrap_or_default();
    let dirty = git(
        &git_root,
        &["status", "--porcelain", "--untracked-files=no"],
    )
    .is_some();
    let build_time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());

    println!("cargo:rustc-env=SYNRA_CORE_GIT_HASH={hash}");
    println!("cargo:rustc-env=SYNRA_CORE_GIT_SHORT_HASH={short_hash}");
    println!("cargo:rustc-env=SYNRA_CORE_GIT_BRANCH={branch}");
    println!("cargo:rustc-env=SYNRA_CORE_COMMIT_TIME={commit_time}");
    println!("cargo:rustc-env=SYNRA_CORE_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=SYNRA_CORE_GIT_DIRTY={dirty}");
    println!("cargo:rerun-if-changed={git_root}/HEAD");
    println!("cargo:rerun-if-changed={git_root}/.git/HEAD");
}
