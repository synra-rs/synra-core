use std::path::{Path, PathBuf};

/// Every `.rs` file under a directory, skipping build output and VCS metadata.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            found.extend(rust_files(&path));
        }
        else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    found
}

/// 3. A `main.rs` reads flags and calls the library.
///
/// The limit is a line count rather than a judgement because a judgement is what the rule is trying to replace: a shell
/// that has grown past this is a shell that has grown logic.
pub(crate) fn guard_bins_are_thin(root: &Path) -> Vec<String> {
    const LIMIT: usize = 60;
    ["apps/synra-cli", "apps/synra-daemon", "tools/synra-plugin-cli"]
        .iter()
        .filter_map(|crate_dir| {
            let main = root.join(crate_dir).join("src/main.rs");
            let text = std::fs::read_to_string(&main).ok()?;
            let count = text.lines().count();
            (count > LIMIT).then(|| format!("{crate_dir}/src/main.rs is {count} lines (limit {LIMIT})"))
        })
        .collect()
}

/// 4. `directories` decides where a platform keeps things, and there is exactly one place that may ask it.
pub(crate) fn guard_directories_is_contained(root: &Path) -> Vec<String> {
    let allowed = Path::new("crates/synra-store/src/paths.rs");
    rust_files(&root.join("crates"))
        .into_iter()
        .filter(|path| path.strip_prefix(root).is_ok_and(|relative| relative != allowed))
        .filter(|path| {
            std::fs::read_to_string(path).is_ok_and(|text| text.contains("directories::"))
        })
        .map(|path| {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            format!("{} uses `directories::`", relative.display())
        })
        .collect()
}

/// 6. A path that deletes a whole directory must be the sandbox's own.
///
/// """ + S + """ Why this one is new, and what it is for.
///
/// `11 §D2` says the kernel must never silently delete a user's data, and the document's evidence for it was a
/// hand-counted number plus the phrase *"all of them are in test code"* — which is not something anybody can check without
/// first deciding what test code is. Counting it properly found **71** call sites rather than 42, and exactly two in
/// production: `sandbox.rs`, removing the sandbox's own cache and root.
///
/// So the rule is written down here with the allow-list it needs. A call site is test code when the file's name says so or
/// the path is a `tests` directory, or when it sits **below** the file's first `#[cfg(test)]` — which is where a Rust test
/// module goes. Everything else is production, and production may only delete a directory in the one place whose whole job
/// is to own one.
pub(crate) fn guard_directory_deletion_is_contained(root: &Path) -> Vec<String> {
    /// The only production file allowed to remove a directory tree, and why: a sandbox owns directories to delete them.
    const ALLOWED: &[&str] = &["crates/synra-store/src/sandbox.rs", "crates/synra-store/src/plugin_files.rs"];

    let mut offenders = Vec::new();
    for base in ["crates", "apps", "tools"] {
        for path in rust_files(&root.join(base)) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let relative = relative.to_string_lossy().replace('\\', "/");
            if is_test_file(&relative) {
                continue;
            }
            if ALLOWED.contains(&relative.as_str()) {
                continue;
            }
            // ★ And a checker cannot check itself: this file contains the name it looks for, in the code that does the
            // looking and in the paragraph explaining it. Counting those as call sites makes the ruler part of what it
            // measures, which is the same mistake as a fixture named after the thing a document makes a claim about.
            //
            // Only this file, and not the other tools: they mention nothing, and `tools/synra-plugin-cli` is a real program
            // that is worth checking.
            if relative.ends_with("tools/guards/src/policy/rust_source.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !text.contains("remove_dir_all") {
                continue;
            }
            for (index, line) in production_lines(&text).enumerate() {
                // ★ A mention is not a use, in the scan too and not only in the boundary above.
                //
                // A module that explains why it does **not** call this has to name it, and the first file to need that
                // was found by this guard reporting its own documentation — a comment is not a call site, and a rule
                // that cannot tell them apart makes writing the reason down a lint error.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains("remove_dir_all") {
                    offenders.push(format!("{relative}:{} removes a directory tree", index + 1));
                }
            }
        }
    }
    offenders
}

/// 7. A command that dials while holding the host's lock makes every other command wait for a network.
///
/// # ★ The rule this checks, and why it can be checked at all
///
/// `Host::dial` and `Host::send` are each **two** things in one call — the network, and the bookkeeping that needs
/// `&mut self`. A caller that already holds the host's lock therefore holds it across the network. That was true in four
/// command paths until rounds 118 and 119 split both, and the halves — `synra_core::dial_peer`, `Host::adopt`,
/// `Host::may_send`, `Host::count_sent` — exist so that it need not be true again.
///
/// The compositions stay, because a caller that holds no lock should be able to dial in one line. This guard is what keeps
/// them out of the daemon's production paths: inside `apps/synra-daemon`, a `.dial(` or a `host.send(` in code that is not
/// test code is a call that would reacquire the lock across a network operation.
pub(crate) fn guard_daemon_dials_without_the_lock(root: &Path) -> Vec<String> {
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("apps/synra-daemon/src")) {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        if is_test_file(&relative) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in production_lines(&text).enumerate() {
            if line.contains(".dial(") || line.contains("host.send(") {
                offenders.push(format!(
                    "{relative}:{} holds the host lock across a network operation",
                    index + 1
                ));
            }
        }
    }
    offenders
}

/// Whether the file name or its parent directory marks it as test code.
fn is_test_file(relative: &str) -> bool {
    relative.rsplit('/').next().is_some_and(|name| name.contains("test"))
        || relative.split('/').any(|part| part == "tests")
}

/// Stops at the inline test boundary. A line comment cannot start with the attribute.
fn production_lines(source: &str) -> impl Iterator<Item = &str> {
    source.lines().take_while(|line| !line.trim_start().starts_with("#[cfg(test)]"))
}
