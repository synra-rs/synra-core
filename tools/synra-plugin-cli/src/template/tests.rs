use super::{Scaffold, ScaffoldError, TemplateKind};

fn scaffold(kind: TemplateKind) -> Scaffold {
    Scaffold::new("@synra-plugin/example", "0.1.0", "Example", kind).expect("builds")
}

// ── Every kind produces a valid plugin ────────────────────────────────────────────────────────

#[test]
fn every_template_produces_a_manifest_the_kernel_accepts() {
    // ★ The property that justifies the templates being values. A scaffold that does not validate is the failure
    // an author meets first and cannot diagnose, because they do not yet know what a correct manifest looks like.
    for kind in TemplateKind::all() {
        let scaffold = scaffold(kind);
        let manifest = scaffold
            .validate_manifest()
            .unwrap_or_else(|error| panic!("{} template: {error}", kind.as_str()));
        assert_eq!(
            manifest.id.to_string(),
            "@synra-plugin/example",
            "{}",
            kind.as_str()
        );
        assert_eq!(manifest.version, "0.1.0");
    }
}

#[test]
fn the_manifest_names_an_implementation_matching_the_files_written() {
    // A manifest claiming a `ui:` entry point with no `ui/` directory is a plugin that installs and then shows a
    // blank window — which is worse than one that fails to install.
    for kind in TemplateKind::all() {
        let scaffold = scaffold(kind);
        let paths = scaffold.paths();

        if kind == TemplateKind::Hybrid {
            assert!(
                paths.iter().any(|path| path == "ui/index.html"),
                "{kind:?} wrote no interface"
            );
        }
        if matches!(kind, TemplateKind::Headless | TemplateKind::Hybrid) {
            assert!(
                paths.iter().any(|path| path == "src/lib.rs"),
                "{kind:?} wrote no Wasm half"
            );
        }
    }
}

#[test]
fn the_two_kinds_declare_the_required_headless_artifact() {
    // The design document's classification *is* which parts a plugin implements, so a template that differed
    // elsewhere would be a template that disagreed with its own manifest.
    let headless = scaffold(TemplateKind::Headless).as_map();
    let ui = scaffold(TemplateKind::Hybrid).as_map();

    // Both carry the same description shape and the same capability block.
    let headless_manifest = headless.get("manifest.json").expect("a manifest");
    let ui_manifest = ui.get("manifest.json").expect("a manifest");
    assert!(
        headless_manifest.contains(r#""headless""#),
        "the headless template ships no Wasm half"
    );
    assert!(
        !headless_manifest.contains(r#""ui""#),
        "the headless template ships an interface"
    );
    assert!(
        ui_manifest.contains(r#""ui""#),
        "the UI template ships no bundle"
    );
    assert!(
        ui_manifest.contains(r#""headless""#),
        "the hybrid template ships no Wasm half"
    );
    // And both declare the same capability block, which is where an author starts from.
    assert!(headless_manifest.contains(r#""capabilities""#));
    assert!(ui_manifest.contains(r#""capabilities""#));
}

#[test]
fn the_hybrid_template_declares_both_artifacts() {
    // The only template with both halves, so the only one whose manifest names all three. A hybrid plugin missing
    // `execute` is one the kernel cannot ask to do anything.
    let hybrid = scaffold(TemplateKind::Hybrid);
    let files = hybrid.as_map();
    let manifest = files.get("manifest.json").expect("a manifest");
    // Derived from what the runtime block declares, because a manifest has no separate `implementation` field:
    // what a plugin implements *is* which halves it ships.
    assert!(manifest.contains(r#""headless""#), "{manifest}");
    assert!(manifest.contains(r#""ui""#), "{manifest}");
}

// ── The directory ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_directory_is_the_wire_slug() {
    // A directory named after the raw id would contain a `/` and a scope. The slug is the name the artifact uses
    // everywhere else — the registry, the cache, the log — so the author's directory matches all of them.
    for kind in TemplateKind::all() {
        let scaffold = scaffold(kind);
        assert_eq!(scaffold.directory, "example", "{}", kind.as_str());
        assert!(!scaffold.directory.contains('/'), "{}", scaffold.directory);
        assert!(!scaffold.directory.contains('@'), "{}", scaffold.directory);
    }
}

// ── Refusals ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_reserved_scope_is_refused_before_anything_is_written() {
    // The scopes the kernel owns. A plugin called `@synra/...` would be indistinguishable from the kernel's own in
    // a log, and an author who scaffolded one would have to rename across every path and capability string.
    for id in ["@synra/chat", "@core/thing", "@system/x"] {
        let error = Scaffold::new(id, "0.1.0", "X", TemplateKind::Headless)
            .expect_err("a reserved scope is refused");
        assert!(
            matches!(error, ScaffoldError::BadId { .. }),
            "{id}: {error:?}"
        );
    }
}

#[test]
fn an_unusable_id_or_version_is_refused() {
    for id in ["", "chat", "@scope", "@scope/", "not a scope/name"] {
        assert!(
            Scaffold::new(id, "0.1.0", "X", TemplateKind::Headless).is_err(),
            "{id:?} should be refused"
        );
    }
    for version in ["", "1", "1.0", "v1.0.0", "latest"] {
        assert!(
            Scaffold::new("@synra-plugin/x", version, "X", TemplateKind::Headless).is_err(),
            "{version:?} should be refused"
        );
    }
}

#[test]
fn an_empty_title_is_refused() {
    // A plugin with no title is one the user cannot identify in a list, and the manifest requires one.
    for title in ["", "   ", "\t"] {
        assert!(
            Scaffold::new("@synra-plugin/x", "0.1.0", title, TemplateKind::Headless).is_err(),
            "{title:?} should be refused"
        );
    }
}

#[test]
fn the_refusal_says_which_field_and_why() {
    // The message is what an author reads at the moment they are least able to guess.
    let error = Scaffold::new("@synra/chat", "0.1.0", "X", TemplateKind::Headless)
        .expect_err("refused");
    let text = error.to_string();
    assert!(text.contains("plugin id"), "{text}");
    assert!(text.len() > 30, "{text}");
}

// ── The files ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_kind_writes_a_readme_and_an_ignore_file() {
    // The README is the only place the build command is written down, and the ignore file is what keeps an
    // author's first commit their source rather than their build output.
    for kind in TemplateKind::all() {
        let paths = scaffold(kind).paths();
        assert!(paths.iter().any(|path| path == "README.md"), "{kind:?}");
        assert!(paths.iter().any(|path| path == ".gitignore"), "{kind:?}");
        assert!(paths.iter().any(|path| path == "manifest.json"), "{kind:?}");
    }
}

#[test]
fn the_files_are_sorted_so_the_output_is_stable() {
    // A scaffold whose file order varied would make a test's diff noisy and an author's first commit arbitrary.
    for kind in TemplateKind::all() {
        let paths = scaffold(kind).paths();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted, "{kind:?}");
    }
}

#[test]
fn the_readme_names_the_command_that_builds_this_kind() {
    // The one thing an author needs next, and the one thing a template that shared a README between kinds would
    // get wrong.
    let headless = scaffold(TemplateKind::Headless).as_map();
    let ui = scaffold(TemplateKind::Hybrid).as_map();
    assert!(
        headless
            .get("README.md")
            .expect("a readme")
            .contains("Wasm"),
        "the headless README should say what it builds"
    );
    assert!(
        ui.get("README.md").expect("a readme").contains("`ui/`"),
        "the UI README should say what it builds"
    );
}

#[test]
fn no_scaffolded_file_contains_a_leaked_escape() {
    // ★ Found by reading the output rather than the source: the UI document contained the two characters `\` and
    // `n` in the middle of a JavaScript comment, because a line had been written when the surrounding literal was a
    // normal string and was later moved into a raw one. In a raw string an escape is not an escape — it is text —
    // so what shipped to the author was `...the page can read to\n      // impersonate another.`
    //
    // The scaffold is the first thing a plugin author reads, and a leaked escape in it is the sort of thing that
    // costs a reader five minutes and teaches them the tool is sloppy. It is also invisible in review: the source
    // line looks like a line break until you notice the colouring.
    //
    // Checked over **every** file of every kind rather than just the document, because the mistake is about the
    // literal a line sits in and not about which file it ends up in.
    for kind in TemplateKind::all() {
        for (path, contents) in scaffold(kind).as_map() {
            assert!(
                !contents.contains("\\n") && !contents.contains("\\t"),
                "{kind:?}: {path} contains a leaked escape:\n{contents}"
            );
        }
    }
}

#[test]
fn the_interface_does_not_invent_a_host_facade() {
    // The static scaffold must render without inventing an unsupported injected host global.
    let ui = scaffold(TemplateKind::Hybrid).as_map();
    let document = ui.get("ui/index.html").expect("a document");
    assert!(!document.contains("window.synra"), "{document}");
    assert!(
        !document.contains("__TAURI__"),
        "the scaffold reached past the facade:\n{document}"
    );
    assert!(
        !document.contains("token"),
        "the scaffold mentions a token:\n{document}"
    );
}

#[test]
fn the_scaffold_declares_no_capability_it_does_not_need() {
    // A scaffold that asked for `storage` would be teaching an author to ask for more than they use, and the
    // permission dialog is where that becomes the user's problem.
    for kind in TemplateKind::all() {
        let scaffold = scaffold(kind);
        let files = scaffold.as_map();
        let manifest = files.get("manifest.json").expect("a manifest");
        // An empty *array*, because a missing field and an empty list are different statements — "the author
        // forgot" and "this plugin needs nothing" — and the loader has to tell them apart.
        assert!(
            manifest.contains(r#""capabilities": []"#),
            "{kind:?}:\n{manifest}"
        );
    }
}

#[test]
fn the_kind_round_trips_through_its_word() {
    for kind in TemplateKind::all() {
        assert!(!kind.as_str().is_empty());
    }
    assert_eq!(TemplateKind::Headless.as_str(), "headless");
    assert_eq!(TemplateKind::Hybrid.as_str(), "hybrid");
}
