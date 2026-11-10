use super::*;

#[test]
fn the_store_is_reachable_through_one_closure() {
    // The reason the closure exists: `rusqlite`'s connection is `!Sync`, and a reference that outlived the call would
    // be a connection used from two threads — which is a race the compiler cannot catch through a `&`.
    let kernel = kernel();
    let counted = kernel.with_store(|store| store.counts().expect("counts"));
    assert!(!counted.is_empty(), "the migrated schema has tables");
}

#[test]
fn a_device_that_paired_is_in_the_snapshot_and_an_unknown_one_is_not() {
    // The lookup an interface makes when it is told about a device it has.
    let path = temp_path("paired");
    let _ = std::fs::remove_file(&path);
    let kernel = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device = DeviceId::new();
    kernel.with_store(|store| {
        store
            .pair_device(&synra_store::sqlite::Paired {
                device_id: device.to_string(),
                display_name: "Laptop".to_owned(),
                platform: "windows".to_owned(),
                features: "[]".to_owned(),
                address: Some("10.0.0.4:51000".to_owned()),
                paired_at_ms: 1_700,
            })
            .expect("pairs");
    });

    let snapshot = kernel.snapshot().expect("a snapshot");
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.sendable().len(), 1, "a device that is not blocked may be sent to");
    let found = snapshot.device(device).expect("the device that just paired");
    assert_eq!(found.display_name, "Laptop");
    assert_eq!(found.address.as_deref(), Some("10.0.0.4:51000"));
    assert!(snapshot.device(DeviceId::new()).is_none(), "an unknown id finds nothing");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_identity_is_read_from_the_row_it_was_written_to() {
    // The store is the single source: what a peer sees after a restart is the row, not a value held in memory.
    let path = temp_path("roundtrip");
    let _ = std::fs::remove_file(&path);
    let first = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device_id = first.identity().device_id;
    let name = first.identity().display_name.clone();
    drop(first);

    let second = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    assert_eq!(second.identity().device_id, device_id);
    assert_eq!(second.identity().display_name, name);
    assert_eq!(second.identity().platform, std::env::consts::OS);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_kernel_reads_the_clock_at_one_moment() {
    // `created_at_ms` is the reference every later timestamp is compared against, so it is read once rather than asked
    // for again — a value that changed between two reads would make an uptime negative.
    let kernel = kernel();
    assert!(kernel.created_at_ms() > 0);
    assert!(Kernel::now_ms() >= kernel.created_at_ms());
}

#[test]
fn the_debug_form_names_the_device_and_the_role() {
    // What a bug report quotes, and a device id is what tells two installations apart.
    let kernel = kernel();
    let text = format!("{kernel:?}");
    assert!(text.contains("Kernel"), "{text}");
    // The role prints as the *value*, because a bug report is read by whoever wrote the code — and `as_str` is what a
    // log line uses.
    assert!(text.contains("Daemon"), "{text}");
    assert!(text.contains(&kernel.identity().device_id.to_string()), "{text}");
}

#[test]
fn a_kernel_with_no_crash_log_reads_a_clean_verdict() {
    // A first run, or a test: there is nothing to read, and the answer is "start normally" rather than a guess about a
    // crash that did not happen.
    let kernel = kernel();
    assert_eq!(kernel.startup_verdict(), StartupVerdict::Clean);
    assert!(!kernel.startup_verdict().needs_attention());
    assert!(kernel.startup_verdict().allows_plugins());
}

#[test]
fn a_directory_with_no_reports_is_a_clean_verdict_and_a_plugin_that_acted_is_in_the_audit() {
    // ★ Why the audit ring is on the kernel rather than on a plugin host: the ring outlives any one plugin, so a plugin
    // that was removed still has the actions it took.
    let path = temp_path("observe");
    let crashes = path.join("crashes");
    let config = KernelConfig { crash_log: Some(crashes), ..KernelConfig::headless() };
    let kernel = Kernel::open(&path, &config).expect("a kernel");
    assert_eq!(kernel.startup_verdict(), StartupVerdict::Clean);

    let plugin = synra_protocol::ids::PluginId::parse("@acme/chat").expect("a plugin id");
    let capability = synra_capability::Capability::parse("storage:local:write").expect("a capability");
    kernel.record_action(synra_observe::audit::AuditEntry::new(
        1_700,
        plugin.clone(),
        capability,
        synra_observe::audit::AuditOutcome::Allowed,
        Some(3),
    ));
    assert_eq!(kernel.audit().len(), 1);
    assert_eq!(kernel.audit_for(&plugin).len(), 1);
    let other = synra_protocol::ids::PluginId::parse("@acme/other").expect("a plugin id");
    assert!(kernel.audit_for(&other).is_empty(), "the ring is per plugin");
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        KernelError::Store { detail: "the disk is full".to_owned() },
        KernelError::AlreadyStarted,
        KernelError::ShutDown,
    ];
    for error in &errors {
        let sentence = error.to_string();
        assert!(sentence.len() > 10, "{error:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
    assert!(errors[0].to_string().contains("disk"));
}
