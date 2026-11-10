use super::*;

#[test]
fn a_kernel_bootstraps_with_an_identity_a_store_and_an_empty_supervisor() {
    let kernel = kernel();
    assert!(!kernel.identity().device_id.to_string().is_empty());
    assert!(!kernel.identity().display_name.is_empty());
    assert_eq!(kernel.role(), NodeRole::Daemon);
    assert!(!kernel.is_started(), "bootstrap does not start the network");
    assert!(kernel.supervisor().is_empty(), "nothing is registered until a role says what runs");
    assert_eq!(kernel.supervisor().started_at_ms(), kernel.created_at_ms());
}

#[test]
fn bootstrapping_twice_over_one_store_keeps_one_identity() {
    // ★ The failure the whole identity module is about: a device that made a new id on every start would appear to
    // every peer as a new device, and every pairing would be lost — silently, because a new device is legitimate.
    let path = temp_path("identity");
    let _ = std::fs::remove_file(&path);

    let first = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device_id = first.identity().device_id;

    let again = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    assert_eq!(again.identity().device_id, device_id, "the identity is read back, not remade");
    assert_eq!(again.identity().display_name, first.identity().display_name);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_open_constructor_migrates_a_file_that_has_never_been_opened() {
    // A first start: the file does not exist, and the kernel is expected to make it usable rather than to report that
    // its tables are missing.
    let path = temp_path("fresh");
    let _ = std::fs::remove_file(&path);
    let kernel = Kernel::open(&path, &KernelConfig::desktop()).expect("a kernel");
    assert_eq!(kernel.role(), NodeRole::Desktop);
    assert_eq!(kernel.snapshot().expect("a snapshot").devices.len(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_host_is_built_from_the_identity_that_was_loaded() {
    // ★ The ordering that matters: a host announcing itself has to know what to announce, so the identity is read or
    // created first and the host is built *from* it. A host built from a fresh identity would announce a device that
    // does not exist.
    let kernel = kernel();
    let announced = kernel.with_host(|host| host.identity().device_id);
    assert_eq!(announced, kernel.identity().device_id);
    let name = kernel.with_host(|host| host.local_peer().display_name.clone());
    assert_eq!(name, kernel.identity().display_name);
}

#[test]
fn a_role_says_whether_a_person_is_in_front_of_it() {
    // What an interface decision is made from: a prompt is right for a desktop and wrong for a daemon, where it would
    // sit unanswered while the sender waited.
    assert!(NodeRole::Desktop.has_a_user());
    assert!(NodeRole::Mobile.has_a_user());
    assert!(!NodeRole::Cli.has_a_user());
    assert!(!NodeRole::Daemon.has_a_user());
    assert_eq!(NodeRole::Daemon.as_str(), "daemon");
}

#[test]
fn the_two_configurations_name_their_own_roles_and_the_platform() {
    assert_eq!(KernelConfig::desktop().role, NodeRole::Desktop);
    assert!(KernelConfig::desktop().discovery);
    assert_eq!(KernelConfig::headless().role, NodeRole::Daemon);
    assert!(!KernelConfig::headless().discovery, "a test wants no sockets");
    assert_eq!(KernelConfig::headless().platform, std::env::consts::OS);
    assert_eq!(KernelConfig::headless().with_role(NodeRole::Cli).role, NodeRole::Cli);
}
