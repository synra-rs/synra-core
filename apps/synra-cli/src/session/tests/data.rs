use std::path::PathBuf;

use super::super::{DATA_DIR_VAR, data_root, data_root_from};

#[test]
fn the_data_root_follows_the_environment() {
    // The daemon's answer, so `doctor` checks the installation the user actually has rather than a directory
    // nobody uses — which would report a healthy installation on a broken machine.
    //
    // The value is passed rather than set: `std::env::set_var` is `unsafe` in edition 2024 and this workspace
    // forbids `unsafe`, so the decision is a function of its input and a test supplies the input. What is not
    // covered here is the `var_os` call itself, which is one line of std in `data_root`.
    assert_eq!(
        data_root_from(Some(std::ffi::OsString::from("/custom/synra"))),
        PathBuf::from("/custom/synra")
    );
}

#[test]
fn an_empty_data_root_falls_back_rather_than_naming_the_current_directory() {
    // An unset variable and one set to nothing are the same intention everywhere else, and `PathBuf::from("")` is
    // the current directory — which would put the kernel's database wherever the user happened to be standing.
    let fallback = data_root_from(None);
    assert!(fallback.ends_with("synra"), "{fallback:?}");
    assert!(fallback.is_absolute(), "a relative data root depends on the cwd: {fallback:?}");
    assert_eq!(data_root_from(Some(std::ffi::OsString::new())), fallback);
}

#[test]
fn the_root_is_read_from_the_variable_that_is_documented() {
    // The wiring, asserted once: `data_root` reads `SYNRA_DATA_DIR`. Asserted through the constant, so a rename in
    // one place and not the other is a failure here rather than a user's environment variable being ignored.
    assert_eq!(DATA_DIR_VAR, "SYNRA_DATA_DIR");
    assert!(data_root().is_absolute());
}
