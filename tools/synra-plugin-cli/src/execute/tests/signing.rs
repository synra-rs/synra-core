use crate::args::SignArgs;
use crate::run::sign_plugin;
use super::super::execute;
use super::Cleanup;

#[test]
fn a_signature_is_written_beside_the_public_key() {
    // So `--verify` has the one thing it needs without the author copying a key between files.
    let dir = Cleanup::new("signature");
    dir.plugin();
    dir.write("plugin.wasm", b"the module");
    let key_path = dir.path().join("key.txt");
    std::fs::write(
        &key_path,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .expect("writes");

    let outcome = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: Some(key_path),
        generate_key: false,
        verify: None,
    })
    .expect("signs");

    let executed = execute(&outcome, false);
    assert_eq!(executed.code, 0, "{executed:?}");
    assert!(
        dir.path()
            .join(synra_plugin_api::publisher::SIGNATURE_FILE)
            .exists(),
        "the document the host reads is what a package carries"
    );
    assert!(dir.path().join("public-key.txt").exists());
    assert!(
        executed.lines[0].contains(synra_plugin_api::publisher::SIGNATURE_FILE),
        "{:?}",
        executed.lines
    );
}

#[test]
fn a_signature_verifies_against_the_plugin_it_signed() {
    // The end-to-end property, through the files the command writes rather than through the library's own
    // functions: sign, then check, then change a byte and check again.
    let dir = Cleanup::new("sign-verify");
    dir.plugin();
    dir.write("plugin.wasm", b"the module");
    let key_path = dir.path().join("key.txt");
    std::fs::write(
        &key_path,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .expect("writes");

    let signed = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: Some(key_path),
        generate_key: false,
        verify: None,
    })
    .expect("signs");
    assert_eq!(execute(&signed, false).code, 0);

    let check = |dir: &Cleanup| {
        sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: None,
            generate_key: false,
            verify: Some(dir.path().join(synra_plugin_api::publisher::SIGNATURE_FILE)),
        })
        .expect("checks")
    };

    let good = check(&dir);
    assert_eq!(good.exit_code(), 0, "{:?}", good.lines());
    assert!(
        good.lines()[0].contains("is signed by"),
        "{:?}",
        good.lines()
    );

    // One byte different, and the signature stops meaning anything.
    dir.write("plugin.wasm", b"the modul3");
    let bad = check(&dir);
    assert_eq!(bad.exit_code(), 1);
    assert!(bad.is_failure());
}

#[test]
fn generating_a_key_prints_both_halves() {
    // ★ Printing the secret is the point: a tool that hid it would be one whose keys the author cannot back up, and
    // a publisher who loses theirs cannot ship an update to a plugin users already trust.
    let dir = Cleanup::new("generate");
    let outcome = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: None,
        generate_key: true,
        verify: None,
    })
    .expect("generates");

    let lines = outcome.lines().join("\n");
    assert!(lines.contains("secret  "), "{lines}");
    assert!(lines.contains("public  "), "{lines}");
    // The two are different, which is the property a `public_hex` returning the secret would break.
    let secret = lines
        .lines()
        .find_map(|line| line.strip_prefix("secret  "))
        .expect("a secret");
    let public = lines
        .lines()
        .find_map(|line| line.strip_prefix("public  "))
        .expect("a public key");
    assert_ne!(secret, public);
    assert_eq!(secret.len(), 64);
    assert_eq!(public.len(), 64);
}

#[test]
fn signing_without_a_key_says_what_to_pass() {
    // A user who typed `sign` and nothing else needs the flag's name, not a usage line.
    let dir = Cleanup::new("no-key");
    dir.plugin();
    dir.write("plugin.wasm", b"x");
    let error = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: None,
        generate_key: false,
        verify: None,
    })
    .expect_err("refused");
    assert!(error.contains("--key"), "{error}");
    assert!(error.contains("--generate-key"), "{error}");
}

#[test]
fn signing_a_plugin_whose_artifact_is_missing_says_so() {
    let dir = Cleanup::new("no-artifact");
    dir.plugin();
    let error = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: None,
        generate_key: true,
        verify: None,
    });
    // Key generation does not read the artifact, so it succeeds — and that is the honest behaviour: an author
    // makes their key once, before there is anything to sign.
    assert!(error.is_ok());

    // With a key that exists, so the refusal is about the artifact rather than about the key — the two are
    // different problems and the message has to be about the one that happened.
    let key_path = dir.path().join("key.txt");
    std::fs::write(
        &key_path,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .expect("writes");
    let error = sign_plugin(&SignArgs {
        dir: dir.path().to_path_buf(),
        key: Some(key_path),
        generate_key: false,
        verify: None,
    })
    .expect_err("refused");
    assert!(error.contains("plugin.wasm"), "{error}");
    assert!(error.contains("nothing to sign"), "{error}");
}
