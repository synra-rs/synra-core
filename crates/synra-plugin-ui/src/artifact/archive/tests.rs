use super::*;

fn zip(entries: &[(&str, &[u8])], compressed: bool) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let method = if compressed {
        zip::CompressionMethod::Deflated
    } else {
        zip::CompressionMethod::Stored
    };
    for (name, body) in entries {
        writer
            .start_file(
                *name,
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(body).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn actual_zip_bytes_produce_a_valid_ui_index() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    std::fs::write(
        &path,
        zip(
            &[("index.html", b"page"), ("assets/app.js", b"code")],
            false,
        ),
    )
    .unwrap();
    let info = inspect_ui(&path, "index.html", ArchiveLimits::artifact()).unwrap();
    assert_eq!(info.len(), 2);
    assert_eq!(info.total_bytes(), 8);
    assert!(matches!(
        inspect_ui(&path, "missing.html", ArchiveLimits::artifact()),
        Err(UnpackError::Artifact(ArtifactError::MissingEntry { .. }))
    ));
}

#[test]
fn changing_the_input_file_cannot_change_the_validated_archive_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    std::fs::write(&path, zip(&[("index.html", b"original")], false)).unwrap();
    let mut archive = Archive::open(
        &path,
        ArchiveLimits::artifact(),
        crate::artifact::MAX_ARCHIVE_BYTES,
    )
    .unwrap();
    std::fs::write(&path, zip(&[("index.html", b"replaced")], false)).unwrap();
    let mut bytes = Vec::new();
    archive.copy(0, &mut bytes).unwrap();
    assert_eq!(bytes, b"original");
}

#[test]
fn unsafe_metadata_is_refused_before_destination_creation() {
    for name in [
        "../escape",
        "assets/../../escape",
        "C:/escape",
        "bad\\escape",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ui.zip");
        std::fs::write(&path, zip(&[("index.html", b"ok"), (name, b"no")], false)).unwrap();
        let output = root.path().join("output");
        assert!(crate::artifact::unpack(&path, &output, ArchiveLimits::artifact()).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn real_compression_bombs_are_rejected_by_inspection_and_extraction() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    std::fs::write(&path, zip(&[("index.html", &vec![0; 32_768])], true)).unwrap();
    for error in [
        inspect_ui(&path, "index.html", ArchiveLimits::artifact()).unwrap_err(),
        crate::artifact::unpack(
            &path,
            &root.path().join("output"),
            ArchiveLimits::artifact(),
        )
        .unwrap_err(),
    ] {
        assert!(
            matches!(
                error,
                UnpackError::Artifact(ArtifactError::CompressionBomb { .. })
            ),
            "{error}"
        );
    }
    assert!(!root.path().join("output").exists());
}

#[test]
fn corrupt_data_removes_partial_files_and_new_directories() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    let mut bytes = zip(
        &[
            ("assets/first.txt", b"first"),
            ("assets/second.txt", b"corrupt-me"),
        ],
        false,
    );
    let at = bytes
        .windows(10)
        .position(|part| part == b"corrupt-me")
        .unwrap();
    bytes[at] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(inspect_ui(&path, "assets/first.txt", ArchiveLimits::artifact()).is_err());
    let output = root.path().join("output");
    assert!(crate::artifact::unpack(&path, &output, ArchiveLimits::artifact()).is_err());
    assert!(!output.exists());
}

#[test]
fn extraction_never_overwrites_or_deletes_existing_destination_files() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    std::fs::write(&path, zip(&[("index.html", b"new")], false)).unwrap();
    let output = root.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("index.html"), b"original").unwrap();
    assert!(crate::artifact::unpack(&path, &output, ArchiveLimits::artifact()).is_err());
    assert_eq!(
        std::fs::read(output.join("index.html")).unwrap(),
        b"original"
    );
}

#[test]
fn symbolic_link_entries_are_refused_before_any_writes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .add_symlink(
            "escape",
            "../outside",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    let output = root.path().join("output");
    assert!(matches!(
        crate::artifact::unpack(&path, &output, ArchiveLimits::artifact()),
        Err(UnpackError::Artifact(ArtifactError::ForbiddenEntry { .. }))
    ));
    assert!(!output.exists());
}

#[test]
fn duplicate_names_cannot_be_hidden_by_the_zip_readers_name_index() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ui.zip");
    let mut bytes = zip(&[("a.html", b"first"), ("b.html", b"second")], false);
    for at in 0..bytes.len().saturating_sub(5) {
        if bytes.get(at..at + 6) == Some(b"b.html") {
            bytes[at] = b'a';
        }
    }
    std::fs::write(&path, bytes).unwrap();
    let error = inspect_ui(&path, "a.html", ArchiveLimits::artifact()).unwrap_err();
    assert!(error.to_string().contains("duplicate"), "{error}");
    let output = root.path().join("output");
    assert!(crate::artifact::unpack(&path, &output, ArchiveLimits::artifact()).is_err());
    assert!(!output.exists());
}

#[test]
fn declared_entry_count_is_bounded_before_allocating_the_name_index() {
    let mut bytes = zip(&[("index.html", b"page")], false);
    let footer = bytes.len() - 22;
    for at in [footer + 8, footer + 10] {
        bytes[at..at + 2].copy_from_slice(&5000u16.to_le_bytes());
    }
    assert!(matches!(
        inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()),
        Err(UnpackError::Artifact(ArtifactError::TooManyFiles { .. }))
    ));
}

#[test]
fn zip64_directory_metadata_uses_the_same_content_rules() {
    let mut bytes = zip(&[("index.html", b"page")], false);
    let footer_at = bytes.len() - 22;
    let mut footer = bytes.split_off(footer_at);
    let size = u32::from_le_bytes(footer[12..16].try_into().unwrap());
    let offset = u32::from_le_bytes(footer[16..20].try_into().unwrap());
    bytes.extend_from_slice(b"PK\x06\x06");
    bytes.extend_from_slice(&44u64.to_le_bytes());
    bytes.extend_from_slice(&45u16.to_le_bytes());
    bytes.extend_from_slice(&45u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    for value in [1, 1, u64::from(size), u64::from(offset)] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(b"PK\x06\x07");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&u64::try_from(footer_at).unwrap().to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    footer[8..12].fill(0xff);
    footer[12..20].fill(0xff);
    bytes.extend_from_slice(&footer);
    let info = inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()).unwrap();
    assert_eq!(info.total_bytes(), 4);
    // Some writers emit ZIP64 even when the legacy fields fit. It must still
    // use the bounded extended count, rather than bypassing preflight.
    let footer_at = bytes.len() - 22;
    bytes[footer_at + 8..footer_at + 10].copy_from_slice(&1u16.to_le_bytes());
    bytes[footer_at + 10..footer_at + 12].copy_from_slice(&1u16.to_le_bytes());
    bytes[footer_at + 12..footer_at + 16].copy_from_slice(&size.to_le_bytes());
    bytes[footer_at + 16..footer_at + 20].copy_from_slice(&offset.to_le_bytes());
    assert!(inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()).is_ok());
    let extended_at = footer_at - 20 - 56;
    bytes[extended_at + 24..extended_at + 32].copy_from_slice(&5000u64.to_le_bytes());
    bytes[extended_at + 32..extended_at + 40].copy_from_slice(&5000u64.to_le_bytes());
    assert!(matches!(
        inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()),
        Err(UnpackError::Artifact(ArtifactError::TooManyFiles { .. }))
    ));
}

#[test]
fn windows_aliases_and_case_collisions_are_refused_before_extraction() {
    for name in [
        "index.html:stream",
        "assets/CON.txt",
        "assets/a. ",
        "assets/LPT1",
        "assets/COM¹.txt",
    ] {
        let bytes = zip(&[("index.html", b"page"), (name, b"bad")], false);
        assert!(
            inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()).is_err(),
            "{name}"
        );
    }
    let bytes = zip(&[("index.html", b"page"), ("INDEX.HTML", b"other")], false);
    assert!(matches!(
        inspect_ui_bytes(&bytes, "index.html", ArchiveLimits::artifact()),
        Err(UnpackError::Artifact(ArtifactError::DuplicatePath { .. }))
    ));
    for path in [
        "Manifest.JSON",
        "SOURCE.json",
        "UI/plugin.wasm",
        "signature.json",
        ".synra-build.json",
    ] {
        assert!(
            crate::artifact::check_package_artifact_path(path).is_err(),
            "{path}"
        );
    }
    assert!(crate::artifact::check_package_artifact_path("artifacts/plugin.wasm").is_ok());
    let bytes = zip(
        &[("assets", b"file"), ("assets/index.html", b"page")],
        false,
    );
    assert!(inspect_ui_bytes(&bytes, "assets/index.html", ArchiveLimits::artifact()).is_err());
}
