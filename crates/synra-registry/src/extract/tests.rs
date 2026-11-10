use std::io::Write as _;

use flate2::Compression;
use flate2::write::GzEncoder;

use super::{ExtractError, Limits, extract_tgz};

/// A `.tgz` holding these entries, written in memory.
fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, name, *bytes).expect("an entry");
    }
    builder.into_inner().expect("the encoder").finish().expect("a gzip tail")
}

fn scratch(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("synra-registry-{label}-{}", std::process::id()))
}

#[test]
fn an_npm_shaped_tarball_lands_without_its_prefix() {
    let archive = tgz(&[
        ("package/manifest.json", b"{}"),
        ("package/plugin.wasm", b"\0asm\x01\0\0\0"),
    ]);
    let destination = scratch("ok");
    let written = extract_tgz(&archive, &destination, Some("package"), Limits::default())
        .expect("the archive is extracted");

    assert_eq!(written.len(), 2);
    assert!(destination.join("manifest.json").is_file());
    assert!(destination.join("plugin.wasm").is_file());
    let _ = std::fs::remove_dir_all(&destination);
}

/// A `.tgz` holding this raw tar stream.
fn gzipped(raw: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(raw).expect("the raw tar");
    encoder.finish().expect("a gzip tail")
}

/// A tar stream written by hand, so a hostile name can be expressed.
///
/// ★ `tar::Builder` refuses to write an entry whose path contains `..` — a good default for producing archives, and
/// exactly why the test cannot use it to produce the archive this module has to refuse.
fn raw_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let mut header = [0u8; 512];
        let bytes = name.as_bytes();
        header[..bytes.len()].copy_from_slice(bytes);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

#[test]
fn an_entry_that_escapes_the_directory_is_refused_and_nothing_is_left() {
    // ★ The entry is after a legitimate one, so this also proves the cleanup: `a.txt` was written before the escape
    // was seen, and a refused archive must not leave it behind.
    let archive = gzipped(&raw_tar(&[("a.txt", b"kept?"), ("../escape.txt", b"outside")]));
    let destination = scratch("escape");
    let parent = destination.parent().expect("a parent").to_path_buf();

    let refused = extract_tgz(&archive, &destination, None, Limits::default()).expect_err("the entry escapes");

    assert!(matches!(refused, ExtractError::BadPath { .. }), "{refused}");
    assert!(!parent.join("escape.txt").exists(), "the entry was written outside the destination");
    assert!(!destination.join("a.txt").exists(), "the cleanup missed a written file");
    let _ = std::fs::remove_dir_all(&destination);
}

#[test]
fn a_symlink_is_refused_by_its_type() {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("manifest.json").expect("a link target");
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_data(&mut header, "package/link", std::io::empty())
        .expect("an entry");
    let archive = builder.into_inner().expect("the encoder").finish().expect("a gzip tail");
    let destination = scratch("link");

    let refused = extract_tgz(&archive, &destination, Some("package"), Limits::default())
        .expect_err("a link is not a file");

    assert!(matches!(refused, ExtractError::RefusedKind { .. }), "{refused}");
    let _ = std::fs::remove_dir_all(&destination);
}

#[test]
fn a_file_over_the_per_file_ceiling_is_refused_before_it_is_written() {
    let archive = tgz(&[("package/big.bin", b"12345")]);
    let destination = scratch("size");
    let limits = Limits { max_single_file: 4, ..Limits::default() };

    let refused = extract_tgz(&archive, &destination, Some("package"), limits).expect_err("too big");

    assert!(matches!(refused, ExtractError::TooLarge { found: 5, limit: 4, .. }), "{refused}");
    assert!(!destination.join("big.bin").exists());
    let _ = std::fs::remove_dir_all(&destination);
}

#[test]
fn a_tarball_that_does_not_use_the_prefix_is_refused_rather_than_unpacked_at_the_wrong_depth() {
    let archive = tgz(&[("manifest.json", b"{}")]);
    let destination = scratch("prefix");

    let refused = extract_tgz(&archive, &destination, Some("package"), Limits::default())
        .expect_err("no prefix");

    assert!(matches!(refused, ExtractError::BadPath { .. }), "{refused}");
    let _ = std::fs::remove_dir_all(&destination);
}

#[test]
fn gzip_corruption_is_a_named_error() {
    let mut not_gzip = Vec::new();
    not_gzip.write_all(b"not a gzip stream").expect("bytes");
    assert!(matches!(super::decompress(&not_gzip), Err(ExtractError::Gzip(_))));
}
