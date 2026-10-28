//! Explicit UI build configuration and deterministic ZIP production.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use synra_plugin_ui::artifact::{ArchiveLimits, MAX_ARCHIVE_BYTES, check_path};

use super::Step;

pub(super) fn configuration(root: &Path) -> Result<(PathBuf, Option<Step>), String> {
    let text = match std::fs::read_to_string(root.join("Cargo.toml")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.to_string()),
    };
    let document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| error.to_string())?;
    let config = document
        .get("package")
        .and_then(|item| item.get("metadata"))
        .and_then(|item| item.get("synra"))
        .and_then(|item| item.get("ui"));
    let Some(config) = config else {
        return Ok((PathBuf::from("ui"), None));
    };
    let table = config
        .as_table_like()
        .ok_or("package.metadata.synra.ui must be a table")?;
    if table
        .iter()
        .any(|(key, _)| !matches!(key, "source" | "directory" | "command"))
    {
        return Err("unknown package.metadata.synra.ui field".to_owned());
    }
    let string = |key, default: &str| -> Result<String, String> {
        table.get(key).map_or_else(
            || Ok(default.to_owned()),
            |item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("UI {key} must be a string"))
            },
        )
    };
    let source = string("source", "ui")?;
    relative(&source)?;
    if source == "dist" || source.starts_with("dist/") || source.starts_with(".synra-build") {
        return Err(
            "UI source must be separate from the package output and staging directories".to_owned(),
        );
    }
    let directory = string("directory", ".")?;
    if directory != "." {
        relative(&directory)?;
    }
    let step = if let Some(command) = table.get("command") {
        let array = command
            .as_array()
            .ok_or("UI command must be an argv array")?;
        let args: Vec<String> = array
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "UI command arguments must be strings".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let (program, args) = args
            .split_first()
            .filter(|(program, _)| !program.trim().is_empty())
            .ok_or("UI command cannot be empty")?;
        if args.len() > 128 || program.len() + args.iter().map(String::len).sum::<usize>() > 32_768
        {
            return Err("UI command exceeds its argument budget".to_owned());
        }
        Some(Step {
            program: program.clone(),
            args: args.to_vec(),
            in_dir: if directory == "." {
                PathBuf::new()
            } else {
                PathBuf::from(directory)
            },
            why: "build UI assets using the author's explicit command".to_owned(),
            component: None,
        })
    } else {
        None
    };
    Ok((PathBuf::from(source), step))
}

pub(super) fn relative(path: &str) -> Result<(), String> {
    check_path(path).map_err(|error| error.to_string())
}

pub(super) fn pack(source: &Path, destination: &Path, entry: &str) -> Result<(), String> {
    let limits = ArchiveLimits::artifact();
    let mut pending = vec![source.to_path_buf()];
    let mut files = Vec::new();
    let mut seen = 0usize;
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        seen = seen.saturating_add(1);
        if seen > limits.max_entries {
            return Err("UI source exceeds the entry budget".to_owned());
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err("UI sources cannot contain symbolic links".to_owned());
        }
        let name = path
            .strip_prefix(source)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        if !name.is_empty() {
            relative(&name)?;
            if name.split('/').count() > limits.max_path_depth {
                return Err("UI source exceeds the path depth budget".to_owned());
            }
        }
        if metadata.is_dir() {
            for child in std::fs::read_dir(&path).map_err(|error| error.to_string())? {
                if seen + pending.len() >= limits.max_entries {
                    return Err("UI source exceeds the entry budget".to_owned());
                }
                pending.push(child.map_err(|error| error.to_string())?.path());
            }
        } else if metadata.is_file() && !name.is_empty() {
            total = total.saturating_add(metadata.len());
            if total > synra_plugin_ui::MAX_ARTIFACT_BYTES
                || files.len() >= synra_plugin_ui::MAX_ARTIFACT_FILES
            {
                return Err("UI source exceeds the content budget".to_owned());
            }
            files.push((name, path, metadata.len()));
        } else {
            return Err("UI source must contain only regular files and directories".to_owned());
        }
    }
    files.sort_by(|first, second| first.0.cmp(&second.0));
    let parent = destination.parent().ok_or("UI archive has no parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let output = std::fs::File::create(destination).map_err(|error| error.to_string())?;
    let mut zip = zip::ZipWriter::new(output);
    for (name, path, size) in files {
        // The outer package compresses these bytes; stored entries avoid nested compression
        // and never make a legitimate generated asset violate the expansion-ratio budget.
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .last_modified_time(zip::DateTime::default())
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o644),
        )
        .map_err(|error| error.to_string())?;
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let copied = std::io::copy(&mut file.take(size.saturating_add(1)), &mut zip)
            .map_err(|error| error.to_string())?;
        if copied != size {
            return Err("UI source changed while packaging".to_owned());
        }
    }
    let mut output = zip.finish().map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    if output.metadata().map_err(|error| error.to_string())?.len() > MAX_ARCHIVE_BYTES {
        return Err("encoded UI archive exceeds its byte budget".to_owned());
    }
    drop(output);
    synra_plugin_ui::artifact::inspect_ui(destination, entry, limits)
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_assets_are_a_deterministic_archive_that_the_host_can_expand() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("ui");
        std::fs::create_dir_all(source.join("assets")).unwrap();
        std::fs::write(
            source.join("index.html"),
            "<script src='assets/app.js'></script>",
        )
        .unwrap();
        std::fs::write(source.join("assets/app.js"), "console.log('ready')").unwrap();
        let first = root.path().join("first.zip");
        let second = root.path().join("second.zip");
        pack(&source, &first, "index.html").unwrap();
        pack(&source, &second, "index.html").unwrap();
        assert_eq!(
            std::fs::read(&first).unwrap(),
            std::fs::read(second).unwrap()
        );
        let output = root.path().join("expanded");
        synra_plugin_ui::artifact::unpack(&first, &output, ArchiveLimits::artifact()).unwrap();
        assert_eq!(
            std::fs::read(output.join("assets/app.js")).unwrap(),
            b"console.log('ready')"
        );
    }

    #[test]
    fn ui_source_cannot_be_the_cli_output_or_escape_the_project() {
        for source in [
            "dist",
            "dist/ui",
            "../ui",
            "/tmp/ui",
            ".synra-build-previous",
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(
                root.path().join("Cargo.toml"),
                format!("[package.metadata.synra.ui]\nsource = {source:?}\n"),
            )
            .unwrap();
            assert!(configuration(root.path()).is_err(), "{source}");
        }
    }
}
