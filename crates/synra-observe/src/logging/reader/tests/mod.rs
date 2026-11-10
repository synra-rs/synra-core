use std::io::Write as _;
use std::path::{Path, PathBuf};

mod follow;
mod tail;

fn scratch(label: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("synra-follow-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a directory");
    directory
}

fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("the log");
    file.write_all(text.as_bytes()).expect("a line");
    file.flush().expect("flushed");
}
