use std::time::Duration;
use super::super::{path_in, tail};
use super::scratch;

#[test]
fn the_tail_reaches_back_into_the_rotated_files() {
    // ★ Rotation renames the file, so a reader that only opened the current one answered "the last three lines" with
    // the one line written since the rename — at exactly the moment a user is reading the log.
    let directory = scratch("tail-rotated");
    std::fs::write(directory.join("synra.log.2"), "oldest one\noldest two\n").expect("a rotated log");
    std::fs::write(directory.join("synra.log.1"), "older one\nolder two\nolder three\n")
        .expect("a rotated log");
    std::fs::write(directory.join("synra.log"), "newest one\n").expect("the active log");

    let three = tail(&directory, 3, false, None);
    assert_eq!(three.lines, vec!["older two", "older three", "newest one"]);
    // The reader read the current file and `.1` — it stopped once it had enough, so `.2` was not opened, and the count
    // says "four matched" rather than pretending it saw the whole history.
    assert_eq!(three.matched, 4);

    let five = tail(&directory, 5, false, None);
    assert_eq!(
        five.lines,
        vec!["oldest two", "older one", "older two", "older three", "newest one"]
    );
    assert_eq!(five.matched, 6, "the oldest file was read for the last two lines");
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn the_tail_filters_the_rotated_files_with_the_same_rule() {
    let directory = scratch("tail-rotated-filter");
    std::fs::write(
        directory.join("synra.log.1"),
        "visible one\nDEBUG hidden\nvisible two\n",
    )
    .expect("a rotated log");
    std::fs::write(directory.join("synra.log"), "newest\n").expect("the active log");

    let quiet = tail(&directory, 2, false, None);
    assert_eq!(quiet.lines, vec!["visible two", "newest"]);
    assert_eq!(quiet.matched, 3, "the hidden line is not counted as matched");

    let verbose = tail(&directory, 4, true, None);
    assert_eq!(
        verbose.lines,
        vec!["visible one", "DEBUG hidden", "visible two", "newest"]
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn the_active_file_wins_over_a_rotated_one_even_when_its_clock_is_older() {
    // ★ The two are written in the same clock tick at a rotation, and on a tie the reader must not pick `.1`: the file
    // with the plain name is the one being written, because rotation renames the old one away.
    let directory = scratch("tail-active");
    std::fs::write(path_in(&directory), "current\n").expect("the active log");
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(directory.join("synra.log.1"), "rotated\n").expect("a rotated log");

    let read = tail(&directory, 12, false, None);
    assert_eq!(read.lines, vec!["rotated", "current"]);
    assert_eq!(read.source.as_deref(), Some(path_in(&directory).as_path()));
    let _ = std::fs::remove_dir_all(&directory);
}
