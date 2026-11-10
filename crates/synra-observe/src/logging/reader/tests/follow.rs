use std::time::Duration;
use super::super::{follow, path_in};
use super::{append, scratch};

#[test]
fn following_sends_the_tail_then_each_appended_line() {
    // ★ The tail is the starting point, not the answer: a follow that returned after its first read would be the
    // snapshot `--follow` used to pretend to be. The sink appends a line to prove the second read happens.
    let directory = scratch("tail");
    let path = path_in(&directory);
    std::fs::write(&path, "one\ntwo\nthree\n").expect("a log");

    let mut seen = Vec::new();
    let summary = follow(&directory, 1, false, None, Duration::from_millis(5), |line| {
        seen.push(line.to_owned());
        if seen.len() == 1 {
            append(&path, "four\n");
            true
        }
        else {
            false
        }
    });

    assert_eq!(seen, vec!["three", "four"]);
    assert_eq!(summary.lines, 2, "both lines were handed over");
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn following_hides_debug_lines_unless_asked() {
    // ★ One filter, two readers: the same `keep` that `tail` uses, so a follower cannot show a line `synra logs`
    // hides. `DEBUG` is a level token, not a message word — the reader's own rule.
    let directory = scratch("levels");
    let path = path_in(&directory);
    std::fs::write(&path, "ERROR one\nDEBUG two\n").expect("a log");

    let mut quiet = Vec::new();
    follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
        quiet.push(line.to_owned());
        false
    });
    assert_eq!(quiet, vec!["ERROR one"]);

    let mut verbose = Vec::new();
    follow(&directory, 10, true, None, Duration::from_millis(5), |line| {
        verbose.push(line.to_owned());
        verbose.len() < 2
    });
    assert_eq!(verbose, vec!["ERROR one", "DEBUG two"]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn following_starts_over_when_the_file_is_truncated() {
    // ★ Rotation and truncation are the same correction: a length smaller than the offset means the bytes the reader
    // was waiting past are gone. Reading on would sit at an offset the new file never reaches.
    let directory = scratch("rotation");
    let path = path_in(&directory);
    std::fs::write(&path, "before\n").expect("a log");

    let mut seen = Vec::new();
    follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
        seen.push(line.to_owned());
        if seen.len() == 1 {
            std::fs::write(&path, "after\n").expect("a truncated log");
            true
        }
        else {
            false
        }
    });

    assert_eq!(seen, vec!["before", "after"]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn lines_written_just_before_a_rotation_are_not_lost() {
    // ★ The old file's unread bytes belong to the old handle. A follower that reopened by path on every poll would
    // miss them and then read the *new* file from the old offset — two half-lines of garbage where two real lines were.
    // The new file is deliberately **longer** than the old, so a length comparison would read it as "it grew"; the
    // inode catches it on unix, and the opening bytes catch it where no file id exists (Windows).
    let directory = scratch("rotation-loss");
    let path = path_in(&directory);
    std::fs::write(&path, "one\n").expect("a log");
    let rotated = directory.join("synra.log.1");

    let mut seen = Vec::new();
    follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
        seen.push(line.to_owned());
        if seen.len() == 1 {
            append(&path, "two\n");
            std::fs::rename(&path, &rotated).expect("rotates");
            std::fs::write(&path, "three\nfour\nfive\n").expect("a new log");
        }
        seen.len() < 5
    });

    assert_eq!(seen, vec!["one", "two", "three", "four", "five"]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_rotation_to_a_shorter_file_keeps_what_the_old_one_held() {
    // The cross-platform case: the new file is shorter than what the reader has consumed, so the length fallback
    // detects it even where no file identity is available.
    let directory = scratch("rotation-short");
    let path = path_in(&directory);
    std::fs::write(&path, "one\n").expect("a log");
    let rotated = directory.join("synra.log.1");

    let mut seen = Vec::new();
    follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
        seen.push(line.to_owned());
        if seen.len() == 1 {
            append(&path, "two\n");
            std::fs::rename(&path, &rotated).expect("rotates");
            std::fs::write(&path, "x\n").expect("a new log");
        }
        seen.len() < 3
    });

    assert_eq!(seen, vec!["one", "two", "x"]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_partial_line_waits_for_its_newline() {
    // A reader can catch a writer mid-line. The fragment must not be sent as a line of its own and must not be
    // dropped: it is joined with the next append.
    let directory = scratch("partial");
    let path = path_in(&directory);
    std::fs::write(&path, "complete\nhalf").expect("a log");

    let mut seen = Vec::new();
    follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
        seen.push(line.to_owned());
        if seen.len() == 1 {
            append(&path, "-done\n");
            true
        }
        else {
            false
        }
    });

    assert_eq!(seen, vec!["complete", "half-done"]);
    let _ = std::fs::remove_dir_all(&directory);
}
