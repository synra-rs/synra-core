use super::*;

#[test]
fn asking_for_verbose_logs_raises_what_the_daemon_writes() {
    // ★ `--verbose` used to be a promise with nothing behind it. The subscriber was built with a fixed level and
    // `tracing` allows one subscriber per process, so no debug line could ever be written — the CLI asked for debug
    // lines, the file had none, and the command answered with the same lines as the default. Nothing failed; the flag
    // simply did nothing.
    //
    // The assertion is on the **logger's own state**, because that is what decides whether a debug line is written at
    // all. Reading the answer's `lines` could not distinguish "the flag is wired" from "the file happens to have
    // debug lines in it from some earlier run".
    let dir = TempDir::new("logs-raise-verbose");
    let runtime = runtime(dir.path());
    let verbosity = runtime
        .verbosity
        .as_ref()
        .expect("a fixture with a logger")
        .clone();

    assert_eq!(
        verbosity.effective(),
        synra_observe::logging::LogLevel::Info,
        "the configured level"
    );
    assert!(!verbosity.is_raised());

    // A plain read asks for nothing and must not change the level: a command that quietly made the log verbose would
    // fill a disk on a machine nobody is watching.
    let plain = runtime.logs_value(10, false, None).expect("an answer");
    assert_eq!(plain["raised"], false);
    assert_eq!(
        verbosity.effective(),
        synra_observe::logging::LogLevel::Info,
        "a plain read changed nothing"
    );

    let answer = runtime.logs_value(10, true, None).expect("an answer");
    assert_eq!(
        answer["raised"], true,
        "the raise has to be reported: {answer}"
    );
    assert_eq!(answer["level"], "debug");
    assert_eq!(
        verbosity.effective(),
        synra_observe::logging::LogLevel::Debug,
        "the logger itself has to change, not just the answer"
    );
    assert!(
        verbosity.remaining().is_some(),
        "and it has to lapse, or a flag left on fills the disk"
    );
}

#[test]
fn a_log_answer_carries_the_writers_counters() {
    // ★ The fields are always present, even when the fixture keeps no writer: a client reading the answer must be able to
    // tell "zero dropped" from "this build does not report drops", and an absent field cannot say the first.
    let dir = TempDir::new("logs-counters");
    let runtime = runtime(dir.path());
    let answer = runtime.logs_value(1, false, None).expect("an answer");
    assert_eq!(answer["dropped"], 0);
    assert_eq!(answer["writeErrors"], 0);
}

#[test]
fn a_trace_filter_asks_for_more_than_verbose_does() {
    // Following one identifier is narrower and more deliberate than asking for everything, so it is worth more detail.
    // Both are bounded by the same window.
    let dir = TempDir::new("logs-raise-trace");
    let runtime = runtime(dir.path());
    let verbosity = runtime
        .verbosity
        .as_ref()
        .expect("a fixture with a logger")
        .clone();

    let answer = runtime
        .logs_value(10, false, Some("abc"))
        .expect("an answer");
    assert_eq!(answer["raised"], true);
    assert_eq!(
        answer["level"], "trace",
        "a trace filter raises further than --verbose: {answer}"
    );
    assert_eq!(
        verbosity.effective(),
        synra_observe::logging::LogLevel::Trace
    );
}

#[test]
fn a_daemon_with_no_log_does_not_claim_to_have_raised_anything() {
    // ★ `None` is the state of a daemon whose log file could not be opened. It still answers the command — a host that
    // cannot write a diagnostic file is still a host — and it must not report a raise it did not perform. This is the
    // one case where the difference between "did it" and "said it did" is the whole assertion.
    let dir = TempDir::new("logs-no-logger");
    let mut runtime = runtime(dir.path());
    runtime.verbosity = None;

    let answer = runtime.logs_value(10, true, None).expect("an answer");
    assert_eq!(answer["raised"], false, "{answer}");
    assert_eq!(
        answer["level"],
        serde_json::Value::Null,
        "and it says it has no level to report: {answer}"
    );
}

// ── Logs ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_fresh_installation_has_no_log_and_that_is_not_an_error() {
    let dir = TempDir::new("logs-empty");
    let value = runtime(dir.path()).logs(10, false, None).expect("logs");
    assert_eq!(value["lines"].as_array().map(Vec::len), Some(0));
    assert!(value["source"].is_null());
}

#[test]
fn the_tail_is_the_last_lines_in_order() {
    let dir = TempDir::new("logs-tail");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(log_dir.join("kernel.log"), "one\ntwo\nthree\nfour\n").expect("a log");

    let value = runtime(dir.path()).logs(2, false, None).expect("logs");
    let lines: Vec<&str> = value["lines"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(lines, ["three", "four"]);
    assert_eq!(value["total"], 4);
}

#[test]
fn asking_for_more_lines_than_exist_gives_everything() {
    // A `saturating_sub` rather than a subtraction: a request for a thousand lines from a four-line log must not
    // underflow into an empty answer.
    let dir = TempDir::new("logs-more");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(log_dir.join("kernel.log"), "one\ntwo\n").expect("a log");

    let value = runtime(dir.path()).logs(1_000, false, None).expect("logs");
    assert_eq!(value["lines"].as_array().map(Vec::len), Some(2));
}

#[test]
fn the_log_reader_and_the_log_writer_agree_on_the_directory() {
    // ★ The failure this catches is silent, which is why it is worth a test of its own.
    //
    // Two places decide where the log lives. The writer takes it from `Paths::log_dir()` (`serve.rs`), and the reader
    // builds `self.data_dir.join("logs")` by hand (`reports.rs`). Today they agree — `Paths` defines `log_dir` as
    // exactly that join — but the agreement is a coincidence of two independent lines rather than one rule, and if
    // `Paths` ever moved the log somewhere else the symptom would be `synra logs` returning an empty list forever while
    // the daemon wrote to a file nobody read. No error, no warning, and the log looks like it is simply quiet.
    let root = PathBuf::from("/tmp/synra-agreement");
    let paths = synra_store::Paths::new(root.clone(), root.join("cache"));

    // The reader's directory, exactly as `logs_value` builds it.
    let reader = root.join("logs");
    assert_eq!(
        paths.log_dir(),
        reader,
        "the writer's log directory and the reader's are not the same place, so `synra logs` would always be empty"
    );
}

#[test]
fn a_trace_filter_keeps_only_the_lines_that_mention_it() {
    // ★ The half of `--trace` that did not exist. The CLI carried the flag, the flag parsed, and the id was thrown away
    // before it reached the request — so this filter had nothing to filter on and the command returned everything. A
    // user following one action got the whole log and no sign that their filter had been ignored.
    let dir = TempDir::new("logs-trace");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(
        log_dir.join("kernel.log"),
        "INFO started trace_id=trace-1\n\
         DEBUG detail trace_id=trace-2\n\
         INFO finished trace_id=trace-1\n\
         INFO unrelated\n",
    )
    .expect("a log");

    // A trace filter widens the level — a trace's lines are the debug ones — and then keeps only its own.
    let only = runtime(dir.path())
        .logs(10, true, Some("trace-1"))
        .expect("logs");
    let lines: Vec<&str> = only["lines"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "expected the two trace-1 lines, got {lines:?}"
    );
    assert!(
        lines.iter().all(|line| line.contains("trace-1")),
        "{lines:?}"
    );

    // The other trace is not in there, which is what makes this a filter rather than a substring coincidence.
    assert!(
        !lines.iter().any(|line| line.contains("trace-2")),
        "{lines:?}"
    );

    // ★ And the id is echoed, so a caller can tell "this trace has no lines" from "the filter was dropped on the way
    // here" — the exact confusion the discarded id produced.
    assert_eq!(only["trace"].as_str(), Some("trace-1"));

    // An id nothing matches is an empty list rather than every line, which is the failure the old code produced.
    let none = runtime(dir.path())
        .logs(10, true, Some("trace-does-not-exist"))
        .expect("logs");
    assert_eq!(none["lines"].as_array().map(Vec::len), Some(0));

    // And no filter still returns everything, so the field's absence is not a filter of its own.
    let all = runtime(dir.path()).logs(10, true, None).expect("logs");
    assert_eq!(all["lines"].as_array().map(Vec::len), Some(4));
}

#[test]
fn debug_lines_are_hidden_unless_they_are_asked_for() {
    // The level is in the line, and filtering here keeps the daemon from needing an index of its own log.
    let dir = TempDir::new("logs-verbose");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(
        log_dir.join("kernel.log"),
        "INFO started\nDEBUG detail\nINFO finished\n",
    )
    .expect("a log");

    // Quiet hides `DEBUG` and `TRACE`, and keeps everything else — two `INFO` lines out of three. A filter that kept
    // only `INFO` would hide warnings and errors, which are the lines a user is actually looking for.
    let quiet = runtime(dir.path()).logs(10, false, None).expect("logs");
    assert_eq!(quiet["lines"].as_array().map(Vec::len), Some(2));
    let verbose = runtime(dir.path()).logs(10, true, None).expect("logs");
    assert_eq!(verbose["lines"].as_array().map(Vec::len), Some(3));

    // And the shape the real log has, where a timestamp comes first — the case the naive `contains(" DEBUG ")` did
    // happen to handle, which is why the bug survived being read.
    std::fs::write(
        log_dir.join("kernel.log"),
        "2026-01-01T00:00:00Z INFO started\n2026-01-01T00:00:01Z DEBUG detail\n",
    )
    .expect("a log");
    let stamped = runtime(dir.path()).logs(10, false, None).expect("logs");
    let lines: Vec<&str> = stamped["lines"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{lines:?}");
}

#[test]
fn the_newest_log_file_is_the_one_read() {
    // A rotated log leaves several, and a user asking "what happened" wants the recent one.
    let dir = TempDir::new("logs-newest");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(log_dir.join("a-old.log"), "old\n").expect("a log");
    // A sleep, because the ordering is by modification time and two writes in one millisecond are ordered by
    // nothing.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(log_dir.join("b-new.log"), "new\n").expect("a log");

    let value = runtime(dir.path()).logs(10, false, None).expect("logs");
    let lines: Vec<&str> = value["lines"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(lines, ["new"]);
}
