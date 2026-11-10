use super::*;

#[test]
fn levels_order_from_most_to_least_verbose() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);
}

#[test]
fn a_threshold_admits_its_own_level_and_worse() {
    assert!(LogLevel::Info.admits(LogLevel::Info));
    assert!(LogLevel::Info.admits(LogLevel::Warn));
    assert!(LogLevel::Info.admits(LogLevel::Error));
    assert!(!LogLevel::Info.admits(LogLevel::Debug));
    assert!(!LogLevel::Info.admits(LogLevel::Trace));

    // Off admits nothing, including an error.
    for level in [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ] {
        assert!(!LogLevel::Off.admits(level), "{level}");
    }
}

#[test]
fn only_the_persisted_levels_reach_disk() {
    // Debug and trace are for a bounded diagnostic window; keeping them forever is how a log
    // directory reaches a gigabyte.
    assert!(!LogLevel::Trace.is_persisted());
    assert!(!LogLevel::Debug.is_persisted());
    assert!(LogLevel::Info.is_persisted());
    assert!(LogLevel::Warn.is_persisted());
    assert!(LogLevel::Error.is_persisted());
}

#[test]
fn level_names_round_trip() {
    for level in [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
        LogLevel::Off,
    ] {
        assert_eq!(LogLevel::parse(level.as_str()), Ok(level));
        assert_eq!(level.to_string(), level.as_str());
    }
    // Case and whitespace are tolerated, because these come from a config file a person edited.
    assert_eq!(LogLevel::parse("  INFO "), Ok(LogLevel::Info));
    assert_eq!(LogLevel::parse("WARNING"), Ok(LogLevel::Warn));
    assert!(LogLevel::parse("loud").is_err());
}

#[test]
fn the_default_level_is_info() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
}

#[test]
fn an_unknown_level_names_itself_in_the_error() {
    match LogLevel::parse("loud") {
        Err(error) => assert_eq!(error.name, "loud"),
        Ok(level) => panic!("expected an error, got {level}"),
    }
}
