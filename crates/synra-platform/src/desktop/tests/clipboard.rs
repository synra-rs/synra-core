use crate::guard::check_clipboard_text;
use crate::host::Platform;
use crate::{MAX_CLIPBOARD_BYTES, PlatformError};

use super::super::Desktop;
use super::{over_printer, over_recorder};

#[test]
fn a_clipboard_read_returns_what_the_program_printed() {
    let (recorder, platform) = over_printer(Desktop::MacOs, "the clipboard");
    assert_eq!(platform.read_clipboard().expect("read"), Some("the clipboard".to_owned()));
    assert_eq!(recorder.commands(), vec!["pbpaste".to_owned()]);

    let (_, platform) = over_recorder(Desktop::Linux);
    let _ = platform.read_clipboard().expect("read");
}

#[test]
fn a_clipboard_write_delivers_utf8_data_as_standard_input() {
    let (recorder, platform) = over_recorder(Desktop::MacOs);
    let text = "\"literal\"; $value\r\n中文🖱️";
    platform.write_clipboard(text).expect("write");
    assert_eq!(
        *recorder.input.lock().expect("input"),
        [Some(text.to_owned())]
    );
    assert_eq!(recorder.commands(), ["pbcopy"]);
}

#[test]
fn clipboard_writes_feed_each_desktop_without_interpolating_data() {
    let text = "\"literal\"; $value\r\n中文🖱️";
    for desktop in [Desktop::Linux, Desktop::MacOs, Desktop::Windows] {
        let (recorder, platform) = over_recorder(desktop);
        platform.write_clipboard(text).expect("written");
        assert_eq!(
            *recorder.input.lock().expect("input"),
            [Some(text.to_owned())]
        );
        assert!(
            !recorder.commands().join(" ").contains(text),
            "data entered the command line"
        );
        assert_eq!(recorder.count(), 1);
    }
}

#[test]
fn windows_clipboard_reads_nullable_json_without_losing_empty_text() {
    for value in [None, Some(""), Some("null"), Some("中文🖱️\\\"\r\n")] {
        let answer = serde_json::to_string(&value).expect("JSON");
        let (_, platform) = over_printer(Desktop::Windows, &answer);
        assert_eq!(platform.read_clipboard().expect("read").as_deref(), value);
    }
    let (_, platform) = over_printer(Desktop::Windows, "not JSON");
    assert!(matches!(
        platform.read_clipboard(),
        Err(PlatformError::RunnerFailed { .. })
    ));
}

#[test]
fn clipboard_limits_count_utf8_bytes_before_writes_and_after_reads() {
    let too_long = "选".repeat(MAX_CLIPBOARD_BYTES / 3 + 1);
    for desktop in [Desktop::Linux, Desktop::MacOs, Desktop::Windows] {
        let (recorder, platform) = over_recorder(desktop);
        assert!(matches!(
            platform.write_clipboard(&too_long),
            Err(PlatformError::TooLong { .. })
        ));
        assert_eq!(recorder.count(), 0);
        let answer = if desktop == Desktop::Windows {
            serde_json::to_string(&Some(&too_long)).expect("JSON")
        } else {
            too_long.clone()
        };
        let (_, platform) = over_printer(desktop, &answer);
        assert!(matches!(
            platform.read_clipboard(),
            Err(PlatformError::RunnerOutputTooLong { .. })
        ));
    }
    assert!(matches!(
        crate::HeadlessPlatform::new().write_clipboard(&too_long),
        Err(PlatformError::TooLong { .. })
    ));
    let at_limit = "x".repeat(MAX_CLIPBOARD_BYTES);
    assert!(check_clipboard_text(&at_limit).is_ok());
}
