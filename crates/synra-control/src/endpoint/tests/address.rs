use std::path::{Path, PathBuf};
use crate::ChannelError;
use super::super::{Client, Listener, MAX_SOCKET_PATH_BYTES, REPLY_TIMEOUT, SOCKET_FILE_NAME, SocketError, check_bindable, socket_path};
use super::TempDir;

#[test]
fn the_socket_lives_beside_the_database() {
    // ★ So the two always agree. A socket in the platform's runtime directory would be found by a client pointed at
    // a different data directory, and it would talk to the installation it is not supposed to.
    let path = socket_path(Path::new("/var/lib/synra"));
    assert!(path.ends_with(SOCKET_FILE_NAME));
    assert_eq!(path.parent(), Some(Path::new("/var/lib/synra")));
}

#[test]
fn a_path_of_ordinary_length_is_bindable() {
    assert!(check_bindable(Path::new("/var/lib/synra/kernel.sock")).is_ok());
}

#[test]
fn a_path_too_long_to_bind_is_refused_with_a_sentence_that_says_so() {
    // ★ The operating system refuses an over-long socket address with an error that says nothing about length, and a
    // data directory under a deep temporary path is the ordinary way to hit it. "invalid argument" leaves the user
    // with nothing to do.
    let deep = "a".repeat(200);
    let path = Path::new("/tmp").join(&deep).join(SOCKET_FILE_NAME);
    match check_bindable(&path) {
        Err(SocketError::Bind { why, .. }) => {
            assert!(why.contains("103"), "{why}");
            assert!(why.contains("shorter"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_limit_counts_bytes_rather_than_characters() {
    // A path of non-ASCII characters is longer in bytes than in characters, and the limit is bytes — so a check that
    // counted characters would accept a path the operating system then refuses.
    let wide = "日".repeat(40);
    let path = Path::new("/tmp").join(&wide).join(SOCKET_FILE_NAME);
    assert!(path.as_os_str().len() > MAX_SOCKET_PATH_BYTES);
    assert!(check_bindable(&path).is_err());
}

#[test]
fn a_path_exactly_at_the_limit_is_accepted() {
    // The boundary, asserted because an off-by-one here refuses a data directory that would have worked.
    //
    // The arithmetic counts both separators: the path is `/` + filler + `/` + the file name, so the filler is the
    // limit less the file name less the two separators. The first version of this forgot one of them and the test
    // measured 104.
    let filler = "a".repeat(MAX_SOCKET_PATH_BYTES - SOCKET_FILE_NAME.len() - 2);
    let path = Path::new("/").join(&filler).join(SOCKET_FILE_NAME);
    assert_eq!(path.as_os_str().len(), MAX_SOCKET_PATH_BYTES, "{:?}", path);
    assert!(check_bindable(&path).is_ok(), "{:?}", check_bindable(&path));

    // And one byte more is refused, so the pair pins the boundary from both sides.
    let over = "a".repeat(MAX_SOCKET_PATH_BYTES - SOCKET_FILE_NAME.len() - 1);
    let path = Path::new("/").join(&over).join(SOCKET_FILE_NAME);
    assert_eq!(path.as_os_str().len(), MAX_SOCKET_PATH_BYTES + 1);
    assert!(check_bindable(&path).is_err());
}

#[test]
fn every_socket_error_explains_itself() {
    let errors = [
        SocketError::Bind {
            path: PathBuf::from("/tmp/x"),
            why: "in use".to_owned(),
        },
        SocketError::Connect {
            path: PathBuf::from("/tmp/x"),
            why: "no such file".to_owned(),
        },
        SocketError::Transport {
            why: "reset".to_owned(),
        },
        SocketError::TimedOut {
            timeout: REPLY_TIMEOUT,
        },
        SocketError::Channel(ChannelError::Malformed {
            why: "x".to_owned(),
        }),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn a_stale_socket_does_not_stop_the_next_kernel_binding() {
    // ★ A unix socket outlives the process that made it: a kernel that was killed leaves one behind, and binding
    // where it is fails with "address in use" for a kernel that is not running. A user who killed a kernel and
    // started another has to be able to start it.
    let dir = TempDir::new("stale");
    let first = Listener::bind(dir.path()).expect("binds");
    let path = first.path().to_path_buf();
    drop(first);
    // On unix the entry remains; on Windows a named pipe leaves nothing. Either way the next bind has to work.
    let _ = path;

    let second = Listener::bind(dir.path());
    assert!(
        second.is_ok(),
        "a stale socket stopped the bind: {:?}",
        second.err()
    );
}

#[test]
fn a_client_with_no_kernel_reports_where_it_looked() {
    // The error a user sees when nothing is running, so its sentence has to name the path — otherwise the message is
    // "no such file" about a file they never knew existed.
    let dir = TempDir::new("absent");
    match Client::connect(dir.path()) {
        Err(SocketError::Connect { path, .. }) => {
            assert!(path.ends_with(SOCKET_FILE_NAME), "{}", path.display());
        }
        other => panic!("expected a connect failure, got {other:?}"),
    }
}

#[test]
fn the_socket_is_created_in_the_data_directory() {
    let dir = TempDir::new("location");
    let listener = Listener::bind(dir.path()).expect("binds");
    assert_eq!(listener.path(), socket_path(dir.path()));
}

#[test]
fn a_second_kernel_cannot_bind_while_the_first_is_listening() {
    // ★ Two kernels on one data directory would be two writers to one database, and the second one's claim file is
    // what the daemon checks — but the socket is the thing that makes it *observable*. The bind must fail rather
    // than silently take the name.
    let dir = TempDir::new("exclusive");
    let first = Listener::bind(dir.path()).expect("the first binds");
    let second = Listener::bind(dir.path());
    assert!(second.is_err(), "a second kernel bound the same socket");
    drop(first);
}
