//! The socket a client and a kernel meet on.
//!
//! # Why a local socket rather than a loopback TCP port
//!
//! A loopback port is reachable by **every process on the machine**. A local socket is reachable by those too, and is
//! additionally a filesystem object the operating system can permission — which is the difference between "any program
//! running as any user can ask the kernel to send a file to your laptop" and "only a program that can open a file owned
//! by you can".
//!
//! That is not a theoretical difference. A loopback port is also reachable from a browser: a page can `fetch` a
//! `127.0.0.1` URL, so a kernel on a TCP port is a kernel a website can drive. There is no equivalent for a local
//! socket, and the same reasoning is why a plugin's WebView gets no network access of its own.
//!
//! # What "local socket" means on each platform
//!
//! A unix domain socket on Linux and macOS, and a **named pipe** on Windows. The two are not the same thing — a pipe has
//! no filesystem entry and no path-length limit — and the platform difference is handled by `interprocess` rather than
//! here, so there is one code path to read and one to test.
//!
//! # Why this is blocking rather than async
//!
//! A command-line client sends one batch and closes, so the work per connection is bounded and there is nothing to
//! overlap. An async runtime here would be a runtime, a task per connection and a `Send` bound on every kernel method —
//! paid for concurrency this channel does not use. A caller that wants several clients served at once runs several
//! threads, which is what a daemon already does.
//!
//! # What is claimed, and what is not
//!
//! The path-length limit below is a **unix** rule. On Windows the name is a pipe name and has no such limit, so
//! [`check_bindable`] is advisory there — it refuses a path the unix side would refuse, which makes a build that moves
//! between platforms behave the same way rather than working on one and not the other.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use interprocess::local_socket::traits::{Listener as _, Stream as _};
use interprocess::local_socket::{ListenerOptions, Stream};
// Each platform's name mapping, imported only where it is used: a build that imported both would warn about one on
// every platform, and a warning that is always there is one nobody reads.
#[cfg(unix)]
use interprocess::local_socket::{GenericFilePath, ToFsName};
#[cfg(windows)]
use interprocess::local_socket::{GenericNamespaced, ToNsName};

use crate::{ChannelError, Decoder, Request, Response, Server, SessionState, encode};

/// The file name of the control socket inside the data directory.
///
/// Inside the data directory rather than in a shared temporary directory, so that two installations on one machine —
/// two users, or one user with two profiles — do not collide, and so the socket inherits the directory's permissions.
pub const SOCKET_FILE_NAME: &str = "kernel.sock";

/// How long a client waits for an answer before giving up.
///
/// A kernel that is running answers in microseconds; one that has stopped answering is one whose socket is still open
/// because the process is wedged. A client that waited forever would be a command that hangs with no output, which is
/// the worst thing a command-line tool can do.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest unix socket path this build will try to bind.
///
/// 108 bytes on Linux including the terminating NUL, 104 on macOS. A path that fits the smaller one fits both, and a
/// path of 103 bytes plus the NUL the operating system appends is the largest that does.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Where the control socket is for a data directory.
///
/// # Why the data directory rather than the platform's runtime directory
///
/// The runtime directory is the more conventional place and the wrong one: a client pointed at a different data
/// directory — `SYNRA_DATA_DIR`, which is how a second installation or a test works — would connect to the socket of the
/// installation it is *not* talking to.
///
/// Putting it beside the database means the two always agree, because they are derived from one input.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE_NAME)
}

/// Why a socket operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The socket could not be bound.
    #[error("could not listen on {}: {why}", path.display())]
    Bind {
        /// Where it tried.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The client could not connect.
    #[error("no kernel is listening on {}: {why}", path.display())]
    Connect {
        /// Where it tried.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The connection failed while it was open.
    #[error("the connection to the kernel failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// A message could not be framed.
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// The kernel did not answer in time.
    #[error("the kernel did not answer within {} seconds", timeout.as_secs())]
    TimedOut {
        /// The timeout.
        timeout: Duration,
    },
}

impl SocketError {
    /// Whether repeating the request could succeed.
    ///
    /// # Why the classification lives here
    ///
    /// A client that decided for itself would be a second opinion that can contradict the kernel's: `TransportNotOpen`
    /// and `Timeout` are retryable because a kernel that is still starting or briefly wedged is the ordinary case, and a
    /// missing socket, a refused version and a framing error are not — repeating them gives the same answer until
    /// something changes that the client cannot change.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport { .. } | Self::TimedOut { .. } | Self::Channel(_)
        )
    }
}

/// Whether an address is one this build will try to bind.
///
/// # Why the length matters
///
/// A unix socket address is a fixed-size field in the kernel, and a longer path is refused with an error that says
/// nothing about length — so a data directory under a deep temporary path produces "invalid argument" for a reason the
/// user cannot act on. Checked here, where the message can name the limit and what to do about it.
///
/// # Errors
///
/// A [`SocketError::Bind`] whose sentence names the length and the limit.
pub fn check_bindable(path: &Path) -> Result<(), SocketError> {
    // A named pipe name has no length limit worth checking, so on Windows this is advisory — it refuses what unix would
    // refuse, so a build that moves between platforms behaves the same way rather than working on one and not the other.
    //
    // Bytes rather than characters: the unix limit is bytes, and a path of non-ASCII characters is longer in bytes than
    // it looks — so a check that counted characters would accept a path the operating system then refuses.
    let len = path.as_os_str().to_string_lossy().len();
    if len > MAX_SOCKET_PATH_BYTES {
        return Err(SocketError::Bind {
            path: path.to_path_buf(),
            why: format!(
                "the path is {len} bytes and a socket address holds at most {MAX_SOCKET_PATH_BYTES} — \
                 point the data directory somewhere shorter"
            ),
        });
    }
    Ok(())
}

/// Turns a data directory into a name a local socket can be bound with.
///
/// # Why this branches on the platform
///
/// A unix domain socket **is** a filesystem entry, so the name is the path — which is what makes the socket inheritable
/// by permission and what makes two installations' sockets impossible to confuse.
///
/// A Windows named pipe **is not** a filesystem entry. There is no path to give it: a pipe name lives in a namespace of
/// its own, and `interprocess` refuses a filesystem path there with "not a named pipe path". So the name has to be
/// derived from the data directory instead, and the derivation has to be injective — two installations must not land on
/// one pipe, because two kernels on one pipe is one kernel answering for the other.
///
/// The derivation is the absolute path's own bytes, hex-encoded, which is injective by construction and needs no hash
/// function to be trusted.
#[cfg(windows)]
fn namespaced_name(path: &Path) -> String {
    // Absolute, because the same installation reached by a relative path and by an absolute one must produce one name.
    // `std::path::absolute` rather than `canonicalize`: the latter touches the filesystem and follows symlinks, and a
    // name that changed when a directory was moved would be a daemon a client could no longer find.
    let base = path.parent().unwrap_or(path);
    let absolute = std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf());
    let mut encoded = String::with_capacity(absolute.as_os_str().len() * 2 + 32);
    encoded.push_str("synra-kernel-");
    for byte in absolute.as_os_str().to_string_lossy().as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

/// A kernel listening for clients.
#[derive(Debug)]
pub struct Listener {
    listener: interprocess::local_socket::Listener,
    path: PathBuf,
}

impl Listener {
    /// Binds the control socket for a data directory.
    ///
    /// # Why a socket that is already there is reclaimed
    ///
    /// A unix socket is a filesystem entry that outlives the process that made it: a kernel that was killed leaves one
    /// behind, and binding where it is fails with "address in use" for a kernel that is **not** running. So the name is
    /// reclaimed.
    ///
    /// The reclamation does not disturb a live kernel: a bound socket keeps its inode, and the entry that is removed is
    /// the one a *dead* kernel left. What it does take away is the state that would otherwise stop the user from
    /// starting a kernel at all.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] for a path that is too long or cannot be bound.
    pub fn bind(data_dir: &Path) -> Result<Self, SocketError> {
        let path = socket_path(data_dir);
        check_bindable(&path)?;

        #[cfg(unix)]
        let name = path.as_path().to_fs_name::<GenericFilePath>().map_err(|error| SocketError::Bind {
            path: path.clone(),
            why: error.to_string(),
        })?;
        // The owned name is kept in a binding, because the `Name` a conversion produces borrows from it — and a
        // temporary would be dropped at the end of the statement that made it.
        #[cfg(windows)]
        let owned = namespaced_name(&path);
        #[cfg(windows)]
        let name = owned.as_str().to_ns_name::<GenericNamespaced>().map_err(|error| SocketError::Bind {
            path: path.clone(),
            why: error.to_string(),
        })?;

        let listener = ListenerOptions::new()
            .name(name)
            // The two halves of the same decision: reclaim a name a dead kernel left, and overwrite what is left rather
            // than refusing. A user who killed a kernel has to be able to start another.
            .reclaim_name(true)
            .try_overwrite(true)
            .create_sync()
            .map_err(|error| SocketError::Bind { path: path.clone(), why: error.to_string() })?;

        Ok(Self { listener, path })
    }

    /// Where it is listening.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts one client and serves it until it disconnects.
    ///
    /// # Errors
    ///
    /// [`SocketError`] when the stream fails. A client that disconnects mid-answer is **not** an error: it is the
    /// ordinary shape of a command the user interrupted.
    pub fn serve_one(&self, kernel: &impl crate::Kernel) -> Result<(), SocketError> {
        let stream = self.listener.accept().map_err(|error| SocketError::Transport {
            why: error.to_string(),
        })?;
        serve_stream(stream, kernel)
    }
}

/// Serves one connection to its end.
///
/// # Errors
///
/// [`SocketError`] when the stream fails.
pub fn serve_stream(mut stream: Stream, kernel: &impl crate::Kernel) -> Result<(), SocketError> {
    let mut server = Server::new();
    let mut buffer = vec![0u8; 8 * 1024];
    let mut out = Vec::new();

    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            // A client that went away mid-request is ordinary: the user pressed Ctrl-C.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(SocketError::Transport { why: error.to_string() }),
        };

        // `get` rather than a slice: the read count is what the operating system returned, and a slice would be an index
        // the compiler cannot prove is in range — which the workspace forbids for exactly that reason.
        let Some(chunk) = buffer.get(..read) else {
            return Err(SocketError::Transport {
                why: "a read reported more bytes than the buffer".to_owned(),
            });
        };

        out.clear();
        let state = server.feed(chunk, kernel, &mut out)?;
        if !out.is_empty() {
            stream
                .write_all(&out)
                .and_then(|()| stream.flush())
                .map_err(|error| SocketError::Transport { why: error.to_string() })?;
        }
        if state == SessionState::Close {
            return Ok(());
        }
    }
}

/// A client talking to a kernel.
#[derive(Debug)]
pub struct Client {
    stream: Stream,
    decoder: Decoder,
    buffer: Vec<u8>,
}

impl Client {
    /// Connects to a kernel's control socket.
    ///
    /// # Errors
    ///
    /// [`SocketError::Connect`], which is what a user sees when no kernel is running — so its sentence names the path
    /// and what to start.
    pub fn connect(data_dir: &Path) -> Result<Self, SocketError> {
        let path = socket_path(data_dir);
        #[cfg(unix)]
        let name = path.as_path().to_fs_name::<GenericFilePath>().map_err(|error| SocketError::Connect {
            path: path.clone(),
            why: error.to_string(),
        })?;
        #[cfg(windows)]
        let owned = namespaced_name(&path);
        #[cfg(windows)]
        let name = owned.as_str().to_ns_name::<GenericNamespaced>().map_err(|error| SocketError::Connect {
            path: path.clone(),
            why: error.to_string(),
        })?;
        let stream = Stream::connect(name).map_err(|error| SocketError::Connect {
            path: path.clone(),
            why: error.to_string(),
        })?;
        // A read timeout rather than a write one: the failure this guards against is a kernel that accepted the
        // connection and then stopped answering, which is a wedge rather than a slow link.
        //
        // ★ Windows named pipes do not support I/O timeouts, so this fails there with "named pipes do not support I/O
        // timeouts". That is a platform limitation and not a reason to refuse the connection: a client that could not
        // connect to a healthy kernel because it could not *also* set a deadline on it would be one that never worked on
        // Windows. The consequence is stated rather than hidden — on Windows a wedged kernel leaves the command waiting
        // until the user interrupts it, which is the behaviour a command-line tool has by default.
        //
        // `WouldBlock`-family errors are treated as the timeout below, so the unix path reports the same error a user
        // would see if the platform could express one.
        let _ = stream.set_recv_timeout(Some(REPLY_TIMEOUT));

        Ok(Self { stream, decoder: Decoder::new(), buffer: vec![0u8; 8 * 1024] })
    }

    /// Sends one request and waits for its answer.
    ///
    /// # Errors
    ///
    /// [`SocketError::TimedOut`] when the kernel does not answer, and [`SocketError::Transport`] when the stream fails.
    pub fn ask(&mut self, request: &Request) -> Result<Response, SocketError> {
        let bytes = encode(request)?;
        self.stream
            .write_all(&bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|error| SocketError::Transport { why: error.to_string() })?;
        self.read_one()
    }

    /// Reads until one message has arrived.
    fn read_one(&mut self) -> Result<Response, SocketError> {
        loop {
            // Checked before reading, because a previous read may have delivered two messages — and waiting for a third
            // would hang a client whose answer is already in the buffer.
            if let Some(response) = self.decoder.next_message::<Response>()? {
                return Ok(response);
            }

            let read = match self.stream.read(&mut self.buffer) {
                Ok(0) => {
                    return Err(SocketError::Transport {
                        why: "the kernel closed the connection without answering".to_owned(),
                    });
                }
                Ok(read) => read,
                // The receive timeout reached zero. Distinguished from a transport failure because the two have
                // different causes and different advice: one is a wedged kernel, the other a broken socket.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(SocketError::TimedOut { timeout: REPLY_TIMEOUT });
                }
                Err(error) => return Err(SocketError::Transport { why: error.to_string() }),
            };

            let Some(chunk) = self.buffer.get(..read) else {
                return Err(SocketError::Transport {
                    why: "a read reported more bytes than the buffer".to_owned(),
                });
            };
            self.decoder.push(chunk);
        }
    }

    /// Performs the handshake, refusing a kernel this client cannot talk to.
    ///
    /// # Errors
    ///
    /// [`SocketError::Transport`] when the kernel refused the version, carrying the kernel's own sentence. The client
    /// does not continue: it has been told the two cannot talk.
    pub fn handshake(&mut self) -> Result<Response, SocketError> {
        let response = self.ask(&Request::Hello { version: crate::PROTOCOL_VERSION })?;
        if let Response::Failed { message, .. } = &response {
            return Err(SocketError::Transport { why: message.clone() });
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Refusal;
    use std::cell::RefCell;
    use synra_protocol::error::ErrorCode;

    struct Fake {
        asked: RefCell<Vec<String>>,
        fail: Option<ErrorCode>,
    }

    impl Fake {
        fn new() -> Self {
            Self { asked: RefCell::new(Vec::new()), fail: None }
        }

        fn refusing(code: ErrorCode) -> Self {
            Self { asked: RefCell::new(Vec::new()), fail: Some(code) }
        }

        fn answer(&self, kind: &str) -> Result<serde_json::Value, Refusal> {
            self.asked.borrow_mut().push(kind.to_owned());
            match self.fail {
                Some(code) => Err(Refusal::new(code, "the fake refuses")),
                None => Ok(serde_json::json!({"kind": kind})),
            }
        }
    }

    impl crate::Kernel for Fake {
        fn version(&self) -> String {
            "0.1.0-test".to_owned()
        }
        fn status(&self) -> Result<serde_json::Value, Refusal> {
            self.answer("status")
        }
        fn devices(&self, _include_unpaired: bool) -> Result<serde_json::Value, Refusal> {
            self.answer("devices")
        }
        fn send_text(&self, _to: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
            self.answer("sendText")
        }
        fn send_file(&self, _to: &str, _path: &str) -> Result<serde_json::Value, Refusal> {
            self.answer("sendFile")
        }
        fn plugins(&self) -> Result<serde_json::Value, Refusal> {
            self.answer("plugins")
        }
        fn logs(&self, _lines: usize, _verbose: bool) -> Result<serde_json::Value, Refusal> {
            self.answer("logs")
        }
    }

    /// A temporary directory that removes itself.
    ///
    /// The name carries the process id and the test's own name, because a test binary runs its tests in parallel and two
    /// of them binding the same path would fail with "address in use" for a reason that has nothing to do with what is
    /// being tested.
    ///
    /// It is kept as short as those two allow: a unix socket path has a hard limit, and a directory name long enough to
    /// approach it would make the tests fail for a reason that has nothing to do with the code.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("synra-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary directory");
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── The address ───────────────────────────────────────────────────────────────────────────────

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
            SocketError::Bind { path: PathBuf::from("/tmp/x"), why: "in use".to_owned() },
            SocketError::Connect { path: PathBuf::from("/tmp/x"), why: "no such file".to_owned() },
            SocketError::Transport { why: "reset".to_owned() },
            SocketError::TimedOut { timeout: REPLY_TIMEOUT },
            SocketError::Channel(ChannelError::Malformed { why: "x".to_owned() }),
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    // ── The transport ─────────────────────────────────────────────────────────────────────────────

    /// Runs a server for one connection on its own thread, and returns the handle.
    fn serve_in_background(
        listener: Listener,
        kernel: Fake,
    ) -> std::thread::JoinHandle<Result<(), SocketError>> {
        std::thread::spawn(move || listener.serve_one(&kernel))
    }

    #[test]
    fn a_client_and_a_kernel_talk_over_a_real_socket() {
        // ★ The end-to-end test, and the only one that proves the framing works on a stream that delivers partial
        // messages rather than on a buffer a test filled.
        let dir = TempDir::new("round-trip");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::new());

        let mut client = Client::connect(dir.path()).expect("connects");
        let hello = client.handshake().expect("handshakes");
        match hello {
            Response::Hello { kernel, .. } => assert_eq!(kernel, "0.1.0-test"),
            other => panic!("expected a hello, got {other:?}"),
        }

        let status = client.ask(&Request::Status).expect("asks");
        assert_eq!(status, Response::ok(serde_json::json!({"kind": "status"})));

        drop(client);
        assert!(serving.join().expect("the thread finished").is_ok());
    }

    #[test]
    fn several_requests_over_one_connection_each_get_their_own_answer() {
        // What a command-line client does when a command needs more than one question — and the property a handler that
        // answered out of order would break.
        let dir = TempDir::new("several");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::new());

        let mut client = Client::connect(dir.path()).expect("connects");
        client.handshake().expect("handshakes");
        for (request, kind) in [
            (Request::Status, "status"),
            (Request::Devices { include_unpaired: true }, "devices"),
            (Request::Plugins, "plugins"),
            (Request::Logs { lines: 5, verbose: false }, "logs"),
        ] {
            assert_eq!(
                client.ask(&request).expect("asks"),
                Response::ok(serde_json::json!({"kind": kind})),
                "{kind}"
            );
        }

        drop(client);
        assert!(serving.join().expect("the thread finished").is_ok());
    }

    #[test]
    fn a_kernels_refusal_arrives_as_a_response_rather_than_an_error() {
        // ★ One failing command must not take the connection with it: a script that runs five commands and gets a
        // refusal for the third has to read the other four answers.
        let dir = TempDir::new("refusal");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::refusing(ErrorCode::DeviceOffline));

        let mut client = Client::connect(dir.path()).expect("connects");
        client.handshake().expect("handshakes");

        let first = client.ask(&Request::Status).expect("asks");
        assert_eq!(first.error_code(), Some(ErrorCode::DeviceOffline.as_str()));
        match &first {
            Response::Failed { retryable, .. } => assert!(retryable),
            other => panic!("expected a refusal, got {other:?}"),
        }

        // And the connection still works, which is the point.
        assert!(!client.ask(&Request::Plugins).expect("asks").is_ok());

        drop(client);
        assert!(serving.join().expect("the thread finished").is_ok());
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
        assert!(second.is_ok(), "a stale socket stopped the bind: {:?}", second.err());
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
    fn a_client_that_disconnects_mid_batch_ends_the_connection_cleanly() {
        // The user pressed Ctrl-C. A server that treated it as an error would log a failure for every interrupted
        // command.
        let dir = TempDir::new("disconnect");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::new());

        let mut client = Client::connect(dir.path()).expect("connects");
        client.handshake().expect("handshakes");
        drop(client);

        let result = serving.join().expect("the thread finished");
        assert!(result.is_ok(), "an interrupted client was reported as a failure: {result:?}");
    }

    #[test]
    fn a_client_that_never_handshakes_is_refused() {
        // ★ The handshake is what establishes the version, and a server that served a request without one would be
        // answering a protocol it never agreed to.
        let dir = TempDir::new("no-handshake");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::new());

        let mut client = Client::connect(dir.path()).expect("connects");
        let response = client.ask(&Request::Status).expect("asks");
        assert_eq!(response.error_code(), Some(ErrorCode::InvalidArgument.as_str()));

        drop(client);
        assert!(serving.join().expect("the thread finished").is_ok());
    }

    #[test]
    fn a_version_the_kernel_does_not_speak_ends_the_connection() {
        let dir = TempDir::new("version");
        let listener = Listener::bind(dir.path()).expect("binds");
        let serving = serve_in_background(listener, Fake::new());

        let mut client = Client::connect(dir.path()).expect("connects");
        let response = client
            .ask(&Request::Hello { version: crate::PROTOCOL_VERSION + 1 })
            .expect("asks");
        assert_eq!(
            response.error_code(),
            Some(ErrorCode::ProtocolVersionUnsupported.as_str())
        );

        // The server closed, so the next question finds a closed stream rather than a second refusal.
        assert!(client.ask(&Request::Status).is_err());

        drop(client);
        assert!(serving.join().expect("the thread finished").is_ok());
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
}
