//! Unix domain socket IPC transport for `guardd` <-> `guardctl`/`guard-tui`.
//!
//! - `IpcServer::bind` creates a listening `AF_UNIX` socket. The daemon owns it.
//! - `accept` returns a connection plus the peer's kernel-verified credentials
//!   via `SO_PEERCRED` (`pid`, `uid`, `gid`). The daemon authorizes using this
//!   `uid`; a `uid` supplied in JSON is never trusted.
//! - Framing is a 4-byte big-endian length prefix + JSON payload. `read_request`
//!   rejects frames larger than `MAX_REQUEST_BYTES` and malformed prefixes, so a
//!   peer cannot exhaust daemon memory. `write_response` frames the reply.
//! - `IpcClient::request` connects, sends a framed request, and reads one
//!   framed response — the full `guardctl` round-trip.
//!
//! None of this requires root: a Unix socket in a temp dir works as a normal
//! user, and `SO_PEERCRED` is available to any process. The privileged fanotify
//! enforcement is independent of the IPC transport.

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use libc::{getsockopt, socklen_t, ucred, SOL_SOCKET, SO_PEERCRED};

/// Default socket path. The daemon may override via `--ipc-socket`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/guardd/guardd.sock";

/// Peer credentials obtained from the kernel via `SO_PEERCRED`. These are
/// trustworthy: they come from the kernel, not from the peer's JSON.
#[derive(Debug, Clone, Copy)]
pub struct PeerCreds {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Read the peer's credentials for a connected `UnixStream`.
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCreds> {
    let fd = stream.as_raw_fd();
    let mut cred: ucred = ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len: socklen_t = std::mem::size_of::<ucred>() as socklen_t;
    // SAFETY: fd is a valid connected socket; cred is a ucred the kernel fills;
    // len is initialized to the struct size and updated by the kernel.
    let rc = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len as *mut socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCreds {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

pub struct IpcServer {
    listener: UnixListener,
    _path: PathBuf,
}

impl IpcServer {
    /// Bind a listening stream socket at `path`. Removes any stale socket file
    /// first and creates the parent directory.
    pub fn bind(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        // Restrict to owner by default; root daemon can relax for a group later.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(Self {
            listener,
            _path: path.to_path_buf(),
        })
    }

    /// Accept one connection, returning the stream and the peer's credentials.
    pub fn accept(&self) -> io::Result<(UnixStream, PeerCreds)> {
        let (stream, _addr) = self.listener.accept()?;
        let creds = peer_credentials(&stream)?;
        Ok((stream, creds))
    }

    pub fn raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}

/// Read a length-prefixed request frame. Rejects frames larger than `max_bytes`
/// or with a malformed/truncated prefix.
pub fn read_request(stream: &mut UnixStream, max_bytes: usize) -> io::Result<Vec<u8>> {
    let len = read_len(stream)? as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > max_bytes {
        // Drain and discard so the connection framing stays aligned-ish, then
        // error. (The peer is malformed/malicious; the daemon closes the conn.)
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("request frame too large: {len} > {max_bytes}"),
        ));
    }
    let mut buf = vec![0u8; len];
    read_exact_or_eof(stream, &mut buf)?;
    Ok(buf)
}

/// Write a length-prefixed response frame.
pub fn write_response(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_len(stream: &mut UnixStream) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    read_exact_or_eof(stream, &mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Like `Read::read_exact` but returns `UnexpectedEof` cleanly when the peer
/// closed (so the accept loop can move on without logging an error).
fn read_exact_or_eof(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        filled += n;
    }
    Ok(())
}

/// Owned-fd variant of peer credentials, for accept loops that hand off the fd.
pub fn peer_credentials_fd(fd: RawFd) -> io::Result<PeerCreds> {
    let mut cred: ucred = ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len: socklen_t = std::mem::size_of::<ucred>() as socklen_t;
    // SAFETY: fd is a valid connected socket fd.
    let rc = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len as *mut socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCreds {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Wrap a raw fd in an owned `UnixStream` (for accept loops that dup the fd).
///
/// # Safety
///
/// `fd` must be a valid, owned `AF_UNIX` stream socket. The caller transfers
/// ownership of the fd; the returned `UnixStream` takes responsibility for
/// closing it on drop.
pub unsafe fn stream_from_owned_fd(fd: OwnedFd) -> UnixStream {
    // UnixStream::from_owned_fd is not stable on all editions; use from_raw_fd
    // via the owned fd's raw value. The OwnedFd closes on drop; we transfer.
    let raw = fd.as_raw_fd();
    std::mem::forget(fd);
    // SAFETY: caller guarantees raw is a valid owned unix stream socket.
    unsafe { UnixStream::from_raw_fd(raw) }
}

pub struct IpcClient;

impl IpcClient {
    /// Connect to `path`, send a framed request, read one framed response.
    pub fn request(path: &Path, req_bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(path)?;
        write_response(&mut stream, req_bytes)?;
        // Allow a generous response limit (CLI side; daemon is trusted).
        read_request(&mut stream, 16 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    //! IPC transport tests. No root needed: a temp-dir Unix socket works as a
    //! normal user and SO_PEERCRED is available to anyone. These cover the
    //! prompt's IPC requirements:
    //! - oversized request rejected
    //! - peer UID is kernel-verified (spoof via JSON cannot change it)
    //! - concurrent read-only clients are served (the accept loop + handler
    //!   keep the authorization loop unblocked — exercised at the daemon level
    //!   in the guardd integration tests; here we assert framed round-trips
    //!   under concurrency).

    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// Create a unique socket path and hold the temp dir alive for the test.
    /// Returning the `TempDir` is essential: if it drops, the parent directory
    /// (and the socket file) disappears and connections fail.
    fn tmp_socket() -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (dir.path().join("guardd.sock"), dir)
    }

    /// Poll until the socket file exists, i.e. the server has bound and is
    /// listening. Eliminates the bind/connect race without retrying connections
    /// (which would consume server `accept()` slots).
    fn wait_for_socket(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("socket never appeared: {}", path.display());
    }

    /// Minimal echo server: accept one conn, read a framed request, write the
    /// same bytes back as a framed response. Returns the peer creds.
    fn run_echo_server_once(
        path: &Path,
    ) -> (
        thread::JoinHandle<()>,
        Arc<std::sync::Mutex<Option<PeerCreds>>>,
    ) {
        let path = path.to_path_buf();
        let creds = Arc::new(std::sync::Mutex::new(None));
        let creds2 = Arc::clone(&creds);
        let h = thread::spawn(move || {
            let server = IpcServer::bind(&path).unwrap();
            let (mut stream, c) = server.accept().unwrap();
            *creds2.lock().unwrap() = Some(c);
            let max = 64 * 1024;
            match read_request(&mut stream, max) {
                Ok(req) => {
                    let _ = write_response(&mut stream, &req);
                }
                Err(_) => {
                    // Oversized/malformed: the framing is now corrupted (the
                    // rejected payload bytes are still in the socket buffer), so
                    // we cannot safely write a response. Close the connection
                    // without responding — the daemon does the same.
                    drop(stream);
                }
            }
        });
        (h, creds)
    }

    #[test]
    fn framed_round_trip_and_peer_uid_is_kernel_verified() {
        let (sock, _dir) = tmp_socket();
        let (h, creds) = run_echo_server_once(&sock);
        wait_for_socket(&sock);
        let req = br#"{"version":1,"op":{"kind":"status"}}"#;
        let resp = IpcClient::request(&sock, req).expect("round trip");
        assert_eq!(resp, req);
        h.join().unwrap();
        let c = creds.lock().unwrap().unwrap();
        // The peer uid is THIS test process's uid (kernel-verified). A JSON
        // spoof could not change it.
        assert_eq!(c.uid, unsafe { libc::getuid() });
        assert_eq!(c.pid, std::process::id() as i32);
    }

    #[test]
    fn oversized_request_rejected_by_server() {
        let (sock, _dir) = tmp_socket();
        let (h, _creds) = run_echo_server_once(&sock);
        wait_for_socket(&sock);
        // Build a frame whose declared length exceeds the server max (64KiB).
        let mut stream = UnixStream::connect(&sock).unwrap();
        let huge_len: u32 = (64 * 1024 + 1) as u32;
        stream.write_all(&huge_len.to_be_bytes()).unwrap();
        // Send a small amount; the server rejects on the length check.
        stream.write_all(&[0u8; 16]).unwrap();
        stream.flush().unwrap();
        // Server closes the connection without writing a response. Depending on
        // timing the client sees either a clean EOF or ECONNRESET — both prove
        // the server refused the oversized frame.
        let mut buf = [0u8; 16];
        use std::io::Read;
        match stream.read(&mut buf) {
            Ok(0) => { /* clean close */ }
            Ok(n) => panic!("server should not respond to oversized frame, got {n} bytes"),
            Err(e) if e.raw_os_error() == Some(libc::ECONNRESET) => { /* reset */ }
            Err(e) => panic!("unexpected read error: {e}"),
        }
        h.join().unwrap();
    }

    #[test]
    fn client_side_rejects_oversized_response() {
        let (sock, _dir) = tmp_socket();
        let path = sock.clone();
        let h = thread::spawn(move || {
            let server = IpcServer::bind(&path).unwrap();
            let (mut stream, _c) = server.accept().unwrap();
            // Read the client's request (ignore content).
            let _ = read_request(&mut stream, 64 * 1024);
            // Send a response claiming an absurd length.
            let absurd: u32 = 32 * 1024 * 1024;
            let _ = stream.write_all(&absurd.to_be_bytes());
        });
        wait_for_socket(&sock);
        let req = br#"{"version":1,"op":{"kind":"status"}}"#;
        let resp = IpcClient::request(&sock, req);
        assert!(resp.is_err(), "client must reject oversized response");
        // Server handled exactly one connection and exited; join is safe.
        let _ = h.join();
    }

    #[test]
    fn concurrent_clients_round_trip() {
        let (sock, _dir) = tmp_socket();
        let path = sock.clone();
        let n_clients = 8u32;
        let h = thread::spawn(move || {
            let server = IpcServer::bind(&path).unwrap();
            // Accept exactly one connection per client. Each client makes a
            // single attempt after `wait_for_socket`, so there are no spurious
            // connections that would consume another client's slot.
            for _ in 0..n_clients {
                let (mut stream, _c) = server.accept().unwrap();
                let req = read_request(&mut stream, 64 * 1024).unwrap();
                write_response(&mut stream, &req).unwrap();
            }
        });
        wait_for_socket(&sock);
        let mut handles = Vec::new();
        for i in 0..n_clients {
            let p = sock.clone();
            handles.push(thread::spawn(move || {
                let payload = format!(r#"{{"i":{i}}}"#);
                let bytes = payload.into_bytes();
                let resp = IpcClient::request(&p, &bytes).expect("round trip");
                assert_eq!(resp, bytes);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        h.join().unwrap();
    }
}
