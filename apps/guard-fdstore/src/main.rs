//! LFH4 experiment helper: prove systemd fdstore can preserve a fanotify group
//! across a daemon crash+restart, shrinking the fail-open window.
//!
//! Usage (inside a systemd unit with Type=notify, FileDescriptorStoreMax=1,
//! FileDescriptorStorePreserve=restart, Restart=always):
//!
//!   guard-fdstore store PROTECTED_FILE            # create group, store fd, run
//!   guard-fdstore claim PROTECTED_FILE            # after restart: claim stored fd
//!
//! `store` creates a FAN_CLASS_CONTENT group, marks PROTECTED_FILE with
//! FAN_OPEN_PERM, uploads the group fd to the systemd fdstore (FD_STORE=1 via
//! NOTIFY_SOCKET + SCM_RIGHTS), then notifies READY and blocks forever reading
//! events — DENYing every permission event it sees.
//!
//! `claim` runs in the restarted unit, claiming the stored group fd via
//! LISTEN_FDS/PID_FDS (fd 3), re-notifies READY, and resumes reading+DENYing.
//! This proves the kernel fanotify group (marks, queue, permission-wait list)
//! survived the crash and that a restarted daemon can keep enforcing.
//!
//! A probe process that opens PROTECTED_FILE while the daemon is dead must
//! remain blocked (its open waits on the permission answer, which only a
//! listener of the SAME group can give). After `claim` resumes, the probe
//! receives DENY. That is the LFH4 Experiment A oracle.

use std::os::unix::io::RawFd;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "guard-fdstore",
    about = "LFH4 systemd fdstore fanotify experiment"
)]
struct Cli {
    /// Protected synthetic file to mark.
    protected: std::path::PathBuf,
    /// Explicit role. Default: auto — claim if LISTEN_FDS is set (systemd
    /// passed us a stored fd on restart), otherwise store the new group.
    #[arg(long, value_enum)]
    role: Option<Role>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Role {
    Store,
    Claim,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let listen_fds: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let role = cli.role.unwrap_or(if listen_fds >= 1 {
        Role::Claim
    } else {
        Role::Store
    });
    match role {
        Role::Store => run_store(&cli.protected),
        Role::Claim => run_claim(&cli.protected),
    }
}

const FAN_CLASS_CONTENT: u64 = 0x0000_0004;
const FAN_CLOEXEC: u64 = 0x0000_0001;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_MARK_ADD: u64 = 0x0000_0001;
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
const FAN_NOFD: i32 = -1;

fn fanotify_init() -> anyhow::Result<RawFd> {
    // SAFETY: fanotify_init is a pure kernel fd allocation.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            (FAN_CLASS_CONTENT | FAN_CLOEXEC) as i32,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd as RawFd)
}

fn fanotify_mark(group: RawFd, path: &std::path::Path) -> anyhow::Result<()> {
    let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| anyhow::anyhow!("path contains NUL"))?;
    // SAFETY: group is a valid fanotify fd; c outlives the call.
    // flags = FAN_MARK_ADD only; FAN_OPEN_PERM is a MASK bit, not a flags bit
    // (putting it in flags makes the kernel return EINVAL).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            group,
            FAN_MARK_ADD as i64,
            FAN_OPEN_PERM,
            libc::AT_FDCWD,
            c.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Store `fd` in the systemd fdstore: send a datagram to $NOTIFY_SOCKET with
/// SCM_RIGHTS carrying the fd and the text "FDSTORE=1\n".
fn fdstore_store(fd: RawFd) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    let socket_path = std::env::var_os("NOTIFY_SOCKET")
        .ok_or_else(|| anyhow::anyhow!("NOTIFY_SOCKET unset; not a systemd notify service"))?;
    let sock = UnixDatagram::unbound()?;
    // An unconnected datagram socket cannot sendmsg without a destination
    // address (EDESTADDRREQ); connect to the notify socket like the rest of
    // the sd_notify protocol expects.
    sock.connect(&socket_path)?;
    let msg = b"FDSTORE=1\n";
    let mut cmsg_buf = [0u8; 64];
    // SAFETY: cmsg_buf is writable; we build one SCM_RIGHTS cmsg.
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    // msg_control must be set BEFORE CMSG_FIRSTHDR, otherwise the macro sees
    // msg_controllen=0 and returns NULL (dereferencing it is UB).
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    // SAFETY: CMSG_SPACE is a compile-time-ish size computation on the buffer.
    msghdr.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    let mut iov = [libc::iovec {
        iov_base: msg.as_ptr() as *mut _,
        iov_len: msg.len(),
    }];
    msghdr.msg_iov = iov.as_mut_ptr();
    msghdr.msg_iovlen = 1;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        assert!(!cmsg.is_null(), "cmsg buffer too small");
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }
    // SAFETY: sendmsg on the connected datagram socket to the notify socket.
    let rc = unsafe { libc::sendmsg(sock.as_raw_fd(), &msghdr, libc::MSG_NOSIGNAL) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Tell systemd the service is ready (READY=1) over NOTIFY_SOCKET.
fn sd_notify_ready() {
    use std::os::unix::net::UnixDatagram;
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Ok(sock) = UnixDatagram::unbound() {
        let _ = sock.send_to(b"READY=1\n", path);
    }
}

/// Loop reading fanotify events and DENYing every permission event. `claim`
/// mode additionally prints whether the group fd is valid fanotify.
fn event_loop(group: RawFd, tag: &str) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut n = 0u64;
    loop {
        // SAFETY: read into a valid buffer from a valid fd.
        let read = unsafe { libc::read(group, buf.as_mut_ptr() as *mut _, buf.len()) };
        if read < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) || err.raw_os_error() == Some(libc::EAGAIN) {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            return Err(err.into());
        }
        // Minimal metadata parse (LFH4 helper): find each event, respond DENY.
        let bytes = &buf[..read as usize];
        let hdr = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut off = 0;
        while off + hdr <= bytes.len() {
            // SAFETY: at least hdr bytes remain; only fixed fields are read.
            let meta: &libc::fanotify_event_metadata =
                unsafe { &*(bytes.as_ptr().add(off) as *const libc::fanotify_event_metadata) };
            let ev_len = meta.event_len as usize;
            if ev_len < hdr || off + ev_len > bytes.len() {
                break;
            }
            let is_overflow = (meta.mask & FAN_Q_OVERFLOW) != 0;
            if meta.fd != FAN_NOFD && !is_overflow {
                let resp = libc::fanotify_response {
                    fd: meta.fd,
                    // FAN_DENY (0x02 since the modern UAPI; 0 was the legacy
                    // value and is now rejected with EINVAL).
                    response: libc::FAN_DENY,
                };
                // SAFETY: writing a fanotify_response is the permission UAPI.
                let wr = unsafe {
                    libc::write(
                        group,
                        &resp as *const _ as *const _,
                        std::mem::size_of::<libc::fanotify_response>(),
                    )
                };
                if wr < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                // SAFETY: close the event fd once.
                unsafe {
                    libc::close(meta.fd);
                }
                n += 1;
            }
            off += ev_len;
        }
        if n > 0 {
            println!("[{tag}] denied {n} events so far");
        }
    }
}

fn run_store(protected: &std::path::Path) -> anyhow::Result<()> {
    let group = fanotify_init()?;
    fanotify_mark(group, protected)?;
    fdstore_store(group)?;
    println!("stored group fd={group}; READY");
    sd_notify_ready();
    event_loop(group, "store")
}

fn run_claim(protected: &std::path::Path) -> anyhow::Result<()> {
    // systemd passes stored fds starting at fd 3. LISTEN_FDS=1 means fd 3.
    let listen_fds: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if listen_fds < 1 {
        return Err(anyhow::anyhow!("no stored fd (LISTEN_FDS={listen_fds})"));
    }
    let group = 3; // first stored fd
                   // Validate the claimed fd is a fanotify group by marking the file again
                   // (fails with EBADF/EINVAL if the fd is not a usable fanotify group).
    fanotify_mark(group, protected)?;
    println!("claimed stored group fd={group} (LISTEN_FDS={listen_fds}); READY");
    sd_notify_ready();
    event_loop(group, "claim")
}
