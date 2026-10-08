use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use fsearch::{Engine, Options};
use std::time::Duration;

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.port")
}

pub fn serve(dir: PathBuf, home: String, handle_fn: fn(TcpStream, &Engine)) {
    std::fs::create_dir_all(&dir).ok();

    let lock_path = dir.join("socket.lock");
    let lock_file = match std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&lock_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};

    let handle = lock_file.as_raw_handle() as *mut std::ffi::c_void;
    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };

    let locked = unsafe {
        LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &mut overlapped)
    };

    if locked == 0 {
        eprintln!("{} another fsearch daemon is running", crate::query::now_secs());
        return;
    }

    let engine = match Engine::start(Options { dir: dir.clone(), home, skip: None }) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", crate::query::now_secs());
            return;
        }
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let port = listener.local_addr().unwrap().port();

    let port_file = socket_path(&dir);
    std::fs::write(&port_file, port.to_string()).expect("write port");

    for conn in listener.incoming().flatten() {
        let e = engine.clone();
        std::thread::spawn(move || handle_fn(conn, &e));
    }
}

pub fn connect(dir: &Path) -> std::io::Result<TcpStream> {
    let port_file = socket_path(dir);

    let connect_to_port = || -> std::io::Result<TcpStream> {
        let port_str = std::fs::read_to_string(&port_file)?;
        let port: u16 = port_str.trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad port"))?;
        TcpStream::connect(("127.0.0.1", port))
    };

    if let Ok(s) = connect_to_port() {
        return Ok(s);
    }

    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("daemon.log"))?;

    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    // CREATE_NO_WINDOW | DETACHED_PROCESS
    cmd.creation_flags(0x08000000 | 0x00000008);
    cmd.arg("serve").stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log).spawn()?;

    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(30));
        if let Ok(s) = connect_to_port() {
            return Ok(s);
        }
    }

    connect_to_port()
}
