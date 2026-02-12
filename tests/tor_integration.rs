use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Check if the `tor` binary is available on PATH.
fn tor_available() -> bool {
    Command::new("tor").arg("--version").output().is_ok()
}

/// Find the first subdirectory in `dir` whose name starts with the given prefix.
fn find_generated_dir(dir: &std::path::Path, prefix: &str) -> Option<std::path::PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(prefix) {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Bind to port 0 and return the OS-assigned free port.
fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// SOCKS5 helper (minimal, no external dependency)
// ---------------------------------------------------------------------------

/// Perform a SOCKS5 CONNECT through `proxy_addr` to `target_host:target_port`.
/// Returns the connected TCP stream tunnelled through the proxy.
fn socks5_connect(proxy_port: u16, target_host: &str, target_port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Auth negotiation: version 5, 1 method, NO AUTH
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    if buf != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 auth failed: {:?}", buf),
        ));
    }

    // CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (DOMAINNAME)
    let host_bytes = target_host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream.write_all(&req)?;

    // Read CONNECT response header (4 bytes minimum)
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp)?;
    if resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 CONNECT failed with reply code: {}", resp[1]),
        ));
    }

    // Drain the bound address depending on ATYP
    match resp[3] {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut drain = [0u8; 6];
            stream.read_exact(&mut drain)?;
        }
        0x03 => {
            // Domain: 1 byte len + domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf)?;
            let mut drain = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut drain)?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut drain = [0u8; 18];
            stream.read_exact(&mut drain)?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("SOCKS5 unexpected ATYP: {}", other),
            ));
        }
    }

    Ok(stream)
}

// ---------------------------------------------------------------------------
// Tor process guard (kills on drop)
// ---------------------------------------------------------------------------

struct TorProcess {
    child: Option<Child>,
}

impl TorProcess {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
        }
    }

    fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---------------------------------------------------------------------------
// Test 1: Quick — verify-config + brief startup (existing)
// ---------------------------------------------------------------------------

#[test]
#[ignore] // requires tor binary installed
fn test_generated_keys_accepted_by_tor() {
    if !tor_available() {
        eprintln!("Skipping test: tor binary not found");
        return;
    }

    let tmp = tempdir().expect("failed to create temp directory");
    let tmp_path = tmp.path();

    // Step 1: Generate an address using the oniongen binary
    let bin_path = env!("CARGO_BIN_EXE_oniongen");
    let gen_output = Command::new(bin_path)
        .args(["test", "-n", "1", "-t", "2"])
        .current_dir(tmp_path)
        .output()
        .expect("failed to run oniongen binary");

    assert!(
        gen_output.status.success(),
        "oniongen failed: {}",
        String::from_utf8_lossy(&gen_output.stderr)
    );

    // Step 2: Find the generated hidden service directory
    let hs_dir = find_generated_dir(tmp_path, "test")
        .expect("no generated directory found starting with 'test'");
    eprintln!("Generated HS directory: {}", hs_dir.display());

    // Verify expected files exist
    assert!(hs_dir.join("hs_ed25519_secret_key").exists());
    assert!(hs_dir.join("hs_ed25519_public_key").exists());
    assert!(hs_dir.join("hostname").exists());

    // Step 3: Fix permissions — Tor requires 700 on the HS directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hs_dir, fs::Permissions::from_mode(0o700))
            .expect("failed to chmod HS directory");
    }

    // Step 4: Create a minimal torrc
    let data_dir = tmp_path.join("data");
    fs::create_dir_all(&data_dir).expect("failed to create data directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
            .expect("failed to chmod data directory");
    }

    let torrc_path = tmp_path.join("torrc");
    let torrc_content = format!(
        "DataDirectory {data_dir}\n\
         SocksPort 0\n\
         ORPort 0\n\
         HiddenServiceDir {hs_dir}\n\
         HiddenServicePort 80 127.0.0.1:8080\n",
        data_dir = data_dir.display(),
        hs_dir = hs_dir.display(),
    );
    fs::write(&torrc_path, &torrc_content).expect("failed to write torrc");
    eprintln!("torrc contents:\n{torrc_content}");

    // Step 5: Run `tor --verify-config` to validate config and keys
    let verify_output = Command::new("tor")
        .args(["--verify-config", "-f", &torrc_path.to_string_lossy()])
        .output()
        .expect("failed to run tor --verify-config");

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify_output.stderr);
    eprintln!("tor --verify-config stdout:\n{verify_stdout}");
    eprintln!("tor --verify-config stderr:\n{verify_stderr}");

    assert!(
        verify_output.status.success(),
        "tor --verify-config failed (exit code {:?}):\nstdout: {}\nstderr: {}",
        verify_output.status.code(),
        verify_stdout,
        verify_stderr,
    );

    let combined_output = format!("{verify_stdout}{verify_stderr}");
    assert!(
        combined_output.contains("Configuration was valid"),
        "tor did not confirm valid configuration in output:\n{combined_output}"
    );

    // Step 6: Brief real startup to confirm key loading.
    let mut tor_child = Command::new("tor")
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start tor");

    // Give Tor enough time to load keys and start bootstrapping
    std::thread::sleep(Duration::from_secs(3));

    // Kill tor — we only need the early startup output
    let _ = tor_child.kill();
    let final_output = tor_child.wait_with_output().expect("failed to wait on tor");

    let tor_stdout = String::from_utf8_lossy(&final_output.stdout);
    let tor_stderr = String::from_utf8_lossy(&final_output.stderr);
    let tor_output = format!("{tor_stdout}{tor_stderr}");
    eprintln!("tor startup output:\n{tor_output}");

    let bootstrapped = tor_output.contains("Bootstrapped");
    assert!(
        bootstrapped,
        "tor did not reach bootstrap phase — keys may be invalid. Full output:\n{tor_output}"
    );

    let has_key_error = tor_output.contains("[err]") || tor_output.contains("[warn]");
    assert!(
        !has_key_error,
        "tor logged errors/warnings during startup:\n{tor_output}"
    );

    eprintln!("SUCCESS: Tor accepted the generated onion address keys");
}

// ---------------------------------------------------------------------------
// Test 2: Full end-to-end — echo through a live .onion service
// ---------------------------------------------------------------------------

#[test]
#[ignore] // requires tor binary + network access; ~1-3 min
fn test_onion_service_echo_through_tor() {
    if !tor_available() {
        eprintln!("Skipping test: tor binary not found");
        return;
    }

    let tmp = tempdir().expect("failed to create temp directory");
    let tmp_path = tmp.path();

    // --- 1. Start a TCP echo server ---
    let echo_port = find_free_port();
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_stop_clone = Arc::clone(&echo_stop);

    let echo_handle = std::thread::spawn(move || {
        let listener =
            TcpListener::bind(("127.0.0.1", echo_port)).expect("echo server: failed to bind");
        listener
            .set_nonblocking(true)
            .expect("echo server: failed to set non-blocking");
        eprintln!("Echo server listening on 127.0.0.1:{echo_port}");

        while !echo_stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut conn, addr)) => {
                    eprintln!("Echo server: connection from {addr}");
                    // Accepted sockets inherit non-blocking from listener on
                    // macOS — switch back to blocking for the echo loop.
                    conn.set_nonblocking(false).ok();
                    conn.set_read_timeout(Some(Duration::from_secs(120))).ok();
                    conn.set_write_timeout(Some(Duration::from_secs(30))).ok();
                    let mut buf = [0u8; 4096];
                    loop {
                        match conn.read(&mut buf) {
                            Ok(0) => {
                                eprintln!("Echo server: EOF from {addr}");
                                break;
                            }
                            Ok(n) => {
                                eprintln!("Echo server: read {n} bytes from {addr}, echoing back");
                                if conn.write_all(&buf[..n]).is_err() {
                                    eprintln!("Echo server: write failed for {addr}");
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Echo server: read error from {addr}: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("Echo server accept error: {e}");
                    break;
                }
            }
        }
        eprintln!("Echo server stopped");
    });

    // --- 2. Generate .onion keys ---
    let bin_path = env!("CARGO_BIN_EXE_oniongen");
    let gen_output = Command::new(bin_path)
        .args(["test", "-n", "1", "-t", "2"])
        .current_dir(tmp_path)
        .output()
        .expect("failed to run oniongen binary");

    assert!(
        gen_output.status.success(),
        "oniongen failed: {}",
        String::from_utf8_lossy(&gen_output.stderr)
    );

    let hs_dir = find_generated_dir(tmp_path, "test")
        .expect("no generated directory found starting with 'test'");
    eprintln!("Generated HS directory: {}", hs_dir.display());

    // Read the .onion hostname
    let hostname_raw = fs::read_to_string(hs_dir.join("hostname")).expect("failed to read hostname");
    let onion_host = hostname_raw.trim().to_string();
    eprintln!("Onion address: {onion_host}");
    assert!(
        onion_host.ends_with(".onion"),
        "unexpected hostname format: {onion_host}"
    );

    // --- 3. Set permissions ---
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hs_dir, fs::Permissions::from_mode(0o700))
            .expect("failed to chmod HS directory");
    }

    let data_dir = tmp_path.join("data");
    fs::create_dir_all(&data_dir).expect("failed to create data directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
            .expect("failed to chmod data directory");
    }

    // --- 4. Write torrc ---
    let socks_port = find_free_port();
    let torrc_path = tmp_path.join("torrc");
    let torrc_content = format!(
        "DataDirectory {data_dir}\n\
         SocksPort {socks_port}\n\
         HiddenServiceDir {hs_dir}\n\
         HiddenServicePort 80 127.0.0.1:{echo_port}\n",
        data_dir = data_dir.display(),
        socks_port = socks_port,
        hs_dir = hs_dir.display(),
        echo_port = echo_port,
    );
    fs::write(&torrc_path, &torrc_content).expect("failed to write torrc");
    eprintln!("torrc contents:\n{torrc_content}");

    // --- 5. Spawn Tor ---
    let tor_child = Command::new("tor")
        .args(["-f", &torrc_path.to_string_lossy()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start tor");

    let mut tor_guard = TorProcess::new(tor_child);
    let child = tor_guard.child.as_mut().unwrap();

    // Capture stdout and stderr in background threads
    let log = Arc::new(Mutex::new(String::new()));
    let bootstrapped = Arc::new(AtomicBool::new(false));

    let stdout = child.stdout.take().expect("failed to take tor stdout");
    let stderr = child.stderr.take().expect("failed to take tor stderr");

    // Spawn log readers
    let log_clone = Arc::clone(&log);
    let boot_clone = Arc::clone(&bootstrapped);
    let stdout_handle = std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        use std::io::BufRead;
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    eprintln!("[tor stdout] {line}");
                    let mut log = log_clone.lock().unwrap();
                    log.push_str(&line);
                    log.push('\n');
                    if line.contains("Bootstrapped 100%") {
                        boot_clone.store(true, Ordering::Release);
                    }
                }
                Err(_) => break,
            }
        }
    });

    let log_clone2 = Arc::clone(&log);
    let boot_clone2 = Arc::clone(&bootstrapped);
    let stderr_handle = std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        use std::io::BufRead;
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    eprintln!("[tor stderr] {line}");
                    let mut log = log_clone2.lock().unwrap();
                    log.push_str(&line);
                    log.push('\n');
                    if line.contains("Bootstrapped 100%") {
                        boot_clone2.store(true, Ordering::Release);
                    }
                }
                Err(_) => break,
            }
        }
    });

    // --- 6. Wait for bootstrap ---
    let bootstrap_timeout = Duration::from_secs(120);
    let start = Instant::now();
    eprintln!("Waiting for Tor to bootstrap (timeout: {bootstrap_timeout:?})...");

    while !bootstrapped.load(Ordering::Acquire) {
        if start.elapsed() > bootstrap_timeout {
            let log_snapshot = log.lock().unwrap().clone();
            tor_guard.kill();
            echo_stop.store(true, Ordering::Relaxed);
            panic!(
                "Tor did not bootstrap within {:?}.\nTor log:\n{}",
                bootstrap_timeout, log_snapshot
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "Tor bootstrapped in {:.1}s",
        start.elapsed().as_secs_f64()
    );

    // --- 7. Connect through SOCKS5 and verify echo ---
    let retry_timeout = Duration::from_secs(180);
    let retry_start = Instant::now();
    let payload = b"hello onion world!";
    let mut last_err = String::new();
    let mut success = false;

    eprintln!("Attempting SOCKS5 connection to {onion_host}:80 via 127.0.0.1:{socks_port}...");

    while retry_start.elapsed() < retry_timeout {
        match socks5_connect(socks_port, &onion_host, 80) {
            Ok(mut stream) => {
                eprintln!("SOCKS5 connected! Sending payload...");
                if let Err(e) = stream.write_all(payload) {
                    last_err = format!("write failed: {e}");
                    eprintln!("  {last_err}, retrying...");
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
                // Read back exactly payload.len() bytes (don't rely on EOF
                // propagation through Tor — half-close doesn't always work)
                let mut response = vec![0u8; payload.len()];
                match stream.read_exact(&mut response) {
                    Ok(_) => {
                        if response == payload {
                            success = true;
                            eprintln!("Echo response matches payload!");
                            break;
                        } else {
                            last_err = format!(
                                "echo mismatch: expected {:?}, got {:?}",
                                String::from_utf8_lossy(payload),
                                String::from_utf8_lossy(&response)
                            );
                            eprintln!("  {last_err}, retrying...");
                        }
                    }
                    Err(e) => {
                        last_err = format!("read failed: {e}");
                        eprintln!("  {last_err}, retrying...");
                    }
                }
            }
            Err(e) => {
                last_err = format!("SOCKS5 connect failed: {e}");
                eprintln!("  {last_err}, retrying in 10s...");
            }
        }
        std::thread::sleep(Duration::from_secs(10));
    }

    // --- 8. Cleanup ---
    tor_guard.kill();
    echo_stop.store(true, Ordering::Relaxed);

    // Wait for log reader threads to finish
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
    let _ = echo_handle.join();

    assert!(
        success,
        "Failed to echo through .onion service within {:?}. Last error: {last_err}",
        retry_timeout,
    );

    eprintln!("SUCCESS: Full end-to-end .onion echo test passed!");
}
