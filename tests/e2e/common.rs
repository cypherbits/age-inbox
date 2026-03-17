use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

pub struct E2eServer {
    pub base_url: String,
    _vaults_dir: tempfile::TempDir,
    child: tokio::process::Child,
}

impl Drop for E2eServer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl E2eServer {
    pub async fn shutdown(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener
        .local_addr()
        .expect("failed to read local addr")
        .port()
}

fn resolve_binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_age-inbox-server") {
        return PathBuf::from(path);
    }

    if let Ok(path) = std::env::var("CARGO_BIN_EXE_age_inbox_server") {
        return PathBuf::from(path);
    }

    panic!("missing CARGO_BIN_EXE_age-inbox-server env var; run with `cargo test`");
}

pub async fn spawn_server() -> E2eServer {
    let port = find_free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let vaults_dir = tempfile::tempdir().expect("failed to create temp vault dir");

    let binary = resolve_binary_path();
    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--vaults-dir")
        .arg(vaults_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().expect("failed to spawn API server process");

    wait_until_ready(&base_url).await;

    E2eServer {
        base_url,
        _vaults_dir: vaults_dir,
        child,
    }
}

async fn wait_until_ready(base_url: &str) {
    let client = reqwest::Client::new();

    for _ in 0..80 {
        match client.get(format!("{base_url}/inbox")).send().await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }

    panic!("server did not become ready at {base_url}");
}

