use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Get an OS-assigned free port
pub async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Get a minimal valid config TOML string
pub fn minimal_config(ssh_port: u16, password_hash: &str) -> String {
    format!(
        r##"
[server]
ssh_listen = "127.0.0.1:{ssh_port}"
host_key_path = "/tmp/sks5-test-host-key"

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    )
}
