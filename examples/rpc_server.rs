//! # Local JSON-RPC server + dispatch
//!
//! Starts the loopback JSON-RPC server (`127.0.0.1`, bearer token), then:
//!
//! 1. checks the unauthenticated `GET /health` probe;
//! 2. calls `POST /rpc` over a raw TCP connection with
//!    `Authorization: Bearer <token>` (the exact wire format the HTTP
//!    transport uses);
//! 3. calls the same method through [`corduit::rpc::dispatch`] directly —
//!    the single dispatch table that FFI, HTTP and WebSocket all share.
//!
//! ```bash
//! cargo run --example rpc_server
//! ```

use corduit::api::{get_rpc_server_status, start_rpc_server, stop_rpc_server};
use corduit::rpc::dispatch;
use std::io::{Read, Write};
use std::net::TcpStream;

/// Send one HTTP/1.1 request and return the response body (headers dropped).
fn http_request(addr: &str, raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(raw.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    // Split header block from body at the first blank line. The server closes
    // the connection because every request below carries `Connection: close`.
    let text = String::from_utf8_lossy(&response);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    Ok(body.trim().to_string())
}

/// The server's accept loop runs on a background thread; poll the status until
/// it reports running (bounded wait, so a broken bind fails fast).
fn wait_ready(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let status = get_rpc_server_status()?;
        if status.running {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(format!("RPC server on 127.0.0.1:{port} did not start").into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("CORDUIT_RPC_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(17895);
    let token = "example-token";

    start_rpc_server(port, Some(token.to_string()))?;
    wait_ready(port)?;

    let status = get_rpc_server_status()?;
    println!(
        "rpc server running = {}, addr = {:?}, token_set = {}",
        status.running, status.addr, status.token_set
    );

    let addr = format!("127.0.0.1:{port}");

    // 1. Health probe (unauthenticated by design).
    let health = http_request(
        &addr,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    println!("GET /health -> {health}");

    // 2. POST /rpc with the bearer token.
    let payload = r#"{"method":"get_version"}"#;
    let request = format!(
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let response = http_request(&addr, &request)?;
    println!("POST /rpc get_version -> {response}");

    // 3. Same method through the typed dispatch table.
    let value = dispatch("get_version", &nextjson::Value::Null)?;
    println!("dispatch(get_version) -> {value}");

    stop_rpc_server()?;
    let status = get_rpc_server_status()?;
    println!("rpc server running = {}", status.running);
    Ok(())
}
