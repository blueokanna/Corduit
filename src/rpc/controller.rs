//! External controller (`external-controller`): the REST control protocol the
//! dashboards that already exist speak.
//!
//! A dashboard implements exactly one control protocol, and this is it, so the
//! route paths and the payload shapes below are a **compatibility contract**
//! rather than a design of our own — that is what makes the engine drivable
//! from an ecosystem we did not write. Where the contract cannot be honoured
//! truthfully, the deviation is documented at the route instead of being
//! papered over with a plausible-looking value.
//!
//! Every route is a thin translation onto [`crate::rpc::dispatch`], the same
//! method table the C ABI and the JSON-RPC server use. Nothing here reaches
//! into the engine directly, which is what keeps the two protocols from
//! drifting apart behaviourally: a route that cannot be expressed through the
//! dispatch table is a missing engine capability, not a controller feature.
//!
//! # Security
//!
//! The controller is a full remote control for the proxy: it switches the
//! proxy mode, selects outbounds and tears down connections. It is therefore
//! guarded twice.
//!
//! * When `secret` is set, every request must present it as
//!   `Authorization: Bearer <secret>`. A bare secret in the same header is
//!   also accepted, because that is what deployed dashboards send. The
//!   comparison is constant-time ([`crate::crypto::util::ct_eq`]).
//! * Binding to an address that is not loopback *without* a secret is refused
//!   at bind time ([`ExternalControllerConfig::guard`]), so a misconfiguration
//!   cannot publish an open controller to the local network. This is the one
//!   incident every one of these proxies has had at least once.
//!
//! # Deviations from the reference protocol
//!
//! Each of these is a deliberate, documented difference rather than an
//! oversight. They are listed here because a dashboard author needs to know
//! them up front, not after a timeout.
//!
//! * `/traffic` and `/memory` answer with a **single sample** instead of a
//!   stream. Streamed bodies built with `courierust_body::channel` deliver
//!   nothing through `serve_connection` (measured: no response bytes at all in
//!   ten seconds, while every buffered route answers immediately, and the
//!   connection then fails to shut down cleanly). A route that hangs a
//!   dashboard is worse than one that does not stream.
//! * There is no `/logs` route. The reference streams it; the engine's log
//!   accessor returns a snapshot, and the same streamed-body limitation
//!   applies.
//! * `GET /connections` reports the engine's rule string whole in `rule` and
//!   leaves `rulePayload` empty, and `chains` holds the single outbound the
//!   connection left through rather than the full selection chain — that is
//!   what the engine records. `sourceIP` and `sourcePort` are empty as well,
//!   because the engine keeps no client address at all; presenting the
//!   destination's address as a source would be wrong data, not missing data.
//! * `PATCH /configs` applies `mode` and `log-level` only. The ports and
//!   `allow-lan` would mean rebinding a listener at runtime, so they are
//!   refused with a message instead of being accepted and ignored.
//! * `PUT /configs` reloads from a `path`; an inline configuration document is
//!   not accepted, because the engine's reload path is file-based.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use courierust::courierust_body::Body;
use courierust::courierust_http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use courierust::courierust_server::{serve_connection, Handler, ServerConfig};

use crate::common::listener::ConnectionListener;
use crate::crypto::util::ct_eq;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Largest request head we will parse.
const MAX_REQUEST_HEAD: usize = 64 * 1024;
/// Largest request body we will read. `PUT /configs` carries a path, not a
/// whole configuration, so this stays small on purpose.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// Concurrent connections served at once.
const MAX_CONNECTIONS: usize = 64;
/// Ceiling on a single connection's lifetime.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(600);
/// Default timeout for `GET /proxies/:name/delay` when the client does not
/// ask for one.
const DEFAULT_DELAY_TIMEOUT_MS: u64 = 5000;
/// Default probe URL for a delay test. A latency probe only needs to know how
/// long a complete round trip takes, so the endpoint answers `204` and nothing
/// else is transferred.
const DEFAULT_DELAY_URL: &str = "http://www.gstatic.com/generate_204";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Where the controller listens and what protects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalControllerConfig {
    /// The address to bind. Port `0` asks the OS for one.
    pub addr: SocketAddr,
    /// The shared secret. Empty means "no authentication", which is only
    /// allowed on loopback.
    pub secret: String,
}

impl ExternalControllerConfig {
    /// Parse `general.external-controller` (`host:port`, `:port`, `port`)
    /// together with `general.secret`.
    ///
    /// A missing host (`:9090`) means "every interface", and a bare port is
    /// accepted as the same for convenience. Both parse to an unspecified
    /// address, which [`Self::guard`] then holds to the same secret requirement
    /// as any other non-loopback bind.
    pub fn parse(external_controller: &str, secret: Option<&str>) -> Result<Self, String> {
        let raw = external_controller.trim();
        if raw.is_empty() {
            return Err("external-controller is empty".to_string());
        }

        let candidate = if let Some(rest) = raw.strip_prefix(':') {
            format!("0.0.0.0:{rest}")
        } else if !raw.contains(':') {
            // A bare port number, e.g. `9090`.
            format!("0.0.0.0:{raw}")
        } else {
            raw.to_string()
        };

        let addr: SocketAddr = candidate
            .parse()
            .map_err(|_| format!("external-controller `{raw}` is not a host:port address"))?;

        Ok(Self {
            addr,
            secret: secret.unwrap_or_default().to_string(),
        })
    }

    /// Whether a request must present the secret.
    pub fn secret_required(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Reject a configuration that would expose an unauthenticated remote
    /// control.
    ///
    /// A secret is required for any listener that is not loopback, because an
    /// open controller can select outbounds and drop connections for anyone
    /// who can reach the port.
    pub fn guard(&self) -> Result<(), String> {
        if !self.addr.ip().is_loopback() && self.secret.is_empty() {
            return Err(format!(
                "refusing to expose the external controller on {} without a secret: \
                 set `secret`, or bind to 127.0.0.1",
                self.addr
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A bound, not yet running controller.
pub struct ExternalController {
    listener: Option<std::net::TcpListener>,
    addr: SocketAddr,
    secret: Arc<str>,
    secret_required: bool,
    config: Arc<ServerConfig>,
}

impl ExternalController {
    /// Bind the controller. Fails with `InvalidInput` when
    /// [`ExternalControllerConfig::guard`] rejects the configuration.
    pub fn bind(config: ExternalControllerConfig) -> std::io::Result<Self> {
        config
            .guard()
            .map_err(|reason| std::io::Error::new(std::io::ErrorKind::InvalidInput, reason))?;

        let listener = std::net::TcpListener::bind(config.addr)?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let server_config = ServerConfig {
            read_timeout: Some(CONNECTION_LIFETIME),
            max_header_list: MAX_REQUEST_HEAD,
            max_body: MAX_REQUEST_BODY,
            http2: false,
            tls: None,
            handshake_timeout: None,
            max_connections: MAX_CONNECTIONS,
            ..ServerConfig::default()
        };

        Ok(Self {
            listener: Some(listener),
            addr,
            secret: Arc::from(config.secret.as_str()),
            secret_required: !config.secret.is_empty(),
            config: Arc::new(server_config),
        })
    }

    /// The bound address (useful when binding to port `0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Start serving on a background thread.
    pub fn spawn(mut self) -> ExternalControllerHandle {
        let listener = self
            .listener
            .take()
            .expect("controller listener consumed before spawn");
        let handler = ControllerHandler {
            secret: Arc::clone(&self.secret),
        };
        let config = Arc::clone(&self.config);

        let mut server = ConnectionListener::new(listener, self.addr, MAX_CONNECTIONS);
        server
            .start("corduit-controller", move |stream, peer| {
                if let Err(e) = serve_connection(stream, &handler, config.as_ref()) {
                    tracing::debug!("external controller connection from {peer} ended: {e}");
                }
            })
            .expect("start external controller accept loop");

        ExternalControllerHandle {
            addr: self.addr,
            secret_required: self.secret_required,
            server: parking_lot::Mutex::new(Some(server)),
        }
    }
}

/// A running controller.
pub struct ExternalControllerHandle {
    addr: SocketAddr,
    secret_required: bool,
    server: parking_lot::Mutex<Option<ConnectionListener>>,
}

impl ExternalControllerHandle {
    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether requests must present a secret.
    pub fn secret_required(&self) -> bool {
        self.secret_required
    }

    /// Whether the accept loop is still running.
    pub fn is_running(&self) -> bool {
        self.server
            .lock()
            .as_ref()
            .map(ConnectionListener::is_running)
            .unwrap_or(false)
    }

    /// Request a graceful shutdown and wait for the accept loop to exit.
    /// Idempotent. Connections already being served finish on their own
    /// threads, bounded by the connection lifetime.
    pub fn stop(&self) {
        let mut server = self.server.lock().take();
        if let Some(server) = server.as_mut() {
            server.stop();
        }
    }

    /// Stop in one call (the handle is consumed).
    pub fn join(self) {
        self.stop();
    }
}

impl Drop for ExternalControllerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

/// The HTTP handler behind the controller.
struct ControllerHandler {
    secret: Arc<str>,
}

impl Handler for ControllerHandler {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        route(req, &self.secret)
    }
}

/// Authenticate and route one request.
fn route(req: Request<Body>, secret: &str) -> Response<Body> {
    let method = req.method.clone();

    if method == Method::OPTIONS {
        return cors_response(StatusCode::NO_CONTENT);
    }

    if !authorized(&req, secret) {
        return unauthorized();
    }

    let path = req.uri.path().to_string();
    let segments: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(percent_decode)
        .collect();
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let query = req.uri.query().unwrap_or_default().to_string();

    match (method, parts.as_slice()) {
        (Method::GET, ["version"]) => handle_version(),

        (Method::GET, ["configs"]) => handle_configs_get(),
        (Method::PATCH, ["configs"]) => handle_configs_patch(&req),
        (Method::PUT, ["configs"]) => handle_configs_put(&req),

        (Method::GET, ["proxies"]) => handle_proxies(),
        (Method::GET, ["proxies", name]) => handle_proxy_get(name),
        (Method::PUT, ["proxies", name]) => handle_proxy_select(name, &req),
        (Method::GET, ["proxies", name, "delay"]) => handle_proxy_delay(name, &query),

        (Method::GET, ["rules"]) => handle_rules(),

        (Method::GET, ["connections"]) => handle_connections(),
        (Method::DELETE, ["connections"]) => handle_connections_close_all(),
        (Method::DELETE, ["connections", id]) => handle_connection_close(id),

        (Method::GET, ["traffic"]) => handle_traffic(),
        (Method::GET, ["memory"]) => handle_memory(),

        (Method::GET, []) => handle_index(),

        _ => not_found(),
    }
}

/// Whether the request presents the shared secret.
///
/// With an empty secret configured, anything is accepted — the bind guard has
/// already established that only loopback can be reached in that case.
fn authorized(req: &Request<Body>, secret: &str) -> bool {
    if secret.is_empty() {
        return true;
    }
    let Some(presented) = req
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    // Both `Bearer <secret>` and the bare secret are accepted.
    let presented = presented
        .strip_prefix("Bearer ")
        .unwrap_or(presented)
        .trim();
    ct_eq(presented.as_bytes(), secret.as_bytes())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `GET /version`.
///
/// `premium` and `meta` advertise vendor extensions (provider hot-reloading,
/// `/providers/*`, rule-set APIs). This controller implements the subset the
/// common protocol defines, so a dashboard that trusted those flags would call
/// routes that do not exist here. Reporting `false` makes it fall back to the
/// common API, which is the honest answer.
fn handle_version() -> Response<Body> {
    let version = call("get_version", &null_args())
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let mut map = object();
    put(&mut map, "version", nextjson::Value::from(version));
    put(&mut map, "premium", nextjson::Value::from(false));
    put(&mut map, "meta", nextjson::Value::from(false));
    json_ok(nextjson::Value::Object(map))
}

/// `GET /` — a short index, so a human who opens the port in a browser can see
/// that the controller is alive and authenticated.
fn handle_index() -> Response<Body> {
    let mut map = object();
    put(
        &mut map,
        "controller",
        nextjson::Value::from("Corduit external controller"),
    );
    put(
        &mut map,
        "routes",
        nextjson::Value::from(vec![
            nextjson::Value::from("GET /version"),
            nextjson::Value::from("GET /configs"),
            nextjson::Value::from("PATCH /configs"),
            nextjson::Value::from("PUT /configs"),
            nextjson::Value::from("GET /proxies"),
            nextjson::Value::from("GET /proxies/:name"),
            nextjson::Value::from("PUT /proxies/:name"),
            nextjson::Value::from("GET /proxies/:name/delay"),
            nextjson::Value::from("GET /rules"),
            nextjson::Value::from("GET /connections"),
            nextjson::Value::from("DELETE /connections"),
            nextjson::Value::from("DELETE /connections/:id"),
            nextjson::Value::from("GET /traffic"),
            nextjson::Value::from("GET /memory"),
        ]),
    );
    json_ok(nextjson::Value::Object(map))
}

/// `GET /configs`.
fn handle_configs_get() -> Response<Body> {
    let snapshot = match crate::api::get_general_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };

    let mut map = object();

    put(
        &mut map,
        "mode",
        nextjson::Value::from(mode_name(snapshot.runtime_mode, &snapshot.mode)),
    );
    put(
        &mut map,
        "log-level",
        nextjson::Value::from(snapshot.log_level),
    );
    put(
        &mut map,
        "allow-lan",
        nextjson::Value::from(snapshot.allow_lan),
    );
    put(
        &mut map,
        "bind-address",
        nextjson::Value::from(snapshot.bind_address),
    );
    put(&mut map, "ipv6", nextjson::Value::from(snapshot.ipv6));
    put(
        &mut map,
        "tcp-concurrent",
        nextjson::Value::from(snapshot.tcp_concurrent),
    );
    if let Some(port) = snapshot.socks_port {
        put(&mut map, "socks-port", nextjson::Value::from(port));
    }
    if let Some(port) = snapshot.mixed_port {
        put(&mut map, "mixed-port", nextjson::Value::from(port));
    }
    if let Ok(dns) = call("get_dns_config", &null_args()) {
        put(&mut map, "dns", dns);
    }

    json_ok(nextjson::Value::Object(map))
}

/// `PATCH /configs` — the fields that can change while the engine runs.
///
/// Only `mode` and `log-level` are applied. The protocol also defines the ports
/// and `allow-lan` on this route, which would mean rebinding a listener at
/// runtime; that is not implemented, and it is refused rather than accepted and
/// ignored.
fn handle_configs_patch(req: &Request<Body>) -> Response<Body> {
    let Some(body) = parse_body(req) else {
        return json_error(StatusCode::BAD_REQUEST, "request body is not valid JSON");
    };

    let mut applied: Vec<&str> = Vec::new();

    if let Some(mode) = str_field(&body, "mode") {
        let Some(runtime) = runtime_mode(&mode) else {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("unknown mode `{mode}`: expected `rule`, `global` or `direct`"),
            );
        };
        if let Err(error) = call(
            "set_proxy_mode",
            &args(&[("mode", num_i64(runtime as i64))]),
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error);
        }
        applied.push("mode");
    }

    if let Some(level) = str_field(&body, "log-level") {
        if let Err(error) = call("set_log_level", &args(&[("level", text(level))])) {
            return json_error(StatusCode::BAD_REQUEST, &error);
        }
        applied.push("log-level");
    }

    if applied.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "no supported field to patch: this controller applies `mode` and `log-level`",
        );
    }
    empty(StatusCode::NO_CONTENT)
}

/// `PUT /configs` — reload from a file.
///
/// The protocol also allows a whole configuration object in the body. This
/// controller does not: the engine's reload path is file-based, and accepting
/// an inline document would mean inventing a second configuration pipeline.
fn handle_configs_put(req: &Request<Body>) -> Response<Body> {
    let Some(body) = parse_body(req) else {
        return json_error(StatusCode::BAD_REQUEST, "request body is not valid JSON");
    };

    let Some(path) = str_field(&body, "path") else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "reload requires a `path` field pointing at a configuration file",
        );
    };

    match call(
        "reload_config_from_file",
        &args(&[("config_path", text(path))]),
    ) {
        Ok(_) => empty(StatusCode::NO_CONTENT),
        Err(error) => json_error(StatusCode::BAD_REQUEST, &error),
    }
}

/// `GET /proxies` — every outbound, plus every policy group.
fn handle_proxies() -> Response<Body> {
    let table = match proxy_table() {
        Ok(table) => table,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };

    let mut map = object();
    put(&mut map, "proxies", nextjson::Value::Object(table));
    json_ok(nextjson::Value::Object(map))
}

/// Build the proxy table, keyed by name.
///
/// Both `/proxies` and `/proxies/:name` are built from this one function, so a
/// single object can never differ from the object the table serves: a
/// dashboard must not see two shapes for the same proxy.
fn proxy_table() -> Result<nextjson::Map, String> {
    let proxies = call("get_proxies", &null_args())?;
    let groups = call("get_proxy_groups", &null_args()).unwrap_or_else(|_| empty_array());

    let mut table = object();
    for proxy in array_items(&proxies) {
        let Some(name) = str_field(&proxy, "tag") else {
            continue;
        };
        let mut entry = object();
        put(&mut entry, "name", nextjson::Value::from(name.clone()));
        put(
            &mut entry,
            "type",
            nextjson::Value::from(str_field(&proxy, "protocol_type").unwrap_or_default()),
        );
        if let Some(server) = str_field(&proxy, "server") {
            put(&mut entry, "server", nextjson::Value::from(server));
        }
        if let Some(port) = u64_field(&proxy, "port") {
            put(&mut entry, "port", nextjson::Value::from(port));
        }
        if let Some(alive) = bool_field(&proxy, "alive") {
            put(&mut entry, "alive", nextjson::Value::from(alive));
        }
        put(&mut entry, "history", delay_history(&proxy));
        put(&mut entry, "all", empty_array());
        put(&mut entry, "now", nextjson::Value::from(String::new()));
        table.insert(name, nextjson::Value::Object(entry));
    }

    for group in array_items(&groups) {
        let Some(name) = str_field(&group, "tag") else {
            continue;
        };
        let mut entry = object();
        put(&mut entry, "name", nextjson::Value::from(name.clone()));
        put(
            &mut entry,
            "type",
            nextjson::Value::from(str_field(&group, "group_type").unwrap_or_default()),
        );
        put(
            &mut entry,
            "all",
            nextjson::Value::Array(
                array_items(&value_of(&group, "proxies"))
                    .into_iter()
                    .filter_map(|item| item.as_str().map(nextjson::Value::from))
                    .collect(),
            ),
        );
        put(
            &mut entry,
            "now",
            nextjson::Value::from(str_field(&group, "selected").unwrap_or_default()),
        );
        put(&mut entry, "history", empty_array());
        table.insert(name, nextjson::Value::Object(entry));
    }

    Ok(table)
}

/// `GET /proxies/:name` — one outbound or group.
fn handle_proxy_get(name: &str) -> Response<Body> {
    let table = match proxy_table() {
        Ok(table) => table,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };
    match table.get(name) {
        Some(entry) => json_ok(entry.clone()),
        None => not_found(),
    }
}

/// `PUT /proxies/:name` — select a member inside a group.
fn handle_proxy_select(name: &str, req: &Request<Body>) -> Response<Body> {
    let Some(body) = parse_body(req) else {
        return json_error(StatusCode::BAD_REQUEST, "request body is not valid JSON");
    };
    let Some(selected) = str_field(&body, "name") else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "selecting a proxy requires a `name` field",
        );
    };

    match call(
        "select_proxy",
        &args(&[("group_tag", text(name)), ("proxy_tag", text(selected))]),
    ) {
        // A selection is answered with 204 and no body.
        Ok(_) => empty(StatusCode::NO_CONTENT),
        Err(error) => json_error(StatusCode::BAD_REQUEST, &error),
    }
}

/// `GET /proxies/:name/delay` — measure one proxy's latency.
///
/// A failed test answers 504, which is how a dashboard learns to show the proxy
/// as timed out; that is reproduced here rather than reported as a server error.
fn handle_proxy_delay(name: &str, query: &str) -> Response<Body> {
    let url = query_value(query, "url").unwrap_or_else(|| DEFAULT_DELAY_URL.to_string());
    let timeout = delay_timeout_ms(query);

    let params = args(&[
        ("tag", text(name)),
        ("test_url", text(url)),
        ("timeout_ms", nextjson::Value::from(timeout)),
    ]);

    match call("test_proxy_latency_dto", &params) {
        Ok(value) => {
            let latency = u64_field(&value, "latency_ms");
            match latency {
                Some(delay) => {
                    let mut map = object();
                    put(&mut map, "delay", nextjson::Value::from(delay));
                    json_ok(nextjson::Value::Object(map))
                }
                None => {
                    let message = str_field(&value, "error")
                        .unwrap_or_else(|| "latency test failed".to_string());
                    json_error(StatusCode::GATEWAY_TIMEOUT, &message)
                }
            }
        }
        Err(error) => json_error(StatusCode::GATEWAY_TIMEOUT, &error),
    }
}

/// `GET /rules`.
fn handle_rules() -> Response<Body> {
    let rules = match call("get_rules", &null_args()) {
        Ok(value) => value,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };

    let entries: Vec<nextjson::Value> = array_items(&rules)
        .iter()
        .map(|rule| {
            let mut entry = object();
            put(
                &mut entry,
                "type",
                nextjson::Value::from(rule_type_name(
                    &str_field(rule, "rule_type").unwrap_or_default(),
                )),
            );
            put(
                &mut entry,
                "payload",
                nextjson::Value::from(str_field(rule, "payload").unwrap_or_default()),
            );
            put(
                &mut entry,
                "proxy",
                nextjson::Value::from(str_field(rule, "outbound").unwrap_or_default()),
            );
            nextjson::Value::Object(entry)
        })
        .collect();

    let mut map = object();
    put(&mut map, "rules", nextjson::Value::Array(entries));
    json_ok(nextjson::Value::Object(map))
}

/// `GET /connections`.
///
/// Three deviations, all caused by what the engine records: `rule` carries the
/// engine's rule string whole instead of the `rule`/`rulePayload` split,
/// `chains` holds the single outbound the
/// connection left through rather than the full selection chain, and the
/// `sourceIP`/`sourcePort` fields are empty because the engine keeps no client
/// address.
fn handle_connections() -> Response<Body> {
    let connections = match call("get_connections_dto", &null_args()) {
        Ok(value) => value,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };
    let stats = call("get_traffic_stats_dto", &null_args())
        .unwrap_or_else(|_| nextjson::Value::Object(object()));

    let entries: Vec<nextjson::Value> = array_items(&connections)
        .iter()
        .map(connection_entry)
        .collect();

    let mut map = object();
    put(
        &mut map,
        "downloadTotal",
        nextjson::Value::from(u64_field(&stats, "total_download").unwrap_or(0)),
    );
    put(
        &mut map,
        "uploadTotal",
        nextjson::Value::from(u64_field(&stats, "total_upload").unwrap_or(0)),
    );
    put(&mut map, "connections", nextjson::Value::Array(entries));
    json_ok(nextjson::Value::Object(map))
}

/// Translate one `ConnectionDto` into the connection object this route serves.
fn connection_entry(connection: &nextjson::Value) -> nextjson::Value {
    let mut entry = object();
    put(
        &mut entry,
        "id",
        nextjson::Value::from(str_field(connection, "id").unwrap_or_default()),
    );
    put(
        &mut entry,
        "upload",
        nextjson::Value::from(u64_field(connection, "upload").unwrap_or(0)),
    );
    put(
        &mut entry,
        "download",
        nextjson::Value::from(u64_field(connection, "download").unwrap_or(0)),
    );

    let started = i64_field(connection, "start_time").unwrap_or_default();
    put(
        &mut entry,
        "start",
        nextjson::Value::from(epoch_to_rfc3339(started)),
    );

    let (_, destination_port) =
        split_host_port(&str_field(connection, "src_addr").unwrap_or_default());
    let destination_ip = str_field(connection, "dst_addr").unwrap_or_default();
    let host = str_field(connection, "dst_domain")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| destination_ip.clone());

    let mut metadata = object();
    put(&mut metadata, "network", nextjson::Value::from("tcp"));
    put(
        &mut metadata,
        "type",
        nextjson::Value::from(str_field(connection, "protocol").unwrap_or_default()),
    );
    put(
        &mut metadata,
        "sourceIP",
        nextjson::Value::from(String::new()),
    );
    put(
        &mut metadata,
        "sourcePort",
        nextjson::Value::from(String::new()),
    );
    put(
        &mut metadata,
        "destinationIP",
        nextjson::Value::from(destination_ip),
    );
    put(
        &mut metadata,
        "destinationPort",
        nextjson::Value::from(destination_port),
    );
    put(&mut metadata, "host", nextjson::Value::from(host));
    put(&mut entry, "metadata", nextjson::Value::Object(metadata));

    let outbound = str_field(connection, "outbound").unwrap_or_default();
    put(
        &mut entry,
        "rule",
        nextjson::Value::from(str_field(connection, "rule").unwrap_or_default()),
    );
    put(
        &mut entry,
        "rulePayload",
        nextjson::Value::from(String::new()),
    );
    put(
        &mut entry,
        "chains",
        nextjson::Value::Array(vec![nextjson::Value::from(outbound)]),
    );
    nextjson::Value::Object(entry)
}

/// `DELETE /connections` — close every connection.
fn handle_connections_close_all() -> Response<Body> {
    match call("close_all_connections_dto", &null_args()) {
        Ok(_) => empty(StatusCode::NO_CONTENT),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

/// `DELETE /connections/:id` — close one connection.
fn handle_connection_close(id: &str) -> Response<Body> {
    match call("close_connection_by_id", &args(&[("id", text(id))])) {
        Ok(_) => empty(StatusCode::NO_CONTENT),
        Err(error) => json_error(StatusCode::NOT_FOUND, &error),
    }
}

/// `GET /traffic` — the current rate sample.
///
/// **A deviation, measured rather than assumed.** The protocol streams this
/// endpoint (one JSON object per second). A streamed body built with
/// `courierust_body::channel` delivers nothing through `serve_connection`: with
/// an otherwise identical request, every buffered route answers immediately
/// while the streaming one produced no response bytes at all within ten
/// seconds, and the connection then failed to shut down cleanly. A route that
/// hangs a dashboard is worse than a route that does not stream, so this
/// reports one sample and the client polls.
///
/// `up`/`down` are the engine's per-interval counters; the lifetime totals are
/// on `GET /connections`.
fn handle_traffic() -> Response<Body> {
    let stats = match call("get_traffic_stats_dto", &null_args()) {
        Ok(stats) => stats,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    };

    let mut map = object();
    put(
        &mut map,
        "up",
        nextjson::Value::from(u64_field(&stats, "upload").unwrap_or(0)),
    );
    put(
        &mut map,
        "down",
        nextjson::Value::from(u64_field(&stats, "download").unwrap_or(0)),
    );
    json_ok(nextjson::Value::Object(map))
}

/// `GET /memory` — the engine's memory use (see `handle_traffic` for why this
/// answers once instead of streaming).
///
/// `inuse` is the engine process's resident memory in bytes (`sysinfo` reports
/// bytes) and `oslimit` the machine's total memory.
fn handle_memory() -> Response<Body> {
    let info = match crate::api::get_system_info() {
        Ok(info) => info,
        Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &format!("{error:?}")),
    };

    let mut map = object();
    put(&mut map, "inuse", nextjson::Value::from(info.memory_used));
    put(
        &mut map,
        "oslimit",
        nextjson::Value::from(info.memory_total),
    );
    json_ok(nextjson::Value::Object(map))
}

// ---------------------------------------------------------------------------
// Dispatch bridge
// ---------------------------------------------------------------------------

/// Call the shared dispatch surface.
fn call(method: &str, params: &nextjson::Value) -> Result<nextjson::Value, String> {
    crate::rpc::dispatch(method, params)
}

/// An absent argument object.
fn null_args() -> nextjson::Value {
    nextjson::Value::Object(object())
}

/// Build an argument object from pairs.
fn args(pairs: &[(&str, nextjson::Value)]) -> nextjson::Value {
    let mut map = object();
    for (key, value) in pairs {
        put(&mut map, key, value.clone());
    }
    nextjson::Value::Object(map)
}

/// A JSON string argument.
fn text(value: impl Into<String>) -> nextjson::Value {
    nextjson::Value::from(value.into())
}

/// A JSON integer argument.
fn num_i64(value: i64) -> nextjson::Value {
    nextjson::Value::from(value)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

/// A new empty object.
fn object() -> nextjson::Map {
    nextjson::Map::default()
}

/// Insert into an object.
fn put(map: &mut nextjson::Map, key: &str, value: nextjson::Value) {
    map.insert(key.to_string(), value);
}

/// An empty JSON array.
fn empty_array() -> nextjson::Value {
    nextjson::Value::Array(Vec::new())
}

/// The items of a JSON array (empty for anything else).
fn array_items(value: &nextjson::Value) -> Vec<nextjson::Value> {
    value.as_array().cloned().unwrap_or_default()
}

/// Read a field, treating a missing field as `Null`.
fn value_of(value: &nextjson::Value, key: &str) -> nextjson::Value {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .cloned()
        .unwrap_or(nextjson::Value::Null)
}

/// Read a string field, treating a missing or non-string field as absent.
fn str_field(value: &nextjson::Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// Read an unsigned field.
fn u64_field(value: &nextjson::Value, key: &str) -> Option<u64> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(|value| value.as_u64())
}

/// Read a signed field.
fn i64_field(value: &nextjson::Value, key: &str) -> Option<i64> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(|value| value.as_i64())
}

/// Read a boolean field.
fn bool_field(value: &nextjson::Value, key: &str) -> Option<bool> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(|value| value.as_bool())
}

/// The delay samples for a proxy, in the `history` shape the proxy object uses.
fn delay_history(proxy: &nextjson::Value) -> nextjson::Value {
    match u64_field(proxy, "latency_ms") {
        Some(delay) => {
            let mut sample = object();
            put(&mut sample, "time", nextjson::Value::from(now_rfc3339()));
            put(&mut sample, "delay", nextjson::Value::from(delay));
            nextjson::Value::Array(vec![nextjson::Value::Object(sample)])
        }
        None => empty_array(),
    }
}

// ---------------------------------------------------------------------------
// Values with a shape contract
// ---------------------------------------------------------------------------

/// The engine's runtime proxy mode → the mode string this protocol uses.
///
/// The runtime numbers are the engine's own convention, not this protocol's
/// (see `api::set_proxy_mode`): `1` global, `2` direct, `3` rule, anything else
/// meaning "no runtime override". In that last case the configured mode is
/// what routes traffic, so that is what is reported.
fn mode_name(runtime: i32, configured: &str) -> String {
    match runtime {
        1 => "global".to_string(),
        2 => "direct".to_string(),
        3 => "rule".to_string(),
        _ => configured.to_string(),
    }
}

/// The mode string → the number `set_proxy_mode` expects.
fn runtime_mode(mode: &str) -> Option<i32> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "global" => Some(1),
        "direct" => Some(2),
        "rule" => Some(3),
        _ => None,
    }
}

/// The engine's rule-type spelling → this protocol's spelling.
///
/// The engine spells rule types in lower case with `-` or `_`; the protocol
/// uses the upper-case, hyphenated form (`DOMAIN-SUFFIX`, `IP-CIDR`).
fn rule_type_name(spelling: &str) -> String {
    spelling.replace('_', "-").to_ascii_uppercase()
}

/// Split `"host:port"` into its parts, tolerating IPv6 in brackets and a
/// missing port.
fn split_host_port(addr: &str) -> (String, String) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.to_string());
        }
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host.to_string(), port.to_string()),
        _ => (addr.to_string(), String::new()),
    }
}

/// Decode `%XX` escapes in a URL path segment.
///
/// Group and proxy names are user data: they contain spaces and non-ASCII
/// characters, which every dashboard percent-encodes. A segment that is not
/// valid UTF-8 after decoding is taken as-is, so a malformed name simply fails
/// to match instead of failing the request.
fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = (bytes[i + 1] as char).to_digit(16);
            let low = (bytes[i + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Read a query parameter's value.
fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| percent_decode(value))
    })
}

/// The `timeout` of a delay test, in milliseconds.
///
/// `?timeout=` is in milliseconds and the dispatch argument is `timeout_ms`, so
/// the value is passed through unchanged; a missing or unparsable value falls
/// back to the default.
fn delay_timeout_ms(query: &str) -> u64 {
    query_value(query, "timeout")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DELAY_TIMEOUT_MS)
}

/// Format a Unix timestamp as RFC 3339 in UTC.
///
/// A value too small to be a wall-clock time cannot be one — it would be a
/// duration — so no date is claimed for it.
fn epoch_to_rfc3339(seconds: i64) -> String {
    const PLAUSIBLE_TIMESTAMP: i64 = 1_000_000_000;
    if seconds < PLAUSIBLE_TIMESTAMP {
        return String::new();
    }
    let days = seconds.div_euclid(86_400);
    let remainder = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (remainder / 3600, (remainder % 3600) / 60, remainder % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The current time as RFC 3339 in UTC.
fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default();
    epoch_to_rfc3339(seconds)
}

/// Days since the Unix epoch → `(year, month, day)`, using Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Parse a request body as JSON.
fn parse_body(req: &Request<Body>) -> Option<nextjson::Value> {
    let bytes = req.body.as_bytes()?;
    if bytes.is_empty() {
        return None;
    }
    nextjson::from_slice::<nextjson::Value>(bytes).ok()
}

/// A `200` JSON response.
fn json_ok(value: nextjson::Value) -> Response<Body> {
    let body = nextjson::to_string(&value)
        .unwrap_or_else(|_| r#"{"error":"response encode failed"}"#.to_string());
    json_response(StatusCode::OK, &body)
}

/// An error response. The protocol reports failures as `{"message": ...}`.
fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    let mut map = object();
    put(
        &mut map,
        "message",
        nextjson::Value::from(message.to_string()),
    );
    let body = nextjson::to_string(&nextjson::Value::Object(map))
        .unwrap_or_else(|_| r#"{"message":"request failed"}"#.to_string());
    json_response(status, &body)
}

/// A `404` for an unrouted path or an unknown object.
fn not_found() -> Response<Body> {
    json_error(StatusCode::NOT_FOUND, "not found")
}

/// A `401`, without saying whether the secret was wrong or absent.
fn unauthorized() -> Response<Body> {
    json_error(StatusCode::UNAUTHORIZED, "unauthorized")
}

/// An empty response.
fn empty(status: StatusCode) -> Response<Body> {
    let mut response = Response::with_status(status);
    add_cors(&mut response);
    response
}

/// A JSON response with permissive CORS headers.
fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::with_status(status);
    response.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    add_cors(&mut response);
    response.body = Body::from(body.as_bytes().to_vec());
    response
}

/// A CORS preflight response.
fn cors_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::with_status(status);
    add_cors(&mut response);
    response
}

/// CORS headers for a browser dashboard.
///
/// Deliberately wider than the JSON-RPC server's: this API is its own protocol
/// with `PUT`, `PATCH` and `DELETE` routes, and it is a *preflighted* API, so
/// the origin policy is not what protects it — the secret is.
fn add_cors(response: &mut Response<Body>) {
    response.headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    response.headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
    );
    response.headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("Authorization, Content-Type"),
    );
    response.headers.insert(
        HeaderName::from_static("access-control-max-age"),
        HeaderValue::from_static("86400"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    const SECRET: &str = "s3cret-token";

    fn spawn_loopback(secret: &str) -> ExternalControllerHandle {
        let config = ExternalControllerConfig::parse("127.0.0.1:0", Some(secret)).expect("parse");
        ExternalController::bind(config).expect("bind").spawn()
    }

    /// Raw HTTP/1.1 client (test-only, plain `std` sockets).
    fn http_request(
        addr: SocketAddr,
        method: &str,
        path: &str,
        secret: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(secret) = secret {
            req.push_str(&format!("Authorization: Bearer {secret}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream.write_all(req.as_bytes()).unwrap();

        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp);
        let text = String::from_utf8_lossy(&resp);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn get(addr: SocketAddr, path: &str, secret: Option<&str>) -> (u16, String) {
        http_request(addr, "GET", path, secret, "")
    }

    fn json(addr: SocketAddr, path: &str, secret: Option<&str>) -> nextjson::Value {
        let (status, body) = get(addr, path, secret);
        assert_eq!(status, 200, "{path} → {body}");
        nextjson::from_str(&body).unwrap_or_else(|e| panic!("{path} is not JSON ({e}): {body}"))
    }

    // -- configuration -----------------------------------------------------

    #[test]
    fn bare_port_means_every_interface() {
        let config = ExternalControllerConfig::parse("9090", None).expect("parse");
        assert_eq!(config.addr.to_string(), "0.0.0.0:9090");
        assert!(!config.secret_required());
        // ...and that is exactly the configuration that must be refused.
        assert!(config.guard().is_err());
    }

    #[test]
    fn colon_port_means_every_interface() {
        let config = ExternalControllerConfig::parse(":9090", None).expect("parse");
        assert_eq!(config.addr.to_string(), "0.0.0.0:9090");
        assert!(config.guard().is_err());
    }

    #[test]
    fn a_secret_permits_a_public_bind() {
        let config =
            ExternalControllerConfig::parse("0.0.0.0:9090", Some("hunter2")).expect("parse");
        assert_eq!(config.addr.to_string(), "0.0.0.0:9090");
        assert!(config.secret_required());
        assert!(config.guard().is_ok());
    }

    #[test]
    fn loopback_without_a_secret_is_allowed() {
        let config = ExternalControllerConfig::parse("127.0.0.1:9090", None).expect("parse");
        assert!(config.guard().is_ok());

        let config = ExternalControllerConfig::parse("[::1]:9090", None).expect("parse");
        assert!(config.guard().is_ok(), "IPv6 loopback is loopback");
    }

    #[test]
    fn host_names_are_not_addresses() {
        let error = ExternalControllerConfig::parse("localhost:9090", None).expect_err("must fail");
        assert!(error.contains("host:port"), "{error}");
    }

    #[test]
    fn an_empty_external_controller_is_refused() {
        assert!(ExternalControllerConfig::parse("   ", None).is_err());
    }

    #[test]
    fn binding_a_public_address_without_a_secret_is_refused() {
        let config = ExternalControllerConfig::parse("0.0.0.0:0", None).expect("parse");
        // `expect_err` would require the controller to be `Debug`, which its
        // internals have no reason to be.
        let error = match ExternalController::bind(config) {
            Ok(_) => panic!("a public bind without a secret must be refused"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("without a secret"), "{error}");
    }

    // -- authentication ----------------------------------------------------

    #[test]
    fn a_request_without_the_secret_is_rejected() {
        let server = spawn_loopback(SECRET);
        let (status, body) = get(server.addr(), "/version", None);
        assert_eq!(status, 401, "{body}");
        assert!(body.contains("unauthorized"), "{body}");
        server.stop();
    }

    #[test]
    fn a_wrong_secret_is_rejected() {
        let server = spawn_loopback(SECRET);
        let (status, _) = get(server.addr(), "/version", Some("wrong"));
        assert_eq!(status, 401);
        server.stop();
    }

    #[test]
    fn a_bare_secret_header_is_accepted() {
        let server = spawn_loopback(SECRET);
        let (status, body) = http_request(server.addr(), "GET", "/version", None, "");
        assert_eq!(status, 401, "no header at all: {body}");

        // A bare secret in the header (no `Bearer ` prefix).
        let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req = format!(
            "GET /version HTTP/1.1\r\nHost: {}\r\nAuthorization: {SECRET}\r\nConnection: close\r\n\r\n",
            server.addr()
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        server.stop();
    }

    #[test]
    fn an_empty_secret_serves_without_a_header() {
        let server = spawn_loopback("");
        let (status, body) = get(server.addr(), "/version", None);
        assert_eq!(status, 200, "{body}");
        server.stop();
    }

    #[test]
    fn a_preflight_is_answered_without_a_secret() {
        let server = spawn_loopback(SECRET);
        let (status, _) = http_request(server.addr(), "OPTIONS", "/proxies", None, "");
        assert_eq!(status, 204, "a preflight carries no credentials by design");
        server.stop();
    }

    // -- routing -----------------------------------------------------------

    #[test]
    fn an_unknown_path_is_not_found() {
        let server = spawn_loopback(SECRET);
        let (status, body) = get(server.addr(), "/providers/proxies", Some(SECRET));
        assert_eq!(status, 404, "{body}");
        assert!(body.contains("message"), "{body}");
        server.stop();
    }

    #[test]
    fn an_unrouted_method_is_not_found() {
        let server = spawn_loopback(SECRET);
        let (status, _) = http_request(server.addr(), "POST", "/proxies", Some(SECRET), "{}");
        assert_eq!(status, 404);
        server.stop();
    }

    #[test]
    fn the_index_lists_the_routes() {
        let server = spawn_loopback(SECRET);
        // `GET /` has an empty segment list.
        let (status, body) = get(server.addr(), "/", Some(SECRET));
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("GET /traffic"), "{body}");
        server.stop();
    }

    // -- shapes ------------------------------------------------------------

    #[test]
    fn version_reports_no_vendor_extensions() {
        let server = spawn_loopback(SECRET);
        let value = json(server.addr(), "/version", Some(SECRET));
        assert!(value.get("version").and_then(|v| v.as_str()).is_some());
        // No vendor extension is implemented, so neither flag may be set.
        assert_eq!(value.get("meta").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(value.get("premium").and_then(|v| v.as_bool()), Some(false));
        server.stop();
    }

    #[test]
    fn mode_translation_round_trips_the_engines_own_numbers() {
        // The engine's runtime numbers are its own: 1 global, 2 direct,
        // 3 rule.
        assert_eq!(runtime_mode("global"), Some(1));
        assert_eq!(runtime_mode("Direct"), Some(2));
        assert_eq!(runtime_mode(" RULE "), Some(3));
        assert_eq!(runtime_mode("config"), None);

        assert_eq!(mode_name(1, "x"), "global");
        assert_eq!(mode_name(2, "x"), "direct");
        assert_eq!(mode_name(3, "x"), "rule");
        // 0 means "no runtime override": report what the configuration says.
        assert_eq!(mode_name(0, "rule"), "rule");
    }

    #[test]
    fn rule_types_use_the_protocol_spelling() {
        assert_eq!(rule_type_name("domain-suffix"), "DOMAIN-SUFFIX");
        assert_eq!(rule_type_name("ip_cidr"), "IP-CIDR");
        assert_eq!(rule_type_name("DOMAIN"), "DOMAIN");
    }

    #[test]
    fn host_port_splitting_handles_ipv6_and_missing_ports() {
        assert_eq!(
            split_host_port("1.2.3.4:443"),
            ("1.2.3.4".into(), "443".into())
        );
        assert_eq!(split_host_port("[::1]:443"), ("::1".into(), "443".into()));
        assert_eq!(
            split_host_port("1.2.3.4"),
            ("1.2.3.4".into(), String::new())
        );
        assert_eq!(split_host_port(""), (String::new(), String::new()));
    }

    #[test]
    fn epochs_render_as_rfc3339_and_implausible_ones_do_not_render_at_all() {
        assert_eq!(epoch_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(epoch_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(epoch_to_rfc3339(86_400), "", "a duration is not a date");
        assert_eq!(epoch_to_rfc3339(-1), "");
        let now = now_rfc3339();
        assert!(now.starts_with("20"), "{now}");
        assert!(now.ends_with('Z'), "{now}");
    }

    #[test]
    fn percent_decoding_handles_names_that_are_user_data() {
        assert_eq!(percent_decode("%E8%8A%82%E7%82%B9"), "节点");
        assert_eq!(percent_decode("my%20group"), "my group");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("bad%2"), "bad%2");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
    }

    #[test]
    fn query_values_are_decoded() {
        assert_eq!(
            query_value("url=http%3A%2F%2Fx%2F204&timeout=2000", "url").as_deref(),
            Some("http://x/204")
        );
        assert_eq!(
            query_value("url=a&timeout=2000", "timeout").as_deref(),
            Some("2000")
        );
        assert_eq!(query_value("url=a", "missing"), None);
    }

    #[test]
    fn a_delay_timeout_is_used_in_milliseconds() {
        assert_eq!(delay_timeout_ms("timeout=2000"), 2000);
        assert_eq!(delay_timeout_ms("url=http://x&timeout=1500"), 1500);
        assert_eq!(delay_timeout_ms(""), DEFAULT_DELAY_TIMEOUT_MS);
        assert_eq!(delay_timeout_ms("timeout=abc"), DEFAULT_DELAY_TIMEOUT_MS);
    }

    #[test]
    fn a_connection_reports_the_destination_and_admits_the_missing_source() {
        let connection: nextjson::Value = nextjson::from_str(
            r#"{"id":"c1","src_addr":"example.com:443","dst_addr":"93.184.216.34",
                "dst_domain":"example.com","protocol":"tcp","outbound":"proxy-a",
                "upload":10,"download":20,"start_time":1700000000,
                "rule":"DOMAIN,example.com,proxy-a"}"#,
        )
        .expect("a connection DTO");

        let entry = connection_entry(&connection);
        let metadata = entry.get("metadata").expect("metadata");
        let field = |key: &str| metadata.get(key).and_then(|value| value.as_str());

        assert_eq!(field("destinationIP"), Some("93.184.216.34"));
        assert_eq!(field("destinationPort"), Some("443"));
        assert_eq!(field("host"), Some("example.com"));
        assert_eq!(field("type"), Some("tcp"));
        assert_eq!(field("sourceIP"), Some(""));
        assert_eq!(field("sourcePort"), Some(""));

        assert_eq!(entry.get("upload").and_then(|v| v.as_u64()), Some(10));
        assert_eq!(entry.get("download").and_then(|v| v.as_u64()), Some(20));
        assert_eq!(
            entry.get("start").and_then(|v| v.as_str()),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(
            entry.get("chains").and_then(|v| v.as_array()).map(Vec::len),
            Some(1)
        );
    }

    // -- endpoints that need no engine -------------------------------------

    #[test]
    fn configs_report_an_error_when_the_engine_is_not_running() {
        let server = spawn_loopback(SECRET);
        let (status, body) = get(server.addr(), "/configs", Some(SECRET));
        assert_eq!(status, 503, "{body}");
        assert!(body.contains("message"), "{body}");
        server.stop();
    }

    #[test]
    fn patching_an_unknown_mode_is_refused() {
        let server = spawn_loopback(SECRET);
        let (status, body) = http_request(
            server.addr(),
            "PATCH",
            "/configs",
            Some(SECRET),
            r#"{"mode":"turbo"}"#,
        );
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("unknown mode"), "{body}");
        server.stop();
    }

    #[test]
    fn patching_nothing_is_refused() {
        let server = spawn_loopback(SECRET);
        let (status, body) = http_request(
            server.addr(),
            "PATCH",
            "/configs",
            Some(SECRET),
            r#"{"mixed-port":7890}"#,
        );
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("no supported field"), "{body}");
        server.stop();
    }

    #[test]
    fn reloading_without_a_path_is_refused() {
        let server = spawn_loopback(SECRET);
        let (status, body) = http_request(
            server.addr(),
            "PUT",
            "/configs",
            Some(SECRET),
            r#"{"mode":"rule"}"#,
        );
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("path"), "{body}");
        server.stop();
    }

    #[test]
    fn a_broken_body_is_reported_as_a_bad_request() {
        let server = spawn_loopback(SECRET);
        let (status, body) =
            http_request(server.addr(), "PATCH", "/configs", Some(SECRET), "not json");
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("not valid JSON"), "{body}");
        server.stop();
    }

    #[test]
    fn selecting_a_proxy_needs_a_name() {
        let server = spawn_loopback(SECRET);
        let (status, body) =
            http_request(server.addr(), "PUT", "/proxies/G", Some(SECRET), r#"{}"#);
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("`name`"), "{body}");
        server.stop();
    }

    #[test]
    fn the_proxy_table_answers_with_a_table_or_says_it_cannot() {
        let server = spawn_loopback(SECRET);
        let (status, body) = get(server.addr(), "/proxies", Some(SECRET));
        assert!(status == 200 || status == 503, "{status}: {body}");
        if status == 200 {
            let value: nextjson::Value = nextjson::from_str(&body).expect("a JSON proxy table");
            assert!(value.get("proxies").is_some(), "{body}");
        } else {
            assert!(body.contains("message"), "{body}");
        }
        server.stop();
    }

    #[test]
    fn the_sample_routes_answer_with_one_object() {
        let server = spawn_loopback(SECRET);

        // `/memory` needs no engine: it reads this process's own memory.
        let value = json(server.addr(), "/memory", Some(SECRET));
        assert!(
            value.get("inuse").and_then(|v| v.as_u64()).is_some(),
            "no `inuse` in the memory sample"
        );
        assert!(
            value.get("oslimit").and_then(|v| v.as_u64()).is_some(),
            "no `oslimit` in the memory sample"
        );

        // `/traffic` reads engine state, so an engine that another test in
        // this process started makes a sample the correct answer. A fabricated
        // zero would not be, so the shape is what is asserted.
        let (status, body) = get(server.addr(), "/traffic", Some(SECRET));
        assert!(status == 200 || status == 503, "{status}: {body}");
        if status == 200 {
            let value: nextjson::Value = nextjson::from_str(&body).expect("a JSON traffic sample");
            assert!(value.get("up").is_some(), "{body}");
            assert!(value.get("down").is_some(), "{body}");
        } else {
            assert!(body.contains("message"), "{body}");
        }

        server.stop();
    }

    #[test]
    fn stopping_is_idempotent_and_frees_the_port() {
        let server = spawn_loopback(SECRET);
        let addr = server.addr();
        assert!(server.is_running());
        server.stop();
        server.stop();
        assert!(!server.is_running());
        // The port is free again.
        assert!(std::net::TcpListener::bind(addr).is_ok());
    }
}
