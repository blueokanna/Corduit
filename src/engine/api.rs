use crate::engine::config::Config;
use crate::engine::health_check::{HealthMonitor, HealthStatus};
use crate::engine::proxy::ProxyManager;
use crate::engine::traffic_stats::TrafficStatsManager;
use courierust::courierust_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use nextjson::{NsonDeserialize, NsonSerialize};
use std::sync::Arc;

/// API server state (plain `Arc`, no nested wrappers).
#[derive(Clone)]
pub struct ApiState {
    pub proxy_manager: Arc<ProxyManager>,
    pub health_monitor: Arc<HealthMonitor>,
    pub traffic_stats: Arc<TrafficStatsManager>,
    /// Server start time, used for the `uptime` field.
    pub start_time: std::time::Instant,
}

/// Uniform REST envelope: `{ "success": bool, "data": T?, "error": String? }`.
#[derive(NsonSerialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// Server info response
#[derive(NsonSerialize)]
struct ServerInfo {
    version: String,
    uptime: u64,
    active_connections: usize,
}

/// Traffic stats response
#[derive(NsonSerialize)]
struct TrafficResponse {
    upload_bytes: u64,
    download_bytes: u64,
    total_bytes: u64,
    connections: u64,
    connection_time_secs: u64,
}

/// Health status response
#[derive(NsonSerialize)]
struct HealthResponse {
    tag: String,
    status: String,
    details: Option<String>,
}

/// Proxy info response
#[derive(NsonSerialize)]
struct ProxyInfo {
    tag: String,
    proxy_type: String,
    server: Option<String>,
    port: Option<u16>,
    healthy: bool,
}

/// Config update request
#[derive(NsonDeserialize)]
struct ConfigUpdateRequest {
    config: Config,
}

// ---------------------------------------------------------------------------
// JSON plumbing (hand-written, nextjson only)
// ---------------------------------------------------------------------------

/// Serialize `value` to JSON and wrap it in a courierust response.
fn json_response<T: NsonSerialize>(status: StatusCode, value: &T) -> Response<Body> {
    let (status, body) = match nextjson::to_string(value) {
        Ok(json) => (status, json),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{"success":false,"error":"response encode failed: {e}"}}"#),
        ),
    };
    let mut response = Response::new(status);
    response.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    response.body = Body::from(body.into_bytes());
    response
}

/// The entire request body as a UTF-8 string, bounded to 16 MiB so a
/// hostile client cannot force unbounded buffering. The serving transport
/// (courierust H/1) materializes the body with its own cap before the
/// handler runs; the cap here is a defensive second gate.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

fn read_body(req: &Request<Body>) -> Result<String, String> {
    let bytes = match req.body.as_bytes() {
        Some(b) if b.len() <= MAX_BODY_BYTES => b.to_vec(),
        Some(_) => return Err("request body exceeds 16 MiB limit".to_string()),
        None => Vec::new(),
    };
    String::from_utf8(bytes).map_err(|_| "request body is not valid UTF-8".to_string())
}

// ---------------------------------------------------------------------------
// Handlers (plain `&ApiState`, no framework extractors)
// ---------------------------------------------------------------------------

async fn get_server_info(state: &ApiState) -> Response<Body> {
    let active_connections = state.traffic_stats.active_connections();
    json_response(
        StatusCode::OK,
        &ApiResponse::success(ServerInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: state.start_time.elapsed().as_secs(),
            active_connections,
        }),
    )
}

async fn get_traffic_stats(state: &ApiState) -> Response<Body> {
    let stats = state.traffic_stats.global_stats();
    json_response(
        StatusCode::OK,
        &ApiResponse::success(TrafficResponse {
            upload_bytes: stats.upload_bytes,
            download_bytes: stats.download_bytes,
            total_bytes: stats.total_bytes(),
            connections: stats.connections,
            connection_time_secs: stats.connection_time_secs,
        }),
    )
}

async fn reset_traffic_stats(state: &ApiState) -> Response<Body> {
    state.traffic_stats.reset().await;
    json_response(
        StatusCode::OK,
        &ApiResponse::success("Traffic statistics reset".to_string()),
    )
}

async fn get_health_status(state: &ApiState) -> Response<Body> {
    let health_statuses: Vec<HealthResponse> = state
        .health_monitor
        .get_all_health()
        .into_iter()
        .map(|(tag, status)| {
            let (status_str, details) = match status {
                HealthStatus::Healthy => ("healthy".to_string(), None),
                HealthStatus::Unhealthy { reason, last_error } => {
                    let details = match (reason, last_error) {
                        (r, Some(e)) => format!("{}: {}", r, e),
                        (r, None) => r,
                    };
                    ("unhealthy".to_string(), Some(details))
                }
                HealthStatus::Unknown => ("unknown".to_string(), None),
            };
            HealthResponse {
                tag,
                status: status_str,
                details,
            }
        })
        .collect();

    json_response(StatusCode::OK, &ApiResponse::success(health_statuses))
}

async fn get_proxies(state: &ApiState) -> Response<Body> {
    let config = state.proxy_manager.get_config().await;
    let proxies: Vec<ProxyInfo> = config
        .outbounds
        .into_iter()
        .map(|outbound| {
            let healthy = state
                .health_monitor
                .get_health(&outbound.tag)
                .map(|status| matches!(status, HealthStatus::Healthy))
                .unwrap_or(false);

            ProxyInfo {
                tag: outbound.tag,
                proxy_type: outbound.outbound_type.as_str().to_string(),
                server: outbound.server,
                port: outbound.port,
                healthy,
            }
        })
        .collect();

    json_response(StatusCode::OK, &ApiResponse::success(proxies))
}

async fn get_proxy(state: &ApiState, tag: &str) -> Response<Body> {
    let config = state.proxy_manager.get_config().await;

    if let Some(outbound) = config.outbounds.into_iter().find(|o| o.tag == tag) {
        let healthy = state
            .health_monitor
            .get_health(&outbound.tag)
            .map(|status| matches!(status, HealthStatus::Healthy))
            .unwrap_or(false);

        json_response(
            StatusCode::OK,
            &ApiResponse::success(ProxyInfo {
                tag: outbound.tag,
                proxy_type: outbound.outbound_type.as_str().to_string(),
                server: outbound.server,
                port: outbound.port,
                healthy,
            }),
        )
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            &ApiResponse::<ProxyInfo>::error(format!("Proxy '{tag}' not found")),
        )
    }
}

async fn get_config(state: &ApiState) -> Response<Body> {
    let config = state.proxy_manager.get_config().await;
    json_response(StatusCode::OK, &ApiResponse::success(config))
}

async fn update_config(state: &ApiState, body: String) -> Response<Body> {
    let request: ConfigUpdateRequest = match nextjson::from_str(&body) {
        Ok(request) => request,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &ApiResponse::<String>::error(format!("Invalid JSON body: {e}")),
            );
        }
    };
    match state.proxy_manager.reload(request.config).await {
        Ok(()) => json_response(
            StatusCode::OK,
            &ApiResponse::success("Configuration updated successfully".to_string()),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ApiResponse::<String>::error(format!("Failed to update configuration: {e}")),
        ),
    }
}

async fn get_rules(state: &ApiState) -> Response<Body> {
    let config = state.proxy_manager.get_config().await;
    let rules: Vec<nextjson::Value> = config
        .rules
        .into_iter()
        .map(|rule| {
            nextjson::json!({
                "type": format!("{:?}", rule.rule_type),
                "payload": rule.payload,
                "outbound": rule.outbound,
                "process_name": rule.process_name,
            })
        })
        .collect();

    json_response(StatusCode::OK, &ApiResponse::success(rules))
}

// ---------------------------------------------------------------------------
// Router (hand-written dispatch, no framework)
// ---------------------------------------------------------------------------

/// Split a path into non-empty segments.
fn path_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// API server built on courierust's HTTP types — no web framework, no serde.
pub struct ApiServer {
    state: ApiState,
}

impl ApiServer {
    /// Create a new API server.
    pub fn new(
        proxy_manager: Arc<ProxyManager>,
        health_monitor: Arc<HealthMonitor>,
        traffic_stats: Arc<TrafficStatsManager>,
    ) -> Self {
        Self {
            state: ApiState {
                proxy_manager,
                health_monitor,
                traffic_stats,
                start_time: std::time::Instant::now(),
            },
        }
    }

    /// Get the API state.
    pub fn state(&self) -> &ApiState {
        &self.state
    }

    /// Serve one HTTP request. Wire this into any courierust-based server
    /// (e.g. [`crate::common::http_server::HttpServer`]) by adapting the
    /// request/response pair.
    pub async fn serve(&self, req: Request<Body>) -> Response<Body> {
        let method = req.method.clone();
        let path = req.uri.path().to_owned();
        let body = match read_body(&req) {
            Ok(b) => b,
            Err(e) => {
                return json_response(StatusCode::BAD_REQUEST, &ApiResponse::<String>::error(e));
            }
        };
        self.dispatch(method, &path, &body).await
    }

    /// Match `(method, path)` to a handler and run it.
    async fn dispatch(&self, method: Method, path: &str, body: &str) -> Response<Body> {
        // `/api/v1/proxies/:tag` (GET) — parameterized route handled first.
        let segments = path_segments(path);
        if segments.len() == 4
            && segments[0] == "api"
            && segments[1] == "v1"
            && segments[2] == "proxies"
            && method == Method::GET
        {
            return get_proxy(&self.state, segments[3]).await;
        }

        match (method.as_str(), path) {
            ("GET", "/api/v1/info") => get_server_info(&self.state).await,
            ("GET", "/api/v1/traffic") => get_traffic_stats(&self.state).await,
            ("POST", "/api/v1/traffic/reset") => reset_traffic_stats(&self.state).await,
            ("GET", "/api/v1/health") => get_health_status(&self.state).await,
            ("GET", "/api/v1/proxies") => get_proxies(&self.state).await,
            ("GET", "/api/v1/config") => get_config(&self.state).await,
            ("POST", "/api/v1/config") => update_config(&self.state, body.to_owned()).await,
            ("GET", "/api/v1/rules") => get_rules(&self.state).await,
            _ => json_response(
                StatusCode::NOT_FOUND,
                &ApiResponse::<()>::error("route not found".to_string()),
            ),
        }
    }
}

/// Convenience constructor for embedding the dashboard into a server task.
/// The returned server exposes [`ApiServer::serve`], which pairs with any
/// courierust-based HTTP transport.
pub fn create_server(
    proxy_manager: Arc<ProxyManager>,
    health_monitor: Arc<HealthMonitor>,
    traffic_stats: Arc<TrafficStatsManager>,
) -> ApiServer {
    ApiServer::new(proxy_manager, health_monitor, traffic_stats)
}
