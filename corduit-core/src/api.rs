use crate::config::Config;
use crate::health_check::{HealthMonitor, HealthStatus};
use crate::proxy::ProxyManager;
use crate::traffic_stats::TrafficStatsManager;
use hyper::body::Incoming;
use hyper::http::{header, Method, Request, Response, StatusCode};
use hyper::service::service_fn;
use nextjson::{NsonDeserialize, NsonSerialize};
use std::convert::Infallible;
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

/// Serialize `value` to JSON and wrap it in a `hyper` response.
fn json_response<T: NsonSerialize>(status: StatusCode, value: &T) -> Response<String> {
    let (status, body) = match nextjson::to_string(value) {
        Ok(json) => (status, json),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{"success":false,"error":"response encode failed: {e}"}}"#),
        ),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
}

/// Read the entire request body as a UTF-8 string, bounded to 16 MiB so a
/// hostile client cannot force unbounded buffering.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

async fn read_body(body: Incoming) -> Result<String, String> {
    let limited = http_body_util::Limited::new(body, MAX_BODY_BYTES);
    let bytes = http_body_util::BodyExt::collect(limited)
        .await
        .map_err(|_| "request body exceeds 16 MiB limit or is malformed".to_string())?
        .to_bytes();
    String::from_utf8(bytes.to_vec()).map_err(|_| "request body is not valid UTF-8".to_string())
}

// ---------------------------------------------------------------------------
// Handlers (plain `&ApiState`, no framework extractors)
// ---------------------------------------------------------------------------

async fn get_server_info(state: &ApiState) -> Response<String> {
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

async fn get_traffic_stats(state: &ApiState) -> Response<String> {
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

async fn reset_traffic_stats(state: &ApiState) -> Response<String> {
    state.traffic_stats.reset().await;
    json_response(
        StatusCode::OK,
        &ApiResponse::success("Traffic statistics reset".to_string()),
    )
}

async fn get_health_status(state: &ApiState) -> Response<String> {
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

async fn get_proxies(state: &ApiState) -> Response<String> {
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

async fn get_proxy(state: &ApiState, tag: &str) -> Response<String> {
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

async fn get_config(state: &ApiState) -> Response<String> {
    let config = state.proxy_manager.get_config().await;
    json_response(StatusCode::OK, &ApiResponse::success(config))
}

async fn update_config(state: &ApiState, body: String) -> Response<String> {
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

async fn get_rules(state: &ApiState) -> Response<String> {
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

/// API server built directly on `hyper` — no web framework, no serde.
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

    /// Serve one HTTP request.
    pub async fn serve(&self, req: Request<Incoming>) -> Response<String> {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let body = match read_body(req.into_body()).await {
            Ok(b) => b,
            Err(e) => {
                return json_response(StatusCode::BAD_REQUEST, &ApiResponse::<String>::error(e));
            }
        };
        self.dispatch(method, &path, &body).await
    }

    /// Match `(method, path)` to a handler and run it.
    async fn dispatch(&self, method: Method, path: &str, body: &str) -> Response<String> {
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

    /// Build a `hyper` `Service` for `hyper::server::conn::http1::Builder`.
    pub fn into_service(
        self,
    ) -> impl hyper::service::Service<
        Request<Incoming>,
        Response = Response<String>,
        Error = Infallible,
    > + Clone {
        let state = Arc::new(self.state);
        service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            async move {
                let server = ApiServer {
                    state: (*state).clone(),
                };
                Ok::<_, Infallible>(server.serve(req).await)
            }
        })
    }
}

/// Convenience constructor for embedding the dashboard into a server task.
pub fn create_service(
    proxy_manager: Arc<ProxyManager>,
    health_monitor: Arc<HealthMonitor>,
    traffic_stats: Arc<TrafficStatsManager>,
) -> impl hyper::service::Service<Request<Incoming>, Response = Response<String>, Error = Infallible>
       + Clone {
    ApiServer::new(proxy_manager, health_monitor, traffic_stats).into_service()
}
