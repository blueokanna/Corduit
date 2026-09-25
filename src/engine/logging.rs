use crate::engine::config::LogLevel;
use crate::engine::error::{Error, Result};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Once, OnceLock};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Format the current UTC time as `YYYY-MM-DD HH:MM:SS`.
fn now_timestamp() -> String {
    crate::common::clock::now_utc_timestamp()
}

static INIT: Once = Once::new();

/// The live console filter.
///
/// `init_logging` installs at most one subscriber per process, so without a
/// handle onto its filter the level chosen at startup would be the only level
/// there could ever be — and a later request to change it would be accepted and
/// then dropped. The handle swaps the filter in place: the formatter stays, the
/// UI buffer layer stays, and because the buffer is not filtered at all,
/// nothing already captured disappears when the level narrows.
type FilterHandle = tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static CONSOLE_FILTER: OnceLock<FilterHandle> = OnceLock::new();

/// The console filter for `level`.
///
/// `RUST_LOG` is read first, so an operator can widen the filter from the
/// environment; the configured level is applied on top of it.
fn console_filter(level: LogLevel) -> Result<EnvFilter> {
    let directives = [
        match level {
            LogLevel::Silent => "corduit=off",
            LogLevel::Error => "corduit=error",
            LogLevel::Warning => "corduit=warn",
            LogLevel::Info => "corduit=info",
            LogLevel::Debug => "corduit=debug",
        },
        "tokio=warn",
    ];

    let mut filter = EnvFilter::from_default_env();
    for raw in directives {
        let directive = raw
            .parse()
            .map_err(|e| Error::config(format!("Invalid log directive '{raw}': {e}")))?;
        filter = filter.add_directive(directive);
    }
    Ok(filter)
}

/// Global log buffer for storing recent logs
/// Increased buffer size to 5000 to store more logs
static LOG_BUFFER: once_cell::sync::Lazy<Arc<Mutex<LogBuffer>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(LogBuffer::new(5000))));

/// Buffer for storing recent log messages
pub struct LogBuffer {
    logs: VecDeque<String>,
    max_size: usize,
}

impl LogBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            logs: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    pub fn push(&mut self, log: String) {
        if self.logs.len() >= self.max_size {
            self.logs.pop_front();
        }
        self.logs.push_back(log);
    }

    pub fn get_logs(&self, count: usize) -> Vec<String> {
        // If count is 0 or very large, return all logs
        if count == 0 || count >= self.logs.len() {
            return self.logs.iter().cloned().collect();
        }
        let start = self.logs.len() - count;
        self.logs.iter().skip(start).cloned().collect()
    }

    pub fn clear(&mut self) {
        self.logs.clear();
    }
}

/// Get recent logs from the buffer
pub fn get_recent_logs(count: usize) -> Vec<String> {
    if let Ok(buffer) = LOG_BUFFER.lock() {
        buffer.get_logs(count)
    } else {
        vec![]
    }
}

/// Clear the log buffer
pub fn clear_logs() {
    if let Ok(mut buffer) = LOG_BUFFER.lock() {
        buffer.clear();
    }
}

/// Add a log entry to the buffer
pub fn add_log(message: String) {
    if let Ok(mut buffer) = LOG_BUFFER.lock() {
        buffer.push(message);
    }
}

/// Initialize logging system
pub fn init_logging(level: LogLevel) -> Result<()> {
    let mut result = Ok(());

    INIT.call_once(|| {
        result = init_logging_inner(level);
    });

    result
}

fn init_logging_inner(level: LogLevel) -> Result<()> {
    if matches!(level, LogLevel::Silent) {
        return Ok(()); // Silent means no subscriber at all, not a muted one.
    }

    // The filter lives behind a reload layer, which is what lets
    // `set_log_level` retarget it later without rebuilding the subscriber.
    let (filter_layer, filter_handle) =
        tracing_subscriber::reload::Layer::new(console_filter(level)?);

    // Create formatter for console
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact()
        .with_filter(filter_layer);

    // Create buffer layer for capturing logs
    let buffer_layer = BufferLayer;

    // Initialize subscriber with both layers
    // Use try_init to avoid panic if tracing is already initialized
    let installed = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(buffer_layer)
        .try_init();

    if installed.is_err() {
        // Someone else owns the subscriber, so there is no filter of ours to
        // swap later either; saying so here beats failing at the first attempt
        // to change the level.
        add_log("[INFO] Tracing already initialized, using existing subscriber".to_string());
        return Ok(());
    }

    let _ = CONSOLE_FILTER.set(filter_handle);
    add_log(format!("[INFO] Logging initialized at level: {level:?}"));
    tracing::info!("Logging initialized at level: {level:?}");
    Ok(())
}

/// Retarget the console filter of a running engine.
///
/// Fails rather than pretending when logging was never installed (a `silent`
/// configuration, or a host application that owns the subscriber): there is no
/// filter to change, and a caller who believed otherwise would be debugging a
/// level that was never in effect.
pub fn set_log_level(level: LogLevel) -> Result<()> {
    let filter = console_filter(level)?;
    let Some(handle) = CONSOLE_FILTER.get() else {
        return Err(Error::Internal {
            message: "logging is not installed, so there is no console filter to change"
                .to_string(),
            source: None,
        });
    };
    handle.reload(filter).map_err(|error| Error::Internal {
        message: format!("Failed to change the console log level: {error}"),
        source: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directive each level maps to.
    ///
    /// `silent` is the one worth reading twice: it has to silence *our*
    /// targets, not the whole process, so that a host application that shares
    /// the subscriber keeps its own logging. `corduit=off` does that; a global
    /// `off` would not.
    #[test]
    fn every_level_maps_to_a_directive_for_our_targets_only() {
        for (level, expected) in [
            (LogLevel::Silent, "corduit=off"),
            (LogLevel::Error, "corduit=error"),
            (LogLevel::Warning, "corduit=warn"),
            (LogLevel::Info, "corduit=info"),
            (LogLevel::Debug, "corduit=debug"),
        ] {
            let filter = console_filter(level).expect("the directive table is valid");
            let rendered = filter.to_string();
            assert!(rendered.contains(expected), "{level:?}: {rendered}");
        }
    }
}

/// Custom layer that captures logs to the buffer
struct BufferLayer;

impl<S> tracing_subscriber::Layer<S> for BufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Format the log message
        let metadata = event.metadata();
        let level = metadata.level();
        let target = metadata.target();

        // Skip internal logs
        if target.starts_with("tokio")
            || target.starts_with("hyper")
            || target.starts_with("rustls")
        {
            return;
        }

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let timestamp = now_timestamp();
        let log_line = format!("[{}] [{}] {}", timestamp, level, visitor.message);

        add_log(log_line);
    }
}

#[derive(Default)]
struct LogVisitor {
    message: String,
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" || self.message.is_empty() {
            self.message = value.to_string();
        } else {
            self.message
                .push_str(&format!(" {}={}", field.name(), value));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" || self.message.is_empty() {
            self.message = format!("{:?}", value);
        } else {
            self.message
                .push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
}

/// Log an error with context
pub fn log_error(error: &Error, context: Option<&str>) {
    let level = match error.code() {
        "CONFIG" | "PARSE" => tracing::Level::ERROR,
        "NETWORK" | "TIMEOUT" | "IO" => tracing::Level::WARN,
        _ => tracing::Level::ERROR,
    };

    match level {
        tracing::Level::ERROR => {
            if let Some(ctx) = context {
                tracing::error!("{}: {}", ctx, error);
            } else {
                tracing::error!("{}", error);
            }
        }
        tracing::Level::WARN => {
            if let Some(ctx) = context {
                tracing::warn!("{}: {}", ctx, error);
            } else {
                tracing::warn!("{}", error);
            }
        }
        _ => {}
    }
}

/// Log a recoverable error (warning level)
pub fn log_recoverable_error(error: &Error, context: Option<&str>) {
    if let Some(ctx) = context {
        tracing::warn!("Recoverable error in {}: {}", ctx, error);
    } else {
        tracing::warn!("Recoverable error: {}", error);
    }
}

/// Log successful operation
pub fn log_success(operation: &str, details: Option<&str>) {
    if let Some(details) = details {
        tracing::info!("{}: {}", operation, details);
    } else {
        tracing::info!("{}", operation);
    }
}

/// Log configuration loading
pub fn log_config_load(source: &str) {
    tracing::info!("Configuration loaded from: {}", source);
}

/// Log proxy connection
pub fn log_proxy_connection(
    inbound_type: &str,
    outbound_type: &str,
    target: Option<&str>,
    rule: Option<&str>,
) {
    if let Some(target) = target {
        if let Some(rule) = rule {
            tracing::debug!(
                "Proxy connection: {} -> {} -> {} (rule: {})",
                inbound_type,
                outbound_type,
                target,
                rule
            );
        } else {
            tracing::debug!(
                "Proxy connection: {} -> {} -> {}",
                inbound_type,
                outbound_type,
                target
            );
        }
    } else {
        tracing::debug!("Proxy connection: {} -> {}", inbound_type, outbound_type);
    }
}

/// Performance logging
pub struct PerformanceLogger {
    operation: String,
    start_time: std::time::Instant,
}

impl PerformanceLogger {
    pub fn new<S: Into<String>>(operation: S) -> Self {
        Self {
            operation: operation.into(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn finish(self) {
        let duration = self.start_time.elapsed();
        tracing::debug!("{} completed in {:?}", self.operation, duration);
    }

    pub fn finish_with_result(self, result: &str) {
        let duration = self.start_time.elapsed();
        tracing::debug!("{} completed in {:?}: {}", self.operation, duration, result);
    }
}

/// Create a performance logger guard
pub fn time_operation<S: Into<String>>(operation: S) -> PerformanceLogger {
    PerformanceLogger::new(operation)
}
