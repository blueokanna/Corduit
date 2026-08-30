use tracing_subscriber::layer::Context;

/// Format the current UTC time as `YYYY-MM-DD HH:MM:SS`.
fn now_timestamp() -> String {
    crate::common::clock::now_utc_timestamp()
}

pub struct BridgeLogLayer;

impl<S> tracing_subscriber::Layer<S> for BridgeLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = metadata.level();
        let target = metadata.target();

        // Drop noisy third-party targets (frameworks no longer include
        // tokio, but hyper/mio/courierust-style crates are still chatty);
        // everything else — including the engine's `corduit::*` targets —
        // flows into the UI log buffer.
        if target.is_empty()
            || target.starts_with("tokio")
            || target.starts_with("hyper")
            || target.starts_with("mio")
            || target.starts_with("h2")
            || target.starts_with("want")
            || target.starts_with("tower")
            || target.starts_with("rustls")
            || target.starts_with("courierust")
            || target.starts_with("reqwest")
        {
            return;
        }

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let timestamp = now_timestamp();
        let log_line = format!("[{}] [{}] {}", timestamp, level, visitor.message);

        crate::engine::logging::add_log(log_line);
    }
}

#[derive(Default)]
pub(crate) struct LogVisitor {
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
