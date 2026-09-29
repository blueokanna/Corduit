//! Dispatch-table coverage, checked in a process of its own.
//!
//! `every_declared_method_is_dispatched` answers one question — does
//! [`dispatch`] have an arm for every name in [`CORDUIT_METHODS`] — by calling
//! each name with empty arguments and rejecting only the "unknown method"
//! answer. Several of those calls are process-wide actions:
//! `close_all_connections_dto` and `stop_corduit` cancel **every tracked
//! connection** through the global tracker, and `stop_proxy` reaches the same
//! code.
//!
//! Run from inside the library's own test binary, that cancelled the relays of
//! the engine integration tests placing an echo round-trip at that same moment:
//! the client saw end-of-stream mid-payload and
//! `socks5_relays_to_echo_server` failed. The window is a few milliseconds wide,
//! so it surfaced rarely — often enough to gate CI, never often enough to
//! reproduce on demand.
//!
//! Cargo runs test binaries one after another, so the coverage check lives here
//! instead of next to the code it checks: same assertions, nothing else
//! running in the process whose global state it tears down.

#[test]
fn every_declared_method_is_dispatched() {
    corduit::api::init_app();

    let value = nextjson::Value::Null;
    for method in corduit::rpc::CORDUIT_METHODS {
        let result = corduit::rpc::dispatch(method, &value);
        if let Err(e) = result {
            assert!(
                !e.starts_with("unknown method"),
                "declared method '{method}' is missing from dispatch: {e}"
            );
        }
    }
}
