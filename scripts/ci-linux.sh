#!/usr/bin/env bash
# Local replica of the *Linux* half of .github/workflows/ci.yml:
#   lint job    -> clippy --workspace --all-targets --all-features -D warnings
#   features job-> test --all-features, check --no-default-features [--features std]
#   native job  -> test --workspace, doc --workspace --no-deps --all-features
#
# Cross-running clippy from Windows (`cargo clippy --target <linux triple>`)
# fails with "E0461: couldn't find crate ... with expected target triple", so
# the ubuntu lint job can only be reproduced with a real Linux toolchain —
# WSL on Windows:  wsl -e bash scripts/ci-linux.sh
set -u

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/corduit-target}"
export RUSTFLAGS="-D warnings"
cd "$(dirname "$0")/.." || exit 1

log="${CI_LOCAL_LOG:-target/ci-linux.log}"
tmp=$(mktemp)
: > "$log"
echo "linux CI replica: $(rustc --version) / $(cargo --version)" >> "$log"

run() {
    local name="$1"
    shift
    echo "=== $name ===" >> "$log"
    if "$@" > "$tmp" 2>&1; then
        echo "OK" >> "$log"
    else
        echo "FAILED" >> "$log"
        grep -E '^(error|warning)' "$tmp" | head -30 >> "$log"
        echo "--- tail ---" >> "$log"
        tail -20 "$tmp" >> "$log"
    fi
    grep -E 'test result' "$tmp" >> "$log" 2>/dev/null
}

run "clippy --workspace --all-targets --all-features -D warnings" \
    cargo clippy --workspace --all-targets --all-features -- -D warnings
run "fmt --all -- --check" cargo fmt --all -- --check
run "test --workspace --all-features" cargo test --workspace --all-features
run "test --workspace" cargo test --workspace
run "check --no-default-features --features std" cargo check --no-default-features --features std
run "check --no-default-features" cargo check --no-default-features
run "doc --workspace --no-deps --all-features" cargo doc --workspace --no-deps --all-features

rm -f "$tmp"
echo "=== DONE ===" >> "$log"
cat "$log"
