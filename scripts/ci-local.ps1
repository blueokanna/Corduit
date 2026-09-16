# Local replica of .github/workflows/ci.yml (Windows host + cross targets).
#
# The CI matrix is the source of truth; this script exists because a change
# that only compiles on Windows can still break five CI jobs (that is exactly
# how a platform-`cfg` helper once slipped through: it compiled on Windows,
# Android and iOS, and broke ubuntu/macOS/MSRV/clippy/features).
#
# It pins RUSTC/RUSTDOC per toolchain on purpose: this machine's PATH puts a
# standalone Rust 1.78 install ahead of rustup, and a cargo/rustc (or rustdoc)
# mismatch shows up as "E0463: can't find crate for core" or
# "-Z unstable-options must also be passed to enable check-cfg".
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\ci-local.ps1 [-Filter <substring>]
param(
    [string]$Filter = "",
    [string]$LogPath = ""
)

$ErrorActionPreference = 'Continue'
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
# One log per run: two concurrent invocations must not interleave their
# sections into the same file.
$log = if ($LogPath) { $LogPath } else { "target\ci-local-$PID.log" }
$env:RUSTFLAGS = "-D warnings"
Set-Content -Path $log -Value "local CI replica (RUSTFLAGS=-D warnings)" -Encoding utf8

function Pin-Toolchain([string]$toolchain) {
    $dir = "$env:USERPROFILE\.rustup\toolchains\$toolchain-x86_64-pc-windows-msvc\bin"
    if (Test-Path "$dir\rustc.exe") { $env:RUSTC = "$dir\rustc.exe" } else { $env:RUSTC = "" }
    if (Test-Path "$dir\rustdoc.exe") { $env:RUSTDOC = "$dir\rustdoc.exe" } else { $env:RUSTDOC = "" }
}

function Step {
    param(
        [string]$Title,
        [string]$Toolchain,
        [string[]]$CargoArgs,
        [string]$Target = ""
    )
    if ($Filter -and $Title -notlike "*$Filter*") { return }

    Add-Content -Path $log -Value "=== $Title ===" -Encoding utf8
    Pin-Toolchain $Toolchain
    $full = @()
    if ($Target) { $full = @("--target", $Target) }
    $out = & $cargo "+$Toolchain" @CargoArgs @full 2>&1
    $hits = $out | Select-String -Pattern '^(error|warning)|test result' | Select-Object -First 25
    if ($hits) { $hits | Out-File $log -Append -Encoding utf8 } else { "OK" | Out-File $log -Append -Encoding utf8 }
}

$lint = @("clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")

# --- lint job (ubuntu in CI; the host run is a superset for clippy-only lints)
Step "clippy --workspace --all-targets --all-features -D warnings [host]" "stable" $lint
Step "fmt --all -- --check [host]" "stable" @("fmt", "--all", "--", "--check")

# --- native job: three desktop OSes
Step "check --workspace --all-targets [host]" "stable" @("check", "--workspace", "--all-targets")
Step "check --workspace --all-targets [x86_64-unknown-linux-gnu]" "stable" @("check", "--workspace", "--all-targets") "x86_64-unknown-linux-gnu"
Step "check --workspace --all-targets [x86_64-apple-darwin]" "stable" @("check", "--workspace", "--all-targets") "x86_64-apple-darwin"
Step "test --workspace [host]" "stable" @("test", "--workspace")
Step "doc --workspace --no-deps --all-features [host]" "stable" @("doc", "--workspace", "--no-deps", "--all-features")

# --- msrv job (1.78, linux)
Step "check --workspace --all-targets [1.78.0, x86_64-unknown-linux-gnu]" "1.78.0" @("check", "--workspace", "--all-targets") "x86_64-unknown-linux-gnu"

# --- feature matrix job (ubuntu)
Step "check --workspace --all-targets --all-features [x86_64-unknown-linux-gnu]" "stable" @("check", "--workspace", "--all-targets", "--all-features") "x86_64-unknown-linux-gnu"
Step "check --no-default-features --features std [x86_64-unknown-linux-gnu]" "stable" @("check", "--no-default-features", "--features", "std") "x86_64-unknown-linux-gnu"
Step "check --no-default-features [x86_64-unknown-linux-gnu]" "stable" @("check", "--no-default-features") "x86_64-unknown-linux-gnu"
Step "test --workspace --all-features [host]" "stable" @("test", "--workspace", "--all-features")

# --- android + ios jobs
Step "check --workspace [aarch64-linux-android]" "stable" @("check", "--workspace") "aarch64-linux-android"
Step "check --workspace [x86_64-linux-android]" "stable" @("check", "--workspace") "x86_64-linux-android"
Step "check --workspace [aarch64-apple-ios]" "stable" @("check", "--workspace") "aarch64-apple-ios"

Add-Content -Path $log -Value "=== DONE ===" -Encoding utf8
Get-Content $log