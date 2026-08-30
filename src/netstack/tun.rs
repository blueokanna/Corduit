use crate::common::cancel::CancellationToken;
use crate::netstack::error::{NetStackError, Result};
use bytes::BytesMut;
use std::net::Ipv4Addr;
#[cfg(any(target_os = "android", target_os = "ios"))]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// How long TUN worker threads wait between polls when idle.
const TUN_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// A `std::sync::mpsc::Receiver` that can cross thread boundaries.
///
/// `std::sync::mpsc::Receiver` is deliberately `!Send`/`!Sync`. Here the
/// receiver is created on the thread that starts the TUN device, stored in
/// `TunDevice`, and moved out exactly once (via `take_receiver` / `recv`)
/// before being used on a single consumer thread. It is never shared — this
/// wrapper only exposes `&mut self` accessors, so two threads can never race
/// on the underlying channel.
///
/// # Safety
/// - `Send`: the inner receiver is transferred between threads by ownership
///   only; no other thread retains a reference to it.
/// - `Sync`: a shared reference cannot reach the inner receiver (all
///   accessors require `&mut self`), so concurrent access is impossible.
#[repr(transparent)]
pub struct SendReceiver<T> {
    inner: mpsc::Receiver<T>,
}

unsafe impl<T> Send for SendReceiver<T> {}
unsafe impl<T> Sync for SendReceiver<T> {}

impl<T> SendReceiver<T> {
    fn new(rx: mpsc::Receiver<T>) -> Self {
        Self { inner: rx }
    }

    /// Block until a value is available, checking at most every `timeout`.
    pub fn recv_timeout(&mut self, timeout: Duration) -> std::result::Result<T, RecvTimeoutError> {
        self.inner.recv_timeout(timeout)
    }

    /// Block until a value is available or the channel disconnects.
    pub fn recv(&mut self) -> std::result::Result<T, mpsc::RecvError> {
        self.inner.recv()
    }

    /// Attempt to receive without blocking.
    pub fn try_recv(&mut self) -> std::result::Result<T, mpsc::TryRecvError> {
        self.inner.try_recv()
    }
}

/// Global Android VPN file descriptor
/// Set by the Android layer when VPN service starts
#[cfg(target_os = "android")]
pub static ANDROID_VPN_FD: AtomicI32 = AtomicI32::new(-1);

/// Global Android VPN proxy mode
/// 0 = rule, 1 = global, 2 = direct
#[cfg(target_os = "android")]
pub static ANDROID_PROXY_MODE: AtomicI32 = AtomicI32::new(0);

/// Set the Android VPN file descriptor from the Java/Kotlin layer
#[cfg(target_os = "android")]
pub fn set_android_vpn_fd(fd: i32) {
    info!("Setting Android VPN fd to {}", fd);
    ANDROID_VPN_FD.store(fd, Ordering::SeqCst);
}

/// Get the current Android VPN file descriptor
#[cfg(target_os = "android")]
pub fn get_android_vpn_fd() -> i32 {
    ANDROID_VPN_FD.load(Ordering::SeqCst)
}

/// Clear the Android VPN file descriptor (called when VPN stops)
#[cfg(target_os = "android")]
pub fn clear_android_vpn_fd() {
    info!("Clearing Android VPN fd");
    ANDROID_VPN_FD.store(-1, Ordering::SeqCst);
}

/// Set the Android proxy mode
/// mode: 0 = rule, 1 = global, 2 = direct
#[cfg(target_os = "android")]
pub fn set_android_proxy_mode(mode: i32) {
    info!("Setting Android proxy mode to {}", mode);
    ANDROID_PROXY_MODE.store(mode, Ordering::SeqCst);
}

/// Get the current Android proxy mode
#[cfg(target_os = "android")]
pub fn get_android_proxy_mode() -> i32 {
    ANDROID_PROXY_MODE.load(Ordering::SeqCst)
}

/// Global iOS VPN file descriptor
/// Set by the iOS layer (NetworkExtension PacketTunnelProvider) when the VPN starts
#[cfg(target_os = "ios")]
pub static IOS_VPN_FD: AtomicI32 = AtomicI32::new(-1);

/// Set the iOS VPN file descriptor from the Swift/Objective-C layer
#[cfg(target_os = "ios")]
pub fn set_ios_vpn_fd(fd: i32) {
    info!("Setting iOS VPN fd to {}", fd);
    IOS_VPN_FD.store(fd, Ordering::SeqCst);
}

/// Get the current iOS VPN file descriptor
#[cfg(target_os = "ios")]
pub fn get_ios_vpn_fd() -> i32 {
    IOS_VPN_FD.load(Ordering::SeqCst)
}

/// Clear the iOS VPN file descriptor (called when VPN stops)
#[cfg(target_os = "ios")]
pub fn clear_ios_vpn_fd() {
    info!("Clearing iOS VPN fd");
    IOS_VPN_FD.store(-1, Ordering::SeqCst);
}

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "Corduit".to_string(),
            address: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1500,
            gateway: None,
            dns: vec![Ipv4Addr::new(198, 18, 0, 2)],
        }
    }
}

/// TUN device wrapper
pub struct TunDevice {
    config: TunConfig,
    tx: Option<mpsc::Sender<BytesMut>>,
    rx: Option<SendReceiver<BytesMut>>,
    running: Arc<AtomicBool>,
    shutdown: Option<CancellationToken>,
    #[cfg(windows)]
    windows_session: Option<Arc<wintun_bindings::Session>>,
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    unix_device: Option<tun_rs::SyncDevice>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    vpn_file: Option<std::fs::File>,
}

impl TunDevice {
    pub fn new(name: &str, addr: &str, netmask: &str) -> Result<Self> {
        let address: Ipv4Addr = addr
            .parse()
            .map_err(|e| NetStackError::Parse(format!("Invalid address: {}", e)))?;
        let netmask: Ipv4Addr = netmask
            .parse()
            .map_err(|e| NetStackError::Parse(format!("Invalid netmask: {}", e)))?;

        Ok(Self {
            config: TunConfig {
                name: name.to_string(),
                address,
                netmask,
                ..Default::default()
            },
            tx: None,
            rx: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown: None,
            #[cfg(windows)]
            windows_session: None,
            #[cfg(any(
                all(target_os = "linux", not(target_env = "ohos")),
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            unix_device: None,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            vpn_file: None,
        })
    }

    pub fn with_config(config: TunConfig) -> Result<Self> {
        Ok(Self {
            config,
            tx: None,
            rx: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown: None,
            #[cfg(windows)]
            windows_session: None,
            #[cfg(any(
                all(target_os = "linux", not(target_env = "ohos")),
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            unix_device: None,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            vpn_file: None,
        })
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn start(&mut self) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        info!("Starting TUN device: {}", self.config.name);
        self.running.store(true, Ordering::Release);

        #[cfg(windows)]
        if let Err(error) = self.start_windows() {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(any(
            all(target_os = "linux", not(target_env = "ohos")),
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
        ))]
        if let Err(error) = self.start_unix() {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(target_os = "android")]
        if let Err(error) = self.start_android() {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(target_os = "ios")]
        if let Err(error) = self.start_ios() {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        info!("TUN device {} started successfully", self.config.name);
        Ok(())
    }

    #[cfg(windows)]
    fn start_windows(&mut self) -> Result<()> {
        use crate::netstack::wintun_embed;
        use wintun_bindings::{Adapter, MAX_RING_CAPACITY};

        // Ensure wintun.dll is available and load it
        let dll_path = match wintun_embed::ensure_wintun_available() {
            Ok(path) => path,
            Err(_) => wintun_embed::download_wintun_dll()?,
        };

        info!("Loading wintun.dll from {:?}", dll_path);

        let wintun = unsafe {
            wintun_bindings::load_from_path(&dll_path)
                .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
        };

        // Try to open existing adapter or create new one
        let adapter = match Adapter::open(&wintun, &self.config.name) {
            Ok(adapter) => {
                info!("Opened existing adapter: {}", self.config.name);
                adapter
            }
            Err(_) => {
                info!("Creating new adapter: {}", self.config.name);
                Adapter::create(&wintun, &self.config.name, "Corduit", None).map_err(|e| {
                    NetStackError::TunError(format!("Failed to create adapter: {}", e))
                })?
            }
        };

        // Configure IP address
        let prefix_len = netmask_to_prefix(self.config.netmask);
        self.configure_windows_adapter(prefix_len)?;

        // Start session - returns Arc<Session>
        let session = adapter
            .start_session(MAX_RING_CAPACITY)
            .map_err(|e| NetStackError::TunError(format!("Failed to start session: {}", e)))?;

        info!(
            "Wintun session started with ring capacity: {} bytes",
            MAX_RING_CAPACITY
        );

        // Create channels
        let (tx_to_tun, rx_from_stack) = mpsc::channel::<BytesMut>();
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>();
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(SendReceiver::new(rx_from_tun));
        self.shutdown = Some(shutdown.clone());
        self.windows_session = Some(session.clone());

        let running = self.running.clone();
        let session_read = session.clone();
        let session_write = session.clone();

        // Read task: dedicated thread doing blocking wintun reads.
        let running_read = running.clone();
        let shutdown_read = shutdown.clone();
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                info!("TUN read task started");

                loop {
                    if !running_read.load(Ordering::Relaxed) || shutdown_read.is_cancelled() {
                        break;
                    }

                    match session_read.receive_blocking() {
                        Ok(packet) => {
                            let data = BytesMut::from(packet.bytes());
                            if tx_to_stack.send(data).is_err() {
                                debug!("Stack receiver dropped");
                                break;
                            }
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("shutdown") || err_str.contains("EOF") {
                                info!("TUN adapter terminating");
                                break;
                            } else {
                                warn!("TUN read error: {}", e);
                                std::thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }
                }
                info!("TUN read task stopped");
            })
            .map_err(NetStackError::Io)?;

        // Write task: dedicated thread pulling packets from the stack.
        let running_write = running.clone();
        let shutdown_write = shutdown.clone();
        let rx_from_stack = rx_from_stack;
        std::thread::Builder::new()
            .name("tun-write".into())
            .spawn(move || {
                info!("TUN write task started");

                loop {
                    if shutdown_write.is_cancelled() {
                        debug!("TUN shutdown requested");
                        break;
                    }

                    match rx_from_stack.recv_timeout(TUN_POLL_TIMEOUT) {
                        Ok(packet) => {
                            match session_write.allocate_send_packet(packet.len() as u16) {
                                Ok(mut send_packet) => {
                                    send_packet.bytes_mut().copy_from_slice(&packet);
                                    session_write.send_packet(send_packet);
                                }
                                Err(e) => {
                                    if !e.to_string().contains("ERROR_BUFFER_OVERFLOW") {
                                        error!("Failed to allocate send packet: {}", e);
                                    }
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                running_write.store(false, Ordering::Relaxed);
                info!("TUN write task stopped");
            })
            .map_err(NetStackError::Io)?;

        Ok(())
    }

    #[cfg(windows)]
    fn configure_windows_adapter(&self, prefix_len: u8) -> Result<()> {
        use std::process::Command;

        // The interface name is interpolated into a PowerShell `-Command`
        // string below; reject shell metacharacters before anything is
        // executed (CWE-78).
        let name = crate::netstack::windows_route::sanitize_interface_name(&self.config.name)
            .map_err(NetStackError::InvalidConfig)?;

        let ip_str = self.config.address.to_string();
        info!(
            "Configuring adapter with IP: {}/{} and name {:?}",
            ip_str, prefix_len, name
        );

        // Set IP address using netsh
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &format!("name=\"{}\"", name),
                "source=static",
                &format!("addr={}", ip_str),
                &format!("mask={}", self.config.netmask),
            ])
            .output();

        // Set MTU
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("\"{}\"", name),
                &format!("mtu={}", self.config.mtu),
                "store=active",
            ])
            .output();

        // Configure DNS
        for (i, dns) in self.config.dns.iter().enumerate() {
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    if i == 0 { "set" } else { "add" },
                    "dns",
                    &format!("name=\"{}\"", name),
                    &format!("addr={}", dns),
                ])
                .output();
        }

        // Set interface metric to 1 (highest priority) to ensure DNS queries use this interface
        let _ = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Set-NetIPInterface -InterfaceAlias '{}' -InterfaceMetric 1 -ErrorAction SilentlyContinue",
                    name
                ),
            ])
            .output();

        // Also set IPv4 interface metric via netsh for compatibility
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                &format!("\"{}\"", name),
                "metric=1",
            ])
            .output();

        info!("Adapter configured successfully with high priority DNS");
        Ok(())
    }

    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    fn start_unix(&mut self) -> Result<()> {
        use std::os::fd::AsRawFd;
        use tun_rs::DeviceBuilder;

        let prefix_len = netmask_to_prefix(self.config.netmask);

        let device = DeviceBuilder::new()
            .name(&self.config.name)
            .ipv4(self.config.address, prefix_len, None::<Ipv4Addr>)
            .mtu(self.config.mtu)
            .build_sync()
            .map_err(|e| NetStackError::TunError(format!("Failed to create TUN: {}", e)))?;

        info!(
            "TUN device created: {} with address {}/{}",
            self.config.name, self.config.address, prefix_len
        );

        let (tx_to_tun, rx_from_stack) = mpsc::channel::<BytesMut>();
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>();
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(SendReceiver::new(rx_from_tun));
        self.shutdown = Some(shutdown.clone());
        self.unix_device = Some(device);

        let running = self.running.clone();
        // The device is kept alive by `self.unix_device`; worker threads
        // operate on the underlying fd with poll()-based timeouts so they
        // can observe shutdown while a packet is not yet available.
        let fd = self.unix_device.as_ref().unwrap().as_raw_fd();

        // Read task: poll fd, then read packets into the stack channel.
        let running_read = running.clone();
        let shutdown_read = shutdown.clone();
        let read_fd = fd;
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut read_buf = vec![0u8; 65535];

                loop {
                    if !running_read.load(Ordering::Relaxed) || shutdown_read.is_cancelled() {
                        break;
                    }

                    let mut pfd = libc::pollfd {
                        fd: read_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                    if ret < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        error!("TUN poll error: {}", e);
                        break;
                    }
                    if ret == 0 {
                        // Timeout: poll again.
                        continue;
                    }
                    if pfd.revents & libc::POLLIN != 0 {
                        let n = unsafe {
                            libc::read(read_fd, read_buf.as_mut_ptr().cast(), read_buf.len())
                        };
                        if n < 0 {
                            let e = std::io::Error::last_os_error();
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            error!("TUN read error: {}", e);
                            break;
                        }
                        if n == 0 {
                            info!("TUN read EOF");
                            break;
                        }
                        let packet = BytesMut::from(&read_buf[..n as usize]);
                        if tx_to_stack.send(packet).is_err() {
                            debug!("Stack receiver dropped");
                            break;
                        }
                    }
                }

                running_read.store(false, Ordering::Relaxed);
                info!("TUN read task stopped");
            })
            .map_err(|e| NetStackError::Io(e))?;

        // Write task: pull packets from the stack and write them to the fd.
        let running_write = running.clone();
        let shutdown_write = shutdown.clone();
        let write_fd = fd;
        std::thread::Builder::new()
            .name("tun-write".into())
            .spawn(move || {
                loop {
                    if shutdown_write.is_cancelled() {
                        debug!("TUN shutdown requested");
                        break;
                    }

                    match rx_from_stack.recv_timeout(TUN_POLL_TIMEOUT) {
                        Ok(packet) => {
                            let mut written = 0usize;
                            while written < packet.len() {
                                let n = unsafe {
                                    libc::write(
                                        write_fd,
                                        packet[written..].as_ptr().cast(),
                                        packet.len() - written,
                                    )
                                };
                                if n < 0 {
                                    let e = std::io::Error::last_os_error();
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::Interrupted
                                    {
                                        continue;
                                    }
                                    error!("TUN write error: {}", e);
                                    break;
                                }
                                if n == 0 {
                                    break;
                                }
                                written += n as usize;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                running_write.store(false, Ordering::Relaxed);
                info!("TUN write task stopped");
            })
            .map_err(|e| NetStackError::Io(e))?;

        Ok(())
    }

    /// Shared fd-based TUN implementation for platforms where the OS creates
    /// the TUN device and hands us the file descriptor (Android `VpnService`,
    /// iOS `NetworkExtension`/`PacketTunnelProvider`). The descriptor is
    /// duplicated so we never take ownership of the caller's fd.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn start_from_fd(&mut self, fd: i32) -> Result<()> {
        use std::os::unix::io::FromRawFd;

        if fd < 0 {
            return Err(NetStackError::TunError(
                "VPN file descriptor is not set".to_string(),
            ));
        }

        info!("Starting TUN with VPN fd={}", fd);

        // Duplicate the file descriptor so we don't take ownership of the original
        // The original fd is owned by the OS VPN layer and must remain valid
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(NetStackError::TunError(format!(
                "Failed to duplicate VPN fd: {}",
                std::io::Error::last_os_error()
            )));
        }

        info!("Duplicated VPN fd: {} -> {}", fd, dup_fd);

        // Own the duplicated fd with a File so it is closed when the device
        // is dropped. The worker threads operate on the raw fd below.
        // SAFETY: dup_fd is a valid duplicated fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        self.vpn_file = Some(file);

        // Create channels for packet communication
        let (tx_to_tun, rx_from_stack) = mpsc::channel::<BytesMut>();
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>();
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(SendReceiver::new(rx_from_tun));
        self.shutdown = Some(shutdown.clone());

        let running = self.running.clone();
        let read_shutdown = shutdown.clone();
        let write_shutdown = shutdown;

        // Read task - read packets from TUN and send to stack
        let running_read = running.clone();
        let read_fd = dup_fd;
        std::thread::Builder::new()
            .name("tun-fd-read".into())
            .spawn(move || {
                info!("Android TUN read task started");
                let mut read_buf = vec![0u8; 65535];

                loop {
                    if !running_read.load(Ordering::Relaxed) || read_shutdown.is_cancelled() {
                        break;
                    }

                    let mut pfd = libc::pollfd {
                        fd: read_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                    if ret < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        error!("TUN fd poll error: {}", e);
                        break;
                    }
                    if ret == 0 {
                        continue;
                    }
                    if pfd.revents & libc::POLLIN != 0 {
                        let n = unsafe {
                            libc::read(read_fd, read_buf.as_mut_ptr().cast(), read_buf.len())
                        };
                        if n < 0 {
                            let e = std::io::Error::last_os_error();
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            error!("TUN fd read error: {}", e);
                            break;
                        }
                        if n == 0 {
                            info!("TUN fd read EOF");
                            break;
                        }
                        let packet = BytesMut::from(&read_buf[..n as usize]);
                        if tx_to_stack.send(packet).is_err() {
                            debug!("Stack receiver dropped");
                            break;
                        }
                    }
                }

                running_read.store(false, Ordering::Relaxed);
                info!("Android TUN read task stopped");
            })
            .map_err(|e| NetStackError::Io(e))?;

        // Write task - write packets from stack to TUN
        let running_write = running.clone();
        let write_fd = dup_fd;
        std::thread::Builder::new()
            .name("tun-fd-write".into())
            .spawn(move || {
                info!("Android TUN write task started");

                loop {
                    if write_shutdown.is_cancelled() {
                        debug!("TUN shutdown requested");
                        break;
                    }

                    match rx_from_stack.recv_timeout(TUN_POLL_TIMEOUT) {
                        Ok(packet) => {
                            let mut written = 0usize;
                            while written < packet.len() {
                                let n = unsafe {
                                    libc::write(
                                        write_fd,
                                        packet[written..].as_ptr().cast(),
                                        packet.len() - written,
                                    )
                                };
                                if n < 0 {
                                    let e = std::io::Error::last_os_error();
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::Interrupted
                                    {
                                        continue;
                                    }
                                    error!("TUN fd write error: {}", e);
                                    break;
                                }
                                if n == 0 {
                                    break;
                                }
                                written += n as usize;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                running_write.store(false, Ordering::Relaxed);
                info!("Android TUN write task stopped");
            })
            .map_err(|e| NetStackError::Io(e))?;

        info!("TUN initialized with fd={}", fd);
        Ok(())
    }

    /// Android TUN implementation: the device is created by `VpnService` and
    /// we receive the file descriptor through `set_android_vpn_fd`.
    #[cfg(target_os = "android")]
    fn start_android(&mut self) -> Result<()> {
        let fd = ANDROID_VPN_FD.load(Ordering::Relaxed);
        self.start_from_fd(fd)
    }

    /// iOS TUN implementation: the device is created by `NetworkExtension`
    /// (`PacketTunnelProvider`) and we receive the file descriptor through
    /// `set_ios_vpn_fd`.
    #[cfg(target_os = "ios")]
    fn start_ios(&mut self) -> Result<()> {
        let fd = IOS_VPN_FD.load(Ordering::Relaxed);
        self.start_from_fd(fd)
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.is_running() {
            return Ok(());
        }
        info!("Stopping TUN device: {}", self.config.name);

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.cancel();
        }

        #[cfg(windows)]
        if let Some(session) = self.windows_session.take() {
            let _ = session.shutdown();
        }

        self.tx = None;
        self.rx = None;
        self.running.store(false, Ordering::Release);
        info!("TUN device {} stopped", self.config.name);
        Ok(())
    }

    pub fn send(&self, packet: BytesMut) -> Result<()> {
        if let Some(tx) = &self.tx {
            tx.send(packet).map_err(|_| NetStackError::ChannelClosed)?;
            Ok(())
        } else {
            Err(NetStackError::NotRunning)
        }
    }

    pub fn recv(&mut self) -> Result<BytesMut> {
        if let Some(rx) = &mut self.rx {
            loop {
                match rx.recv_timeout(TUN_POLL_TIMEOUT) {
                    Ok(packet) => return Ok(packet),
                    Err(RecvTimeoutError::Timeout) => {
                        // Disjoint field access: `self.rx` is mutably borrowed
                        // above, but the running flag is a separate field.
                        if !self.running.load(Ordering::Relaxed) {
                            return Err(NetStackError::NotRunning);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(NetStackError::ChannelClosed);
                    }
                }
            }
        } else {
            Err(NetStackError::NotRunning)
        }
    }

    pub fn get_sender(&self) -> Option<mpsc::Sender<BytesMut>> {
        self.tx.clone()
    }
    pub fn take_receiver(&mut self) -> Option<SendReceiver<BytesMut>> {
        self.rx.take()
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.is_running() {
            warn!("TUN device dropped while still running");
        }

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.cancel();
        }

        #[cfg(windows)]
        if let Some(session) = self.windows_session.take() {
            let _ = session.shutdown();
        }

        // Dropping `unix_device` / `vpn_file` closes the underlying fds,
        // which also unblocks any worker thread still polling on them.
        #[cfg(any(
            all(target_os = "linux", not(target_env = "ohos")),
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
        ))]
        {
            self.unix_device.take();
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            self.vpn_file.take();
        }

        self.tx = None;
        self.rx = None;
        self.running.store(false, Ordering::Release);
    }
}

#[allow(dead_code)]
fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    netmask.octets().iter().map(|o| o.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_prefix() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "Corduit");
        assert_eq!(config.address, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(config.mtu, 1500);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux CAP_NET_ADMIN and /dev/net/tun"]
    fn linux_tun_lifecycle() {
        use std::path::Path;
        use std::time::{Duration, Instant};

        let name = format!("vgtest{}", std::process::id() % 100_000);
        let mut device = TunDevice::with_config(TunConfig {
            name: name.clone(),
            address: Ipv4Addr::new(198, 18, 255, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 252),
            mtu: 1_400,
            ..TunConfig::default()
        })
        .expect("TUN configuration should be valid");

        device.start().expect("Linux TUN should start");
        assert!(device.is_running());
        assert!(Path::new(&format!("/sys/class/net/{name}")).exists());

        device.stop().expect("Linux TUN should stop");
        assert!(!device.is_running());

        let interface_path = format!("/sys/class/net/{name}");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Path::new(&interface_path).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !Path::new(&interface_path).exists(),
            "Linux TUN interface was not released after stop"
        );
    }
}
