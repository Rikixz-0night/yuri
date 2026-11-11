use crate::os_detect::{OsDetector, OsFingerprint};
use crate::service::{probe_service, ServiceInfo};
use crate::vuln::{check_vulnerabilities, VulnerabilityAlert};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String, // "open"
    pub service: ServiceInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostScanResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub status: String, // "up", "down"
    pub open_ports: Vec<PortResult>,
    pub os_fingerprint: Option<OsFingerprint>,
    pub vulnerabilities: Vec<VulnerabilityAlert>,
    pub scan_duration_ms: u128,
}

pub struct ScannerConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub detect_os: bool,
    pub detect_service: bool,
    pub check_vulns: bool,
    pub quiet: bool,
}

pub struct YuriScanner {
    config: ScannerConfig,
    os_detector: OsDetector,
}

impl YuriScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config,
            os_detector: OsDetector::new(),
        }
    }

    /// Check if a single TCP port is open and retrieve observed TTL if possible
    async fn check_port(
        target: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Option<(u16, Option<u8>)> {
        let socket_addr = SocketAddr::new(target, port);

        let domain = match target {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let _ = socket.set_nonblocking(true);
        let _ = socket.set_nodelay(true);

        let sock_ref = socket2::SockAddr::from(socket_addr);
        let connect_fut = async {
            match socket.connect(&sock_ref) {
                Ok(_) => {
                    let std_stream: std::net::TcpStream = socket.into();
                    TcpStream::from_std(std_stream).ok()
                }
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                    let std_stream: std::net::TcpStream = socket.into();
                    match TcpStream::from_std(std_stream) {
                        Ok(tokio_stream) => {
                            match tokio_stream.writable().await {
                                Ok(_) => {
                                    if tokio_stream.take_error().map_or(false, |e| e.is_none()) {
                                        Some(tokio_stream)
                                    } else {
                                        None
                                    }
                                }
                                Err(_) => None,
                            }
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            }
        };

        if let Ok(Some(tokio_stream)) = timeout(timeout_duration, connect_fut).await {
            let mut detected_ttl = None;

            #[cfg(unix)]
            {
                unsafe {
                    let mut ttl: libc::c_int = 0;
                    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    if libc::getsockopt(
                        tokio_stream.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_TTL,
                        &mut ttl as *mut _ as *mut libc::c_void,
                        &mut len,
                    ) == 0 && ttl > 0 {
                        detected_ttl = Some(ttl as u8);
                    }
                }
            }

            return Some((port, detected_ttl));
        }

        None
    }

    /// Scan a single target host across all provided ports
    pub async fn scan_host(&self, target: IpAddr, ports: &[u16]) -> HostScanResult {
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        let total_ports = ports.len();

        let pb = if !self.config.quiet {
            let p = ProgressBar::new(total_ports as u64);
            p.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports ({percent}%) | {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            p.set_message("Scanning ports...");
            Some(p)
        } else {
            None
        };

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let open_ports_found = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let observed_ttl = Arc::new(tokio::sync::Mutex::new(None));
        let scanned_counter = Arc::new(AtomicUsize::new(0));

        // Stream all port scan tasks
        let port_tasks = stream::iter(ports.iter().copied()).map(|port| {
            let sem = Arc::clone(&semaphore);
            let open_ports = Arc::clone(&open_ports_found);
            let observed_ttl = Arc::clone(&observed_ttl);
            let pb_clone = pb.clone();
            let counter = Arc::clone(&scanned_counter);

            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = Self::check_port(target, port, timeout_duration).await;
                let count = counter.fetch_add(1, Ordering::Relaxed) + 1;

                if let Some((open_port, ttl)) = res {
                    let mut lock = open_ports.lock().await;
                    lock.push(open_port);

                    if let Some(t) = ttl {
                        let mut ttl_lock = observed_ttl.lock().await;
                        if ttl_lock.is_none() {
                            *ttl_lock = Some(t);
                        }
                    }

                    if let Some(ref p) = pb_clone {
                        p.set_message(format!("Found open port: {} (Total: {})", open_port, lock.len()));
                    }
                }

                if let Some(ref p) = pb_clone {
                    if count % 100 == 0 || count == total_ports {
                        p.set_position(count as u64);
                    }
                }
            }
        });

        // Execute all port tasks concurrently with configured concurrency
        port_tasks.buffer_unordered(self.config.concurrency).collect::<Vec<()>>().await;

        if let Some(p) = pb {
            p.finish_and_clear();
        }

        let mut discovered_ports = open_ports_found.lock().await.clone();
        discovered_ports.sort_unstable();

        let host_up = !discovered_ports.is_empty();
        let ttl_val = *observed_ttl.lock().await;

        // Service Detection
        let mut services_map = HashMap::new();
        if self.config.detect_service && host_up {
            let probe_timeout = Duration::from_millis(self.config.timeout_ms.max(1000));
            for &port in &discovered_ports {
                let srv = probe_service(target, port, probe_timeout).await;
                services_map.insert(port, srv);
            }
        }

        // OS Fingerprinting
        let os_fingerprint = if self.config.detect_os && host_up {
            Some(self.os_detector.detect(&discovered_ports, &services_map, ttl_val))
        } else {
            None
        };

        // Vulnerability Probes
        let vulnerabilities = if self.config.check_vulns && host_up {
            check_vulnerabilities(&discovered_ports, &services_map)
        } else {
            Vec::new()
        };

        // Build list of port results
        let mut port_results = Vec::new();
        for &port in &discovered_ports {
            let service = services_map.remove(&port).unwrap_or_else(|| ServiceInfo {
                name: crate::service::default_service_name(port).to_string(),
                banner: None,
                http_title: None,
                http_server: None,
                ssl: false,
                details: None,
            });
            port_results.push(PortResult {
                port,
                state: "open".to_string(),
                service,
            });
        }

        HostScanResult {
            ip: target,
            hostname: None,
            status: if host_up { "up" } else { "down" }.to_string(),
            open_ports: port_results,
            os_fingerprint,
            vulnerabilities,
            scan_duration_ms: start_time.elapsed().as_millis(),
        }
    }
}
