use crate::service::ServiceInfo;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsFingerprint {
    pub name: String,
    pub vendor: String,
    pub family: String,
    pub device_type: String,
    pub confidence: u8,
    pub ttl: Option<u8>,
    pub estimated_hops: Option<u8>,
    pub details: Vec<String>,
}

pub struct OsDetector {
    re_ubuntu: Regex,
    re_debian: Regex,
    re_rhel: Regex,
    re_windows_iis: Regex,
    re_windows_ssh: Regex,
    re_freebsd: Regex,
    re_openwrt: Regex,
    re_android: Regex,
    re_cisco: Regex,
    re_mikrotik: Regex,
}

impl OsDetector {
    pub fn new() -> Self {
        Self {
            re_ubuntu: Regex::new(r"(?i)ubuntu").unwrap(),
            re_debian: Regex::new(r"(?i)debian").unwrap(),
            re_rhel: Regex::new(r"(?i)(rhel|centos|rocky|alma|fedora|red hat|el[789])").unwrap(),
            re_windows_iis: Regex::new(r"(?i)microsoft-iis/(\d+\.\d+)").unwrap(),
            re_windows_ssh: Regex::new(r"(?i)openssh_for_windows").unwrap(),
            re_freebsd: Regex::new(r"(?i)freebsd").unwrap(),
            re_openwrt: Regex::new(r"(?i)(openwrt|dropbear)").unwrap(),
            re_android: Regex::new(r"(?i)(android console|adb)").unwrap(),
            re_cisco: Regex::new(r"(?i)cisco").unwrap(),
            re_mikrotik: Regex::new(r"(?i)(mikrotik|rosssh)").unwrap(),
        }
    }

    pub fn detect(
        &self,
        open_ports: &[u16],
        services: &HashMap<u16, ServiceInfo>,
        observed_ttl: Option<u8>,
    ) -> OsFingerprint {
        let mut scores: HashMap<&'static str, u32> = HashMap::new();
        let mut details = Vec::new();
        let mut vendor = "Generic".to_string();
        let mut family = "Unknown".to_string();
        let mut device_type = "General Purpose".to_string();

        let mut estimated_hops = None;

        // 1. Analyze TTL
        if let Some(ttl) = observed_ttl {
            let (initial_ttl, os_hint): (u8, &str) = if ttl <= 64 {
                (64, "Linux / macOS / FreeBSD")
            } else if ttl <= 128 {
                (128, "Microsoft Windows")
            } else {
                (255, "Cisco IOS / Solaris / Network Appliance")
            };

            let hops = initial_ttl.saturating_sub(ttl);
            estimated_hops = Some(hops);
            details.push(format!(
                "Observed TTL: {} (Est. Initial TTL: {}, Hop distance: {}) -> {}",
                ttl, initial_ttl, hops, os_hint
            ));

            if initial_ttl == 64 {
                *scores.entry("linux").or_insert(0) += 30;
                *scores.entry("bsd_darwin").or_insert(0) += 20;
            } else if initial_ttl == 128 {
                *scores.entry("windows").or_insert(0) += 40;
            } else if initial_ttl == 255 {
                *scores.entry("network_device").or_insert(0) += 40;
            }
        }

        // 2. Analyze Port signatures
        let has_port = |p: u16| open_ports.contains(&p);

        // Windows specific ports: 445 (SMB), 135 (MSRPC), 139 (NetBIOS), 3389 (RDP), 5985/5986 (WinRM)
        let mut win_port_count = 0;
        if has_port(445) { win_port_count += 1; }
        if has_port(135) { win_port_count += 1; }
        if has_port(139) { win_port_count += 1; }
        if has_port(3389) { win_port_count += 1; }
        if has_port(5985) || has_port(5986) { win_port_count += 1; }

        if win_port_count >= 2 {
            *scores.entry("windows").or_insert(0) += 35;
            details.push(format!("Found {} typical Windows service ports (SMB/RDP/MSRPC)", win_port_count));
        } else if win_port_count == 1 {
            *scores.entry("windows").or_insert(0) += 15;
        }

        // Linux typical ports: 22 (SSH), 111 (rpcbind), 2049 (NFS)
        if has_port(22) {
            *scores.entry("linux").or_insert(0) += 15;
            *scores.entry("bsd_darwin").or_insert(0) += 10;
        }
        if has_port(111) || has_port(2049) {
            *scores.entry("linux").or_insert(0) += 20;
            details.push("Found Unix RPC / NFS service ports".to_string());
        }

        // 3. Application Banners and Header Inspection
        for (&port, srv) in services {
            let combined = format!(
                "{} {} {}",
                srv.banner.as_deref().unwrap_or(""),
                srv.http_server.as_deref().unwrap_or(""),
                srv.http_title.as_deref().unwrap_or("")
            );

            if self.re_ubuntu.is_match(&combined) {
                *scores.entry("ubuntu").or_insert(0) += 70;
                *scores.entry("linux").or_insert(0) += 50;
                details.push(format!("Port {}: Banner mentions 'Ubuntu'", port));
            }
            if self.re_debian.is_match(&combined) {
                *scores.entry("debian").or_insert(0) += 70;
                *scores.entry("linux").or_insert(0) += 50;
                details.push(format!("Port {}: Banner mentions 'Debian'", port));
            }
            if self.re_rhel.is_match(&combined) {
                *scores.entry("rhel").or_insert(0) += 70;
                *scores.entry("linux").or_insert(0) += 50;
                details.push(format!("Port {}: Banner mentions Red Hat/CentOS/Fedora", port));
            }
            if let Some(caps) = self.re_windows_iis.captures(&combined) {
                *scores.entry("windows").or_insert(0) += 65;
                let version = caps.get(1).map_or("", |m| m.as_str());
                details.push(format!("Port {}: Microsoft IIS version {}", port, version));
            }
            if self.re_windows_ssh.is_match(&combined) {
                *scores.entry("windows").or_insert(0) += 70;
                details.push(format!("Port {}: OpenSSH for Windows banner detected", port));
            }
            if self.re_openwrt.is_match(&combined) {
                *scores.entry("openwrt").or_insert(0) += 70;
                details.push(format!("Port {}: Embedded Dropbear / OpenWrt banner detected", port));
            }
            if self.re_android.is_match(&combined) {
                *scores.entry("android").or_insert(0) += 85;
                details.push(format!("Port {}: Android ADB / Console banner detected", port));
            }
            if self.re_mikrotik.is_match(&combined) {
                *scores.entry("mikrotik").or_insert(0) += 80;
                details.push(format!("Port {}: MikroTik RouterOS banner detected", port));
            }
            if self.re_cisco.is_match(&combined) {
                *scores.entry("cisco").or_insert(0) += 80;
                details.push(format!("Port {}: Cisco IOS banner detected", port));
            }
            if self.re_freebsd.is_match(&combined) {
                *scores.entry("freebsd").or_insert(0) += 70;
                details.push(format!("Port {}: FreeBSD banner detected", port));
            }
        }

        // Determine best match
        let is_ubuntu = *scores.get("ubuntu").unwrap_or(&0) > 0;
        let is_debian = *scores.get("debian").unwrap_or(&0) > 0;
        let is_rhel = *scores.get("rhel").unwrap_or(&0) > 0;
        let is_openwrt = *scores.get("openwrt").unwrap_or(&0) > 0;
        let is_android = *scores.get("android").unwrap_or(&0) > 0;
        let is_mikrotik = *scores.get("mikrotik").unwrap_or(&0) > 0;
        let is_cisco = *scores.get("cisco").unwrap_or(&0) > 0;
        let is_freebsd = *scores.get("freebsd").unwrap_or(&0) > 0;

        let linux_score = *scores.get("linux").unwrap_or(&0);
        let win_score = *scores.get("windows").unwrap_or(&0);
        let network_score = *scores.get("network_device").unwrap_or(&0);

        let os_name: String;
        let confidence: u8;

        if is_android {
            os_name = "Android (Linux Kernel)".to_string();
            vendor = "Google / Android Open Source Project".to_string();
            family = "Android / Linux".to_string();
            device_type = "Mobile / Emulator / Android Device".to_string();
            confidence = 96;
        } else if is_mikrotik {
            os_name = "MikroTik RouterOS".to_string();
            vendor = "MikroTik".to_string();
            family = "RouterOS".to_string();
            device_type = "Router / Switch".to_string();
            confidence = 96;
        } else if is_cisco {
            os_name = "Cisco IOS".to_string();
            vendor = "Cisco".to_string();
            family = "IOS".to_string();
            device_type = "Router / Switch".to_string();
            confidence = 95;
        } else if is_openwrt {
            os_name = "Embedded Linux (OpenWrt / Embedded Appliance)".to_string();
            vendor = "OpenWrt / Linux".to_string();
            family = "Linux".to_string();
            device_type = "Embedded / Router".to_string();
            confidence = 94;
        } else if is_ubuntu {
            os_name = "Linux (Ubuntu)".to_string();
            vendor = "Canonical".to_string();
            family = "Linux".to_string();
            device_type = "Server / Workstation".to_string();
            confidence = 95;
        } else if is_debian {
            os_name = "Linux (Debian)".to_string();
            vendor = "Debian Project".to_string();
            family = "Linux".to_string();
            device_type = "Server / Workstation".to_string();
            confidence = 95;
        } else if is_rhel {
            os_name = "Linux (Red Hat / CentOS / Rocky)".to_string();
            vendor = "Red Hat".to_string();
            family = "Linux".to_string();
            device_type = "Server".to_string();
            confidence = 94;
        } else if is_freebsd {
            os_name = "FreeBSD".to_string();
            vendor = "FreeBSD Foundation".to_string();
            family = "BSD".to_string();
            device_type = "Server / Appliance".to_string();
            confidence = 92;
        } else if win_score > linux_score && win_score >= 35 {
            os_name = "Microsoft Windows (10 / 11 / Server 2016-2022)".to_string();
            vendor = "Microsoft".to_string();
            family = "Windows".to_string();
            device_type = "Workstation / Server".to_string();
            confidence = if win_score >= 60 { 92 } else { 85 };
        } else if linux_score >= 30 {
            os_name = "Linux (Kernel 4.x - 6.x)".to_string();
            vendor = "Linux Foundation".to_string();
            family = "Linux".to_string();
            device_type = "Server / Workstation".to_string();
            confidence = if linux_score >= 50 { 90 } else { 80 };
        } else if network_score >= 40 {
            os_name = "Network Appliance (Cisco / Solaris / BSD Network OS)".to_string();
            vendor = "Network Vendor".to_string();
            family = "Embedded OS".to_string();
            device_type = "Router / Switch / Firewall".to_string();
            confidence = 78;
        } else if observed_ttl == Some(64) {
            os_name = "Linux / Unix / macOS".to_string();
            vendor = "Unix/Linux".to_string();
            family = "Unix-like".to_string();
            device_type = "General Purpose".to_string();
            confidence = 70;
        } else if observed_ttl == Some(128) {
            os_name = "Microsoft Windows".to_string();
            vendor = "Microsoft".to_string();
            family = "Windows".to_string();
            device_type = "General Purpose".to_string();
            confidence = 70;
        } else {
            os_name = "Unknown OS".to_string();
            confidence = 25;
        }

        OsFingerprint {
            name: os_name,
            vendor,
            family,
            device_type,
            confidence,
            ttl: observed_ttl,
            estimated_hops,
            details,
        }
    }
}
