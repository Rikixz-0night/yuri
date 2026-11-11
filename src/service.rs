use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub banner: Option<String>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub ssl: bool,
    pub details: Option<String>,
}

pub fn default_service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 | 138 => "netbios",
        139 => "netbios-ssn",
        143 => "imap",
        161 | 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds (smb)",
        465 => "smtps",
        514 => "syslog",
        587 => "submission (smtp)",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks5",
        1194 => "openvpn",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2181 => "zookeeper",
        2222 => "ssh-alt",
        2375 => "docker (plain)",
        2376 => "docker (tls)",
        2379 | 2380 => "etcd",
        3000 => "node / react / grafana",
        3128 => "squid-http",
        3306 => "mysql",
        3389 => "ms-wbt-server (rdp)",
        4000 => "hexo / dev",
        4443 => "https-alt",
        5000 => "upnp / flask / docker-registry",
        5037 => "adb (android debug bridge)",
        5060 | 5061 => "sip",
        5432 => "postgresql",
        5554 => "android-console",
        5555 => "adb-tcp",
        5672 => "rabbitmq",
        5900 | 5901 => "vnc",
        5985 => "winrm-http",
        5986 => "winrm-https",
        6379 => "redis",
        6402 => "vnc / remote-desktop",
        6443 => "kubernetes-api",
        6667 => "irc",
        7000 | 7001 => "cassandra / weblogic",
        8000 => "http-alt / django",
        8008 => "http-alt",
        8080 => "http-proxy / tomcat",
        8081 => "http-alt",
        8443 => "https-alt",
        8500 => "consul",
        8554 => "rtsp / media-server",
        8888 => "jupyter / http-alt",
        9000 => "php-fpm / sonarqube",
        9090 => "prometheus / cockpit",
        9092 => "kafka",
        9100 => "node-exporter / jetdirect",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        11434 => "ollama (ai server)",
        27017 | 27018 => "mongodb",
        50000 => "sap / jenkins",
        _ => "unknown",
    }
}

pub async fn probe_service(ip: IpAddr, port: u16, probe_timeout: Duration) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: default_service_name(port).to_string(),
        banner: None,
        http_title: None,
        http_server: None,
        ssl: port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 5986,
        details: None,
    };

    // Quick TCP connect for probing
    let addr = (ip, port);
    let mut stream = match timeout(probe_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return info,
    };

    // Buffer for reading initial banner or reply
    let mut buf = [0u8; 2048];

    // Handle port-specific probes
    if port == 6379 {
        // Probe Redis
        let _ = stream.write_all(b"PING\r\n").await;
        if let Ok(Ok(n)) = timeout(probe_timeout, stream.read(&mut buf)).await {
            let res = String::from_utf8_lossy(&buf[..n]);
            if res.contains("+PONG") {
                info.name = "redis".to_string();
                info.details = Some("Redis server responding without authentication!".to_string());
                info.banner = Some(res.trim().to_string());
                return info;
            }
        }
    } else if port == 2375 {
        // Probe Docker daemon
        let _ = stream.write_all(b"GET /version HTTP/1.0\r\n\r\n").await;
        if let Ok(Ok(n)) = timeout(probe_timeout, stream.read(&mut buf)).await {
            let res = String::from_utf8_lossy(&buf[..n]);
            if res.contains("ApiVersion") || res.contains("docker") || res.contains("Docker") {
                info.name = "docker-api".to_string();
                info.details = Some("Exposed unauthenticated Docker daemon API!".to_string());
                info.banner = Some(clean_banner(&res));
                return info;
            }
        }
    }

    // Try reading initial greeting (SSH, FTP, SMTP, Telnet send greeting immediately)
    let greeting_timeout = if port == 22 || port == 2222 {
        Duration::from_millis(800)
    } else {
        Duration::from_millis(400)
    };
    if let Ok(Ok(n)) = timeout(greeting_timeout, stream.read(&mut buf)).await {
        if n > 0 {
            let banner_str = String::from_utf8_lossy(&buf[..n]).to_string();
            let cleaned = clean_banner(&banner_str);
            if !cleaned.is_empty() {
                if cleaned.starts_with("SSH-") {
                    info.name = "ssh".to_string();
                } else if cleaned.starts_with("220") && (port == 21 || cleaned.to_lowercase().contains("ftp")) {
                    info.name = "ftp".to_string();
                } else if cleaned.starts_with("220") && (port == 25 || port == 587 || cleaned.to_lowercase().contains("smtp") || cleaned.to_lowercase().contains("postfix") || cleaned.to_lowercase().contains("exim")) {
                    info.name = "smtp".to_string();
                } else if cleaned.starts_with("+OK") {
                    info.name = "pop3".to_string();
                } else if cleaned.starts_with("* OK") {
                    info.name = "imap".to_string();
                }
                info.banner = Some(cleaned);
                return info;
            }
        }
    }

    // Try HTTP probe for web ports or unknown ports
    let is_web = port == 80
        || port == 443
        || port == 8080
        || port == 8443
        || port == 3000
        || port == 5000
        || port == 8000
        || port == 8008
        || port == 8888
        || port == 9000
        || port == 9090
        || info.name == "unknown";

    if is_web {
        // Send a standard HTTP GET
        let host_header = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{}]", v6),
        };
        let http_req = format!(
            "GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (compatible; Yuri/1.0)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            host_header, port
        );

        let _ = stream.write_all(http_req.as_bytes()).await;
        if let Ok(Ok(n)) = timeout(probe_timeout, stream.read(&mut buf)).await {
            if n > 0 {
                let response = String::from_utf8_lossy(&buf[..n]);
                if response.starts_with("HTTP/") {
                    info.name = if port == 443 || port == 8443 { "https" } else { "http" }.to_string();

                    // Parse Server and X-Powered-By headers
                    for line in response.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("server:") {
                            let server_val = line[7..].trim();
                            info.http_server = Some(server_val.to_string());
                        } else if lower.starts_with("x-powered-by:") {
                            let powered_val = line[13..].trim();
                            info.details = Some(format!("X-Powered-By: {}", powered_val));
                        }
                    }

                    // Parse HTML title if present
                    if let Some(title) = extract_html_title(&response) {
                        info.http_title = Some(title);
                    }

                    let status_line = response.lines().next().unwrap_or("").trim();
                    let mut banner_desc = status_line.to_string();
                    if let Some(ref srv) = info.http_server {
                        banner_desc.push_str(&format!(" | Server: {}", srv));
                    }
                    if let Some(ref tit) = info.http_title {
                        banner_desc.push_str(&format!(" | Title: {}", tit));
                    }
                    info.banner = Some(banner_desc);
                    return info;
                }
            }
        }
    }

    info
}

fn clean_banner(raw: &str) -> String {
    let first_line = raw.lines().next().unwrap_or("");
    first_line
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>()
        .trim()
        .to_string()
}

fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start_tag = "<title>";
    let end_tag = "</title>";

    if let Some(start_idx) = lower.find(start_tag) {
        let content_start = start_idx + start_tag.len();
        if let Some(end_offset) = lower[content_start..].find(end_tag) {
            let title = &html[content_start..content_start + end_offset];
            let cleaned = title.split_whitespace().collect::<Vec<_>>().join(" ");
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}
