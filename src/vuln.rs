use crate::service::ServiceInfo;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityAlert {
    pub port: u16,
    pub title: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    pub description: String,
    pub remediation: String,
}

pub fn check_vulnerabilities(
    open_ports: &[u16],
    services: &HashMap<u16, ServiceInfo>,
) -> Vec<VulnerabilityAlert> {
    let mut alerts = Vec::new();

    for &port in open_ports {
        let srv = services.get(&port);
        let srv_name = srv.map(|s| s.name.as_str()).unwrap_or("");
        let details = srv.and_then(|s| s.details.as_deref()).unwrap_or("");

        // 1. Docker Daemon unauthenticated
        if port == 2375 || srv_name == "docker-api" || details.contains("Docker") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Docker Remote API (Unauthenticated)".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Docker daemon socket is exposed over cleartext TCP without TLS authentication. Any attacker can gain full root access to the host system by spawning privileged containers.".to_string(),
                remediation: "Bind Docker to a Unix socket only, or enable mutual TLS (mTLS) authentication on port 2376.".to_string(),
            });
        }

        // 2. Redis unauthenticated
        if port == 6379 || srv_name == "redis" {
            if details.contains("Redis server responding without authentication") {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: "Unauthenticated Redis Database Instance".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "Redis answered PING without requiring 'AUTH'. Attackers can read/write data, overwrite SSH authorized_keys, or achieve remote code execution via cron tasks or modules.".to_string(),
                    remediation: "Enable 'requirepass' in redis.conf and bind Redis strictly to localhost (127.0.0.1) or internal VPN.".to_string(),
                });
            } else {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: "Exposed Redis Port".to_string(),
                    severity: "HIGH".to_string(),
                    description: "Redis port 6379 is accessible. Ensure strong authentication and network access control are enforced.".to_string(),
                    remediation: "Set strong password with requirepass and restrict access using a firewall.".to_string(),
                });
            }
        }

        // 3. Telnet cleartext
        if port == 23 || srv_name == "telnet" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Insecure Telnet Protocol in Use".to_string(),
                severity: "HIGH".to_string(),
                description: "Telnet transmits all credentials, commands, and session data in unencrypted plaintext, vulnerable to passive network sniffing and MITM attacks.".to_string(),
                remediation: "Disable the Telnet daemon immediately and migrate to SSH (port 22).".to_string(),
            });
        }

        // 4. Exposed SMB / Microsoft DS
        if port == 445 || port == 139 {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed SMB / NetBIOS Service".to_string(),
                severity: "HIGH".to_string(),
                description: "Server Message Block (SMB) is exposed. Historically targeted by critical exploits (EternalBlue, WannaCry, SMBGhost, SambaCry).".to_string(),
                remediation: "Block ports 445 and 139 at the network perimeter. Keep OS patched and ensure SMBv1 is disabled.".to_string(),
            });
        }

        // 5. Exposed Memcached
        if port == 11211 || srv_name == "memcached" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Memcached Server".to_string(),
                severity: "HIGH".to_string(),
                description: "Memcached without SASL authentication allows unrestricted cache dump and can be abused as a high-bandwidth DDoS reflection vector.".to_string(),
                remediation: "Bind Memcached to 127.0.0.1, disable UDP, or enable SASL authentication.".to_string(),
            });
        }

        // 6. Exposed Elasticsearch / CouchDB
        if port == 9200 || port == 9300 || srv_name == "elasticsearch" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Elasticsearch REST API".to_string(),
                severity: "HIGH".to_string(),
                description: "Elasticsearch HTTP interface is accessible. Default or missing security configurations can lead to full database leakage or tampering.".to_string(),
                remediation: "Enable Elasticsearch security features (X-Pack), configure RBAC, and bind to private network.".to_string(),
            });
        }

        // 7. Exposed MongoDB
        if port == 27017 || port == 27018 || srv_name == "mongodb" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed MongoDB Database".to_string(),
                severity: "MEDIUM".to_string(),
                description: "MongoDB port is directly reachable. Verify that authentication is enforced and databases are not publicly queryable.".to_string(),
                remediation: "Enable authorization (auth = true) and restrict IP bindings in mongod.conf.".to_string(),
            });
        }

        // 8. Exposed VNC
        if port == 5900 || port == 5901 || srv_name == "vnc" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed VNC Remote Desktop".to_string(),
                severity: "MEDIUM".to_string(),
                description: "VNC servers frequently suffer from weak authentication, truncated 8-character passwords, and unencrypted traffic.".to_string(),
                remediation: "Tunnel VNC sessions over SSH or VPN, and mandate strong passwords.".to_string(),
            });
        }

        // 9. Exposed Cleartext FTP
        if port == 21 && srv_name == "ftp" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Cleartext FTP Service Enabled".to_string(),
                severity: "LOW".to_string(),
                description: "Plain FTP transmits user credentials and files unencrypted across the network.".to_string(),
                remediation: "Enforce FTPS (FTP over TLS) or migrate to SFTP via SSH.".to_string(),
            });
        }
    }

    alerts
}
