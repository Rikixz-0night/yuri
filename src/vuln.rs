use crate::service::ServiceInfo;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityAlert {
    pub port: u16,
    pub title: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    pub cve: Option<String>,
    pub cvss: Option<f32>,
    pub description: String,
    pub remediation: String,
}

pub fn check_vulnerabilities(
    open_ports: &[u16],
    services: &HashMap<u16, ServiceInfo>,
) -> Vec<VulnerabilityAlert> {
    let mut alerts = Vec::new();

    // Regex matchers for version auditing
    let re_openssh = Regex::new(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?").unwrap();
    let re_dropbear = Regex::new(r"dropbear[_-](\d{4})\.?(\d+)?").unwrap();
    let re_libssh = Regex::new(r"libssh[_-](\d+)\.(\d+)\.(\d+)").unwrap();
    let re_apache = Regex::new(r"Apache/(\d+)\.(\d+)\.(\d+)").unwrap();
    let re_nginx = Regex::new(r"nginx/(\d+)\.(\d+)\.(\d+)").unwrap();
    let re_php = Regex::new(r"PHP/(\d+)\.(\d+)\.(\d+)").unwrap();
    let re_iis = Regex::new(r"Microsoft-IIS/(\d+)\.(\d+)").unwrap();
    let re_grafana = Regex::new(r"Grafana\s+v?(\d+)\.(\d+)\.(\d+)").unwrap();

    for &port in open_ports {
        let srv = services.get(&port);
        let srv_name = srv.map(|s| s.name.as_str()).unwrap_or("");
        let banner = srv.and_then(|s| s.banner.as_deref()).unwrap_or("");
        let http_server = srv.and_then(|s| s.http_server.as_deref()).unwrap_or("");
        let http_title = srv.and_then(|s| s.http_title.as_deref()).unwrap_or("");
        let details = srv.and_then(|s| s.details.as_deref()).unwrap_or("");

        let combined = format!("{} {} {} {}", banner, http_server, http_title, details);

        // =========================================================================
        // 1. SSH PROTOCOL & VERSION VULNERABILITY AUDITING
        // =========================================================================
        if port == 22 || port == 2222 || srv_name.contains("ssh") || banner.starts_with("SSH-") {
            // Audit OpenSSH versions
            if let Some(caps) = re_openssh.captures(&combined) {
                let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                let patch: u32 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));

                let version_float = major as f32 + (minor as f32 / 10.0);

                // CVE-2024-6387 regreSSHion (OpenSSH 8.5p1 to 9.7p1)
                let is_regresshion = (major == 8 && minor >= 5)
                    || (major == 9 && minor < 8)
                    || (major == 9 && minor == 7 && patch <= 1);

                if is_regresshion {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("OpenSSH {}.{}p{} - regreSSHion Unauthenticated Remote Code Execution", major, minor, patch),
                        severity: "CRITICAL".to_string(),
                        cve: Some("CVE-2024-6387".to_string()),
                        cvss: Some(8.1),
                        description: "A critical signal handler race condition in sshd allows unauthenticated remote code execution as root on glibc-based Linux systems.".to_string(),
                        remediation: "Immediately upgrade OpenSSH to >= 9.8p1. If immediate patching is not possible, set 'LoginGraceTime 0' in /etc/ssh/sshd_config as a temporary mitigation.".to_string(),
                    });
                }

                // CVE-2023-48795 Terrapin Attack (OpenSSH < 9.6)
                if (major < 9) || (major == 9 && minor < 6) {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("OpenSSH {}.{}p{} - Terrapin Attack (Prefix Truncation / BAP)", major, minor, patch),
                        severity: "HIGH".to_string(),
                        cve: Some("CVE-2023-48795".to_string()),
                        cvss: Some(7.5),
                        description: "Vulnerable to cryptographic handshake manipulation that allows a MITM attacker to truncate extension negotiation packets and downgrade connection security when using ChaCha20-Poly1305 or CBC-EtM.".to_string(),
                        remediation: "Upgrade OpenSSH to version 9.6p1 or newer which supports the strict key exchange ('kex-strict') extension.".to_string(),
                    });
                }

                // CVE-2023-38408 PKCS#11 Forwarding RCE (OpenSSH < 9.3p2)
                if (major < 9) || (major == 9 && minor < 3) || (major == 9 && minor == 3 && patch < 2) {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("OpenSSH {}.{}p{} - PKCS#11 Forwarding Arbitrary Library Load RCE", major, minor, patch),
                        severity: "HIGH".to_string(),
                        cve: Some("CVE-2023-38408".to_string()),
                        cvss: Some(8.8),
                        description: "Flaw in ssh-agent's PKCS#11 provider allows remote code execution on the client via forwarded ssh-agent sockets when connecting to compromised or untrusted servers.".to_string(),
                        remediation: "Upgrade OpenSSH to 9.3p2 or newer, and avoid using ssh-agent forwarding ('ssh -A') with untrusted hosts.".to_string(),
                    });
                }

                // CVE-2018-15473 Username Enumeration (OpenSSH < 7.7)
                if version_float < 7.7 {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("OpenSSH {}.{}p{} - User Enumeration Oracle Vulnerability", major, minor, patch),
                        severity: "MEDIUM".to_string(),
                        cve: Some("CVE-2018-15473".to_string()),
                        cvss: Some(5.3),
                        description: "Discrepancy in authentication request parsing allows unauthenticated remote attackers to determine whether a given username exists on the system.".to_string(),
                        remediation: "Upgrade OpenSSH to version 7.7 or newer.".to_string(),
                    });
                }

                // Legacy & Deprecated OpenSSH Versions (< 7.0)
                if version_float < 7.0 {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("Obsolete OpenSSH {}.{} Detected (< 7.0)", major, minor),
                        severity: "CRITICAL".to_string(),
                        cve: Some("CVE-2016-0777 / CVE-2016-0778".to_string()),
                        cvss: Some(9.8),
                        description: "Extremely old OpenSSH release lacking modern cipher suites and vulnerable to Roaming memory disclosure and multiple remote vulnerabilities.".to_string(),
                        remediation: "Upgrade to the latest maintained OpenSSH release.".to_string(),
                    });
                }
            }

            // Audit libssh
            if let Some(caps) = re_libssh.captures(&combined) {
                let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                let patch: u32 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));

                if (major == 0 && minor == 6)
                    || (major == 0 && minor == 7 && patch <= 5)
                    || (major == 0 && minor == 8 && patch <= 3)
                {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("libssh {}.{}.{} - Authentication Bypass", major, minor, patch),
                        severity: "CRITICAL".to_string(),
                        cve: Some("CVE-2018-10933".to_string()),
                        cvss: Some(9.1),
                        description: "Severe authentication bypass in libssh server: sending SSH2_MSG_USERAUTH_SUCCESS causes the server to grant authenticated session access without credentials.".to_string(),
                        remediation: "Immediately upgrade libssh to version 0.7.6, 0.8.4, or newer.".to_string(),
                    });
                }
            }

            // Audit Dropbear
            if let Some(caps) = re_dropbear.captures(&combined) {
                let year: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                if year < 2022 {
                    alerts.push(VulnerabilityAlert {
                        port,
                        title: format!("Outdated Dropbear SSH Server (Build {})", year),
                        severity: "MEDIUM".to_string(),
                        cve: Some("CVE-2016-7406 / CVE-2018-15599".to_string()),
                        cvss: Some(7.0),
                        description: "Older Dropbear releases suffer from memory safety vulnerabilities, username enumeration, and weak legacy ciphers.".to_string(),
                        remediation: "Upgrade Dropbear SSH to >= 2022.82.".to_string(),
                    });
                }
            }
        }

        // =========================================================================
        // 2. WEB SERVERS & APPLICATION ENGINES (Apache, Nginx, IIS, PHP, Spring)
        // =========================================================================
        if let Some(caps) = re_apache.captures(&combined) {
            let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let patch: u32 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));

            // CVE-2021-41773 & CVE-2021-42013 (Apache 2.4.49 & 2.4.50)
            if major == 2 && minor == 4 && (patch == 49 || patch == 50) {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("Apache HTTP Server 2.4.{} - Path Traversal & Remote Code Execution", patch),
                    severity: "CRITICAL".to_string(),
                    cve: Some("CVE-2021-41773 / CVE-2021-42013".to_string()),
                    cvss: Some(9.8),
                    description: "Path traversal flaw in URI normalization allows unauthenticated remote attackers to read arbitrary files and execute code if CGI scripts are enabled.".to_string(),
                    remediation: "Upgrade Apache HTTP Server to version 2.4.51 or later immediately.".to_string(),
                });
            } else if major == 2 && minor == 4 && patch < 54 {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("Apache HTTP Server 2.4.{} - Multiple High Severity Flaws", patch),
                    severity: "HIGH".to_string(),
                    cve: Some("CVE-2022-22720 / CVE-2022-23943".to_string()),
                    cvss: Some(7.5),
                    description: "Version vulnerable to HTTP request smuggling, memory corruption in mod_sed, and buffer overflows.".to_string(),
                    remediation: "Upgrade Apache HTTP Server to the latest release (>= 2.4.58).".to_string(),
                });
            }
        }

        if let Some(caps) = re_nginx.captures(&combined) {
            let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let patch: u32 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));

            // Nginx 1-byte memory overwrite CVE-2021-23017 (< 1.20.1)
            if (major == 1 && minor < 20) || (major == 1 && minor == 20 && patch == 0) {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("Nginx {}.{}.{} - 1-byte Memory Overwrite in DNS Resolver", major, minor, patch),
                    severity: "HIGH".to_string(),
                    cve: Some("CVE-2021-23017".to_string()),
                    cvss: Some(7.7),
                    description: "1-byte memory overwrite flaw in Nginx DNS resolver module allows remote attackers to crash the worker or potentially execute code.".to_string(),
                    remediation: "Upgrade Nginx to version 1.20.1, 1.22.0, or newer.".to_string(),
                });
            }
        }

        if let Some(caps) = re_php.captures(&combined) {
            let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));

            // End-of-Life PHP (PHP < 8.1)
            if major < 8 || (major == 8 && minor == 0) {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("End-of-Life PHP Engine ({}.{}) Detected", major, minor),
                    severity: "HIGH".to_string(),
                    cve: Some("CWE-1104".to_string()),
                    cvss: Some(7.5),
                    description: format!("PHP {}.{} reached official End-of-Life (EOL) and receives no security updates or vulnerability fixes.", major, minor),
                    remediation: "Migrate application to actively maintained PHP versions (PHP 8.2 or 8.3+).".to_string(),
                });
            }
        }

        if let Some(caps) = re_iis.captures(&combined) {
            let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            if major <= 7 {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("Legacy Microsoft IIS Server (Version {}.x)", major),
                    severity: "CRITICAL".to_string(),
                    cve: Some("MS15-034 / CVE-2015-1635".to_string()),
                    cvss: Some(9.8),
                    description: "Obsolete IIS web server running on unsupported Windows Server releases, susceptible to HTTP.sys remote code execution attacks.".to_string(),
                    remediation: "Upgrade to supported Windows Server 2019/2022 with IIS 10.0 and modern TLS stacks.".to_string(),
                });
            }
        }

        if let Some(caps) = re_grafana.captures(&combined) {
            let major: u32 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let minor: u32 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            let patch: u32 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));

            if major == 8 && (minor < 3 || (minor == 3 && patch == 0)) {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: format!("Grafana {}.{}.{} - Directory Traversal / Arbitrary File Read", major, minor, patch),
                    severity: "CRITICAL".to_string(),
                    cve: Some("CVE-2021-43798".to_string()),
                    cvss: Some(7.5),
                    description: "Unauthenticated directory traversal vulnerability allows remote attackers to read arbitrary files such as /etc/passwd and grafana.ini via installed plugin assets endpoint.".to_string(),
                    remediation: "Upgrade Grafana to version 8.3.1, 8.2.7, or newer immediately.".to_string(),
                });
            }
        }

        // Spring Boot Actuator Exposure
        if combined.contains("Whitelabel Error Page") || combined.contains("actuator") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Spring Boot Application / Exposed Actuator Signature".to_string(),
                severity: "MEDIUM".to_string(),
                cve: Some("CWE-200".to_string()),
                cvss: Some(5.3),
                description: "Spring Boot indicators detected. If Actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/jolokia) are accessible, sensitive credentials and tokens may be leaked.".to_string(),
                remediation: "Set 'management.endpoints.web.exposure.exclude=*' or ensure Actuator endpoints require strict authentication.".to_string(),
            });
        }

        // =========================================================================
        // 3. INFRASTRUCTURE & ORCHESTRATION (Docker, K8s, etcd, Consul)
        // =========================================================================
        // Docker Daemon unauthenticated
        if port == 2375 || srv_name == "docker-api" || details.contains("Docker") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Docker Remote API (Unauthenticated TCP Socket)".to_string(),
                severity: "CRITICAL".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(9.8),
                description: "Docker daemon socket is exposed over cleartext TCP without TLS authentication. Any remote attacker can gain full root access to the host system by spawning privileged containers with root filesystem mount.".to_string(),
                remediation: "Bind Docker to a local Unix socket only (/var/run/docker.sock) or configure mutual TLS (mTLS) certificates on port 2376.".to_string(),
            });
        }

        // Kubernetes Kubelet Unauthenticated API (Port 10250)
        if port == 10250 {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Kubernetes Kubelet API (Port 10250)".to_string(),
                severity: "CRITICAL".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(9.8),
                description: "Kubelet API port is accessible. If anonymous-auth is enabled, attackers can query cluster metrics, read pod logs, and execute remote commands in running containers via the /run or /exec endpoints.".to_string(),
                remediation: "Set '--anonymous-auth=false' and mandate Webhook token authentication in kubelet configuration.".to_string(),
            });
        }

        // etcd Key-Value Store (Port 2379 / 2380)
        if port == 2379 || port == 2380 || srv_name.contains("etcd") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed etcd Cluster Store (Port 2379/2380)".to_string(),
                severity: "CRITICAL".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(9.8),
                description: "etcd distributed store is accessible over network. etcd stores all cluster configuration, secrets, and cryptographic keys without encryption if client certificate verification is omitted.".to_string(),
                remediation: "Enable TLS client certificate authentication (--client-cert-auth) and bind strictly to private control plane network.".to_string(),
            });
        }

        // HashiCorp Consul (Port 8500)
        if port == 8500 || srv_name.contains("consul") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed HashiCorp Consul Management API / UI".to_string(),
                severity: "HIGH".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(8.6),
                description: "HashiCorp Consul API is exposed. Unauthenticated access can allow attackers to read/write Key-Value configurations and execute script checks (remote command execution).".to_string(),
                remediation: "Enable Consul ACL system with default deny, disable script checks ('enable_script_checks: false'), and enable TLS.".to_string(),
            });
        }

        // Apache ActiveMQ (Port 61616 / 8161)
        if port == 61616 || port == 8161 || combined.contains("ActiveMQ") {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Potential Apache ActiveMQ OpenWire RCE Exposure".to_string(),
                severity: "CRITICAL".to_string(),
                cve: Some("CVE-2023-46604".to_string()),
                cvss: Some(9.8),
                description: "Apache ActiveMQ brokers running vulnerable versions allow unauthenticated remote attackers to execute arbitrary shell commands via untrusted class unmarshaling in OpenWire protocol.".to_string(),
                remediation: "Upgrade ActiveMQ to versions 5.15.16, 5.16.7, 5.17.6, 5.18.3, or newer.".to_string(),
            });
        }

        // =========================================================================
        // 4. DATABASES & CACHING SYSTEMS
        // =========================================================================
        // Redis
        if port == 6379 || srv_name == "redis" {
            if details.contains("Redis server responding without authentication") {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: "Unauthenticated Redis Database Instance (Verified +PONG Response)".to_string(),
                    severity: "CRITICAL".to_string(),
                    cve: Some("CWE-306".to_string()),
                    cvss: Some(9.8),
                    description: "Redis answered PING without requiring 'AUTH'. Remote unauthenticated attackers can execute commands, read/dump keys, tamper with configurations, overwrite ~/.ssh/authorized_keys, or gain shell via cron or rogue modules.".to_string(),
                    remediation: "Enable 'requirepass <strong_password>' in redis.conf, bind Redis strictly to 127.0.0.1 ('bind 127.0.0.1 ::1'), and enable protected-mode.".to_string(),
                });
            } else {
                alerts.push(VulnerabilityAlert {
                    port,
                    title: "Exposed Redis Port (6379)".to_string(),
                    severity: "HIGH".to_string(),
                    cve: Some("CWE-284".to_string()),
                    cvss: Some(7.5),
                    description: "Redis database port is exposed to the network. If weak credentials or password guessing is possible, full database compromise can occur.".to_string(),
                    remediation: "Enforce a cryptographically random password with requirepass and restrict access using a local firewall.".to_string(),
                });
            }
        }

        // Memcached
        if port == 11211 || srv_name == "memcached" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Memcached Server (Port 11211)".to_string(),
                severity: "HIGH".to_string(),
                cve: Some("CVE-2018-1000115".to_string()),
                cvss: Some(7.5),
                description: "Memcached without SASL authentication allows unrestricted cache dump and can be abused as a massive UDP amplification DDoS reflection vector (factor up to 50,000x).".to_string(),
                remediation: "Bind Memcached to 127.0.0.1, disable UDP (-U 0), or enable SASL authentication.".to_string(),
            });
        }

        // Elasticsearch
        if port == 9200 || port == 9300 || srv_name == "elasticsearch" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed Elasticsearch REST API / Cluster Port".to_string(),
                severity: "HIGH".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(7.5),
                description: "Elasticsearch HTTP interface is accessible. If security features (X-Pack) are disabled or default credentials are in use, all indexes can be dumped or modified.".to_string(),
                remediation: "Enable Elasticsearch security features (xpack.security.enabled: true), configure RBAC, and bind to private network.".to_string(),
            });
        }

        // MongoDB
        if port == 27017 || port == 27018 || srv_name == "mongodb" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed MongoDB Database (Port 27017/27018)".to_string(),
                severity: "MEDIUM".to_string(),
                cve: Some("CWE-306".to_string()),
                cvss: Some(6.5),
                description: "MongoDB port is directly reachable. Verify that authentication is enforced and databases are not queryable anonymously.".to_string(),
                remediation: "Enable authorization ('security.authorization: enabled') in mongod.conf and bind strictly to private IPs.".to_string(),
            });
        }

        // PostgreSQL
        if port == 5432 || srv_name == "postgresql" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed PostgreSQL Database Port (5432)".to_string(),
                severity: "MEDIUM".to_string(),
                cve: Some("CWE-284".to_string()),
                cvss: Some(6.0),
                description: "PostgreSQL port is reachable over the network. Ensure pg_hba.conf does not use 'trust' authentication and enforce scram-sha-256.".to_string(),
                remediation: "Require scram-sha-256 authentication and enforce TLS connections ('hostssl').".to_string(),
            });
        }

        // MySQL
        if port == 3306 || srv_name == "mysql" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed MySQL / MariaDB Database Port (3306)".to_string(),
                severity: "MEDIUM".to_string(),
                cve: Some("CWE-284".to_string()),
                cvss: Some(6.0),
                description: "MySQL database port is exposed to network queries. Subject to brute-force attacks and potential auth bypass flaws in older engines.".to_string(),
                remediation: "Bind MySQL to 127.0.0.1 or internal VPN, and ensure root remote login is disabled.".to_string(),
            });
        }

        // =========================================================================
        // 5. INSECURE & CLEARTEXT REMOTE ACCESS PROTOCOLS
        // =========================================================================
        // Telnet
        if port == 23 || srv_name == "telnet" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Insecure Telnet Protocol in Use (Cleartext Communication)".to_string(),
                severity: "HIGH".to_string(),
                cve: Some("CWE-319".to_string()),
                cvss: Some(7.5),
                description: "Telnet transmits all usernames, passwords, commands, and output completely unencrypted across the network, trivial to intercept via network sniffing or ARP spoofing.".to_string(),
                remediation: "Disable the Telnet daemon immediately and migrate to SSH (port 22).".to_string(),
            });
        }

        // Cleartext FTP
        if port == 21 && srv_name == "ftp" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Cleartext FTP Service Enabled".to_string(),
                severity: "LOW".to_string(),
                cve: Some("CWE-319".to_string()),
                cvss: Some(4.3),
                description: "Plain FTP transmits user credentials and uploaded files unencrypted across the network.".to_string(),
                remediation: "Enforce FTPS (FTP over TLS) or migrate to SFTP via SSH.".to_string(),
            });
        }

        // VNC
        if port == 5900 || port == 5901 || srv_name == "vnc" {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed VNC Remote Desktop Service".to_string(),
                severity: "MEDIUM".to_string(),
                cve: Some("CWE-287".to_string()),
                cvss: Some(6.5),
                description: "VNC servers frequently suffer from weak authentication, truncated 8-character passwords, and unencrypted session streaming.".to_string(),
                remediation: "Tunnel VNC sessions over SSH or VPN, and mandate strong passwords.".to_string(),
            });
        }

        // SMB / NetBIOS
        if port == 445 || port == 139 {
            alerts.push(VulnerabilityAlert {
                port,
                title: "Exposed SMB / NetBIOS File Sharing Service".to_string(),
                severity: "HIGH".to_string(),
                cve: Some("MS17-010 / CVE-2020-0796".to_string()),
                cvss: Some(8.5),
                description: "Server Message Block (SMB) is exposed. Historically targeted by critical remote wormable exploits (EternalBlue, SMBGhost, WannaCry, SambaCry).".to_string(),
                remediation: "Block ports 445 and 139 at network firewalls. Ensure SMBv1 is disabled and latest security updates are applied.".to_string(),
            });
        }
    }

    alerts
}
