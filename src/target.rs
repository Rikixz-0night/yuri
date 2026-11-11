use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

pub const TOP_100_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 194, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636, 873, 902, 990, 993,
    995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222,
    3000, 3128, 3306, 3389, 4000, 4443, 5000, 5060, 5432, 5672, 5900, 5985, 5986, 6000, 6379,
    7000, 7001, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 11211, 27017, 27018, 28017, 30000, 32400, 50000, 6443, 2375, 2376, 5005,
    8009, 8088, 8089, 8181,
];

pub fn get_top_1000_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::with_capacity(1000);
    // Add top 100
    for &p in TOP_100_PORTS {
        ports.push(p);
    }
    // Add common well-known and registered ports
    for p in 1..=1024 {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    // Add other widely-used high ports
    let high_ports = [
        1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222,
        2375, 2376, 2379, 2380, 3000, 3001, 3128, 3268, 3269, 3306, 3389, 3690, 4000, 4040,
        4242, 4369, 4443, 4444, 4567, 5000, 5001, 5060, 5061, 5432, 5555, 5672, 5900, 5901,
        5902, 5985, 5986, 6000, 6001, 6379, 6443, 6666, 6667, 7000, 7001, 7070, 7077, 7443,
        7474, 7687, 8000, 8001, 8008, 8009, 8080, 8081, 8082, 8085, 8088, 8089, 8090, 8161,
        8181, 8200, 8300, 8443, 8500, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9100, 9200,
        9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 27019, 28017, 30000, 32400,
        50000, 50070, 61616,
    ];
    for &p in &high_ports {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports.truncate(1000);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn parse_port_specs(spec: &str, exclude: &[u16]) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    let trimmed = spec.trim().to_lowercase();

    if trimmed == "top100" || trimmed == "top-100" {
        ports.extend_from_slice(TOP_100_PORTS);
    } else if trimmed == "top1000" || trimmed == "top-1000" || trimmed == "top" {
        ports = get_top_1000_ports();
    } else if trimmed == "all" || trimmed == "full" || trimmed == "1-65535" {
        ports = (1..=65535).collect();
    } else {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() != 2 {
                    return Err(format!("Invalid port range: {}", part));
                }
                let start: u16 = range[0]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid start port: {}", range[0]))?;
                let end: u16 = range[1]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid end port: {}", range[1]))?;
                if start == 0 || end == 0 || start > end {
                    return Err(format!("Invalid range: {}-{}", start, end));
                }
                for p in start..=end {
                    ports.push(p);
                }
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| format!("Invalid port number: {}", part))?;
                if port == 0 {
                    return Err("Port 0 is invalid".to_string());
                }
                ports.push(port);
            }
        }
    }

    // Exclude requested ports
    ports.retain(|p| !exclude.contains(p));
    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        return Err("No valid ports specified".to_string());
    }

    Ok(ports)
}

pub fn parse_targets(target_str: &str) -> Result<Vec<IpAddr>, String> {
    let mut result = Vec::new();
    let trimmed = target_str.trim();

    // Check if target is a CIDR block e.g. 192.168.1.0/24
    if trimmed.contains('/') {
        let net = IpNet::from_str(trimmed)
            .map_err(|e| format!("Invalid CIDR '{}': {}", trimmed, e))?;
        for ip in net.hosts() {
            result.push(ip);
        }
        return Ok(result);
    }

    // Check if target is an IP range e.g. 192.168.1.1-100 or 192.168.1.1-192.168.1.100
    if trimmed.contains('-') && !trimmed.starts_with('-') {
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 2 {
            let start_str = parts[0].trim();
            let end_str = parts[1].trim();

            if let Ok(start_ip) = Ipv4Addr::from_str(start_str) {
                let end_ip = if let Ok(ip) = Ipv4Addr::from_str(end_str) {
                    ip
                } else if let Ok(last_octet) = end_str.parse::<u8>() {
                    let octets = start_ip.octets();
                    Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
                } else {
                    return Err(format!("Invalid end of IP range: {}", end_str));
                };

                let start_u32 = u32::from(start_ip);
                let end_u32 = u32::from(end_ip);
                if start_u32 > end_u32 {
                    return Err(format!("Start IP cannot be greater than end IP in range {}", trimmed));
                }
                for ip_num in start_u32..=end_u32 {
                    result.push(IpAddr::V4(Ipv4Addr::from(ip_num)));
                }
                return Ok(result);
            }
        }
    }

    // Single IP address
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        result.push(ip);
        return Ok(result);
    }

    // Hostname resolution e.g. "localhost", "scanme.nmap.org"
    let host_port = format!("{}:80", trimmed);
    match host_port.to_socket_addrs() {
        Ok(addrs) => {
            let mut resolved = false;
            for addr in addrs {
                result.push(addr.ip());
                resolved = true;
            }
            if !resolved {
                return Err(format!("Could not resolve host: {}", trimmed));
            }
            result.sort_unstable();
            result.dedup();
            Ok(result)
        }
        Err(e) => Err(format!("Failed to resolve '{}': {}", trimmed, e)),
    }
}
