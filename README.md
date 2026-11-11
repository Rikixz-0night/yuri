<div align="center">

```
  __     __           _ 
  \ \   / /   _ _ __ (_)
   \ \ / / | | | '__|| |
    \ V /| |_| | |   | |
     \_/  \__,_|_|   |_|
```

# ⚡ Yuri

**Next-Gen Ultra-Fast Asynchronous Port Scanner & Heuristic OS Fingerprinting Engine**

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://kernel.org)
[![Performance](https://img.shields.io/badge/speed-65k%20ports%20in%20%3C1s-brightgreen.svg)]()

*Scan 65,535 ports in under 1 second, fingerprint target operating systems with precision, grab live service banners, and audit vulnerabilities with zero bloat.*

</div>

---

## 🌟 Overview

**Yuri** is an ultra-high performance network reconnaissance tool and port scanner engineered in **Rust** using **Tokio**. Built for security professionals, penetration testers, and network engineers who find standard tools like `nmap` too slow for wide-scope enumeration.

Traditional tools often choke on large port ranges due to single-threaded designs, synchronous I/O, or rigid socket timeouts. **Yuri** solves this with an asynchronous lock-free architecture that can dispatch **5,000 to 20,000+ simultaneous connections**, auto-elevates Linux file descriptor limits (`ulimit -n`), and implements multi-layer OS fingerprinting combining packet TTL hop calculation with application layer banner inspection.

---

## 🚀 Speed Comparison: Yuri vs. Nmap

| Metric / Feature | **⚡ Yuri** | **Nmap** |
| :--- | :--- | :--- |
| **All 65,535 Ports (Local/LAN)** | **~0.84 seconds** ⚡ | ~3 to 5 minutes |
| **Concurrency Model** | Lock-free Async Tokio Green Threads | Synchronous Multiplexed (select/poll) |
| **Engine Language** | Modern Rust (Memory safe, Zero GC) | C / C++ |
| **Automatic OS Fingerprinting** | ✅ Multi-layer (TTL + TCP + Banners) | ✅ Signature DB (Requires -O / root) |
| **Live Service & Banner Grabbing** | ✅ Built-in Async Prober | ✅ Requires `-sV` |
| **Unauthenticated Service Auditing** | ✅ Docker, Redis, Telnet, SMB | ⚠️ Requires NSE scripts |
| **Nmap Native Script Pipeline** | ✅ Built-in `--pipe-nmap` flag | N/A |
| **Zero External Runtime Dependencies** | ✅ Single standalone binary | ❌ Requires libraries & data files |

---

## 📥 Installation

### 1. One-Liner Quick Install (Linux)

You can install Yuri automatically on any Linux distribution using the shell script:

```bash
curl -sSL https://raw.githubusercontent.com/Rikixz-0night/yuri/main/install.sh | sh
```

Or using `bash`:

```bash
curl -sSL https://raw.githubusercontent.com/Rikixz-0night/yuri/main/install.sh | bash
```

The installer handles:
- Detecting or bootstrapping the Rust/Cargo toolchain via rustup.
- Compiling an optimized release binary with Link-Time Optimization (`opt-level=3`, `lto=true`).
- Placing the binary in `/usr/local/bin/yuri` (or `~/.local/bin/yuri`).

---

### 2. Manual Installation from Source

Clone the repository and compile using Cargo:

```bash
# Clone the repository
git clone https://github.com/Rikixz-0night/yuri.git
cd yuri

# Build the release binary
cargo build --release

# Install to your system path
sudo cp target/release/yuri /usr/local/bin/
```

Verify installation:

```bash
yuri --help
```

---

## 🎯 Usage & Examples

### 1. Quick Scan (Top 1,000 Ports)
Scan default top 1,000 ports with live progress and automatic OS detection:
```bash
yuri 192.168.1.1
```

### 2. Full Range (All 65,535 Ports in < 1s)
Scan all 65,535 TCP ports at maximum concurrency:
```bash
yuri 127.0.0.1 -p all
# or
yuri 192.168.1.50 -p 1-65535
```

### 3. Custom Ports & Exclusions
Scan specific services while excluding noisy or rate-limited ports:
```bash
yuri 10.0.0.1 -p 80,443,8080,8443,3000,5000,22,21
yuri 10.0.0.1 -p 1-10000 --exclude-ports 135,139,445
```

### 4. CIDR Subnet Sweep
Discover active hosts across an entire `/24` subnet:
```bash
yuri 192.168.1.0/24 -p top100
```

### 5. IP Range Scanning
Scan sequential blocks of hosts:
```bash
yuri 192.168.1.1-192.168.1.50 -p 22,80,443
```

### 6. JSON Export for Automation & Scripting
Output clean, machine-parseable JSON for integration into pipelines or reporting:
```bash
yuri 192.168.1.1 -p top100 --json > scan_report.json
```

Or save formatted reports using `-o`:
```bash
yuri 192.168.1.1 -p top1000 -o scan_output.txt
```

### 7. Pipeline into Nmap Script Engine
Discover all open ports in seconds with Yuri, then pipe them directly to Nmap for comprehensive vulnerability scanning (`-sC -sV`):
```bash
yuri 192.168.1.1 -p all --pipe-nmap
```

### 8. Custom Command Execution Hook
Run custom tools (like curl, nikto, or nuclei) automatically on discovered open ports:
```bash
yuri 192.168.1.1 -p 80,8080 --exec "curl -I http://{ip}:{ports}"
```

---

## 🧠 OS Fingerprinting Architecture

Yuri uses a hybrid heuristic inference engine that combines multiple layers of network and application evidence:

1. **Network Layer (TTL & Hop Distance)**:
   - Captures incoming packet Time-to-Live (TTL).
   - Differentiates base operating system kernels:
     - `TTL <= 64`: Linux, Android, FreeBSD, macOS, iOS.
     - `TTL <= 128`: Microsoft Windows (10, 11, Server 2016-2022).
     - `TTL <= 255`: Cisco IOS, Solaris, Juniper, Network appliances.
   - Computes network hop distance: `hops = initial_ttl - captured_ttl`.

2. **Application Layer (Service Banner Recognition)**:
   - Regex matching on HTTP `Server:` and `X-Powered-By:` headers (Apache Ubuntu/Debian/CentOS, IIS versions).
   - SSH daemon banner signatures (`OpenSSH_Ubuntu`, `OpenSSH_Debian`, `OpenSSH_for_Windows`, `dropbear`).
   - Service responses for Android Console, FTP, SMTP, and databases.

3. **Composite Confidence Scoring**:
   - Scores candidate OS families and outputs an exact OS identification with confidence percentage bar.

---

## ⚠️ Built-in Security & Vulnerability Auditing

Yuri automatically detects dangerous network misconfigurations:
- 🚨 **Exposed Docker API (`port 2375`)**: Flags unauthenticated Docker daemon sockets that allow root container breakout.
- 🚨 **Unauthenticated Redis (`port 6379`)**: Probes Redis with `PING` and warns if accessible without password.
- ⚠️ **Cleartext Telnet (`port 23`)**: Warns about unencrypted credential transmission.
- ⚠️ **Exposed SMB (`ports 445, 139`)**: Warns about public SMB exposure.
- ⚠️ **Exposed Memcached / MongoDB / Elasticsearch**: Warns about unprotected databases.

---

## ⚙️ CLI Reference

```
Usage: yuri [OPTIONS] <TARGETS>...

Arguments:
  <TARGETS>...  Target IP address, hostname, CIDR block (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-50)

Options:
  -p, --ports <PORTS>              Ports to scan: 'top100', 'top1000', 'all' (1-65535), '80,443', or '1-1024' [default: top1000]
  -c, --concurrency <CONCURRENCY>  Number of concurrent connection tasks [default: 4500]
  -t, --timeout <TIMEOUT>          Connection timeout in milliseconds [default: 800]
      --no-os                      Disable OS detection and fingerprinting
      --no-service                 Disable service banner grabbing
      --no-vuln                    Disable vulnerability heuristics
      --exclude-ports <EXCLUDE>    Comma-separated list of ports to exclude from scanning
      --json                       Output scan results in JSON format
  -o, --output <OUTPUT>            Save output report to specified file
      --pipe-nmap                  Automatically pipe discovered open ports directly into Nmap (-sC -sV)
      --exec <EXEC>                Execute custom command for open ports. Placeholders: {ip}, {ports}
  -q, --quiet                      Quiet mode: suppress banners and progress bars
  -h, --help                       Print help
  -V, --version                    Print version
```

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by [Rikixz](https://github.com/Rikixz-0night).
