use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "yuri",
    author = "Rikixz <rikixz67@gmail.com>",
    version = "0.1.0",
    about = "Blazing-fast asynchronous port scanner and OS fingerprinting engine written in Rust",
    long_about = "⚡ Yuri is an ultra-high performance port scanner built in Rust using Tokio.\nIt is designed to be significantly faster than standard nmap scans by utilizing\nlock-free async I/O, adaptive socket timeouts, and intelligent heuristic OS\nfingerprinting that combines TTL, TCP options, and application layer banners."
)]
pub struct Cli {
    /// Target IP address, hostname, CIDR block (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-50)
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Ports to scan: 'top100', 'top1000', 'all' (1-65535), '80,443', or '1-1024'
    #[arg(short = 'p', long = "ports", default_value = "top1000")]
    pub ports: String,

    /// Number of concurrent connection tasks (tune higher for gigabit LAN / lower for rate-limited links)
    #[arg(short = 'c', long = "concurrency", default_value_t = 4500)]
    pub concurrency: usize,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long = "timeout", default_value_t = 800)]
    pub timeout: u64,

    /// Disable OS detection and fingerprinting
    #[arg(long = "no-os", default_value_t = false)]
    pub no_os: bool,

    /// Disable service banner grabbing
    #[arg(long = "no-service", default_value_t = false)]
    pub no_service: bool,

    /// Disable vulnerability heuristics
    #[arg(long = "no-vuln", default_value_t = false)]
    pub no_vuln: bool,

    /// Filter security vulnerabilities by minimum CVSS score (e.g. --min-cvss 7.0)
    #[arg(long = "min-cvss")]
    pub min_cvss: Option<f32>,

    /// Comma-separated list of ports to exclude from scanning
    #[arg(long = "exclude-ports")]
    pub exclude_ports: Option<String>,

    /// Output scan results in JSON format
    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    /// Save output report to specified file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Automatically pipe discovered open ports directly into Nmap for deep script scanning (-sV -sC)
    #[arg(long = "pipe-nmap", default_value_t = false)]
    pub pipe_nmap: bool,

    /// Execute custom command for open ports. Placeholders: {ip}, {ports} (e.g. --exec "nmap -p {ports} -sV {ip}")
    #[arg(long = "exec")]
    pub exec: Option<String>,

    /// Quiet mode: suppress banners and progress bars
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub quiet: bool,
}
