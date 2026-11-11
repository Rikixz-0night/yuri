mod cli;
mod display;
mod os_detect;
mod scanner;
mod service;
mod target;
mod vuln;

use clap::Parser;
use cli::Cli;
use colored::*;
use scanner::{HostScanResult, ScannerConfig, YuriScanner};
use std::process::Command;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    // Optimize environment: Raise open file descriptor limits (nofile) for ultra-high concurrency
    match rlimit::increase_nofile_limit(65535) {
        Ok(limit) => {
            if !args.quiet && !args.json {
                // limits boosted
            }
            let _ = limit;
        }
        Err(e) => {
            if !args.quiet && !args.json {
                eprintln!("{}: Could not raise ulimit: {}", "[Notice]".bright_yellow(), e);
            }
        }
    }

    if !args.quiet && !args.json {
        display::print_banner();
    }

    // Parse excluded ports
    let excluded_ports = if let Some(ref exc) = args.exclude_ports {
        match target::parse_port_specs(exc, &[]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {}", "Error in excluded ports".bright_red(), e);
                std::process::exit(1);
            }
        }
    } else {
        Vec::new()
    };

    // Parse ports to scan
    let ports = match target::parse_port_specs(&args.ports, &excluded_ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {}", "Error parsing ports".bright_red(), e);
            std::process::exit(1);
        }
    };

    // Parse all targets (handles IPs, ranges like 192.168.1.1-100, and CIDRs like 192.168.1.0/24)
    let mut all_targets = Vec::new();
    for target_arg in &args.targets {
        match target::parse_targets(target_arg) {
            Ok(ips) => all_targets.extend(ips),
            Err(e) => {
                eprintln!("{}: {}", "Error resolving target".bright_red(), e);
                std::process::exit(1);
            }
        }
    }

    all_targets.sort_unstable();
    all_targets.dedup();

    if all_targets.is_empty() {
        eprintln!("{}: No valid targets found.", "Error".bright_red());
        std::process::exit(1);
    }

    if !args.quiet && !args.json {
        let target_display = if all_targets.len() == 1 {
            all_targets[0].to_string()
        } else {
            format!("{} targets (Batch / Subnet scan)", all_targets.len())
        };
        display::print_scan_header(&target_display, ports.len(), args.concurrency, args.timeout);
    }

    let config = ScannerConfig {
        concurrency: args.concurrency,
        timeout_ms: args.timeout,
        detect_os: !args.no_os,
        detect_service: !args.no_service,
        check_vulns: !args.no_vuln,
        quiet: args.quiet || args.json,
    };

    let scanner = YuriScanner::new(config);
    let mut scan_results: Vec<HostScanResult> = Vec::new();
    let overall_start = Instant::now();

    for ip in &all_targets {
        let result = scanner.scan_host(*ip, &ports).await;

        if !args.quiet && !args.json {
            display::print_host_result(&result);
        }

        // Pipe into Nmap if requested and open ports exist
        if args.pipe_nmap && !result.open_ports.is_empty() {
            let port_csv: String = result
                .open_ports
                .iter()
                .map(|p| p.port.to_string())
                .collect::<Vec<_>>()
                .join(",");

            println!(
                "\n{} Pipelining into Nmap for deep script scanning: nmap -sC -sV -p {} {}",
                "⚡".bright_green().bold(),
                port_csv.bright_yellow(),
                ip.to_string().bright_cyan()
            );

            let status = Command::new("nmap")
                .arg("-sC")
                .arg("-sV")
                .arg("-p")
                .arg(&port_csv)
                .arg(ip.to_string())
                .status();

            if let Err(e) = status {
                eprintln!("{}: Failed to execute nmap: {}", "Error".bright_red(), e);
            }
        }

        // Execute custom command if requested
        if let Some(ref exec_cmd) = args.exec {
            if !result.open_ports.is_empty() {
                let port_csv: String = result
                    .open_ports
                    .iter()
                    .map(|p| p.port.to_string())
                    .collect::<Vec<_>>()
                    .join(",");

                let cmd_rendered = exec_cmd
                    .replace("{ip}", &ip.to_string())
                    .replace("{ports}", &port_csv);

                println!(
                    "\n{} Executing hook: {}",
                    "⚙️".bright_cyan().bold(),
                    cmd_rendered.bright_white()
                );

                let status = Command::new("sh")
                    .arg("-c")
                    .arg(&cmd_rendered)
                    .status();

                if let Err(e) = status {
                    eprintln!("{}: Failed to execute command: {}", "Error".bright_red(), e);
                }
            }
        }

        scan_results.push(result);
    }

    // Output JSON if requested
    if args.json {
        let json_output = serde_json::to_string_pretty(&scan_results)?;
        println!("{}", json_output);
    }

    // Save output to file if requested
    if let Some(ref file_path) = args.output {
        let content = if args.json || file_path.ends_with(".json") {
            serde_json::to_string_pretty(&scan_results)?
        } else {
            let mut text = format!("Yuri Port Scanner Report\nGenerated at: {}\n\n", chrono::Utc::now());
            for r in &scan_results {
                text.push_str(&format!("Host: {} (Status: {})\n", r.ip, r.status));
                if let Some(ref os) = r.os_fingerprint {
                    text.push_str(&format!("OS: {} ({}% confidence)\n", os.name, os.confidence));
                }
                text.push_str("Open Ports:\n");
                for p in &r.open_ports {
                    text.push_str(&format!(
                        "  Port {:<5}/tcp | {:<15} | {}\n",
                        p.port,
                        p.service.name,
                        p.service.banner.as_deref().unwrap_or("No banner")
                    ));
                }
                if !r.vulnerabilities.is_empty() {
                    text.push_str("Security Alerts:\n");
                    for v in &r.vulnerabilities {
                        text.push_str(&format!("  [{}] Port {}: {} - {}\n", v.severity, v.port, v.title, v.description));
                    }
                }
                text.push_str("\n");
            }
            text
        };

        std::fs::write(file_path, content)?;
        if !args.quiet && !args.json {
            println!(
                "\n{} Scan report saved successfully to {}",
                "💾".bright_green(),
                file_path.bright_white().bold()
            );
        }
    }

    if !args.quiet && !args.json && all_targets.len() > 1 {
        println!(
            "\n{} All {} target scans finished in {:.2}s",
            "🏁".bright_cyan().bold(),
            all_targets.len(),
            overall_start.elapsed().as_secs_f64()
        );
    }

    Ok(())
}
