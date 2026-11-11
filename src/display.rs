use crate::scanner::HostScanResult;
use colored::*;

pub fn print_banner() {
    let banner = r#"
██╗   ██╗██╗   ██╗██████╗ ██╗
╚██╗ ██╔╝██║   ██║██╔══██╗██║
 ╚████╔╝ ██║   ██║██████╔╝██║
  ╚██╔╝  ██║   ██║██╔══██╗██║
   ██║   ╚██████╔╝██║  ██║██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝
"#;
    println!("{}", banner.bright_magenta().bold());
    println!(
        "{} {} | {}\n",
        "⚡ Yuri".bright_cyan().bold(),
        "v0.1.0".bright_yellow(),
        "Next-Gen Ultra-Fast Asynchronous Port Scanner & OS Fingerprinter".white()
    );
}

pub fn print_scan_header(target: &str, ports_count: usize, concurrency: usize, timeout_ms: u64) {
    println!("{}", "─".repeat(70).bright_black());
    println!(
        "{:<15}: {}",
        "🎯 Target".bright_cyan(),
        target.bright_white().bold()
    );
    println!(
        "{:<15}: {} ports",
        "🔌 Port Scope".bright_cyan(),
        ports_count.to_string().bright_yellow()
    );
    println!(
        "{:<15}: {} simultaneous workers (Rate: auto-scaling)",
        "🚀 Concurrency".bright_cyan(),
        concurrency.to_string().bright_green()
    );
    println!(
        "{:<15}: {} ms",
        "⏱️  Timeout".bright_cyan(),
        timeout_ms.to_string().bright_blue()
    );
    println!("{}\n", "─".repeat(70).bright_black());
}

pub fn print_host_result(result: &HostScanResult) {
    println!(
        "\n{} Host: {} is {}",
        "📡".bright_cyan(),
        result.ip.to_string().bright_white().bold(),
        if result.status == "up" {
            "UP".bright_green().bold()
        } else {
            "DOWN / FILTERED".bright_red().bold()
        }
    );

    if result.open_ports.is_empty() {
        println!("{}", "   No open ports discovered.".bright_black());
        return;
    }

    println!("\n{}", "PORT       STATE  SERVICE               BANNER / DETAILS".bright_white().bold());
    println!("{}", "─".repeat(78).bright_black());

    for port_res in &result.open_ports {
        let port_proto = format!("{}/tcp", port_res.port);
        let state = port_res.state.bright_green().bold();
        let service = &port_res.service.name;

        let mut banner = String::new();
        if let Some(ref b) = port_res.service.banner {
            banner = b.clone();
        } else if let Some(ref det) = port_res.service.details {
            banner = det.clone();
        }

        // Truncate banner if too long for clean display
        if banner.len() > 45 {
            banner.truncate(42);
            banner.push_str("...");
        }

        println!(
            "{:<10} {:<6} {:<21} {}",
            port_proto.bright_cyan(),
            state,
            service.bright_yellow(),
            banner.bright_white()
        );
    }
    println!("{}", "─".repeat(78).bright_black());

    // Display OS Fingerprint
    if let Some(ref os) = result.os_fingerprint {
        println!("\n{}", "🧠 OS FINGERPRINT & SYSTEM RECON:".bright_magenta().bold());
        println!("   ├─ OS Guess:       {}", os.name.bright_green().bold());
        println!("   ├─ Family / Type:  {} / {}", os.family.bright_yellow(), os.device_type.bright_cyan());
        println!("   ├─ Vendor:         {}", os.vendor.bright_white());

        let conf_bar_len = (os.confidence as usize / 10).min(10);
        let bar = format!(
            "[{}{}] {}%",
            "█".repeat(conf_bar_len).bright_green(),
            "░".repeat(10 - conf_bar_len).bright_black(),
            os.confidence
        );
        println!("   ├─ Confidence:     {}", bar);

        if let Some(hops) = os.estimated_hops {
            println!("   ├─ Network Hops:   ~{} hops away", hops.to_string().bright_yellow());
        }
        if let Some(ttl) = os.ttl {
            println!("   ├─ Captured TTL:   {}", ttl.to_string().bright_cyan());
        }

        if !os.details.is_empty() {
            println!("   └─ Evidence Clues:");
            for clue in &os.details {
                println!("      • {}", clue.bright_black());
            }
        }
    }

    // Display Vulnerability Alerts
    if !result.vulnerabilities.is_empty() {
        println!("\n{}", "⚠️  VULNERABILITY & SECURITY ALERTS:".bright_red().bold());
        for alert in &result.vulnerabilities {
            let badge = match alert.severity.as_str() {
                "CRITICAL" => "[CRITICAL]".on_red().white().bold(),
                "HIGH" => "[HIGH]".bright_red().bold(),
                "MEDIUM" => "[MEDIUM]".bright_yellow().bold(),
                _ => "[LOW]".bright_blue().bold(),
            };

            println!(
                "\n   {} {} (Port {})",
                badge,
                alert.title.bright_white().bold(),
                alert.port.to_string().bright_cyan()
            );
            println!("   Risk: {}", alert.description.white());
            println!("   Fix:  {}", alert.remediation.bright_green());
        }
    }

    let rate = if result.scan_duration_ms > 0 {
        (result.open_ports.len() as f64 / (result.scan_duration_ms as f64 / 1000.0)) as u64
    } else {
        0
    };

    println!("\n{}", "─".repeat(70).bright_black());
    println!(
        "Scan completed in {:.2}s ({} open ports found)",
        result.scan_duration_ms as f64 / 1000.0,
        result.open_ports.len().to_string().bright_green().bold()
    );
    let _ = rate;
}
