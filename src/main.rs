use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::sync::Arc;
use sysinfo::{SystemExt, ProcessExt, CpuExt, DiskExt, NetworksExt};
use reqwest;
use serde_json::json;
use chrono::Local;
use tokio;
use std::process::Command;
use regex::Regex;
use whois::whois;
use std::collections::HashMap;

const DISCORD_WEBHOOK_URL: &str = "URL"; // Replace 'URL' with your Discord Webhook URL
const DISCORD_MESSAGE_ID: &str = "ID"; // Replace 'ID' with the ID of the message to edit (for editing mode)

const ALERT_ROLE_ID: &str = "ID"; // Replace 'ID' with your Role ID for critical alerts
const NORMAL_ROLE_ID: &str = "ID"; // Replace 'ID' with your Role ID for alert state changes

const CPU_THRESHOLD: f32 = 90.0;
const RAM_THRESHOLD: f32 = 90.0;
const PROCESS_CPU_THRESHOLD: f32 = 80.0;
const PROCESS_RAM_THRESHOLD: f32 = 80.0;
const DDOS_THRESHOLD_MB_PER_SEC: f64 = 100.0;
const DDOS_CHECK_PERIODS: usize = 5;
const FAILED_LOGIN_THRESHOLD: usize = 5; // Replace with the threshold for failed login attempts

const EDIT_MESSAGE: bool = true; // Set to true to edit the existing message, false to send new messages

struct AlertState {
    cpu_alert: bool,
    ram_alert: bool,
    ddos_alert: bool,
    process_alert: bool,
    failed_login_alert: bool,
}

#[tokio::main]
async fn main() {
    let system = Arc::new(Mutex::new(sysinfo::System::new_all()));
    let alert_state = Arc::new(Mutex::new(AlertState {
        cpu_alert: false,
        ram_alert: false,
        ddos_alert: false,
        process_alert: false,
        failed_login_alert: false,
    }));

    let system_clone = Arc::clone(&system);
    let alert_state_clone = Arc::clone(&alert_state);

    tokio::task::spawn(async move {
        let mut last_network_rx = 0;
        let mut last_check = Instant::now();
        let mut network_rates = Vec::with_capacity(DDOS_CHECK_PERIODS);

        loop {
            {
                let sys = system_clone.lock().await;
                check_resources(&sys, &alert_state_clone, &mut last_network_rx, &mut last_check, &mut network_rates).await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            system_clone.lock().await.refresh_all();
        }
    });

    let mut last_summary_update = Instant::now();

    loop {
        {
            let sys = system.lock().await;
            if last_summary_update.elapsed() >= Duration::from_secs(1800) {
                if EDIT_MESSAGE {
                    edit_summary(&sys).await;
                } else {
                    send_summary(&sys).await;
                }
                last_summary_update = Instant::now();
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await; // Check every minute if the summary needs updating
    }
}

async fn check_resources(system: &sysinfo::System, alert_state: &Arc<Mutex<AlertState>>, last_network_rx: &mut u64, last_check: &mut Instant, network_rates: &mut Vec<f64>) {
    let cpu_usage = system.global_cpu_info().cpu_usage();
    let ram_usage = system.used_memory() as f32 / system.total_memory() as f32 * 100.0;
    
    let mut state = alert_state.lock().await;

    // Check CPU usage
    if cpu_usage > CPU_THRESHOLD && !state.cpu_alert {
        send_alert("High CPU Usage", &format!("CPU usage exceeded threshold limit, current usage is {:.2}%", cpu_usage)).await;
        state.cpu_alert = true;
    } else if cpu_usage <= CPU_THRESHOLD && state.cpu_alert {
        send_normal_ping("CPU usage returned to normal").await;
        state.cpu_alert = false;
    }

    // Check RAM usage
    if ram_usage > RAM_THRESHOLD && !state.ram_alert {
        send_alert("High RAM Usage", &format!("RAM usage exceeded threshold limit, current usage is {:.2}%", ram_usage)).await;
        state.ram_alert = true;
    } else if ram_usage <= RAM_THRESHOLD && state.ram_alert {
        send_normal_ping("RAM usage returned to normal").await;
        state.ram_alert = false;
    }

    // Check for high resource-consuming processes
    let mut top_cpu_processes = Vec::new();
    let mut top_ram_processes = Vec::new();

    for (pid, process) in system.processes() {
        let process_cpu = process.cpu_usage();
        let process_ram = process.memory() as f32 / system.total_memory() as f32 * 100.0;

        if process_cpu > PROCESS_CPU_THRESHOLD || process_ram > PROCESS_RAM_THRESHOLD {
            if !state.process_alert {
                send_alert("High Resource-Consuming Process", &format!("Process {} (PID: {}) is using {:.2}% CPU and {:.2}% RAM", process.name(), pid, process_cpu, process_ram)).await;
                state.process_alert = true;
            }
            break;
        } else if state.process_alert {
            state.process_alert = false;
        }

        top_cpu_processes.push((process_cpu, process.name().to_string()));
        top_ram_processes.push((process_ram, process.name().to_string()));
    }

    top_cpu_processes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    top_ram_processes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    // Check for potential DDoS
    let current_network_rx: u64 = system.networks().iter().map(|(_, network)| network.total_received()).sum();
    let elapsed = last_check.elapsed();
    let network_rate_mb_per_s = if elapsed.as_secs() > 0 {
        (current_network_rx - *last_network_rx) as f64 / elapsed.as_secs_f64() / 1_000_000.0
    } else {
        0.0
    };

    network_rates.push(network_rate_mb_per_s);
    if network_rates.len() > DDOS_CHECK_PERIODS {
        network_rates.remove(0);
    }
    let average_rate = network_rates.iter().sum::<f64>() / network_rates.len() as f64;

    if average_rate > DDOS_THRESHOLD_MB_PER_SEC && !state.ddos_alert {
        send_alert("Potential DDoS Attack", &format!("Average network rate exceeded threshold: {:.2} MB/s", average_rate)).await;
        state.ddos_alert = true;
    } else if average_rate <= DDOS_THRESHOLD_MB_PER_SEC && state.ddos_alert {
        send_normal_ping("Network usage returned to normal").await;
        state.ddos_alert = false;
    }

    *last_network_rx = current_network_rx;
    *last_check = Instant::now();

    // Check failed login attempts
    let failed_logins = check_failed_logins().await;
    if !failed_logins.is_empty() && !state.failed_login_alert {
        send_alert("Failed Login Attempts", &failed_logins.join("\n")).await;
        state.failed_login_alert = true;
    } else if failed_logins.is_empty() && state.failed_login_alert {
        send_normal_ping("No recent failed login attempts").await;
        state.failed_login_alert = false;
    }
}

async fn send_alert(title: &str, description: &str) {
    let payload = json!({
        "content": "",
        "embeds": [{
            "title": title,
            "description": description,
            "color": 16711680, // Red color for alerts
            "timestamp": Local::now().to_rfc3339(),
        }]
    });

    let client = reqwest::Client::new();
    client.post(DISCORD_WEBHOOK_URL)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send alert");
}

async fn send_normal_ping(description: &str) {
    let payload = json!({
        "content": "",
        "embeds": [{
            "title": "System Status",
            "description": description,
            "color": 3066993, // Gray color for normal state
            "timestamp": Local::now().to_rfc3339(),
        }]
    });

    let client = reqwest::Client::new();
    client.post(DISCORD_WEBHOOK_URL)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send normal ping");
}

async fn send_summary(system: &sysinfo::System) {
    let payload = create_summary_payload(system).await;

    let client = reqwest::Client::new();
    client.post(DISCORD_WEBHOOK_URL)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send summary");
}

async fn edit_summary(system: &sysinfo::System) {
    let payload = create_summary_payload(system).await;

    let client = reqwest::Client::new();
    client.patch(format!("{}?wait=true", DISCORD_WEBHOOK_URL))
        .json(&payload)
        .send()
        .await
        .expect("Failed to edit summary");
}

async fn create_summary_payload(system: &sysinfo::System) -> serde_json::Value {
    let cpu_usage = system.global_cpu_info().cpu_usage();
    let ram_usage = system.used_memory() as f32 / system.total_memory() as f32 * 100.0;
    let total_disk_space: u64 = system.disks().iter().map(|disk| disk.total_space()).sum();
    let free_disk_space: u64 = system.disks().iter().map(|disk| disk.available_space()).sum();
    let disk_usage = (total_disk_space - free_disk_space) as f32 / total_disk_space as f32 * 100.0;

    let processes: Vec<_> = system.processes().iter().collect();
    let total_processes = processes.len();

    let mut top_cpu_processes: Vec<_> = processes.iter()
        .map(|(pid, process)| (process.cpu_usage(), process.name().to_string(), *pid))
        .collect();
    top_cpu_processes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    let mut top_ram_processes: Vec<_> = processes.iter()
        .map(|(pid, process)| (process.memory() as f32 / system.total_memory() as f32 * 100.0, process.name().to_string(), *pid))
        .collect();
    top_ram_processes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    let network_stats = system.networks().iter()
        .map(|(_, net)| format!("{}: Received: {} bytes, Sent: {} bytes", net.name(), net.total_received(), net.total_transmitted()))
        .collect::<Vec<_>>()
        .join("\n");

    json!({
        "content": "",
        "embeds": [{
            "title": "System Status Summary",
            "fields": [
                {
                    "name": "CPU Usage",
                    "value": format!("{:.2}%", cpu_usage),
                    "inline": true
                },
                {
                    "name": "RAM Usage",
                    "value": format!("{:.2}%", ram_usage),
                    "inline": true
                },
                {
                    "name": "Disk Usage",
                    "value": format!("{:.2}%", disk_usage),
                    "inline": true
                },
                {
                    "name": "Total Processes",
                    "value": total_processes.to_string(),
                    "inline": true
                },
                {
                    "name": "Top CPU Processes",
                    "value": top_cpu_processes.iter()
                        .take(5)
                        .map(|(cpu, name, _)| format!("{}: {:.2}%", name, cpu))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    "inline": false
                },
                {
                    "name": "Top RAM Processes",
                    "value": top_ram_processes.iter()
                        .take(5)
                        .map(|(ram, name, _)| format!("{}: {:.2}%", name, ram))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    "inline": false
                },
                {
                    "name": "Network Stats",
                    "value": network_stats,
                    "inline": false
                }
            ],
            "timestamp": Local::now().to_rfc3339(),
        }]
    })
}

async fn check_failed_logins() -> Vec<String> {
    let output = Command::new("bash")
        .arg("-c")
        .arg("sudo journalctl | grep -E 'Failed password|Invalid user|Failed publickey'")
        .output()
        .expect("Failed to execute command");

    let logs = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Failed password for (\S+) from (\S+) port (\d+)").unwrap();

    let mut failed_logins = Vec::new();
    let mut ip_details_cache = HashMap::new();

    for cap in re.captures_iter(&logs) {
        let user = &cap[1];
        let ip = &cap[2];
        let port = &cap[3];

        let details = if let Some(details) = ip_details_cache.get(ip) {
            details.clone()
        } else {
            let whois_info = match whois(ip).await {
                Ok(info) => info,
                Err(_) => "Could not retrieve IP details".to_string(),
            };
            let details = format!("IP: {} - {}", ip, whois_info);
            ip_details_cache.insert(ip.to_string(), details.clone());
            details
        };

        failed_logins.push(format!("Failed login attempt by user '{}' from IP '{}' on port '{}'\nDetails: {}", user, ip, port, details));
    }

    failed_logins
}
