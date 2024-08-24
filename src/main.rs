use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::sync::Arc;
use sysinfo::{SystemExt, ProcessExt, CpuExt, DiskExt, NetworksExt, NetworkExt};
use reqwest;
use serde_json::json;
use chrono::Local;
use tokio;

// Configuration
const DISCORD_WEBHOOK_URL: &str = "URL"; // Replace with your Discord Webhook URL
const ALERT_ROLE_ID: &str = "ID"; // Replace with your Role ID for critical alerts
const NORMAL_ROLE_ID: &str = "ID"; // Replace with your Role ID for alert state changes

const CPU_THRESHOLD: f32 = 90.0;
const RAM_THRESHOLD: f32 = 90.0;
const PROCESS_CPU_THRESHOLD: f32 = 80.0;
const PROCESS_RAM_THRESHOLD: f32 = 80.0;
const DDOS_THRESHOLD_MB_PER_SEC: f64 = 100.0;
const DDOS_CHECK_PERIODS: usize = 5;

// Configuration for editing messages
const EDIT_MESSAGE: bool = true; // Set to true to edit the existing message, false to send a new one

static mut DISCORD_MESSAGE_ID: Option<String> = None;

struct AlertState {
    cpu_alert: bool,
    ram_alert: bool,
    ddos_alert: bool,
    process_alert: bool,
    failed_logins: u32, // Track the number of failed logins
}

#[tokio::main]
async fn main() {
    let system = Arc::new(Mutex::new(sysinfo::System::new_all()));
    let alert_state = Arc::new(Mutex::new(AlertState {
        cpu_alert: false,
        ram_alert: false,
        ddos_alert: false,
        process_alert: false,
        failed_logins: 0,
    }));

    let system_clone = Arc::clone(&system);
    let alert_state_clone = Arc::clone(&alert_state);

    // Initial message sending
    if EDIT_MESSAGE {
        send_summary(&system.lock().await).await;
    }

    tokio::task::spawn(async move {
        let mut last_network_rx = 0;
        let mut last_check = Instant::now();
        let mut network_rates = Vec::with_capacity(DDOS_CHECK_PERIODS);

        loop {
            {
                let sys = system_clone.lock().await;
                check_resources(&sys, &alert_state_clone, &mut last_network_rx, &mut last_check, &mut network_rates).await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await; // Adjust as needed
            system_clone.lock().await.refresh_all();
        }
    });

    loop {
        {
            let sys = system.lock().await;
            if EDIT_MESSAGE {
                edit_summary(&sys).await;
            } else {
                send_summary(&sys).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(1800)).await; // 30 minutes
    }
}

async fn check_resources(system: &sysinfo::System, alert_state: &Arc<Mutex<AlertState>>, last_network_rx: &mut u64, last_check: &mut Instant, network_rates: &mut Vec<f64>) {
    let cpu_usage = system.global_cpu_info().cpu_usage();
    let ram_usage = system.used_memory() as f32 / system.total_memory() as f32 * 100.0;
    
    let mut state = alert_state.lock().await;

    // Check CPU usage
    if cpu_usage > CPU_THRESHOLD && !state.cpu_alert {
        send_alert("High CPU Usage", &format!("CPU usage exceeded Threshold limit, current usage is {:.2}%", cpu_usage)).await;
        state.cpu_alert = true;
    } else if cpu_usage <= CPU_THRESHOLD && state.cpu_alert {
        send_normal_ping("CPU usage returned to normal").await;
        state.cpu_alert = false;
    }

    // Check RAM usage
    if ram_usage > RAM_THRESHOLD && !state.ram_alert {
        send_alert("High RAM Usage", &format!("RAM usage exceeded Threshold limit, current usage is {:.2}%", ram_usage)).await;
        state.ram_alert = true;
    } else if ram_usage <= RAM_THRESHOLD && state.ram_alert {
        send_normal_ping("RAM usage returned to normal").await;
        state.ram_alert = false;
    }

    // Check for high resource-consuming processes
    for (pid, process) in system.processes() {
        let process_cpu = process.cpu_usage();
        let process_ram = process.memory() as f32 / system.total_memory() as f32 * 100.0;

        if (process_cpu > PROCESS_CPU_THRESHOLD || process_ram > PROCESS_RAM_THRESHOLD) && !state.process_alert {
            send_alert("High Resource-Consuming Process", &format!("Process {} (PID: {}) is using {:.2}% CPU and {:.2}% RAM", process.name(), pid, process_cpu, process_ram)).await;
            state.process_alert = true;
            break;
        }
    }

    // Check for potential DDoS
    let current_network_rx: u64 = system.networks().iter().map(|(_, network)| network.total_received()).sum();
    let elapsed = last_check.elapsed();
    let network_rate_mb_per_s = if elapsed.as_secs() > 0 {
        (current_network_rx - *last_network_rx) as f64 / elapsed.as_secs_f64() / 1_000_000.0
    } else {
        0.0
    };

    // Track network rates for averaging
    network_rates.push(network_rate_mb_per_s);
    if network_rates.len() > DDOS_CHECK_PERIODS {
        network_rates.remove(0);
    }
    let average_rate = network_rates.iter().sum::<f64>() / network_rates.len() as f64;

    if average_rate > DDOS_THRESHOLD_MB_PER_SEC && !state.ddos_alert {
        let traffic_message = format!("Unusual high network traffic detected. Average: {:.2} MB/s", average_rate);
        send_alert("Potential DDoS Attack", &traffic_message).await;
        state.ddos_alert = true;
    } else if average_rate <= DDOS_THRESHOLD_MB_PER_SEC && state.ddos_alert {
        send_normal_ping("Network traffic returned to normal levels").await;
        state.ddos_alert = false;
    }

    *last_network_rx = current_network_rx;
    *last_check = Instant::now();

    // Check failed login attempts
    let failed_logins = check_failed_logins().await;
    if failed_logins > state.failed_logins {
        let new_attempts = failed_logins - state.failed_logins;
        let message = format!("{} new failed login attempts detected!", new_attempts);
        send_alert("Failed Login Attempts", &message).await;
        state.failed_logins = failed_logins;
    }
}

async fn check_failed_logins() -> u32 {
    // Use command to get failed login attempts
    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg("sudo journalctl | grep -E 'Failed password|Invalid user|Failed publickey' | wc -l")
        .output()
        .await
        .expect("Failed to execute command");
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    output_str.trim().parse().unwrap_or(0)
}

async fn send_summary(system: &sysinfo::System) {
    let cpu_usage = system.global_cpu_info().cpu_usage();
    let ram_usage = system.used_memory() as f32 / system.total_memory() as f32 * 100.0;
    let total_disk_space: u64 = system.disks().iter().map(|disk| disk.total_space()).sum();
    let used_disk_space: u64 = system.disks().iter().map(|disk| disk.total_space() - disk.available_space()).sum();
    let disk_usage = used_disk_space as f32 / total_disk_space as f32 * 100.0;
    
    let disk_usage_gb = used_disk_space as f32 / 1e9;
    let total_disk_space_gb = total_disk_space as f32 / 1e9;
    
    let network_tx: u64 = system.networks().iter().map(|(_, network)| network.total_transmitted()).sum();
    let network_rx: u64 = system.networks().iter().map(|(_, network)| network.total_received()).sum();

    let top_cpu_processes = get_top_processes(system, true);
    let top_ram_processes = get_top_processes(system, false);

    let summary = json!({
        "embeds": [{
            "title": "Resource Usage Summary",
            "color": 14869218,
            "fields": [
                {
                    "name": "CPU Usage",
                    "value": format!("- Current Usage: {:.2}%\n- Load Average: {:.2} / {:.2} / {:.2}", 
                                     cpu_usage, system.load_average().one, system.load_average().five, system.load_average().fifteen),
                    "inline": false
                },
                {
                    "name": "Memory Usage",
                    "value": format!("- Current Usage: {:.2}% ({:.2}GB)\n- Total Memory: {:.2} GB\n- Swap Usage: {:.2} / {:.2} GB",
                                     ram_usage, system.used_memory() as f32 / 1e9, 
                                     system.total_memory() as f32 / 1e9,
                                     system.used_swap() as f32 / 1e9, system.total_swap() as f32 / 1e9),
                    "inline": false
                },
                {
                    "name": "Disk Usage",
                    "value": format!("- Current Usage: {:.2}% ({:.2} GB)\n- Total Disk Space: {:.2} GB",
                                     disk_usage, disk_usage_gb,
                                     total_disk_space_gb),
                    "inline": false
                },
                {
                    "name": "Network Usage",
                    "value": format!("- Upstream: {:.2} GB\n- Downstream: {:.2} GB",
                                     network_tx as f32 / 1e9, network_rx as f32 / 1e9),
                    "inline": false
                },
                {
                    "name": "Total Process Count",
                    "value": format!("- {} processes", system.processes().len()),
                    "inline": false
                },
                {
                    "name": "Top CPU Processes",
                    "value": top_cpu_processes,
                    "inline": false
                },
                {
                    "name": "Top RAM Processes",
                    "value": top_ram_processes,
                    "inline": false
                },
                {
                    "name": "System Uptime",
                    "value": format!("- {} hours, {} minutes", system.uptime() / 3600, (system.uptime() % 3600) / 60),
                    "inline": false
                }
            ],
            "timestamp": Local::now().to_rfc3339()
        }]
    });

    if let Some(message_id) = unsafe { DISCORD_MESSAGE_ID.as_ref() } {
        edit_discord_message(&summary, message_id).await;
    } else {
        let res = send_discord_message(&summary).await;
        if let Ok(response) = res {
            unsafe {
                DISCORD_MESSAGE_ID = response.message_id;
            }
        }
    }
}

fn get_top_processes(system: &sysinfo::System, by_cpu: bool) -> String {
    let mut processes: Vec<_> = system.processes().iter().collect();
    processes.sort_by(|a, b| {
        let a_metric = if by_cpu { a.1.cpu_usage() } else { a.1.memory() as f32 / system.total_memory() as f32 * 100.0 };
        let b_metric = if by_cpu { b.1.cpu_usage() } else { b.1.memory() as f32 / system.total_memory() as f32 * 100.0 };
        b_metric.partial_cmp(&a_metric).unwrap()
    });

    processes.iter().take(3)
        .map(|(_, process)| {
            format!("• {}: {:.2}% CPU | {:.2}GB RAM", 
                    process.name(), 
                    process.cpu_usage(), 
                    process.memory() as f32 / 1e9)
        })
        .collect::<Vec<String>>()
        .join("\n")
}

async fn send_alert(title: &str, message: &str) {
    let content = format!("<@&{}>", ALERT_ROLE_ID);

    let payload = json!({
        "content": content,
        "embeds": [{
            "title": title,
            "description": message,
            "color": 15158332 // Red color
        }]
    });

    send_discord_message(&payload).await.unwrap();
}

async fn send_normal_ping(message: &str) {
    let content = format!("<@&{}>", NORMAL_ROLE_ID);
    let payload = json!({
        "content": content,
        "embeds": [{
            "description": message,
            "color": 3066993 // Green color
        }]
    });

    send_discord_message(&payload).await.unwrap();
}

async fn send_discord_message(payload: &serde_json::Value) -> Result<DiscordResponse, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client.post(DISCORD_WEBHOOK_URL)
        .json(payload)
        .send()
        .await?;

    #[derive(Deserialize)]
    struct DiscordResponse {
        id: String,
        channel_id: String,
        // Other fields can be added as needed
    }

    Ok(res.json().await?)
}

async fn edit_discord_message(payload: &serde_json::Value, message_id: &str) {
    let client = reqwest::Client::new();
    let url = format!("{}/messages/{}", DISCORD_WEBHOOK_URL, message_id);
    if let Err(e) = client.patch(&url)
        .json(payload)
        .send()
        .await
    {
        eprintln!("Failed to edit Discord message: {}", e);
    }
}
