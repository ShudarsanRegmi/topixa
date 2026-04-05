use serde::Serialize;
use std::env;

#[derive(Clone, Serialize)]
struct ScannerStatus {
    name: String,
    available: bool,
}

#[derive(Clone, Serialize)]
struct HostNode {
    id: String,
    ip: String,
    label: String,
    subnet: String,
    os_family: String,
    services: Vec<String>,
    risk_score: u8,
    x: f32,
    y: f32,
}

#[derive(Clone, Serialize)]
struct HostEdge {
    source: String,
    target: String,
    relation: String,
}

#[derive(Clone, Serialize)]
struct TopologySnapshot {
    scan_id: String,
    generated_at: String,
    nodes: Vec<HostNode>,
    edges: Vec<HostEdge>,
}

fn has_command_in_path(command_name: &str) -> bool {
    if let Some(path_var) = env::var_os("PATH") {
        for path in env::split_paths(&path_var) {
            let full_path = path.join(command_name);
            if full_path.is_file() {
                return true;
            }

            #[cfg(target_os = "windows")]
            {
                for ext in ["exe", "cmd", "bat"] {
                    let candidate = path.join(format!("{}.{}", command_name, ext));
                    if candidate.is_file() {
                        return true;
                    }
                }
            }
        }
    }

    false
}

#[tauri::command]
fn get_scanner_status() -> Vec<ScannerStatus> {
    ["nmap", "masscan", "rustscan", "zmap"]
        .iter()
        .map(|name| ScannerStatus {
            name: (*name).to_string(),
            available: has_command_in_path(name),
        })
        .collect()
}

#[tauri::command]
fn load_sample_topology() -> TopologySnapshot {
    TopologySnapshot {
        scan_id: "sample-lan-2026-04-05".to_string(),
        generated_at: "2026-04-05T13:30:00Z".to_string(),
        nodes: vec![
            HostNode {
                id: "gateway-01".to_string(),
                ip: "192.168.1.1".to_string(),
                label: "Edge Gateway".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Linux".to_string(),
                services: vec!["ssh".to_string(), "dns".to_string(), "dhcp".to_string()],
                risk_score: 34,
                x: 490.0,
                y: 95.0,
            },
            HostNode {
                id: "web-01".to_string(),
                ip: "192.168.1.20".to_string(),
                label: "Public Docs".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Ubuntu".to_string(),
                services: vec!["http".to_string(), "https".to_string(), "ssh".to_string()],
                risk_score: 52,
                x: 250.0,
                y: 260.0,
            },
            HostNode {
                id: "db-01".to_string(),
                ip: "192.168.1.34".to_string(),
                label: "Inventory DB".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Debian".to_string(),
                services: vec!["postgres".to_string(), "ssh".to_string()],
                risk_score: 67,
                x: 724.0,
                y: 278.0,
            },
            HostNode {
                id: "printer-01".to_string(),
                ip: "192.168.1.50".to_string(),
                label: "Office Printer".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Embedded".to_string(),
                services: vec!["ipp".to_string(), "http".to_string()],
                risk_score: 71,
                x: 170.0,
                y: 454.0,
            },
            HostNode {
                id: "cam-01".to_string(),
                ip: "192.168.1.63".to_string(),
                label: "Lobby Camera".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Embedded".to_string(),
                services: vec!["rtsp".to_string(), "http".to_string()],
                risk_score: 76,
                x: 518.0,
                y: 470.0,
            },
            HostNode {
                id: "devbox-01".to_string(),
                ip: "192.168.1.89".to_string(),
                label: "Developer Workstation".to_string(),
                subnet: "192.168.1.0/24".to_string(),
                os_family: "Windows".to_string(),
                services: vec!["rdp".to_string(), "smb".to_string(), "ssh".to_string()],
                risk_score: 44,
                x: 840.0,
                y: 458.0,
            },
        ],
        edges: vec![
            HostEdge {
                source: "gateway-01".to_string(),
                target: "web-01".to_string(),
                relation: "route".to_string(),
            },
            HostEdge {
                source: "gateway-01".to_string(),
                target: "db-01".to_string(),
                relation: "route".to_string(),
            },
            HostEdge {
                source: "gateway-01".to_string(),
                target: "printer-01".to_string(),
                relation: "route".to_string(),
            },
            HostEdge {
                source: "gateway-01".to_string(),
                target: "cam-01".to_string(),
                relation: "route".to_string(),
            },
            HostEdge {
                source: "gateway-01".to_string(),
                target: "devbox-01".to_string(),
                relation: "route".to_string(),
            },
            HostEdge {
                source: "web-01".to_string(),
                target: "db-01".to_string(),
                relation: "depends-on".to_string(),
            },
            HostEdge {
                source: "devbox-01".to_string(),
                target: "web-01".to_string(),
                relation: "admin".to_string(),
            },
        ],
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_scanner_status, load_sample_topology])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
