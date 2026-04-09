use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};

#[derive(Clone, Serialize)]
struct ScannerStatus {
    name: String,
    available: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanPortResult {
    port: u16,
    protocol: String,
    state: String,
    service: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanHostResult {
    address: String,
    hostname: Option<String>,
    state: String,
    ports: Vec<ScanPortResult>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanSummary {
    total_hosts: usize,
    hosts_up: usize,
    hosts_down: usize,
    open_ports: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanExecutionResult {
    scan_id: String,
    operation_id: String,
    target: String,
    profile_name: String,
    command: String,
    started_at: String,
    finished_at: String,
    duration_ms: u128,
    summary: ScanSummary,
    hosts: Vec<ScanHostResult>,
    stdout: String,
    stderr: String,
    #[serde(default)]
    xml_output: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanJob {
    id: String,
    #[serde(default)]
    name: String,
    target: String,
    profile_id: String,
    profile_name: String,
    nmap_flags: String,
    status: String,
    created_at: String,
    #[serde(default)]
    result_summary: Option<String>,
    #[serde(default)]
    finished_at: Option<String>,
    #[serde(default)]
    result_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Operation {
    id: String,
    name: String,
    description: String,
    target_scope: String,
    created_at: String,
    updated_at: String,
    scan_jobs: Vec<ScanJob>,
}

#[derive(Clone, Serialize)]
struct OperationSummary {
    id: String,
    name: String,
    description: String,
    target_scope: String,
    created_at: String,
    updated_at: String,
    scan_count: usize,
}

#[derive(Clone, Serialize)]
struct ScanTemplate {
    id: String,
    name: String,
    description: String,
    nmap_flags: String,
    category: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct OperationStore {
    operations: Vec<Operation>,
}

#[derive(Clone, Deserialize)]
struct NewOperationInput {
    name: String,
    description: Option<String>,
    target_scope: String,
}

#[derive(Clone, Deserialize)]
struct RunScanInput {
    operation_id: String,
    target: String,
    profile_id: String,
    custom_flags: Option<String>,
    scan_name: Option<String>,
}

#[derive(Clone, Deserialize)]
struct RenameScanInput {
    operation_id: String,
    scan_id: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct DeleteScanInput {
    operation_id: String,
    scan_id: String,
}

#[derive(Clone, Deserialize)]
struct EnqueueQueuedScanInput {
    operation_id: String,
    scan_id: String,
}

#[derive(Clone, Serialize)]
struct ScanQueueProgress {
    operation_id: String,
    scan_id: String,
    status: String,
    progress_percent: f32,
    scanned_hosts: usize,
    total_hosts: usize,
    message: Option<String>,
}

#[derive(Clone)]
struct QueueTask {
    operation_id: String,
    scan_id: String,
}

#[derive(Default)]
struct QueueState {
    running: bool,
    pending: VecDeque<QueueTask>,
    progress_by_scan_id: HashMap<String, ScanQueueProgress>,
}

#[derive(Default)]
struct AppRuntimeState {
    queue: Arc<Mutex<QueueState>>,
}

fn now_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("{}", seconds)
}

fn next_id(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("{}-{}", prefix, millis)
}

fn scan_templates() -> Vec<ScanTemplate> {
    vec![
        ScanTemplate {
            id: "quick-ping".to_string(),
            name: "Quick Ping Sweep".to_string(),
            description: "Identify live hosts quickly using ICMP/ARP discovery.".to_string(),
            nmap_flags: "-sn".to_string(),
            category: "discovery".to_string(),
        },
        ScanTemplate {
            id: "top-ports".to_string(),
            name: "Top 1000 TCP Ports".to_string(),
            description: "Fast default port coverage for broad reconnaissance.".to_string(),
            nmap_flags: "-sS --top-ports 1000".to_string(),
            category: "recon".to_string(),
        },
        ScanTemplate {
            id: "service-version".to_string(),
            name: "Service Version Detection".to_string(),
            description: "Detect service banners and version fingerprints.".to_string(),
            nmap_flags: "-sV -Pn".to_string(),
            category: "service".to_string(),
        },
        ScanTemplate {
            id: "safe-script".to_string(),
            name: "Safe NSE Audit".to_string(),
            description: "Run non-intrusive script checks using safe category scripts.".to_string(),
            nmap_flags: "-sV --script=safe".to_string(),
            category: "audit".to_string(),
        },
        ScanTemplate {
            id: "full-tcp".to_string(),
            name: "Full TCP Range".to_string(),
            description: "Comprehensive 1-65535 TCP scan with service detection.".to_string(),
            nmap_flags: "-sS -p- -sV".to_string(),
            category: "deep".to_string(),
        },
    ]
}

fn operation_store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve app data dir: {}", error))?;

    fs::create_dir_all(&app_data_dir)
        .map_err(|error| format!("failed to create app data dir: {}", error))?;

    Ok(app_data_dir.join("operations.json"))
}

fn load_operation_store(app: &AppHandle) -> Result<OperationStore, String> {
    let store_path = operation_store_path(app)?;

    if !store_path.exists() {
        return Ok(OperationStore {
            operations: Vec::new(),
        });
    }

    let raw = fs::read_to_string(&store_path)
        .map_err(|error| format!("failed to read operations store: {}", error))?;

    serde_json::from_str(&raw).map_err(|error| format!("failed to parse operations store: {}", error))
}

fn save_operation_store(app: &AppHandle, store: &OperationStore) -> Result<(), String> {
    let store_path = operation_store_path(app)?;

    let serialized = serde_json::to_string_pretty(store)
        .map_err(|error| format!("failed to serialize operations store: {}", error))?;

    fs::write(store_path, serialized)
        .map_err(|error| format!("failed to write operations store: {}", error))?;

    Ok(())
}

fn scan_results_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve app data dir: {}", error))?;

    let results_dir = app_data_dir.join("scan_results");
    fs::create_dir_all(&results_dir)
        .map_err(|error| format!("failed to create scan results dir: {}", error))?;

    Ok(results_dir)
}

fn save_scan_result(app: &AppHandle, result: &ScanExecutionResult) -> Result<String, String> {
    let results_dir = scan_results_dir(app)?;
    let result_id = result.scan_id.clone();
    let result_path = results_dir.join(format!("{}.json", result_id));

    let serialized = serde_json::to_string_pretty(result)
        .map_err(|error| format!("failed to serialize scan result: {}", error))?;

    fs::write(&result_path, serialized)
        .map_err(|error| format!("failed to write scan result: {}", error))?;

    Ok(result_id)
}

fn load_scan_result(app: &AppHandle, result_id: &str) -> Result<ScanExecutionResult, String> {
    let results_dir = scan_results_dir(app)?;
    let result_path = results_dir.join(format!("{}.json", result_id));

    if !result_path.exists() {
        return Err(format!("scan result not found: {}", result_id));
    }

    let raw = fs::read_to_string(&result_path)
        .map_err(|error| format!("failed to read scan result: {}", error))?;

    serde_json::from_str(&raw).map_err(|error| format!("failed to parse scan result: {}", error))
}

fn delete_scan_result_file_if_present(app: &AppHandle, result_id: &str) -> Result<(), String> {
    let result_path = scan_results_dir(app)?.join(format!("{}.json", result_id));

    if !result_path.exists() {
        return Ok(());
    }

    fs::remove_file(result_path).map_err(|error| format!("failed to remove scan result: {}", error))
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

fn split_flags(flags: &str) -> Vec<String> {
    flags
        .split_whitespace()
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn estimate_target_host_count(target: &str) -> usize {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return 1;
    }

    if trimmed.contains(',') {
        let total = trimmed
            .split(',')
            .map(|part| estimate_target_host_count(part))
            .sum::<usize>();
        return total.max(1);
    }

    if let Some((_, prefix)) = trimmed.rsplit_once('/') {
        if let Ok(prefix_bits) = prefix.parse::<u32>() {
            if prefix_bits <= 32 {
                let hosts = 2u64.saturating_pow(32 - prefix_bits);
                return hosts.min(65_536) as usize;
            }
        }
    }

    if let Some((base, end_part)) = trimmed.rsplit_once('-') {
        if let Some((prefix, start_part)) = base.rsplit_once('.') {
            let _ = prefix;
            if let (Ok(start), Ok(end)) = (start_part.parse::<u16>(), end_part.parse::<u16>()) {
                if end >= start {
                    return (end - start + 1) as usize;
                }
            }
        }
    }

    1
}

fn parse_nmap_about_percent(line: &str) -> Option<f32> {
    let about_index = line.find("About ")? + 6;
    let rest = &line[about_index..];
    let percent_index = rest.find("%")?;
    let percent_text = rest[..percent_index].trim();
    percent_text.parse::<f32>().ok()
}

fn update_scan_job_status_and_summary(
    store: &mut OperationStore,
    operation_id: &str,
    scan_id: &str,
    status: &str,
    result_summary: Option<String>,
    finished_at: Option<String>,
) -> Result<(), String> {
    let operation = store
        .operations
        .iter_mut()
        .find(|operation| operation.id == operation_id)
        .ok_or_else(|| "operation not found".to_string())?;

    let job = operation
        .scan_jobs
        .iter_mut()
        .find(|job| job.id == scan_id)
        .ok_or_else(|| "scan job not found".to_string())?;

    job.status = status.to_string();
    job.result_summary = result_summary;
    job.finished_at = finished_at;
    operation.updated_at = now_timestamp();
    Ok(())
}

fn output_requires_root(stderr: &str) -> bool {
    let lowered = stderr.to_lowercase();
    lowered.contains("requires root privileges")
        || lowered.contains("you requested a scan type which requires root privileges")
}

fn run_nmap_process(flags: &str, target: &str, xml_output_path: &str, use_pkexec: bool) -> Result<Output, String> {
    let mut args = split_flags(flags);
    args.push("--stats-every".to_string());
    args.push("2s".to_string());
    args.push("-oX".to_string());
    args.push(xml_output_path.to_string());
    args.push(target.to_string());

    let mut command = if use_pkexec {
        if !has_command_in_path("pkexec") {
            return Err("scan requires elevated privileges, but pkexec is not available".to_string());
        }

        let mut command = Command::new("pkexec");
        command.arg("nmap");
        command
    } else {
        Command::new("nmap")
    };

    command.args(args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    command
        .output()
        .map_err(|error| format!("failed to execute nmap: {}", error))
}

fn run_nmap_process_streaming(
    flags: &str,
    target: &str,
    xml_output_path: &str,
    use_pkexec: bool,
    on_progress: Arc<dyn Fn(f32) + Send + Sync>,
) -> Result<(std::process::ExitStatus, String, String), String> {
    let mut args = split_flags(flags);
    args.push("--stats-every".to_string());
    args.push("2s".to_string());
    args.push("-oX".to_string());
    args.push(xml_output_path.to_string());
    args.push(target.to_string());

    let mut command = if use_pkexec {
        if !has_command_in_path("pkexec") {
            return Err("scan requires elevated privileges, but pkexec is not available".to_string());
        }

        let mut command = Command::new("pkexec");
        command.arg("nmap");
        command
    } else {
        Command::new("nmap")
    };

    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to execute nmap: {}", error))?;

    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture nmap stdout".to_string())?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture nmap stderr".to_string())?;

    let stdout_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stdout_pipe);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });

    let progress_callback = on_progress.clone();
    let stderr_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stderr_pipe);
        let mut stderr_output = String::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).unwrap_or(0);
            if bytes == 0 {
                break;
            }

            if let Some(percent) = parse_nmap_about_percent(&line) {
                progress_callback(percent.clamp(0.0, 100.0));
            }

            stderr_output.push_str(&line);
        }

        stderr_output
    });

    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for nmap: {}", error))?;

    let stdout = stdout_handle
        .join()
        .map_err(|_| "failed to read nmap stdout".to_string())?;
    let stderr = stderr_handle
        .join()
        .map_err(|_| "failed to read nmap stderr".to_string())?;

    Ok((status, stdout, stderr))
}

fn extract_nmap_xml_payload(output: &str) -> Option<&str> {
    let start_candidates = ["<?xml", "<nmaprun"];

    start_candidates
        .iter()
        .filter_map(|candidate| output.find(candidate).map(|index| &output[index..]))
        .next()
}

fn sanitize_nmap_xml(xml: &str) -> String {
    xml.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("<!DOCTYPE") && !trimmed.starts_with("<?xml-stylesheet")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace("<!DOCTYPE nmaprun>", "")
        .replace("<?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>", "")
}

fn parse_nmap_xml(xml: &str) -> Result<(Vec<ScanHostResult>, ScanSummary), String> {
    let sanitized_xml = sanitize_nmap_xml(xml);
    let document = Document::parse(&sanitized_xml)
        .map_err(|error| format!("failed to parse nmap XML: {}", error))?;

    let mut hosts = Vec::new();
    let mut total_hosts = 0usize;
    let mut hosts_up = 0usize;
    let mut hosts_down = 0usize;
    let mut open_ports = 0usize;

    for host_node in document.descendants().filter(|node| node.has_tag_name("host")) {
        total_hosts += 1;

        let state = host_node
            .children()
            .find(|node| node.has_tag_name("status"))
            .and_then(|node| node.attribute("state"))
            .unwrap_or("unknown")
            .to_string();

        if state == "up" {
            hosts_up += 1;
        } else if state == "down" {
            hosts_down += 1;
        }

        let address = host_node
            .children()
            .find(|node| node.has_tag_name("address") && node.attribute("addrtype") == Some("ipv4"))
            .and_then(|node| node.attribute("addr"))
            .or_else(|| {
                host_node
                    .children()
                    .find(|node| node.has_tag_name("address"))
                    .and_then(|node| node.attribute("addr"))
            })
            .unwrap_or("unknown")
            .to_string();

        let hostname = host_node
            .descendants()
            .find(|node| node.has_tag_name("hostname"))
            .and_then(|node| node.attribute("name"))
            .map(|name| name.to_string());

        let mut ports = Vec::new();
        if let Some(ports_node) = host_node.children().find(|node| node.has_tag_name("ports")) {
            for port_node in ports_node.children().filter(|node| node.has_tag_name("port")) {
                let port = port_node
                    .attribute("portid")
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(0);
                let protocol = port_node.attribute("protocol").unwrap_or("tcp").to_string();
                let port_state = port_node
                    .children()
                    .find(|node| node.has_tag_name("state"))
                    .and_then(|node| node.attribute("state"))
                    .unwrap_or("unknown")
                    .to_string();
                let service = port_node
                    .children()
                    .find(|node| node.has_tag_name("service"))
                    .and_then(|node| node.attribute("name"))
                    .map(|value| value.to_string());

                if port_state == "open" {
                    open_ports += 1;
                }

                ports.push(ScanPortResult {
                    port,
                    protocol,
                    state: port_state,
                    service,
                });
            }
        }

        hosts.push(ScanHostResult {
            address,
            hostname,
            state,
            ports,
        });
    }

    Ok((
        hosts,
        ScanSummary {
            total_hosts,
            hosts_up,
            hosts_down,
            open_ports,
        },
    ))
}

fn update_operation_scan_job(
    store: &mut OperationStore,
    operation_id: &str,
    scan_id: &str,
    status: &str,
    result_summary: Option<String>,
    finished_at: Option<String>,
) -> Result<(), String> {
    let operation = store
        .operations
        .iter_mut()
        .find(|operation| operation.id == operation_id)
        .ok_or_else(|| "operation not found".to_string())?;

    if let Some(job) = operation.scan_jobs.iter_mut().find(|job| job.id == scan_id) {
        job.status = status.to_string();
        job.result_summary = result_summary;
        job.finished_at = finished_at;
        operation.updated_at = now_timestamp();
        Ok(())
    } else {
        Err("scan job not found".to_string())
    }
}

fn update_progress_state(
    runtime: &Arc<Mutex<QueueState>>,
    scan_id: &str,
    mutator: impl FnOnce(&mut ScanQueueProgress),
) {
    if let Ok(mut queue) = runtime.lock() {
        if let Some(progress) = queue.progress_by_scan_id.get_mut(scan_id) {
            mutator(progress);
        }
    }
}

fn execute_queued_scan_job(
    app: &AppHandle,
    runtime: &Arc<Mutex<QueueState>>,
    operation_id: &str,
    scan_id: &str,
) -> Result<(), String> {
    let (profile_name, target, final_flags) = {
        let mut store = load_operation_store(app)?;
        let operation = find_operation_mut(&mut store, operation_id)
            .ok_or_else(|| "operation not found".to_string())?;
        let job = operation
            .scan_jobs
            .iter_mut()
            .find(|job| job.id == scan_id)
            .ok_or_else(|| "scan job not found".to_string())?;

        job.status = "running".to_string();
        operation.updated_at = now_timestamp();
        let tuple = (job.profile_name.clone(), job.target.clone(), job.nmap_flags.clone());
        save_operation_store(app, &store)?;
        tuple
    };

    let total_hosts = estimate_target_host_count(&target);
    update_progress_state(runtime, scan_id, |progress| {
        progress.status = "running".to_string();
        progress.total_hosts = total_hosts;
        progress.progress_percent = 1.0;
        progress.scanned_hosts = 0;
        progress.message = Some("scan started".to_string());
    });

    let start_instant = Instant::now();
    let started_at = now_timestamp();
    let command_preview = format!("nmap {} {}", final_flags, target);
    let xml_output_path = env::temp_dir()
        .join(format!("topixa-{}-nmap.xml", scan_id))
        .to_string_lossy()
        .to_string();

    let runtime_for_progress = runtime.clone();
    let scan_id_for_progress = scan_id.to_string();
    let progress_callback: Arc<dyn Fn(f32) + Send + Sync> = Arc::new(move |percent| {
        let scanned_hosts = ((percent / 100.0) * total_hosts as f32).round() as usize;
        update_progress_state(&runtime_for_progress, &scan_id_for_progress, |progress| {
            progress.progress_percent = percent;
            progress.scanned_hosts = scanned_hosts.min(total_hosts);
            progress.message = Some(format!("{:.1}% complete", percent));
        });
    });

    let mut process_output = run_nmap_process_streaming(
        &final_flags,
        &target,
        &xml_output_path,
        false,
        progress_callback.clone(),
    )?;

    if !process_output.0.success() && output_requires_root(&process_output.2) {
        process_output = run_nmap_process_streaming(
            &final_flags,
            &target,
            &xml_output_path,
            true,
            progress_callback,
        )?;
    }

    let (status, stdout, stderr) = process_output;
    let finished_at = now_timestamp();
    let duration_ms = start_instant.elapsed().as_millis();

    let xml_raw = fs::read_to_string(&xml_output_path)
        .or_else(|_| {
            extract_nmap_xml_payload(&stdout)
                .or_else(|| extract_nmap_xml_payload(&stderr))
                .map(|xml| xml.to_string())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "xml payload not found"))
        })
        .map_err(|_| {
            let stdout_excerpt = stdout.lines().take(6).collect::<Vec<_>>().join("\n");
            let stderr_excerpt = stderr.lines().take(6).collect::<Vec<_>>().join("\n");
            format!(
                "nmap did not emit XML output. stdout:\n{}\nstderr:\n{}",
                stdout_excerpt, stderr_excerpt
            )
        })?;

    let _ = fs::remove_file(&xml_output_path);

    let (hosts, summary) = parse_nmap_xml(&xml_raw).map_err(|error| {
        let stdout_excerpt = stdout.lines().take(6).collect::<Vec<_>>().join("\n");
        let stderr_excerpt = stderr.lines().take(6).collect::<Vec<_>>().join("\n");
        format!(
            "{}\nstdout:\n{}\nstderr:\n{}",
            error, stdout_excerpt, stderr_excerpt
        )
    })?;

    let result_summary = format!(
        "{} hosts up · {} hosts down · {} open ports",
        summary.hosts_up, summary.hosts_down, summary.open_ports
    );

    let job_status = if status.success() { "completed" } else { "failed" };

    if !status.success() && hosts.is_empty() {
        let mut store = load_operation_store(app)?;
        update_scan_job_status_and_summary(
            &mut store,
            operation_id,
            scan_id,
            job_status,
            Some(result_summary.clone()),
            Some(finished_at.clone()),
        )?;
        save_operation_store(app, &store)?;

        update_progress_state(runtime, scan_id, |progress| {
            progress.status = "failed".to_string();
            progress.progress_percent = 100.0;
            progress.scanned_hosts = progress.total_hosts;
            progress.message = Some("scan failed".to_string());
        });

        return Err(format!("nmap exited with error: {}", stderr.trim()));
    }

    let execution_result = ScanExecutionResult {
        scan_id: scan_id.to_string(),
        operation_id: operation_id.to_string(),
        target,
        profile_name,
        command: command_preview,
        started_at,
        finished_at: finished_at.clone(),
        duration_ms,
        summary,
        hosts,
        stdout,
        stderr,
        xml_output: xml_raw,
    };

    let result_id = save_scan_result(app, &execution_result)?;

    let mut store = load_operation_store(app)?;
    update_scan_job_status_and_summary(
        &mut store,
        operation_id,
        scan_id,
        job_status,
        Some(result_summary),
        Some(finished_at),
    )?;

    if let Some(operation) = find_operation_mut(&mut store, operation_id) {
        if let Some(job) = operation.scan_jobs.iter_mut().find(|job| job.id == scan_id) {
            job.result_id = Some(result_id);
        }
    }

    save_operation_store(app, &store)?;

    update_progress_state(runtime, scan_id, |progress| {
        progress.status = job_status.to_string();
        progress.progress_percent = 100.0;
        progress.scanned_hosts = progress.total_hosts;
        progress.message = Some("scan finished".to_string());
    });

    Ok(())
}

fn start_queue_worker_if_idle(app: &AppHandle, runtime: &Arc<Mutex<QueueState>>) {
    let should_start = {
        if let Ok(mut queue) = runtime.lock() {
            if queue.running {
                false
            } else {
                queue.running = true;
                true
            }
        } else {
            false
        }
    };

    if !should_start {
        return;
    }

    let app_handle = app.clone();
    let runtime_handle = runtime.clone();

    tauri::async_runtime::spawn_blocking(move || {
        loop {
            let task = {
                if let Ok(mut queue) = runtime_handle.lock() {
                    queue.pending.pop_front()
                } else {
                    None
                }
            };

            let Some(task) = task else {
                if let Ok(mut queue) = runtime_handle.lock() {
                    queue.running = false;
                }
                break;
            };

            let result = execute_queued_scan_job(
                &app_handle,
                &runtime_handle,
                &task.operation_id,
                &task.scan_id,
            );

            if let Err(error) = result {
                update_progress_state(&runtime_handle, &task.scan_id, |progress| {
                    progress.status = "failed".to_string();
                    progress.progress_percent = 100.0;
                    progress.scanned_hosts = progress.total_hosts;
                    progress.message = Some(error.clone());
                });
            }
        }
    });
}

fn run_nmap_scan(app: &AppHandle, input: RunScanInput) -> Result<ScanExecutionResult, String> {
    if !has_command_in_path("nmap") {
        return Err("nmap is not installed or not available in PATH".to_string());
    }

    let templates = scan_templates();
    let template = templates
        .iter()
        .find(|template| template.id == input.profile_id)
        .ok_or_else(|| "unknown scan template".to_string())?
        .clone();

    let target = input.target.trim().to_string();
    if target.is_empty() {
        return Err("scan target cannot be empty".to_string());
    }

    let custom_flags = input.custom_flags.unwrap_or_default();
    let final_flags = if custom_flags.trim().is_empty() {
        template.nmap_flags.clone()
    } else {
        custom_flags.trim().to_string()
    };

    let scan_id = next_id("scan");
    let started_at = now_timestamp();
    let start_instant = Instant::now();
    let command_preview = format!("nmap {} {}", final_flags, target);
    let xml_output_path = env::temp_dir()
        .join(format!("topixa-{}-nmap.xml", scan_id))
        .to_string_lossy()
        .to_string();

    let mut store = load_operation_store(app)?;
    let operation_exists = store
        .operations
        .iter()
        .any(|operation| operation.id == input.operation_id);

    if !operation_exists {
        return Err("operation not found".to_string());
    }

    let default_scan_name = format!(
        "scan-{}",
        store
            .operations
            .iter()
            .find(|operation| operation.id == input.operation_id)
            .map_or(1, |operation| operation.scan_jobs.len() + 1)
    );
    let requested_scan_name = input
        .scan_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let final_scan_name = if requested_scan_name.is_empty() {
        default_scan_name
    } else {
        requested_scan_name
    };

    let queued_job = ScanJob {
        id: scan_id.clone(),
        name: final_scan_name,
        target: target.clone(),
        profile_id: template.id.clone(),
        profile_name: template.name.clone(),
        nmap_flags: final_flags.clone(),
        status: "running".to_string(),
        created_at: started_at.clone(),
        result_summary: None,
        finished_at: None,
        result_id: None,
    };

    {
        let operation = store
            .operations
            .iter_mut()
            .find(|operation| operation.id == input.operation_id)
            .ok_or_else(|| "operation not found".to_string())?;
        operation.scan_jobs.push(queued_job);
        operation.updated_at = started_at.clone();
    }

    save_operation_store(app, &store)?;

    let mut output = run_nmap_process(&final_flags, &target, &xml_output_path, false)?;

    let stderr_first = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() && output_requires_root(&stderr_first) {
        output = run_nmap_process(&final_flags, &target, &xml_output_path, true)?;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let duration_ms = start_instant.elapsed().as_millis();
    let finished_at = now_timestamp();

    let xml_raw = fs::read_to_string(&xml_output_path)
        .or_else(|_| {
            extract_nmap_xml_payload(&stdout)
                .or_else(|| extract_nmap_xml_payload(&stderr))
                .map(|xml| xml.to_string())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "xml payload not found"))
        })
        .map_err(|_| {
            let stdout_excerpt = stdout.lines().take(6).collect::<Vec<_>>().join("\n");
            let stderr_excerpt = stderr.lines().take(6).collect::<Vec<_>>().join("\n");

            format!(
                "nmap did not emit XML output. stdout:\n{}\nstderr:\n{}",
                stdout_excerpt, stderr_excerpt
            )
        })?;

    // Best-effort cleanup of temporary XML file used for parsing.
    let _ = fs::remove_file(&xml_output_path);

    let (hosts, summary) = parse_nmap_xml(&xml_raw).map_err(|error| {
        let stdout_excerpt = stdout.lines().take(6).collect::<Vec<_>>().join("\n");
        let stderr_excerpt = stderr.lines().take(6).collect::<Vec<_>>().join("\n");

        format!(
            "{}\nstdout:\n{}\nstderr:\n{}",
            error, stdout_excerpt, stderr_excerpt
        )
    })?;

    let result_summary = format!(
        "{} hosts up · {} hosts down · {} open ports",
        summary.hosts_up, summary.hosts_down, summary.open_ports
    );

    let job_status = if output.status.success() { "completed" } else { "failed" };

    if !output.status.success() && hosts.is_empty() {
        let mut store = load_operation_store(app)?;
        update_operation_scan_job(
            &mut store,
            &input.operation_id,
            &scan_id,
            job_status,
            Some(result_summary.clone()),
            Some(finished_at.clone()),
        )?;
        save_operation_store(app, &store)?;
        return Err(format!("nmap exited with error: {}", stderr.trim()));
    }

    let execution_result = ScanExecutionResult {
        scan_id: scan_id.clone(),
        operation_id: input.operation_id.clone(),
        target,
        profile_name: template.name,
        command: command_preview,
        started_at,
        finished_at: finished_at.clone(),
        duration_ms,
        summary,
        hosts,
        stdout,
        stderr,
        xml_output: xml_raw,
    };

    // Persist full scan payload. Do not swallow failures, otherwise reopening an operation cannot render graph data.
    let result_id = save_scan_result(app, &execution_result)?;

    let mut store = load_operation_store(app)?;
    update_operation_scan_job(
        &mut store,
        &input.operation_id,
        &scan_id,
        job_status,
        Some(result_summary),
        Some(finished_at),
    )?;

    if let Some(operation) = find_operation_mut(&mut store, &input.operation_id) {
        if let Some(job) = operation.scan_jobs.iter_mut().find(|j| j.id == scan_id) {
            job.result_id = Some(result_id);
        }
    }

    save_operation_store(app, &store)?;

    Ok(execution_result)
}

fn find_operation_mut<'a>(store: &'a mut OperationStore, operation_id: &str) -> Option<&'a mut Operation> {
    store.operations.iter_mut().find(|operation| operation.id == operation_id)
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
fn list_scan_templates() -> Vec<ScanTemplate> {
    scan_templates()
}

#[tauri::command]
fn list_operations(app: AppHandle) -> Result<Vec<OperationSummary>, String> {
    let store = load_operation_store(&app)?;

    Ok(store
        .operations
        .iter()
        .map(|operation| OperationSummary {
            id: operation.id.clone(),
            name: operation.name.clone(),
            description: operation.description.clone(),
            target_scope: operation.target_scope.clone(),
            created_at: operation.created_at.clone(),
            updated_at: operation.updated_at.clone(),
            scan_count: operation.scan_jobs.len(),
        })
        .collect())
}

#[tauri::command]
fn create_operation(app: AppHandle, input: NewOperationInput) -> Result<Operation, String> {
    let mut store = load_operation_store(&app)?;
    let now = now_timestamp();

    let operation = Operation {
        id: next_id("op"),
        name: input.name.trim().to_string(),
        description: input.description.unwrap_or_default().trim().to_string(),
        target_scope: input.target_scope.trim().to_string(),
        created_at: now.clone(),
        updated_at: now,
        scan_jobs: Vec::new(),
    };

    if operation.name.is_empty() {
        return Err("operation name cannot be empty".to_string());
    }

    if operation.target_scope.is_empty() {
        return Err("target scope cannot be empty".to_string());
    }

    store.operations.push(operation.clone());
    save_operation_store(&app, &store)?;

    Ok(operation)
}

#[tauri::command]
fn get_operation(app: AppHandle, operation_id: String) -> Result<Operation, String> {
    let store = load_operation_store(&app)?;

    store
        .operations
        .into_iter()
        .find(|operation| operation.id == operation_id)
        .ok_or_else(|| "operation not found".to_string())
}

#[tauri::command]
fn delete_operation(app: AppHandle, operation_id: String) -> Result<(), String> {
    let mut store = load_operation_store(&app)?;
    let before_len = store.operations.len();
    store.operations.retain(|operation| operation.id != operation_id);

    if before_len == store.operations.len() {
        return Err("operation not found".to_string());
    }

    save_operation_store(&app, &store)
}

#[tauri::command]
fn queue_scan_job(app: AppHandle, input: RunScanInput) -> Result<Operation, String> {
    let mut store = load_operation_store(&app)?;
    let templates = scan_templates();
    let template = templates
        .iter()
        .find(|template| template.id == input.profile_id)
        .ok_or_else(|| "unknown scan template".to_string())?;

    let operation = find_operation_mut(&mut store, &input.operation_id)
        .ok_or_else(|| "operation not found".to_string())?;

    let target = input.target.trim().to_string();
    if target.is_empty() {
        return Err("scan target cannot be empty".to_string());
    }

    let custom_flags = input.custom_flags.unwrap_or_default();
    let final_flags = if custom_flags.trim().is_empty() {
        template.nmap_flags.clone()
    } else {
        custom_flags.trim().to_string()
    };

    let default_scan_name = format!("scan-{}", operation.scan_jobs.len() + 1);
    let requested_scan_name = input
        .scan_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let final_scan_name = if requested_scan_name.is_empty() {
        default_scan_name
    } else {
        requested_scan_name
    };

    operation.scan_jobs.push(ScanJob {
        id: next_id("scan"),
        name: final_scan_name,
        target,
        profile_id: template.id.clone(),
        profile_name: template.name.clone(),
        nmap_flags: final_flags,
        status: "queued".to_string(),
        created_at: now_timestamp(),
        result_summary: None,
        finished_at: None,
        result_id: None,
    });

    operation.updated_at = now_timestamp();
    let updated_operation = operation.clone();

    save_operation_store(&app, &store)?;

    Ok(updated_operation)
}

#[tauri::command]
fn enqueue_queued_scan(
    app: AppHandle,
    state: tauri::State<AppRuntimeState>,
    input: EnqueueQueuedScanInput,
) -> Result<(), String> {
    let (target, status) = {
        let store = load_operation_store(&app)?;
        let operation = store
            .operations
            .iter()
            .find(|operation| operation.id == input.operation_id)
            .ok_or_else(|| "operation not found".to_string())?;
        let job = operation
            .scan_jobs
            .iter()
            .find(|job| job.id == input.scan_id)
            .ok_or_else(|| "scan job not found".to_string())?;

        (job.target.clone(), job.status.clone())
    };

    if status != "queued" {
        return Ok(());
    }

    let total_hosts = estimate_target_host_count(&target);

    {
        let mut queue = state
            .queue
            .lock()
            .map_err(|_| "failed to lock queue state".to_string())?;

        if !queue.pending.iter().any(|task| task.scan_id == input.scan_id) {
            queue.pending.push_back(QueueTask {
                operation_id: input.operation_id.clone(),
                scan_id: input.scan_id.clone(),
            });
        }

        queue.progress_by_scan_id.insert(
            input.scan_id.clone(),
            ScanQueueProgress {
                operation_id: input.operation_id.clone(),
                scan_id: input.scan_id.clone(),
                status: "queued".to_string(),
                progress_percent: 0.0,
                scanned_hosts: 0,
                total_hosts,
                message: Some("queued".to_string()),
            },
        );
    }

    start_queue_worker_if_idle(&app, &state.queue);
    Ok(())
}

#[tauri::command]
fn get_scan_progress(
    state: tauri::State<AppRuntimeState>,
    operation_id: String,
    scan_id: String,
) -> Option<ScanQueueProgress> {
    let Ok(queue) = state.queue.lock() else {
        return None;
    };

    let progress = queue.progress_by_scan_id.get(&scan_id)?;
    if progress.operation_id != operation_id {
        return None;
    }

    Some(progress.clone())
}

#[tauri::command]
fn rename_scan_job(app: AppHandle, input: RenameScanInput) -> Result<Operation, String> {
    let mut store = load_operation_store(&app)?;

    let operation = find_operation_mut(&mut store, &input.operation_id)
        .ok_or_else(|| "operation not found".to_string())?;

    let new_name = input.name.trim().to_string();
    if new_name.is_empty() {
        return Err("scan name cannot be empty".to_string());
    }

    let job = operation
        .scan_jobs
        .iter_mut()
        .find(|job| job.id == input.scan_id)
        .ok_or_else(|| "scan job not found".to_string())?;

    job.name = new_name;
    operation.updated_at = now_timestamp();
    let updated_operation = operation.clone();

    save_operation_store(&app, &store)?;
    Ok(updated_operation)
}

#[tauri::command]
fn delete_scan_job(app: AppHandle, input: DeleteScanInput) -> Result<Operation, String> {
    let mut store = load_operation_store(&app)?;

    let operation = find_operation_mut(&mut store, &input.operation_id)
        .ok_or_else(|| "operation not found".to_string())?;

    let scan_index = operation
        .scan_jobs
        .iter()
        .position(|job| job.id == input.scan_id)
        .ok_or_else(|| "scan job not found".to_string())?;

    let removed_scan = operation.scan_jobs.remove(scan_index);
    operation.updated_at = now_timestamp();
    let updated_operation = operation.clone();

    save_operation_store(&app, &store)?;

    let result_id = removed_scan
        .result_id
        .unwrap_or_else(|| removed_scan.id.clone());
    let _ = delete_scan_result_file_if_present(&app, &result_id);

    Ok(updated_operation)
}

#[tauri::command]
fn get_scan_result(app: AppHandle, job_id: String) -> Result<ScanExecutionResult, String> {
    // Backward/forward compatible lookup:
    // 1) try legacy convention where result file is keyed by job_id
    // 2) if missing, resolve job.result_id from operations store
    if let Ok(result) = load_scan_result(&app, &job_id) {
        return Ok(result);
    }

    let store = load_operation_store(&app)?;
    let result_id = store
        .operations
        .iter()
        .flat_map(|operation| operation.scan_jobs.iter())
        .find(|job| job.id == job_id)
        .and_then(|job| job.result_id.clone())
        .ok_or_else(|| format!("scan result not found for job {}", job_id))?;

    load_scan_result(&app, &result_id)
}

#[tauri::command]
async fn run_scan(app: AppHandle, input: RunScanInput) -> Result<ScanExecutionResult, String> {
    tauri::async_runtime::spawn_blocking(move || run_nmap_scan(&app, input))
        .await
        .map_err(|error| format!("failed to join scan task: {}", error))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppRuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            get_scanner_status,
            list_scan_templates,
            list_operations,
            create_operation,
            get_operation,
            delete_operation,
            rename_scan_job,
            delete_scan_job,
            queue_scan_job,
            enqueue_queued_scan,
            get_scan_progress,
            run_scan,
            get_scan_result,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
