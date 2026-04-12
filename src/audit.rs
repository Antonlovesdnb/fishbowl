use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

pub fn run_audit(session_dir: Option<PathBuf>) -> Result<()> {
    let logs_dir = match session_dir {
        Some(dir) => dir,
        None => find_latest_session()?,
    };

    let events = load_events(&logs_dir.join("audit.jsonl"))?;
    let registry = load_json(&logs_dir.join("registry.json"))?;
    let findings = load_events(&logs_dir.join("findings.jsonl")).unwrap_or_default();

    print_report(&logs_dir, &events, &registry, &findings);
    Ok(())
}

pub fn run_check(session_dir: Option<PathBuf>, fail_on: &str) -> Result<()> {
    let logs_dir = match session_dir {
        Some(dir) => dir,
        None => find_latest_session()?,
    };

    let threshold = match fail_on.to_lowercase().as_str() {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        other => bail!("unknown severity level: {other}. Use: low, medium, high, critical"),
    };

    let events = load_events(&logs_dir.join("audit.jsonl"))?;
    let findings = load_events(&logs_dir.join("findings.jsonl")).unwrap_or_default();
    let ebpf_exec = load_events(&logs_dir.join("ebpf_exec.jsonl")).unwrap_or_default();
    let ebpf_file = load_events(&logs_dir.join("ebpf_file.jsonl")).unwrap_or_default();
    let ebpf_connect = load_events(&logs_dir.join("ebpf_connect.jsonl")).unwrap_or_default();

    let mut counts: [u64; 5] = [0; 5]; // info, low, medium, high, critical
    let mut flagged: Vec<(String, String, String)> = Vec::new(); // (severity, event, reason)

    // Count audit events by severity
    for event in events.iter().chain(findings.iter()) {
        let severity = event.get("severity").and_then(Value::as_str).unwrap_or("info");
        let level = severity_level(severity);
        counts[level] += 1;
        if level >= threshold {
            let event_type = event.get("event").and_then(Value::as_str).unwrap_or("unknown");
            let reason = event.get("reason").and_then(Value::as_str).unwrap_or("");
            flagged.push((severity.to_string(), event_type.to_string(), reason.to_string()));
        }
    }

    // Check for suspicious patterns in eBPF data
    // Credential file accessed by curl/wget/nc = high severity
    for event in &ebpf_file {
        let process = event.get("process_name").and_then(Value::as_str).unwrap_or("");
        let path = event.get("raw_path").and_then(Value::as_str).unwrap_or("");
        if matches!(process, "curl" | "wget" | "nc" | "ncat" | "socat" | "python3" | "python" | "node") {
            counts[3] += 1; // high
            if 3 >= threshold {
                flagged.push((
                    "high".to_string(),
                    "credential_access_by_network_tool".to_string(),
                    format!("{process} accessed credential file {path}"),
                ));
            }
        }
    }

    // Config sync-back changes = medium severity (already counted in audit events)

    // Print summary
    println!("Fishbowl Check");
    println!("Session:  {}", logs_dir.display());
    println!("Threshold: --fail-on {fail_on}");
    println!();
    println!("Events:   {} total ({} info, {} low, {} medium, {} high, {} critical)",
        counts.iter().sum::<u64>(),
        counts[0], counts[1], counts[2], counts[3], counts[4],
    );
    println!("eBPF:     {} exec, {} file, {} connect",
        ebpf_exec.len(), ebpf_file.len(), ebpf_connect.len(),
    );
    println!();

    if flagged.is_empty() {
        println!("Result:   PASS (no events at or above {fail_on} severity)");
        Ok(())
    } else {
        println!("Result:   FAIL ({} events at or above {fail_on} severity)", flagged.len());
        println!();
        for (severity, event_type, reason) in &flagged {
            let short_reason = if reason.len() > 80 { &reason[..80] } else { reason };
            println!("  {:<8}  {}: {}", severity.to_uppercase(), event_type, short_reason);
        }
        println!();
        println!("Full audit log: {}", logs_dir.join("audit.jsonl").display());
        std::process::exit(1);
    }
}

fn severity_level(severity: &str) -> usize {
    match severity.to_lowercase().as_str() {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0, // info
    }
}

fn find_latest_session() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
    let latest = home.join(".fishbowl").join("logs").join("latest");
    if latest.exists() {
        let resolved = fs::read_link(&latest).unwrap_or(latest.clone());
        if resolved.is_dir() {
            return Ok(resolved);
        }
    }

    let logs_root = home.join(".fishbowl").join("logs");
    if !logs_root.is_dir() {
        anyhow::bail!("no session logs found in {}", logs_root.display());
    }

    let mut sessions: Vec<_> = fs::read_dir(&logs_root)
        .context("failed to read logs directory")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("session-"))
        })
        .collect();

    sessions.sort_by_key(|entry| entry.file_name());

    match sessions.last() {
        Some(entry) => Ok(entry.path()),
        None => anyhow::bail!("no session logs found in {}", logs_root.display()),
    }
}

fn load_events(path: &Path) -> Result<Vec<Value>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

fn load_json(path: &Path) -> Result<Value> {
    if !path.is_file() {
        return Ok(serde_json::json!({}));
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
}

fn print_report(logs_dir: &Path, events: &[Value], registry: &Value, findings: &[Value]) {
    let agent = events
        .iter()
        .find_map(|e| e.get("agent").and_then(Value::as_str))
        .unwrap_or("shell");

    println!("Fishbowl Audit Report");
    println!("Session: {}", logs_dir.display());
    println!("Agent:   {agent}");
    println!();

    print_credentials(registry);
    print_alerts(events, findings);
    print_network(events);
    println!("Full audit log: {}", logs_dir.join("audit.jsonl").display());
}

fn print_credentials(registry: &Value) {
    let credentials = registry
        .get("credentials")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    println!("Credentials ({}):", credentials.len());
    if credentials.is_empty() {
        println!("  (none discovered)");
    }
    for cred in &credentials {
        let classification = cred
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        let id = cred.get("id").and_then(Value::as_str).unwrap_or("?");
        let access_count = cred
            .get("access_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let destinations = cred
            .get("expected_destinations")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        let dest_info = if destinations.is_empty() {
            String::new()
        } else {
            format!("  -> {destinations}")
        };
        println!("  {classification} ({id}): {access_count} accesses{dest_info}");
    }
    println!();
}

fn print_alerts(events: &[Value], findings: &[Value]) {
    let alert_events: Vec<&Value> = events
        .iter()
        .filter(|e| {
            let severity = e.get("severity").and_then(Value::as_str).unwrap_or("info");
            matches!(severity, "medium" | "high" | "critical")
        })
        .collect();

    let total = alert_events.len() + findings.len();
    println!("Alerts ({total}):");
    if total == 0 {
        println!("  (none)");
    }

    for event in &alert_events {
        let ts = event
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let severity = event
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_uppercase();
        let event_type = event
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let reason = event
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("");
        let short_ts = ts.get(..19).unwrap_or(ts);
        println!("  {short_ts}  {severity:<8}  {event_type}: {reason}");
    }

    for finding in findings {
        let ts = finding
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("critical")
            .to_uppercase();
        let reason = finding
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("");
        let short_ts = ts.get(..19).unwrap_or(ts);
        println!("  {short_ts}  {severity:<8}  credential_egress_correlation: {reason}");
    }
    println!();
}

fn print_network(events: &[Value]) {
    let mut destinations: HashMap<String, (u64, bool)> = HashMap::new();

    for event in events {
        if event.get("event").and_then(Value::as_str) != Some("network_egress") {
            continue;
        }
        let dest = event
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let port = event
            .get("destination_port")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let severity = event
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info");
        let key = format!("{dest}:{port}");
        let entry = destinations.entry(key).or_insert((0, false));
        entry.0 += 1;
        if matches!(severity, "medium" | "high" | "critical") {
            entry.1 = true;
        }
    }

    println!("Network ({} destinations):", destinations.len());
    if destinations.is_empty() {
        println!("  (no outbound connections observed)");
    }

    let mut sorted: Vec<_> = destinations.into_iter().collect();
    sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (dest, (count, alerted)) in &sorted {
        let flag = if *alerted { "  ALERTED" } else { "" };
        println!("  {dest:<45} {count:>4} connections{flag}");
    }
    println!();
}
