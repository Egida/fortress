use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use parking_lot::Mutex;

/// Per-request access logger that writes one JSON line per request.
/// Uses `File` directly (OS kernel handles buffering) so every write
/// is immediately visible in the log file — critical for attack analysis.
pub struct AccessLogger {
    writer: Mutex<File>,
}

impl AccessLogger {
    /// Open (or create) the access log file in append mode.
    pub fn new(path: &str) -> std::io::Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            writer: Mutex::new(file),
        })
    }

    /// Write a single access-log entry as a JSON line.
    pub fn log(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        host: &str,
        status: u16,
        action: &str,
        elapsed_us: u64,
        user_agent: &str,
        country: Option<&str>,
        ray_id: &str,
    ) {
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let line = format!(
            r#"{{"ts":"{}","ip":"{}","method":"{}","host":"{}","path":"{}","status":{},"action":"{}","us":{},"ua":"{}","cc":"{}","ray":"{}"}}"#,
            ts,
            client_ip,
            escape_json(method),
            escape_json(host),
            escape_json(path),
            status,
            action,
            elapsed_us,
            escape_json(user_agent),
            country.unwrap_or("-"),
            ray_id,
        );

        let mut f = self.writer.lock();
        let _ = writeln!(f, "{}", line);
    }
}

/// Minimal JSON string escaping (quotes and backslashes).
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}
