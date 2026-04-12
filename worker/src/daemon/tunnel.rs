//! Cloudflare tunnel management for exposing local daemon to the internet.

use std::fs;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

/// Spawn a Cloudflare tunnel on the given port.
/// Returns the public tunnel URL.
pub(crate) fn spawn_cloudflare_tunnel(port: u16) -> Result<String> {
    tracing::info!("🌐 Starting Cloudflare tunnel...");

    let log_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".inlayer")
        .join("cloudflared.log");

    // Create log file
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Spawn cloudflared process
    let child = Command::new("cloudflared")
        .arg("tunnel")
        .arg("--url")
        .arg(format!("http://localhost:{}", port))
        .stdout(fs::File::create(&log_path).unwrap())
        .stderr(fs::File::create(&log_path).unwrap())
        .spawn()
        .context("failed to spawn cloudflared - is it installed? (brew install cloudflared)")?;

    let pid = child.id();

    // Save PID for cleanup
    let pid_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".inlayer")
        .join("cloudflared.pid");
    fs::write(&pid_path, pid.to_string()).ok();

    tracing::info!("   Waiting for tunnel URL...");

    let re = regex::Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com")
        .expect("invalid regex pattern");

    // Wait for tunnel URL to appear in logs (up to 20 seconds)
    for _ in 1..=20 {
        std::thread::sleep(Duration::from_secs(1));
        tracing::debug!(".");

        if let Ok(log_content) = fs::read_to_string(&log_path) {
            // Extract URL using regex
            if let Some(m) = re.find(&log_content) {
                let url = m.as_str().to_string();
                tracing::info!("   ✅ Tunnel created!");
                tracing::info!("   📍 URL: {}", url);
                return Ok(url);
            }
        }
    }

    anyhow::bail!("timeout waiting for tunnel URL")
}

/// Stop any running Cloudflare tunnel.
pub(crate) fn stop_cloudflare_tunnel() {
    let pid_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".inlayer")
        .join("cloudflared.pid");

    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            tracing::info!("🛑 Stopping Cloudflare tunnel...");
            // Safe: use kill command instead of unsafe libc::kill
            let _ = std::process::Command::new("kill")
                .args([&pid.to_string()])
                .status();
            std::thread::sleep(Duration::from_millis(500));
            let _ = fs::remove_file(&pid_path);
        }
    }
}
