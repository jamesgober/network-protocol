//! File logging must actually write to the log directory. Before 1.3.0 the writer
//! guard was dropped inside `init_logging`, so the file stayed empty.
//!
//! This is its own test binary because `init_logging` only takes effect once per
//! process.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use network_protocol::utils::logging::{init_logging, LogConfig};
use std::time::Duration;

#[test]
fn log_dir_receives_log_lines() {
    let dir = std::env::temp_dir().join(format!("network-protocol-logging-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    init_logging(&LogConfig {
        app_name: "logfiletest".to_string(),
        log_level: tracing::Level::INFO,
        log_dir: Some(dir.to_string_lossy().into_owned()),
        log_to_stdout: false,
        ..Default::default()
    });
    tracing::info!(target: "logfiletest", "line that must reach the file");

    let mut contents = String::new();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        contents.clear();
        for entry in std::fs::read_dir(&dir).unwrap() {
            contents.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap_or_default());
        }
        if contents.contains("line that must reach the file") {
            break;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        contents.contains("line that must reach the file"),
        "log file did not receive the event; contents: {contents:?}"
    );
}
