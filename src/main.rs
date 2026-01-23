use network_protocol::error::Result;
use network_protocol::transport::remote;
use network_protocol::utils::logging::{init_logging, LogConfig};
use std::process;
use tracing::{error, info, Level};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with custom configuration
    let log_config = LogConfig {
        app_name: "network-protocol-server".to_string(),
        log_level: Level::INFO,
        ..Default::default()
    };
    init_logging(&log_config);

    info!("Starting server on 127.0.0.1:7777");

    match remote::start_server("127.0.0.1:7777").await {
        Ok(_) => {
            info!("Server shutdown successfully");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "Server error encountered");
            process::exit(1);
        }
    }
}
