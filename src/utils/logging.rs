use std::sync::Once;
use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    registry, EnvFilter,
};

static INIT: Once = Once::new();

/// LogConfig provides options for configuring the logging system
#[derive(Clone, Debug)]
pub struct LogConfig {
    /// The name of the application
    pub app_name: String,
    /// The log level (trace, debug, info, warn, error)
    pub log_level: Level,
    /// Whether to enable JSON log format (useful for log aggregation)
    pub json_format: bool,
    /// Directory where log files should be stored, None for console only
    pub log_dir: Option<String>,
    /// Whether to log to stdout in addition to files
    pub log_to_stdout: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            app_name: "network-protocol".to_string(),
            log_level: Level::INFO,
            json_format: false,
            log_dir: None,
            log_to_stdout: true,
        }
    }
}

/// Initialize the tracing system with the given configuration
///
/// # Example
/// ```
/// use network_protocol::utils::logging::{LogConfig, init_logging};
/// use tracing::Level;
///
/// let config = LogConfig {
///     app_name: "my-service".to_string(),
///     log_level: Level::DEBUG,
///     ..Default::default()
/// };
///
/// init_logging(&config);
/// ```
pub fn init_logging(config: &LogConfig) {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new(format!(
                "{},{app_name}={level}",
                std::env::var("RUST_LOG").unwrap_or_default(),
                app_name = config.app_name,
                level = config.log_level
            ))
        });

        let registry = registry().with(filter);

        match (&config.log_dir, config.log_to_stdout) {
            // Log to both file and stdout
            (Some(log_dir), true) => {
                let file_appender = rolling::daily(log_dir, format!("{}.log", config.app_name));
                let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

                if config.json_format {
                    let file_layer = fmt::layer()
                        .json()
                        .with_writer(non_blocking)
                        .with_span_events(FmtSpan::CLOSE);

                    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

                    registry.with(file_layer).with(stdout_layer).init();
                } else {
                    let file_layer = fmt::layer()
                        .with_writer(non_blocking)
                        .with_span_events(FmtSpan::CLOSE);

                    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

                    registry.with(file_layer).with(stdout_layer).init();
                }
            }

            // Log only to file
            (Some(log_dir), false) => {
                let file_appender = rolling::daily(log_dir, format!("{}.log", config.app_name));
                let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

                if config.json_format {
                    let file_layer = fmt::layer()
                        .json()
                        .with_writer(non_blocking)
                        .with_span_events(FmtSpan::CLOSE);

                    registry.with(file_layer).init();
                } else {
                    let file_layer = fmt::layer()
                        .with_writer(non_blocking)
                        .with_span_events(FmtSpan::CLOSE);

                    registry.with(file_layer).init();
                }
            }

            // Log only to stdout
            (None, true) => {
                if config.json_format {
                    let stdout_layer = fmt::layer()
                        .json()
                        .with_writer(std::io::stdout)
                        .with_span_events(FmtSpan::CLOSE);

                    registry.with(stdout_layer).init();
                } else {
                    let stdout_layer = fmt::layer()
                        .with_writer(std::io::stdout)
                        .with_ansi(true)
                        .with_span_events(FmtSpan::CLOSE);

                    registry.with(stdout_layer).init();
                }
            }

            // No logging output configured, default to stdout
            (None, false) => {
                let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

                registry.with(stdout_layer).init();

                tracing::warn!("No log output configured, defaulting to stdout");
            }
        }

        tracing::info!("Logging initialized at {} level", config.log_level);
    });
}

/// Setup default logging configuration for quick startup
pub fn setup_default_logging() {
    init_logging(&LogConfig::default());
}
