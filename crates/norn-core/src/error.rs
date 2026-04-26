use thiserror::Error;

#[derive(Debug, Error)]
pub enum NornError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("collector {collector} failed: {source}")]
    Collector {
        collector: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("scanner {scanner} failed for {target}: {source}")]
    Scanner {
        scanner: &'static str,
        target: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("database error: {0}")]
    Database(String),
    #[error("notification error: {0}")]
    Notification(String),
}
