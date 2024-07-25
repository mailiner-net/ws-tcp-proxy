use tokio::time::Duration;
use rusty_paseto::core::{Local, PasetoSymmetricKey, V4};
use slog;

pub struct Config {
    pub bind_addr: String,
    pub listen_port: u16,
    pub log_level: slog::Level,

    pub secret_key: Option<PasetoSymmetricKey<V4, Local>>,
    pub metrics_auth_key: Option<String>,

    pub ws_read_timeout: Duration,
    pub ws_write_timeout: Duration,
    pub tcp_read_timeout: Duration,
    pub tcp_write_timeout: Duration,
    pub tcp_connect_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: String::from("0.0.0.0"),
            listen_port: 9400,
            log_level: slog::Level::Info,
            secret_key: None,
            metrics_auth_key: None,
            ws_read_timeout: Duration::from_secs(30),
            ws_write_timeout: Duration::from_secs(30),
            tcp_read_timeout: Duration::from_secs(30),
            tcp_write_timeout: Duration::from_secs(30),
            tcp_connect_timeout: Duration::from_secs(30),
        }
    }
}