use clap::{arg, command, Parser};
use config::Config;
use rusty_paseto::prelude::*;
use tokio::net::TcpListener;

mod connection;
mod logging;
mod metrics;
mod server;
mod config;

#[macro_use]
extern crate slog;
extern crate slog_term;

use logging::{init_logging, parse_log_level, DEFAULT_LOGGER};
use server::run_proxy;

const MAILINER_PASETO_SECRET: &str = "MAILINER_PASETO_SECRET";
const METRICS_AUTH_TOKEN: &str = "METRICS_AUTH_TOKEN";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 9400)]
    port: u16,

    #[arg(short, long, default_value_t = String::from("0.0.0.0") )]
    bind: String,

    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,
}

fn parse_secret_key() -> Option<PasetoSymmetricKey<V4, Local>> {
    std::env::var(MAILINER_PASETO_SECRET)
        .ok()
        .and_then(|key| {
            Some(PasetoSymmetricKey::<V4, Local>::from(Key::from(
                key.as_bytes(),
            )))
        }).or_else(|| {
            if cfg!(debug_assertions) {
                warn!(
                    DEFAULT_LOGGER.get().unwrap(),
                    "{} is not set, using insecure secret key!", MAILINER_PASETO_SECRET
                );
            } else {
                panic!("{} is not set in production build!", MAILINER_PASETO_SECRET);
            }
            None
        })
}

fn parse_metrics_auth_key() -> Option<String> {
    std::env::var(METRICS_AUTH_TOKEN)
        .ok()
        .or_else(|| {
            if cfg!(debug_assertions) {
                warn!(
                    DEFAULT_LOGGER.get().unwrap(),
                    "{} is not set, metrics will be public!", METRICS_AUTH_TOKEN
                );
            } else {
                panic!("{} is not set in production build!", METRICS_AUTH_TOKEN);
            }
            None
        })
}

#[tokio::main]
async fn main() -> Result<(), tokio::io::Error> {
    let args = Args::parse();

    init_logging(parse_log_level(&args.log_level));
    info!(DEFAULT_LOGGER.get().unwrap(), "Log level set to {}", args.log_level);

    let config = Config{
        bind_addr: args.bind,
        listen_port: args.port,
        secret_key: parse_secret_key(),
        metrics_auth_key: parse_metrics_auth_key(),
        .. Config::default()
    };

    let listener = TcpListener::bind(format!("{}:{}", config.bind_addr, config.listen_port)).await?;
    info!(
        DEFAULT_LOGGER.get().unwrap(),
        "WS<->TCP Proxy listening on {}:{}", config.bind_addr, config.listen_port
    );
    run_proxy(listener, config).await
}
