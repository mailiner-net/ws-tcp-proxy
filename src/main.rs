use clap::{arg, command, Parser};
use rusty_paseto::prelude::*;
use tokio::net::TcpListener;

mod connection;
mod logging;
mod metrics;
mod server;

#[macro_use]
extern crate slog;
extern crate slog_term;

use logging::{init_logging, parse_log_level, DEFAULT_LOGGER};
use server::run_proxy;

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

#[tokio::main]
async fn main() -> Result<(), tokio::io::Error> {
    let args = Args::parse();

    init_logging(parse_log_level(&args.log_level));
    info!(DEFAULT_LOGGER.get().unwrap(), "Log level set to {}", args.log_level);

    let secret_key = std::env::var("MAILINER_PASETO_SECRET")
        .ok()
        .and_then(|key| {
            Some(PasetoSymmetricKey::<V4, Local>::from(Key::from(
                key.as_bytes(),
            )))
        }).or_else(|| {
            if cfg!(debug_assertions) {
                warn!(
                    DEFAULT_LOGGER.get().unwrap(),
                    "MAILINER_PASETO_SECRET is not set, using insecure secret key!"
                );
            } else {
                panic!("MAILINER_PASETO_SECRET is not set in production build!");
            }
            None
        });

    let listener = TcpListener::bind(format!("{}:{}", args.bind, args.port)).await?;
    info!(
        DEFAULT_LOGGER.get().unwrap(),
        "WS<->TCP Proxy listening on {}:{}", args.bind, args.port
    );
    run_proxy(listener, secret_key).await
}
