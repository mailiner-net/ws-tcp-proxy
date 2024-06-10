use std::str::FromStr;
use clap::{arg, command, Parser};
use slog::Logger;
use rusty_paseto::prelude::*;
use once_cell::sync::OnceCell;
use tokio::net::TcpListener;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate slog;
extern crate slog_term;
use slog::Drain;

mod connection;
mod metrics;
mod server;

use server::run_proxy;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 9400)]
    port: u16,

    #[arg(short, long, default_value_t = String::from("0.0.0.0") )]
    bind: String,

    #[arg(short = 'l', long, default_value = "info")]
    log_level: String
}

fn parse_log_level(val: &str) -> slog::Level {
    slog::Level::from_str(val)
        .unwrap_or_else(|_| panic!("Invalid log level {}", val))
}

lazy_static! {
    pub static ref PASETO_SECRET_KEY: Option<PasetoSymmetricKey<V4, Local>> = option_env!("MAILINER_PASETO_SECRET").and_then(|key| {
        Some(PasetoSymmetricKey::<V4, Local>::from(Key::from(key.as_bytes())))
    });
}

static DEFAULT_LOGGER: OnceCell<Logger> = OnceCell::new();

fn init_logging(level: slog::Level) {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = slog::LevelFilter::new(drain, level).fuse();
    DEFAULT_LOGGER.set(slog::Logger::root(drain, o!())).unwrap();
}

#[tokio::main]
async fn main() -> Result<(), tokio::io::Error> {
    let args = Args::parse();

    init_logging(parse_log_level(&args.log_level));

    let listener = TcpListener::bind(format!("{}:{}", args.bind, args.port)).await?;
    info!(DEFAULT_LOGGER.get().unwrap(), "WS<->TCP Proxy listening on {}:{}", args.bind, args.port);
    run_proxy(listener).await
}
