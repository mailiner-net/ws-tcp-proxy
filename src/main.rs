use clap::Parser;
use rusty_paseto::prelude::*;
use tokio::net::TcpListener;

mod config;
mod connection;
mod dest;
mod limits;
mod logging;
mod metrics;
mod proto;
mod server;

#[macro_use]
extern crate slog;
extern crate slog_term;

use config::{env_bool, env_secs, env_u64, env_usize, parse_allowed_ports, AuthMode, Config};
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
    std::env::var(MAILINER_PASETO_SECRET).ok().map(|key| {
        PasetoSymmetricKey::<V4, Local>::from(Key::from(key.as_bytes()))
    })
}

fn parse_auth_mode() -> AuthMode {
    match std::env::var("MAILINER_AUTH")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "public" => AuthMode::Public,
        _ => AuthMode::Paseto,
    }
}

fn apply_env(config: &mut Config) {
    config.auth_mode = parse_auth_mode();
    if let Ok(raw) = std::env::var("MAILINER_ALLOWED_PORTS") {
        config.dest.allowed_ports = parse_allowed_ports(&raw);
    }
    config.dest.allow_private_destinations = env_bool(
        "MAILINER_ALLOW_PRIVATE_DESTS",
        config.dest.allow_private_destinations,
    );
    config.dest.allow_ip_literals = env_bool(
        "MAILINER_ALLOW_IP_LITERALS",
        config.dest.allow_ip_literals,
    );
    config.trust_forwarded_client_ip = env_bool(
        "MAILINER_TRUST_FORWARDED_CLIENT_IP",
        config.trust_forwarded_client_ip,
    );
    config.require_protocol_probe = env_bool(
        "MAILINER_REQUIRE_PROTOCOL_PROBE",
        config.require_protocol_probe,
    );
    config.max_bytes_per_connection = env_u64(
        "MAILINER_MAX_BYTES_PER_CONNECTION",
        config.max_bytes_per_connection,
    );
    config.max_lifetime = env_secs("MAILINER_MAX_LIFETIME_SECS", config.max_lifetime);
    config.limits.max_global_connections = env_usize(
        "MAILINER_MAX_GLOBAL_CONNECTIONS",
        config.limits.max_global_connections,
    );
    config.limits.max_conns_per_ip =
        env_usize("MAILINER_MAX_CONNS_PER_IP", config.limits.max_conns_per_ip);
    config.limits.max_conns_per_dest = env_usize(
        "MAILINER_MAX_CONNS_PER_DEST",
        config.limits.max_conns_per_dest,
    );
    config.limits.connects_per_ip = env_usize(
        "MAILINER_CONNECTS_PER_IP_PER_MIN",
        config.limits.connects_per_ip,
    );
    config.limits.distinct_dests_per_ip = env_usize(
        "MAILINER_DISTINCT_DESTS_PER_IP_PER_MIN",
        config.limits.distinct_dests_per_ip,
    );
    config.limits.global_connects = env_usize(
        "MAILINER_GLOBAL_CONNECTS_PER_SEC",
        config.limits.global_connects,
    );
    config.limits.max_bytes_per_ip = env_u64(
        "MAILINER_MAX_BYTES_PER_IP_PER_HOUR",
        config.limits.max_bytes_per_ip,
    );
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

    let mut config = Config {
        bind_addr: args.bind,
        listen_port: args.port,
        secret_key: parse_secret_key(),
        metrics_auth_key: parse_metrics_auth_key(),
        ..Config::default()
    };
    apply_env(&mut config);

    if config.auth_mode == AuthMode::Paseto && config.secret_key.is_none() {
        if cfg!(debug_assertions) {
            warn!(
                DEFAULT_LOGGER.get().unwrap(),
                "{} is not set, using insecure secret key!", MAILINER_PASETO_SECRET
            );
        } else {
            panic!("{} is not set in production build!", MAILINER_PASETO_SECRET);
        }
    }

    let listener = TcpListener::bind(format!("{}:{}", config.bind_addr, config.listen_port)).await?;
    info!(
        DEFAULT_LOGGER.get().unwrap(),
        "WS<->TCP Proxy listening on {}:{}", config.bind_addr, config.listen_port
    );
    run_proxy(listener, config).await
}
