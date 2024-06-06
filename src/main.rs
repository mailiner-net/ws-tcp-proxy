use std::net::SocketAddr;
use axum::body::Body;
use axum::extract::{Query, WebSocketUpgrade, ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Error, Router};
use axum::routing::get;
use axum::debug_handler;
use clap::{Parser, arg, command};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing_subscriber;
use slog::Logger;
use rusty_paseto::prelude::*;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate slog;
extern crate slog_term;
use slog::Drain;

mod metrics;
use metrics::METRICS;

mod connection;
use connection::Connection;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 9400)]
    port: u16,

    #[arg(short, long, default_value_t = String::from("0.0.0.0") )]
    bind: String
}

lazy_static! {
    pub static ref PASETO_SECRET_KEY: Option<PasetoSymmetricKey<V4, Local>> = option_env!("MAILINER_PASETO_SECRET").and_then(|key| {
        Some(PasetoSymmetricKey::<V4, Local>::from(Key::from(key.as_bytes())))
    });
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let root = slog::Logger::root(drain, o!());

    let app = Router::new()
        .route("/proxy", get(proxy).with_state(root.clone()))
        .route("/metrics", get(dump_metrics));

    let listener = TcpListener::bind(format!("{}:{}", args.bind, args.port)).await.unwrap();
    info!(root, "WS<->TCP Proxy listening on {}:{}", args.bind, args.port);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

#[derive(Deserialize)]
struct Proxy {
    token: String,
    remote: String
}


fn validate_token(token: &String, log: &Logger) ->Result<(), StatusCode> {
    if cfg!(debug_assertions) && token == "testtoken" {
        return Ok(());
    }

    if PASETO_SECRET_KEY.is_none() {
        crit!(log, "PASETO_SECRET_KEY variable is not set, rejecting client!");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    match PasetoParser::<V4, Local>::default().parse(&token, &PASETO_SECRET_KEY.as_ref().unwrap()) {
        Ok(_) => Ok(()),
        Err(_) => Err(StatusCode::UNAUTHORIZED)
    }
}

#[debug_handler]
async fn proxy(query: Query<Proxy>, ws: WebSocketUpgrade, ConnectInfo(addr): ConnectInfo<SocketAddr>, State(log): State<Logger>) -> impl IntoResponse {
    let log = log.new(o!("client" => addr.to_string()));

    if let Err(err) = validate_token(&query.token, &log) {
        return Err::<Body, StatusCode>(err).into_response();
    }

    info!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    ws.on_failed_upgrade(move |error: Error| {
        METRICS.inc_ws_error(metrics::Error::Handshake);
        error!(fail_log, "Failed to upgrade WebSocket connection"; "error" => error.to_string());
    }).on_upgrade(move |socket| {
        async move {
            Connection::new(query.remote.clone(), upgrade_log).run(socket).await;
        }
    })
}

#[debug_handler]
async fn dump_metrics() -> impl IntoResponse {
    METRICS.encode()
}