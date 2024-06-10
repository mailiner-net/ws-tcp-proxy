use std::net::SocketAddr;

use rusty_paseto::prelude::*;
use serde::Deserialize;
use slog::Logger;
use tokio::net::TcpListener;
use tokio::io::Error;

use axum::extract::{Query, WebSocketUpgrade, ConnectInfo, State};
use axum::body::Body;
use axum::debug_handler;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, Router};

use crate::connection::Connection;
use crate::{DEFAULT_LOGGER, PASETO_SECRET_KEY};
use crate::metrics::METRICS;
use crate::metrics;

#[derive(Deserialize)]
struct ProxyQuery {
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
async fn proxy_handler(query: Query<ProxyQuery>, ws: WebSocketUpgrade, ConnectInfo(addr): ConnectInfo<SocketAddr>, State(log): State<Logger>) -> impl IntoResponse {
    let log = log.new(o!("client" => addr.to_string()));

    if let Err(err) = validate_token(&query.token, &log) {
        return Err::<Body, StatusCode>(err).into_response();
    }

    info!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    ws.on_failed_upgrade(move |error: axum::Error| {
        METRICS.inc_ws_error(metrics::Error::Handshake);
        error!(fail_log, "Failed to upgrade WebSocket connection"; "error" => error.to_string());
    }).on_upgrade(move |socket| {
        async move {
            Connection::new(query.remote.clone(), upgrade_log).run(socket).await;
        }
    })
}

#[debug_handler]
async fn metrics_handler() -> impl IntoResponse {
    METRICS.encode()
}

pub async fn run_proxy(listener: TcpListener) -> Result<(), Error>
{
    let logger = DEFAULT_LOGGER.get().unwrap();
    let app = Router::new()
        .route("/proxy", get(proxy_handler).with_state(logger.clone()))
        .route("/metrics", get(metrics_handler));

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}