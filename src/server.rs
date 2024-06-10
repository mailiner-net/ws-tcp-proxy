use std::net::SocketAddr;
use std::sync::Arc;

use rusty_paseto::prelude::*;
use serde::Deserialize;
use slog::Logger;
use tokio::io::Error;
use tokio::net::TcpListener;

use axum::body::Body;
use axum::debug_handler;
use axum::extract::{ConnectInfo, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, Router};

use crate::connection::Connection;
use crate::metrics;
use crate::metrics::METRICS;
use crate::DEFAULT_LOGGER;

#[derive(Deserialize)]
struct ProxyQuery {
    token: String,
    remote: String,
}

#[derive(Clone)]
struct ServerState {
    log: Logger,
    secret_key: Option<Arc<PasetoSymmetricKey<V4, Local>>>,
}

fn validate_token(
    token: &String,
    secret_key: &Option<Arc<PasetoSymmetricKey<V4, Local>>>,
    log: &Logger,
) -> Result<(), StatusCode> {
    if cfg!(debug_assertions) && token == "testtoken" {
        return Ok(());
    }

    if secret_key.is_none() {
        crit!(
            log,
            "PASETO_SECRET_KEY variable is not set, rejecting client!"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    match PasetoParser::<V4, Local>::default().parse(&token, &secret_key.as_ref().unwrap()) {
        Ok(_) => Ok(()),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn proxy_handler(
    query: Query<ProxyQuery>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<ServerState>,
) -> impl IntoResponse {
    let log = state.log.new(o!("client" => addr.to_string()));

    if let Err(err) = validate_token(&query.token, &state.secret_key, &log) {
        return Err::<Body, StatusCode>(err).into_response();
    }

    info!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    ws.on_failed_upgrade(move |error: axum::Error| {
        METRICS.inc_ws_error(metrics::Error::Handshake);
        error!(fail_log, "Failed to upgrade WebSocket connection"; "error" => error.to_string());
    })
    .on_upgrade(move |socket| async move {
        Connection::new(query.remote.clone(), upgrade_log)
            .run(socket)
            .await;
    })
}

#[debug_handler]
async fn metrics_handler() -> impl IntoResponse {
    METRICS.encode()
}

pub async fn run_proxy(
    listener: TcpListener,
    secret_key: Option<PasetoSymmetricKey<V4, Local>>,
) -> Result<(), Error> {
    let state = ServerState {
        log: DEFAULT_LOGGER.get().unwrap().clone(),
        secret_key: secret_key.map(|key| Arc::new(key)),
    };

    let app = Router::new()
        .route("/proxy", get(proxy_handler).with_state(state))
        .route("/metrics", get(metrics_handler));

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use futures_util::{SinkExt, StreamExt};
    use rusty_paseto::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_websockets::client::Builder;
    use tokio_websockets::{upgrade, Message};

    use crate::init_logging;

    use super::run_proxy;

    struct TestServer {
        port: u16,
    }

    impl TestServer {
        async fn new() -> Self {
            let listener = TcpListener::bind("0.0.0.0:0")
                .await
                .expect("Failed to bind listener");
            let port = listener.local_addr().unwrap().port();

            tokio::spawn(async move {
                loop {
                    let (socket, _) = listener
                        .accept()
                        .await
                        .expect("Failed to accept connection");
                    tokio::spawn(async move {
                        let (mut read, mut write) = socket.into_split();
                        let mut buffer = [0; 1024];
                        loop {
                            let size = match read.read(&mut buffer).await {
                                Ok(size) => size,
                                Err(e) => {
                                    eprintln!("Error reading from socket: {}", e);
                                    return;
                                }
                            };

                            if size == 0 {
                                eprintln!("Upstream has closed the connection");
                                return;
                            }

                            if let Err(e) = write.write_all(&buffer[0..size]).await {
                                eprintln!("Error writing to socket: {}", e);
                                return;
                            }
                        }
                    });
                }
            });

            Self { port }
        }
    }

    async fn create_servers(
        secret_key: Option<PasetoSymmetricKey<V4, Local>>,
    ) -> (u16, TestServer) {
        init_logging(slog::Level::Debug);
        let server = TestServer::new().await;
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind proxy");
        let proxy_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = run_proxy(listener, secret_key).await;
        });

        (proxy_port, server)
    }

    #[tokio::test]
    async fn test_connection() {
        let (proxy_port, server) = create_servers(None).await;

        let (mut client, _) = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect("Failed to connect to WebSocket");

        let msg = Message::binary("Hello, World".as_bytes());
        client
            .send(msg.clone())
            .await
            .expect("Failed to send message");
        let resp = client
            .next()
            .await
            .expect("Failed to receive message")
            .expect("Received message without data");

        assert_eq!(
            bytes::Bytes::from(resp.into_payload()),
            bytes::Bytes::from(msg.into_payload())
        );
    }

    #[tokio::test]
    async fn test_missing_remote_returns_bad_request() {
        let (proxy_port, _) = create_servers(None).await;

        let err = Builder::from_uri(
            format!("ws://127.0.0.1:{}/proxy?token=testtoken", proxy_port)
                .parse()
                .unwrap(),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite missing 'remote' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 400)
            }
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_missing_token_returns_bad_request() {
        let (proxy_port, server) = create_servers(None).await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite missing 'token' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 400)
            }
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_missing_paseto_secret_key_returns_server_error() {
        let (proxy_port, server) = create_servers(None).await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=whatever",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite invalid 'token' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 500)
            }
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_invalid_token_returns_unauthorized() {
        let secret = Key::<32>::try_new_random().expect("Failed to generate a new PASETO key");
        let (proxy_port, server) =
            create_servers(Some(PasetoSymmetricKey::<V4, Local>::from(secret))).await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=thisisnotavalidtoken",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite invalid 'token' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 401)
            }
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_valid_token_passes() {
        let secret = Key::<32>::try_new_random().expect("Failed to generate a new PASETO key");
        let (proxy_port, server) =
            create_servers(Some(PasetoSymmetricKey::<V4, Local>::from(secret.clone()))).await;

        let key = PasetoSymmetricKey::<V4, Local>::from(secret);
        let claim = PasetoBuilder::<V4, Local>::default()
            .set_no_expiration_danger_acknowledged()
            .build(&key)
            .expect("Failed to build PASETO claim");

        Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token={}",
                proxy_port, server.port, claim
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect("Failed to connection to proxy");
    }
}
