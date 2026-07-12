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

use crate::config::Config;
use crate::connection::Connection;
use crate::metrics;
use crate::metrics::METRICS;
use crate::DEFAULT_LOGGER;

#[derive(Deserialize)]
struct ProxyQuery {
    token: String,
    remote: String,
}

struct ServerState {
    log: Logger,
    config: Arc<Config>,
}

fn validate_token(
    query: &ProxyQuery,
    secret_key: &Option<PasetoSymmetricKey<V4, Local>>,
    log: &Logger,
) -> Result<(), StatusCode> {
    if cfg!(debug_assertions) && query.token == "testtoken" {
        return Ok(());
    }

    if secret_key.is_none() {
        crit!(
            log,
            "PASETO_SECRET_KEY variable is not set, rejecting client!"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    PasetoParser::<V4, Local>::default()
        .validate_claim(ExpirationClaim::default(), &|_, value| {
            let val = value.as_str().unwrap_or_default();
            // Don't permit non-expiring tokens
            if val.is_empty() {
                return Err(PasetoClaimError::Expired);
            }

            let datetime = chrono::DateTime::parse_from_rfc3339(val).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
            let now = chrono::Utc::now();

            if datetime <= now {
                Err(PasetoClaimError::Expired)
            } else {
                Ok(())
            }
        } )
        .check_claim(
            CustomClaim::try_from(("remote", query.remote.clone()))
                .map_err(|_| StatusCode::UNAUTHORIZED)?,
        )
        .parse(&query.token, &secret_key.as_ref().unwrap())
        .map(|_| ())
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

async fn proxy_handler(
    query: Query<ProxyQuery>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    let log = state.log.new(o!("client" => addr.to_string()));

    if let Err(err) = validate_token(&query, &state.config.secret_key, &log) {
        return Err::<Body, StatusCode>(err).into_response();
    }

    debug!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    ws.on_failed_upgrade(move |error: axum::Error| {
        METRICS.inc_ws_error(metrics::Error::Handshake);
        error!(fail_log, "Failed to upgrade WebSocket connection"; "error" => error.to_string());
    })
    .on_upgrade(move |socket| async move {
        Connection::new(query.remote.clone(), upgrade_log, Arc::clone(&state.config))
            .run(socket)
            .await;
    })
}

#[derive(Deserialize)]
struct MetricsQuery {
    token: Option<String>
}

#[debug_handler]
async fn metrics_handler(State(state): State<Arc<ServerState>>, Query(query): Query<MetricsQuery>) -> impl IntoResponse {
    if let Some(metrics_auth_key) = state.config.metrics_auth_key.as_ref() {
        if query.token.as_deref() != Some(metrics_auth_key) {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }

    info!(state.log, "Serving metrics");
    (StatusCode::OK, METRICS.encode()).into_response()
}

pub async fn run_proxy(
    listener: TcpListener,
    config: Config,
) -> Result<(), Error> {
    let state = Arc::new(ServerState {
        log: DEFAULT_LOGGER.get().unwrap().clone(),
        config: Arc::new(config)
    });

    let app = Router::new()
        .route("/proxy", get(proxy_handler).with_state(Arc::clone(&state)))
        .route("/metrics", get(metrics_handler).with_state(Arc::clone(&state)));

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

    use crate::config::Config;
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
                            let size = read
                                .read(&mut buffer)
                                .await
                                .expect("Failed to read from socket");
                            if size == 0 {
                                return;
                            }

                            write
                                .write_all(&buffer[0..size])
                                .await
                                .expect("Error writing to socket");
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
        create_servers_with_config(Config {
            secret_key,
            ..Default::default()
        })
        .await
    }

    async fn create_servers_with_config(config: Config) -> (u16, TestServer) {
        init_logging(slog::Level::Debug);
        let server = TestServer::new().await;
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind proxy");
        let proxy_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = run_proxy(listener, config).await;
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
                .expect("Fialed to build URI"),
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
            .expect("Failed to build URI"),
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
            .expect("Failed to build URI"),
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
            .expect("Failed to build URI"),
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
    async fn test_expired_token_returns_unauthorized() {
        let secret = Key::<32>::try_new_random().expect("Failed to generate a new PASETO key");
        let (proxy_port, server) =
            create_servers(Some(PasetoSymmetricKey::<V4, Local>::from(secret.clone()))).await;

        let hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
        let key = PasetoSymmetricKey::<V4, Local>::from(secret);
        let claim = PasetoBuilder::<V4, Local>::default()
            .set_claim(
                ExpirationClaim::try_from(hour_ago.to_rfc3339())
                    .expect("Failed to parse expire claim"),
            )
            .set_claim(
                CustomClaim::try_from(("remote", format!("127.0.0.1:{}", server.port)))
                    .expect("Failed to parse remote claim"),
            )
            .build(&key)
            .expect("Failed to build PASETO claim");

        Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token={}",
                proxy_port, server.port, claim
            )
            .parse()
            .expect("Failed to build URI"),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite expired token");
    }

    #[tokio::test]
    async fn test_token_with_wrong_remote_claim_returns_unauthorized() {
        let secret = Key::try_new_random().expect("Failed to generate a new PASETO key");
        let (proxy_port, server) =
            create_servers(Some(PasetoSymmetricKey::<V4, Local>::from(secret.clone()))).await;

        let key = PasetoSymmetricKey::<V4, Local>::from(secret);
        let claim = PasetoBuilder::<V4, Local>::default()
            .set_claim(
                CustomClaim::try_from(("remote", "blablabla"))
                    .expect("Failed to parse remote claim"),
            )
            .build(&key)
            .expect("Failed to build PASETO claim");

        Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token={}",
                proxy_port, server.port, claim
            )
            .parse()
            .expect("Failed to build URI"),
        )
        .connect()
        .await
        .expect_err("Connected successfully despite invalid remote claim");
    }

    /// Idle IMAP-like sessions must not be dropped: after the idle timeout the
    /// proxy sends a WebSocket ping instead of closing, so traffic still works.
    #[tokio::test]
    async fn test_idle_connection_survives_keepalive() {
        use std::time::Duration;

        let (proxy_port, server) = create_servers_with_config(Config {
            ws_idle_timeout: Duration::from_millis(100),
            ..Default::default()
        })
        .await;

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

        // Wait well past several idle intervals; previously this would have
        // closed the connection with "WS read timed out".
        tokio::time::sleep(Duration::from_millis(350)).await;

        let msg = Message::binary("still-alive".as_bytes());
        client
            .send(msg.clone())
            .await
            .expect("Failed to send after idle period");

        // Skip any control frames that may have been queued while idle.
        let resp = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = client
                    .next()
                    .await
                    .expect("Connection closed during idle")
                    .expect("Failed to receive after idle period");
                if frame.is_binary() || frame.is_text() {
                    break frame;
                }
            }
        })
        .await
        .expect("Timed out waiting for echo after idle");

        assert_eq!(
            bytes::Bytes::from(resp.into_payload()),
            bytes::Bytes::from(msg.into_payload())
        );
    }

    #[tokio::test]
    async fn test_valid_token_passes() {
        let secret = Key::<32>::try_new_random().expect("Failed to generate a new PASETO key");
        let (proxy_port, server) =
            create_servers(Some(PasetoSymmetricKey::<V4, Local>::from(secret.clone()))).await;

        let key = PasetoSymmetricKey::<V4, Local>::from(secret);
        // Claims expire in one hour by default, which is good enough for this test
        let claim = PasetoBuilder::<V4, Local>::default()
            .set_claim(
                CustomClaim::try_from(("remote", format!("127.0.0.1:{}", server.port)))
                    .expect("Failed to parse remove claim"),
            )
            .build(&key)
            .expect("Failed to build PASETO claim");

        Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token={}",
                proxy_port, server.port, claim
            )
            .parse()
            .expect("Failed to build URI"),
        )
        .connect()
        .await
        .expect("Failed to connection to proxy");
    }
}
