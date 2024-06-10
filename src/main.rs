use axum::debug_handler;
use axum::extract::{ConnectInfo, Query, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Error, Router};
use clap::{arg, command, Parser};
use serde::Deserialize;
use slog::Logger;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber;

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
    bind: String,
}

pub struct App {
    listener: Option<TcpListener>,
    pub port: u16
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

impl App {
    async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener: Some(listener),
            port: port
        })
    }

    async fn run(&mut self) -> Result<(), io::Error>
    {
        let root = init_logger();
        let app = Router::new()
            .route("/proxy", get(proxy).with_state(root.clone()))
            .route("/metrics", get(dump_metrics));

        axum::serve(
            self.listener.take().unwrap(),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        ).await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Server error"))
    }
}

#[derive(Deserialize)]
struct QueryParams {
    pub token: String,
    pub remote: String,
}

#[debug_handler]
async fn proxy(
    query: Query<QueryParams>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(log): State<Logger>,
) -> impl IntoResponse {
    let log = log.new(o!("client" => addr.to_string()));

    info!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    ws.on_failed_upgrade(move |error: Error| {
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
async fn dump_metrics() -> impl IntoResponse {
    METRICS.encode()
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let mut app = App::bind(format!("{}:{}", args.bind, args.port)).await.unwrap();
    match app.run().await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_websockets::client::Builder;
    use tokio_websockets::{upgrade, Message};
    use futures_util::{StreamExt, SinkExt};
    use crate::App;

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

    fn create_servers() -> (u16, TestServer) {
        let server = TestServer::new().await;
        let mut proxy = App::bind("0.0.0.0:0").await.expect("Failed to bind proxy");
        let proxy_port = proxy.port;
        tokio::spawn(async move {
            let _ = proxy.run().await;
        });

        (proxy_port, server)
    }

    #[tokio::test]
    async fn test_connection() {
        let (proxy_port, server) = create_servers();

        let (mut client, _) = Builder::from_uri(format!(
            "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
            proxy_port, server.port
        ).parse().unwrap())
        .connect()
        .await
        .expect("Failed to connect to WebSocket");

        let msg = Message::binary("Hello, World".as_bytes());
        client.send(msg.clone()).await.expect("Failed to send message");
        let resp = client.next().await.expect("Failed to receive message").expect("Received message without data");

        assert_eq!(bytes::Bytes::from(resp.into_payload()), bytes::Bytes::from(msg.into_payload()));
    }

    #[tokio::test]
    async fn test_missing_remote_returns_error() {
        let (proxy_port, server) = create_servers();

        let err = Builder::from_uri(format!(
            "ws://127.0.0.1:{}/proxy?token=testtoken", proxy_port).parse().unwrap())
            .connect()
            .await
            .expect_err("Connected successfully despite missing 'remote' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 400)
            },
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_missing_token_returns_error() {
        let (proxy_port, server) = create_servers();

        let err = Builder::from_uri(format!("ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}", proxy_port, server.port).parse().unwrap())
            .connect()
            .await
            .expect_err("Connected successfully despite missing 'token' param");)

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 401)
            },
            _ => panic!("Unexpected error: {:?}", err),
        };
    }

    #[tokio::test]
    async fn test_invalid_token_returns_error() {
        let (proxy_port, server) = create_servers();

        let err = Builder::from_uri(format!(
            "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=invalid", proxy_port, server.port).parse().unwrap())
            .connect()
            .await
            .expect_err("Connected successfully despite invalid 'token' param");

        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                assert_eq!(code, 401)
            },
            _ => panic!("Unexpected error: {:?}", err),
        };
        }
}
