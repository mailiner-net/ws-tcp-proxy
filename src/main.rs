use std::borrow::{Borrow, BorrowMut};
use std::net::SocketAddr;
use axum::extract::{ws::Message, ws::WebSocket, Query, WebSocketUpgrade, ConnectInfo, State};
use axum::response::IntoResponse;
use axum::{Error, Router};
use axum::routing::get;
use axum::debug_handler;
use slog::Logger;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use serde::Deserialize;
use tracing_subscriber;
use futures_util::{sink::SinkExt, stream::{StreamExt, SplitSink, SplitStream}};

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate slog;
extern crate slog_term;

use slog::Drain;

mod metrics;
use metrics::{Metrics, ScopeDuration, ScopeGauge};

lazy_static! {
    static ref METRICS: Metrics = Metrics::new();
}

#[tokio::main]
async fn main() {
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

    let listener = TcpListener::bind("0.0.0.0:9400").await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

#[derive(Deserialize)]
struct Proxy {
    token: String,
    remote: String
}

struct Connection {
    remote: String,
    log: Logger
}

impl Connection {

    pub fn new(remote: String, log: Logger) -> Self {
        Connection {
            remote,
            log
        }
    }

    async fn send_tcp_message(&self, tcp: &mut WriteHalf<TcpStream>, data: Vec<u8>) {
        if let Err(e) = tcp.write_all(data.borrow()).await {
            METRICS.inc_tcp_error(metrics::Error::Send);
            error!(self.log, "Error writing to a TCP upstream"; "error" => e.to_string());
        }
        debug!(self.log, "Sent bytes to TCP socket"; "bytes" => data.len());
    }

    async fn ws_to_tcp(&self, ws: &mut SplitStream<WebSocket>, tcp: &mut WriteHalf<TcpStream>) {
        info!(self.log, "Waiting for incoming WS data");
        loop {
            if let Some(msg) = ws.next().await {
                match msg {
                    Ok(msg) => {
                        self.send_tcp_message(tcp, msg.into_data()).await;
                    },
                    Err(e) => {
                        METRICS.inc_ws_error(metrics::Error::Read);
                        error!(self.log, "Error reading from websocket"; "error" => e.to_string());
                        return;
                    }
                }
            } else {
                error!(self.log, "Client has disconnected!");
                return;
            }
        }
    }

    async fn tcp_to_ws(&self, ws: &mut SplitSink<WebSocket, Message>, tcp: &mut ReadHalf<TcpStream>) {
        let mut buffer = [0; 1024];
        loop {
            info!(self.log, "Waiting for incoming TCP data");
            let size = match tcp.read(buffer.borrow_mut()).await {
                Ok(size) => {
                    info!(self.log, "Received data from TCP upstream"; "bytes" => size);
                    size
                },
                Err(e) => {
                    METRICS.inc_tcp_error(metrics::Error::Read);
                    error!(self.log, "Error reading from upstream TCP"; "error" => e.to_string());
                    return;
                }
            };

            if size == 0 {
                info!(self.log, "Upstream has closed the connection");
                return;
            }

            let msg = Message::Binary(buffer[0..size].to_vec());
            if let Err(e) = ws.send(msg).await {
                METRICS.inc_ws_error(metrics::Error::Send);
                error!(self.log, "Error sending message to WebSocket client"; "error" => e.to_string());
                return;
            }
            debug!(self.log, "Sent bytes to WS"; "bytes" => size);
        }
    }

    pub async fn run(&mut self, websocket: WebSocket) {
        let _active_conn = ScopeGauge::new(&METRICS.active_connections);
        let duration = ScopeDuration::new(&METRICS.connection_duration);

        self.log = self.log.new(o!("remote" => self.remote.clone()));

        let tcp = match tokio::net::TcpStream::connect(self.remote.clone()).await {
            Ok(tcp_stream) => {
                info!(self.log, "Established TCP connection to upstream");
                tcp_stream
            },
            Err(e) => {
                METRICS.inc_tcp_error(metrics::Error::Handshake);
                error!(self.log, "Failed to establish TCP connection to upstream"; "error" => e.to_string());
                return;
            }
        };

        let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
        let (mut ws_write, mut ws_read) = websocket.split();

        tokio::select!(
            _ = self.ws_to_tcp(&mut ws_read, &mut tcp_write) => {
                info!(self.log, "WS to TCP task finished");
                if let Err(e) = ws_write.close().await {
                    METRICS.inc_tcp_error(metrics::Error::Shutdown);
                    error!(self.log, "Error closing WS connection"; "error" => e.to_string());
                }
            },
            _ = self.tcp_to_ws(&mut ws_write, &mut tcp_read) => {
                info!(self.log, "TCP to WS task finished");
                if let Err(e) = tcp_write.shutdown().await {
                    METRICS.inc_tcp_error(metrics::Error::Shutdown);
                    error!(self.log, "Error shutting down TCP connection"; "error" => e.to_string());
                }
            }
        );

        info!(self.log, "Conection closed (duration {} s" ,duration.duration());
    }
}



#[debug_handler]
async fn proxy(query: Query<Proxy>, ws: WebSocketUpgrade, ConnectInfo(addr): ConnectInfo<SocketAddr>, State(log): State<Logger>) -> impl IntoResponse {
    let log = log.new(o!("client" => addr.to_string()));

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