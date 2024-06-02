use std::borrow::{Borrow, BorrowMut};
use std::net::SocketAddr;
use axum::extract::{ws::Message, ws::WebSocket, Query, WebSocketUpgrade, ConnectInfo};
use axum::response::IntoResponse;
use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use serde::Deserialize;
use tracing_subscriber;
use axum::debug_handler;
use futures_util::{sink::SinkExt, stream::{StreamExt, SplitSink, SplitStream}};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let app = Router::new()
        .route("/proxy", get(proxy));

    let listener = TcpListener::bind("0.0.0.0:9400").await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

#[derive(Deserialize)]
struct Proxy {
    token: String,
    remote: String
}

#[debug_handler]
async fn proxy(query: Query<Proxy>, ws: WebSocketUpgrade, ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    log::info!("Incoming WS connection from {:?} for remote {}", addr, query.remote);
    ws.on_failed_upgrade(|error| {
        log::error!("Failed to upgrade WebSocket connection: {:?}", error)
    }).on_upgrade(move |socket| handle_socket(socket, query))
}

async fn ws_to_tcp(mut websocket: SplitStream<WebSocket>, mut tcp_socket: WriteHalf<TcpStream>) {
    loop {
        let msg = {
            log::info!("Waiting for incoming WS data");
            if let Some(msg) = websocket.next().await {
                match msg {
                    Ok(msg) => {
                        log::info!("Received message from WS");
                        msg
                    },
                    Err(e) => {
                        log::error!("Error reading from websocket: {:?}", e);
                        return;
                    }
                }
            } else {
                log::error!("Client has disconnected!");
                return;
            }
        };

        if let Err(e) = tcp_socket.write_all(msg.into_data().borrow()).await {
            log::error!("Error writing to a client: {:?}", e);
            return;
        }
        log::debug!("Sent {} bytes to TCP socket", 'X');
    }
}

async fn tcp_to_ws(mut websocket: SplitSink<WebSocket, Message>, mut tcp_socket: ReadHalf<TcpStream>) {
    let mut buffer = [0; 1024];
    loop {
        log::info!("Waiting for incoming TCP data");
        let size = match tcp_socket.read(buffer.borrow_mut()).await {
            Ok(size) => {
                log::info!("Received {} bytes from TCP", size);
                size
            },
            Err(e) => {
                log::error!("Error reading from upstream TCP: {:?}", e);
                return;
            }
        };

        let msg = Message::Binary(buffer[0..size].to_vec());
        {
            if let Err(e) = websocket.send(msg).await {
                log::error!("Error sending message to WebSocket client: {:?}", e);
                return;
            }
            log::debug!("Sent {} bytes to WS", size);
        }
    };
}

async fn handle_socket(websocket: WebSocket, query: Query<Proxy>) {
    let tcp_stream = match tokio::net::TcpStream::connect(query.remote.clone()).await {
        Ok(tcp_stream) => {
            log::info!("Established TCP connection to {}", query.remote);
            tcp_stream
        },
        Err(e) => {
            log::error!("Failed to establish TCP connection to {}: {:?}", query.remote, e);
            return;
        }
    };

    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);
    let (ws_write, ws_read) = websocket.split();

    tokio::select!(
        _ = ws_to_tcp(ws_read, tcp_write) => {
            log::info!("WS to TCP task finished");
        },
        _ = tcp_to_ws(ws_write, tcp_read) => {
            log::info!("TCP to WS task finished");
        }
    );

    log::info!("Conection closed");
}