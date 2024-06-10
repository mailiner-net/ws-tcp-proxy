use axum::extract::{ws::Message, ws::WebSocket};
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use slog::Logger;
use std::borrow::{Borrow, BorrowMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::metrics::{self, ConnectionsLabels};
use crate::metrics::{ScopeDuration, ScopeGauge, METRICS};

pub struct Connection {
    remote: String,
    log: Logger,
}

impl Connection {
    pub fn new(remote: String, log: Logger) -> Self {
        Connection { remote, log }
    }

    async fn send_tcp_message(&self, tcp: &mut WriteHalf<TcpStream>, data: Vec<u8>) {
        if let Err(e) = tcp.write_all(data.borrow()).await {
            METRICS.inc_tcp_error(metrics::Error::Send);
            error!(self.log, "Error writing to a TCP upstream"; "error" => e.to_string());
        }
        trace!(self.log, "Sent bytes to TCP socket"; "bytes" => data.len());
    }

    async fn ws_to_tcp(&self, ws: &mut SplitStream<WebSocket>, tcp: &mut WriteHalf<TcpStream>) {
        trace!(self.log, "Waiting for incoming WS data");
        loop {
            if let Some(msg) = ws.next().await {
                match msg {
                    Ok(msg) => {
                        self.send_tcp_message(tcp, msg.into_data()).await;
                    }
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

    async fn tcp_to_ws(
        &self,
        ws: &mut SplitSink<WebSocket, Message>,
        tcp: &mut ReadHalf<TcpStream>,
    ) {
        let mut buffer = [0; 1024];
        loop {
            trace!(self.log, "Waiting for incoming TCP data");
            let size = match tcp.read(buffer.borrow_mut()).await {
                Ok(size) => {
                    trace!(self.log, "Received data from TCP upstream"; "bytes" => size);
                    size
                }
                Err(e) => {
                    METRICS.inc_tcp_error(metrics::Error::Read);
                    error!(self.log, "Error reading from upstream TCP"; "error" => e.to_string());
                    return;
                }
            };

            if size == 0 {
                debug!(self.log, "Upstream has closed the connection");
                return;
            }

            let msg = Message::Binary(buffer[0..size].to_vec());
            if let Err(e) = ws.send(msg).await {
                METRICS.inc_ws_error(metrics::Error::Send);
                error!(self.log, "Error sending message to WebSocket client"; "error" => e.to_string());
                return;
            }
            trace!(self.log, "Sent bytes to WS"; "bytes" => size);
        }
    }

    pub async fn run(&mut self, websocket: WebSocket) {
        let _active_conn = ScopeGauge::new(&METRICS.active_connections);
        let duration = ScopeDuration::new(&METRICS.connection_duration);
        METRICS
            .connections
            .get_or_create(&ConnectionsLabels {
                remote: self.remote.clone(),
            })
            .inc();

        self.log = self.log.new(o!("remote" => self.remote.clone()));

        let tcp = match tokio::net::TcpStream::connect(self.remote.clone()).await {
            Ok(tcp_stream) => {
                debug!(self.log, "Established TCP connection to upstream");
                tcp_stream
            }
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
                debug!(self.log, "WS to TCP task finished");
                if let Err(e) = ws_write.close().await {
                    METRICS.inc_tcp_error(metrics::Error::Shutdown);
                    error!(self.log, "Error closing WS connection"; "error" => e.to_string());
                }
            },
            _ = self.tcp_to_ws(&mut ws_write, &mut tcp_read) => {
                debug!(self.log, "TCP to WS task finished");
                if let Err(e) = tcp_write.shutdown().await {
                    METRICS.inc_tcp_error(metrics::Error::Shutdown);
                    error!(self.log, "Error shutting down TCP connection"; "error" => e.to_string());
                }
            }
        );

        debug!(self.log, "Conection closed"; "duration_secs" => duration.duration());
    }
}
