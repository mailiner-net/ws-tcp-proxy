use axum::extract::ws::{Message, WebSocket};
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, StreamExt},
};
use slog::Logger;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::metrics::{ScopeDuration, ScopeGauge, METRICS};
use crate::{
    config::Config,
    metrics::{self, ConnectionsLabels},
};

pub struct Connection {
    remote: String,
    log: Logger,
    config: Arc<Config>,
}

impl Connection {
    pub fn new(remote: String, log: Logger, config: Arc<Config>) -> Self {
        Connection {
            remote,
            log,
            config,
        }
    }

    async fn send_tcp(&self, tcp: &mut WriteHalf<TcpStream>, data: &[u8]) -> Result<(), ()> {
        match timeout(self.config.tcp_write_timeout, tcp.write_all(data)).await {
            Ok(Ok(())) => {
                trace!(self.log, "Sent bytes to TCP socket"; "bytes" => data.len());
                Ok(())
            }
            Ok(Err(e)) => {
                METRICS.inc_tcp_error(metrics::Error::Send);
                error!(self.log, "Error writing to a TCP upstream"; "error" => e.to_string());
                Err(())
            }
            Err(_) => {
                METRICS.inc_tcp_timeout(metrics::Error::Timeout);
                error!(self.log, "TCP write timed out");
                Err(())
            }
        }
    }

    async fn send_ws(
        &self,
        ws: &mut SplitSink<WebSocket, Message>,
        msg: Message,
    ) -> Result<(), ()> {
        let kind = match &msg {
            Message::Binary(_) => "binary",
            Message::Text(_) => "text",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::Close(_) => "close",
        };
        match timeout(self.config.ws_write_timeout, ws.send(msg)).await {
            Ok(Ok(())) => {
                trace!(self.log, "Sent message to WS"; "kind" => kind);
                Ok(())
            }
            Ok(Err(e)) => {
                METRICS.inc_ws_error(metrics::Error::Send);
                error!(self.log, "Error sending message to WebSocket client"; "error" => e.to_string());
                Err(())
            }
            Err(_) => {
                METRICS.inc_ws_error(metrics::Error::Timeout);
                error!(self.log, "WS write timed out");
                Err(())
            }
        }
    }

    async fn close_ws(&self, ws: &mut SplitSink<WebSocket, Message>) {
        // Explicit Close frame so the client learns it was disconnected and can
        // reconnect (important for IMAP clients after the session ends).
        if self.send_ws(ws, Message::Close(None)).await.is_err() {
            debug!(self.log, "Could not send WS close frame");
        }
        if let Err(e) = ws.close().await {
            METRICS.inc_ws_error(metrics::Error::Shutdown);
            debug!(self.log, "Error closing WS connection"; "error" => e.to_string());
        }
    }

    async fn close_tcp(&self, tcp: &mut WriteHalf<TcpStream>) {
        if let Err(e) = tcp.shutdown().await {
            METRICS.inc_tcp_error(metrics::Error::Shutdown);
            debug!(self.log, "Error shutting down TCP connection"; "error" => e.to_string());
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

        let tcp = match timeout(
            self.config.tcp_connect_timeout,
            TcpStream::connect(self.remote.clone()),
        )
        .await
        {
            Ok(Ok(tcp_stream)) => {
                debug!(self.log, "Established TCP connection to upstream");
                tcp_stream
            }
            Ok(Err(e)) => {
                METRICS.inc_tcp_error(metrics::Error::Handshake);
                error!(self.log, "Failed to establish TCP connection to upstream"; "error" => e.to_string());
                return;
            }
            Err(_) => {
                METRICS.inc_tcp_timeout(metrics::Error::Timeout);
                error!(self.log, "TCP connection timed out");
                return;
            }
        };

        let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
        let (mut ws_write, mut ws_read) = websocket.split();

        let mut buffer = [0u8; 1024];

        loop {
            tokio::select! {
                // WebSocket → TCP. Idle is normal for IMAP (user reading mail,
                // IDLE, etc.). On idle we send a keepalive ping instead of
                // dropping the connection; a failed ping write means the peer
                // is gone.
                result = timeout(self.config.ws_idle_timeout, ws_read.next()) => {
                    match result {
                        Ok(Some(Ok(msg))) => {
                            match msg {
                                Message::Binary(data) => {
                                    if self.send_tcp(&mut tcp_write, &data).await.is_err() {
                                        break;
                                    }
                                }
                                Message::Text(text) => {
                                    if self.send_tcp(&mut tcp_write, text.as_bytes()).await.is_err()
                                    {
                                        break;
                                    }
                                }
                                Message::Ping(payload) => {
                                    // tungstenite usually auto-replies; respond
                                    // explicitly so we stay correct either way.
                                    trace!(self.log, "Received WS ping");
                                    if self
                                        .send_ws(&mut ws_write, Message::Pong(payload))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Message::Pong(_) => {
                                    trace!(self.log, "Received WS pong");
                                }
                                Message::Close(frame) => {
                                    debug!(
                                        self.log,
                                        "Client closed WebSocket";
                                        "frame" => format!("{:?}", frame)
                                    );
                                    break;
                                }
                            }
                        }
                        Ok(Some(Err(e))) => {
                            METRICS.inc_ws_error(metrics::Error::Read);
                            error!(self.log, "Error reading from WebSocket"; "error" => e.to_string());
                            break;
                        }
                        Ok(None) => {
                            debug!(self.log, "Client has disconnected");
                            break;
                        }
                        Err(_) => {
                            // Idle timeout — do not tear down. Ping keeps NATs/LBs
                            // happy and surfaces a dead peer if the write fails.
                            debug!(self.log, "WS idle; sending keepalive ping");
                            if self
                                .send_ws(&mut ws_write, Message::Ping(Vec::new()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }

                // TCP → WebSocket. No idle timeout: IMAP upstreams are often
                // silent for long stretches.
                result = tcp_read.read(&mut buffer) => {
                    match result {
                        Ok(0) => {
                            debug!(self.log, "Upstream has closed the connection");
                            break;
                        }
                        Ok(size) => {
                            trace!(self.log, "Received data from TCP upstream"; "bytes" => size);
                            let msg = Message::Binary(buffer[..size].to_vec());
                            if self.send_ws(&mut ws_write, msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            METRICS.inc_tcp_error(metrics::Error::Read);
                            error!(self.log, "Error reading from upstream TCP"; "error" => e.to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Always tear down both sides so the client sees a proper disconnect.
        self.close_ws(&mut ws_write).await;
        self.close_tcp(&mut tcp_write).await;

        debug!(self.log, "Connection closed"; "duration_secs" => duration.duration());
    }
}
