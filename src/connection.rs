use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, StreamExt},
};
use slog::Logger;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

use crate::dest::Remote;
use crate::limits::{ConnectionLease, LimitState};
use crate::metrics::{ScopeDuration, ScopeGauge, METRICS};
use crate::proto::{
    greeting_complete, max_greeting_bytes, probe_for_port, tls_record_needed, validate_greeting,
    validate_tls_client_hello, ProbeKind,
};
use crate::{
    config::Config,
    metrics::{self, ConnectionsLabels, RejectReason},
};

pub struct Connection {
    remote: Remote,
    client_ip: IpAddr,
    tcp: Option<TcpStream>,
    lease: Option<ConnectionLease>,
    limits: Arc<LimitState>,
    log: Logger,
    config: Arc<Config>,
}

impl Connection {
    pub fn new(
        remote: Remote,
        client_ip: IpAddr,
        tcp: TcpStream,
        lease: ConnectionLease,
        limits: Arc<LimitState>,
        log: Logger,
        config: Arc<Config>,
    ) -> Self {
        Connection {
            remote,
            client_ip,
            tcp: Some(tcp),
            lease: Some(lease),
            limits,
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

    fn account_bytes(&self, n: usize) -> Result<(), ()> {
        if n == 0 {
            return Ok(());
        }
        if self.limits.add_bytes(self.client_ip, n as u64).is_err() {
            METRICS.inc_reject(RejectReason::ByteCap);
            info!(self.log, "Per-IP byte cap exceeded");
            return Err(());
        }
        Ok(())
    }

    fn over_conn_bytes(&self, total: u64) -> bool {
        let cap = self.config.max_bytes_per_connection;
        cap != 0 && total > cap
    }

    pub async fn run(&mut self, mut websocket: WebSocket) {
        let _active_conn = ScopeGauge::new(&METRICS.active_connections);
        let duration = ScopeDuration::new(&METRICS.connection_duration);
        let dest_key = self.remote.dest_key();
        METRICS
            .connections
            .get_or_create(&ConnectionsLabels {
                port: metrics::PortClass::from_port(self.remote.port),
            })
            .inc();

        self.log = self.log.new(o!("remote" => dest_key));

        let mut tcp = match self.tcp.take() {
            Some(t) => t,
            None => return,
        };

        if self.config.require_protocol_probe {
            if let Some(kind) = probe_for_port(self.remote.port) {
                if let Err(reason) = self.probe(&mut websocket, &mut tcp, kind).await {
                    METRICS.inc_reject(reason);
                    let _ = websocket.send(Message::Close(None)).await;
                    let _ = tcp.shutdown().await;
                    return;
                }
            }
        }

        let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
        let (mut ws_write, mut ws_read) = websocket.split();

        let mut buffer = [0u8; 1024];
        let mut conn_bytes: u64 = 0;
        let deadline = if self.config.max_lifetime.is_zero() {
            None
        } else {
            Some(Instant::now() + self.config.max_lifetime)
        };

        loop {
            let idle = timeout(self.config.ws_idle_timeout, ws_read.next());
            tokio::select! {
                biased;
                _ = async {
                    if let Some(d) = deadline {
                        tokio::time::sleep_until(d).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    METRICS.inc_reject(RejectReason::Lifetime);
                    info!(self.log, "Max connection lifetime reached");
                    break;
                }

                // WebSocket → TCP. Idle is normal for IMAP (user reading mail,
                // IDLE, etc.). On idle we send a keepalive ping instead of
                // dropping the connection; a failed ping write means the peer
                // is gone.
                result = idle => {
                    match result {
                        Ok(Some(Ok(msg))) => {
                            match msg {
                                Message::Binary(data) => {
                                    conn_bytes = conn_bytes.saturating_add(data.len() as u64);
                                    if self.over_conn_bytes(conn_bytes) {
                                        METRICS.inc_reject(RejectReason::ByteCap);
                                        info!(self.log, "Per-connection byte cap exceeded");
                                        break;
                                    }
                                    if self.account_bytes(data.len()).is_err() {
                                        break;
                                    }
                                    if self.send_tcp(&mut tcp_write, &data).await.is_err() {
                                        break;
                                    }
                                }
                                Message::Text(text) => {
                                    conn_bytes = conn_bytes.saturating_add(text.len() as u64);
                                    if self.over_conn_bytes(conn_bytes) {
                                        METRICS.inc_reject(RejectReason::ByteCap);
                                        info!(self.log, "Per-connection byte cap exceeded");
                                        break;
                                    }
                                    if self.account_bytes(text.len()).is_err() {
                                        break;
                                    }
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
                                .send_ws(&mut ws_write, Message::Ping(Bytes::new()))
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
                            conn_bytes = conn_bytes.saturating_add(size as u64);
                            if self.over_conn_bytes(conn_bytes) {
                                METRICS.inc_reject(RejectReason::ByteCap);
                                info!(self.log, "Per-connection byte cap exceeded");
                                break;
                            }
                            if self.account_bytes(size).is_err() {
                                break;
                            }
                            let msg = Message::Binary(Bytes::copy_from_slice(&buffer[..size]));
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
        drop(self.lease.take());

        debug!(self.log, "Connection closed"; "duration_secs" => duration.duration());
    }

    async fn probe(
        &self,
        ws: &mut WebSocket,
        tcp: &mut TcpStream,
        kind: ProbeKind,
    ) -> Result<(), RejectReason> {
        match kind {
            ProbeKind::TlsSni => self.probe_tls_sni(ws, tcp).await,
            ProbeKind::ImapGreeting | ProbeKind::SmtpGreeting => {
                self.probe_greeting(ws, tcp, kind).await
            }
        }
    }

    async fn probe_tls_sni(
        &self,
        ws: &mut WebSocket,
        tcp: &mut TcpStream,
    ) -> Result<(), RejectReason> {
        let mut hello = Vec::new();
        loop {
            let msg = match timeout(self.config.tcp_connect_timeout, ws.next()).await {
                Ok(Some(Ok(m))) => m,
                Ok(Some(Err(e))) => {
                    METRICS.inc_ws_error(metrics::Error::Read);
                    error!(self.log, "WS error during TLS probe"; "error" => e.to_string());
                    return Err(RejectReason::Proto);
                }
                Ok(None) => return Err(RejectReason::Proto),
                Err(_) => {
                    info!(self.log, "Timed out waiting for TLS ClientHello");
                    return Err(RejectReason::Proto);
                }
            };
            match msg {
                Message::Binary(data) => hello.extend_from_slice(&data),
                Message::Text(text) => hello.extend_from_slice(text.as_bytes()),
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => return Err(RejectReason::Proto),
            }
            match tls_record_needed(&hello) {
                Ok(0) => break,
                Ok(_) => {
                    if hello.len() > 16 * 1024 {
                        return Err(RejectReason::Proto);
                    }
                }
                Err(e) => {
                    info!(self.log, "TLS probe failed"; "error" => e.as_str());
                    return Err(RejectReason::Proto);
                }
            }
        }

        if let Err(e) =
            validate_tls_client_hello(&hello, &self.remote.host, self.remote.ip_literal.is_some())
        {
            info!(self.log, "TLS ClientHello rejected"; "error" => e.as_str());
            return Err(RejectReason::Proto);
        }

        timeout(self.config.tcp_write_timeout, tcp.write_all(&hello))
            .await
            .map_err(|_| RejectReason::Proto)?
            .map_err(|_| RejectReason::Proto)?;
        Ok(())
    }

    async fn probe_greeting(
        &self,
        ws: &mut WebSocket,
        tcp: &mut TcpStream,
        kind: ProbeKind,
    ) -> Result<(), RejectReason> {
        let mut greet = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = match timeout(self.config.tcp_connect_timeout, tcp.read(&mut tmp)).await {
                Ok(Ok(0)) => {
                    info!(self.log, "Upstream closed during greeting probe");
                    return Err(RejectReason::Proto);
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    METRICS.inc_tcp_error(metrics::Error::Read);
                    error!(self.log, "TCP error during greeting probe"; "error" => e.to_string());
                    return Err(RejectReason::Proto);
                }
                Err(_) => {
                    info!(self.log, "Timed out waiting for server greeting");
                    return Err(RejectReason::Proto);
                }
            };
            greet.extend_from_slice(&tmp[..n]);
            if greeting_complete(&greet) || greet.len() >= max_greeting_bytes() {
                break;
            }
        }

        if let Err(e) = validate_greeting(&greet, kind) {
            info!(self.log, "Server greeting rejected"; "error" => e.as_str());
            return Err(RejectReason::Proto);
        }

        timeout(
            self.config.ws_write_timeout,
            ws.send(Message::Binary(Bytes::from(greet))),
        )
        .await
        .map_err(|_| RejectReason::Proto)?
        .map_err(|_| RejectReason::Proto)?;
        Ok(())
    }
}
