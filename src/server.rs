use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rusty_paseto::prelude::*;
use serde::Deserialize;
use slog::Logger;
use tokio::io::Error;
use tokio::net::TcpListener;

use axum::body::Body;
use axum::debug_handler;
use axum::extract::{ConnectInfo, Query, State, WebSocketUpgrade};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, Router};

use crate::config::{normalize_host, normalize_origin, AuthMode, Config};
use crate::connection::Connection;
use crate::dest::{self, DestError};
use crate::limits::{LimitError, LimitState};
use crate::metrics;
use crate::metrics::{RejectReason, METRICS};
use crate::DEFAULT_LOGGER;

#[derive(Deserialize)]
struct ProxyQuery {
    #[serde(default)]
    token: String,
    remote: String,
}

struct ServerState {
    log: Logger,
    config: Arc<Config>,
    limits: Arc<LimitState>,
}

fn origin_allowed(headers: &HeaderMap, allowed: &std::collections::HashSet<String>) -> bool {
    if allowed.is_empty() || allowed.contains("*") {
        return true;
    }
    let Some(raw) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        // Native clients omit Origin; browsers always send it on WS.
        return true;
    };
    let got = normalize_origin(raw);
    allowed.iter().any(|o| normalize_origin(o) == got)
}

fn host_allowed(headers: &HeaderMap, allowed: &std::collections::HashSet<String>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(raw) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let got = normalize_host(raw);
    allowed.iter().any(|h| {
        let want = normalize_host(h);
        got == want || got.split(':').next() == Some(want.as_str())
    })
}

fn client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trust_forwarded: bool,
    trusted: &[crate::config::Cidr],
) -> IpAddr {
    if trust_forwarded && trusted.iter().any(|c| c.contains(peer.ip())) {
        for name in ["cf-connecting-ip", "x-real-ip"] {
            if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
                if let Ok(ip) = value.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer.ip()
}

fn reject(log: &Logger, status: StatusCode, reason: RejectReason, msg: &'static str) -> Response {
    METRICS.inc_reject(reason.clone());
    warn!(
        log,
        "Rejected proxy request";
        "reason" => format!("{:?}", reason),
        "status" => status.as_u16()
    );
    (status, msg).into_response()
}

fn dest_status(err: &DestError) -> StatusCode {
    match err {
        DestError::InvalidRemote => StatusCode::BAD_REQUEST,
        DestError::BadPort | DestError::IpLiteral | DestError::PrivateIp => StatusCode::FORBIDDEN,
        DestError::Dns | DestError::Connect => StatusCode::BAD_GATEWAY,
    }
}

fn dest_message(err: &DestError) -> &'static str {
    match err {
        DestError::InvalidRemote => "invalid remote",
        DestError::BadPort => "destination port not allowed",
        DestError::IpLiteral => "IP literals are not allowed",
        DestError::PrivateIp => "destination is not a public address",
        DestError::Dns => "failed to resolve destination",
        DestError::Connect => "failed to connect to destination",
    }
}

fn limit_status(err: &LimitError) -> StatusCode {
    match err {
        LimitError::GlobalFull | LimitError::PerDestFull => StatusCode::SERVICE_UNAVAILABLE,
        LimitError::ByteCap => StatusCode::FORBIDDEN,
        _ => StatusCode::TOO_MANY_REQUESTS,
    }
}

fn limit_message(err: &LimitError) -> &'static str {
    match err {
        LimitError::GlobalFull => "proxy is at capacity",
        LimitError::PerIpFull => "too many connections from this address",
        LimitError::PerDestFull => "too many connections to this destination",
        LimitError::ConnectRate | LimitError::GlobalConnectRate => "connect rate limit exceeded",
        LimitError::DistinctDests => "too many distinct destinations",
        LimitError::ByteCap => "byte limit exceeded",
    }
}

/// Constant-time compare for bearer tokens. Length mismatch still returns
/// false after a dummy pass so short tokens are not a cheap reject.
fn token_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Token from `Sec-WebSocket-Protocol`: `bearer.<token>` or a raw `v4.local.*`.
fn protocol_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .ok()?;
    raw.split(',').map(str::trim).find_map(|p| {
        p.strip_prefix("bearer.")
            .filter(|t| !t.is_empty())
            .or_else(|| p.starts_with("v4.local.").then_some(p))
    })
}

fn offered_auth_protocol(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .ok()?;
    raw.split(',')
        .map(str::trim)
        .find(|p| p.starts_with("bearer.") || p.starts_with("v4.local."))
        .map(str::to_string)
}

fn proxy_token<'a>(query: &'a ProxyQuery, headers: &'a HeaderMap) -> &'a str {
    if !query.token.is_empty() {
        return query.token.as_str();
    }
    if let Some(b) = bearer_token(headers) {
        return b;
    }
    protocol_token(headers).unwrap_or("")
}

fn validate_token(
    token: &str,
    remote: &str,
    auth_mode: AuthMode,
    secret_key: &Option<PasetoSymmetricKey<V4, Local>>,
    max_ttl: std::time::Duration,
    log: &Logger,
) -> Result<(), StatusCode> {
    if auth_mode == AuthMode::Public {
        return Ok(());
    }

    if cfg!(debug_assertions) && token == "testtoken" {
        return Ok(());
    }

    if token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if secret_key.is_none() {
        crit!(
            log,
            "MAILINER_PASETO_SECRET is not set, rejecting client!"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let claims = PasetoParser::<V4, Local>::default()
        .validate_claim(ExpirationClaim::default(), &|_, value| {
            let val = value.as_str().unwrap_or_default();
            // Don't permit non-expiring tokens
            if val.is_empty() {
                return Err(PasetoClaimError::Expired);
            }

            let datetime = chrono::DateTime::parse_from_rfc3339(val)
                .map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
            let now = chrono::Utc::now();

            if datetime <= now {
                Err(PasetoClaimError::Expired)
            } else {
                Ok(())
            }
        })
        .check_claim(
            CustomClaim::try_from(("remote", remote.to_string()))
                .map_err(|_| StatusCode::UNAUTHORIZED)?,
        )
        .parse(token, secret_key.as_ref().unwrap())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !max_ttl.is_zero() {
        let exp = claims
            .get("exp")
            .and_then(|v| v.as_str())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let datetime = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let remaining = datetime.signed_duration_since(chrono::Utc::now());
        if remaining.to_std().map(|d| d > max_ttl).unwrap_or(true) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(())
}

async fn proxy_handler(
    query: Query<ProxyQuery>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    let client = client_ip(
        &headers,
        addr,
        state.config.trust_forwarded_client_ip,
        &state.config.trusted_proxies,
    );
    let log = state.log.new(o!("client" => client.to_string()));

    if !origin_allowed(&headers, &state.config.allowed_origins) {
        return reject(
            &log,
            StatusCode::FORBIDDEN,
            RejectReason::BadOrigin,
            "origin not allowed",
        );
    }
    if !host_allowed(&headers, &state.config.allowed_hosts) {
        return reject(
            &log,
            StatusCode::FORBIDDEN,
            RejectReason::BadHost,
            "host not allowed",
        );
    }

    if let Err(err) = validate_token(
        proxy_token(&query, &headers),
        &query.remote,
        state.config.auth_mode,
        &state.config.secret_key,
        state.config.paseto_max_ttl,
        &log,
    ) {
        let reason = if err == StatusCode::INTERNAL_SERVER_ERROR {
            return Err::<Body, StatusCode>(err).into_response();
        } else {
            RejectReason::Auth
        };
        return reject(&log, err, reason, "unauthorized");
    }

    let remote = match dest::parse_remote(&query.remote) {
        Ok(r) => r,
        Err(e) => {
            return reject(&log, dest_status(&e), RejectReason::from(e), dest_message(&e));
        }
    };

    if let Err(e) = dest::check_policy(&remote, &state.config.dest) {
        return reject(&log, dest_status(&e), RejectReason::from(e), dest_message(&e));
    }

    let dest_key = remote.dest_key();
    if let Err(e) = state.limits.record_attempt(client, &dest_key) {
        return reject(&log, limit_status(&e), RejectReason::from(e), limit_message(&e));
    }

    let addrs = match dest::resolve_filtered(
        &remote,
        &state.config.dest,
        state.config.dns_timeout,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            return reject(&log, dest_status(&e), RejectReason::from(e), dest_message(&e));
        }
    };

    // Dial before taking a live slot so a black-holed dest cannot pin
    // a connection lease for the full connect timeout.
    let tcp = match dest::connect_addrs(&addrs, state.config.tcp_connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            return reject(&log, dest_status(&e), RejectReason::from(e), dest_message(&e));
        }
    };

    let lease = match state.limits.acquire(client, &dest_key) {
        Ok(l) => l,
        Err(e) => {
            return reject(&log, limit_status(&e), RejectReason::from(e), limit_message(&e));
        }
    };

    debug!(log, "Incoming WS connection");
    let fail_log = log.clone();
    let upgrade_log = log.clone();
    let config = Arc::clone(&state.config);
    let limits = Arc::clone(&state.limits);
    let mut ws = ws
        .max_message_size(state.config.ws_max_message_bytes)
        .max_frame_size(state.config.ws_max_frame_bytes);
    if let Some(proto) = offered_auth_protocol(&headers) {
        ws = ws.protocols([proto]);
    }
    ws.on_failed_upgrade(move |error: axum::Error| {
        METRICS.inc_ws_error(metrics::Error::Handshake);
        error!(fail_log, "Failed to upgrade WebSocket connection"; "error" => error.to_string());
    })
    .on_upgrade(move |socket| async move {
        Connection::new(
            remote,
            client,
            tcp,
            lease,
            limits,
            upgrade_log,
            config,
        )
        .run(socket)
        .await;
    })
}

#[derive(Deserialize)]
struct MetricsQuery {
    token: Option<String>,
}

#[debug_handler]
async fn metrics_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<MetricsQuery>,
) -> impl IntoResponse {
    if let Some(metrics_auth_key) = state.config.metrics_auth_key.as_ref() {
        let provided = bearer_token(&headers).or(query.token.as_deref());
        let ok = provided
            .map(|p| token_eq(p.as_bytes(), metrics_auth_key.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }

    info!(state.log, "Serving metrics");
    (StatusCode::OK, METRICS.encode()).into_response()
}

fn proxy_router(state: Arc<ServerState>) -> Router {
    Router::new().route("/proxy", get(proxy_handler).with_state(state))
}

fn metrics_router(state: Arc<ServerState>) -> Router {
    Router::new().route("/metrics", get(metrics_handler).with_state(state))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

pub async fn run_proxy(listener: TcpListener, config: Config) -> Result<(), Error> {
    let limits = Arc::new(LimitState::new(config.limits.clone()));
    let metrics_bind = config.metrics_bind.clone();
    let state = Arc::new(ServerState {
        log: DEFAULT_LOGGER.get().unwrap().clone(),
        config: Arc::new(config),
        limits,
    });

    if let Some(addr) = metrics_bind.clone() {
        let metrics_state = Arc::clone(&state);
        let log = state.log.clone();
        tokio::spawn(async move {
            match TcpListener::bind(&addr).await {
                Ok(mlistener) => {
                    info!(log, "Metrics listening"; "addr" => addr.as_str());
                    let app = metrics_router(metrics_state);
                    if let Err(e) = axum::serve(mlistener, app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await
                    {
                        error!(log, "Metrics server exited"; "error" => e.to_string());
                    }
                }
                Err(e) => {
                    error!(log, "Failed to bind metrics listener"; "addr" => addr.as_str(), "error" => e.to_string());
                }
            }
        });
    }

    let mut app = proxy_router(Arc::clone(&state));
    if metrics_bind.is_none() {
        app = app.merge(metrics_router(state));
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::http::HeaderMap;
    use futures_util::{SinkExt, StreamExt};
    use rusty_paseto::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_websockets::client::Builder;
    use tokio_websockets::{upgrade, Message};

    use crate::config::{AuthMode, Config};
    use crate::init_logging;
    use crate::limits::LimitsConfig;

    use super::{
        bearer_token, client_ip, host_allowed, origin_allowed, protocol_token, run_proxy, token_eq,
    };

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
        let mut config = Config::for_tests();
        config.secret_key = secret_key;
        create_servers_with_config(config).await
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

    fn upgrade_status(err: tokio_websockets::Error) -> u16 {
        match err {
            tokio_websockets::Error::Upgrade(upgrade::Error::DidNotSwitchProtocols(code)) => {
                code
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn client_ip_prefers_cf_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let loopback = crate::config::Cidr::parse("127.0.0.1/32").unwrap();
        assert_eq!(
            client_ip(&headers, peer, true, &[loopback]).to_string(),
            "203.0.113.9"
        );
        assert_eq!(
            client_ip(&headers, peer, true, &[]).to_string(),
            "127.0.0.1"
        );
        assert_eq!(
            client_ip(&headers, peer, false, &[loopback]).to_string(),
            "127.0.0.1"
        );
        let other = crate::config::Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            client_ip(&headers, peer, true, &[other]).to_string(),
            "127.0.0.1"
        );
    }

    #[test]
    fn token_eq_is_length_aware() {
        assert!(token_eq(b"abc", b"abc"));
        assert!(!token_eq(b"abc", b"abd"));
        assert!(!token_eq(b"abc", b"ab"));
        assert!(!token_eq(b"abc", b"abcd"));
    }

    #[test]
    fn bearer_token_parses_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer s3cret".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("s3cret"));
        headers.insert("authorization", "bearer  also".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("also"));
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn protocol_token_accepts_bearer_and_paseto() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-websocket-protocol",
            "bearer.v4.local.abc".parse().unwrap(),
        );
        assert_eq!(protocol_token(&headers), Some("v4.local.abc"));
        headers.insert("sec-websocket-protocol", "v4.local.xyz".parse().unwrap());
        assert_eq!(protocol_token(&headers), Some("v4.local.xyz"));
        headers.insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        assert_eq!(protocol_token(&headers), None);
    }

    #[test]
    fn origin_allowlist_rejects_foreign_browser() {
        use std::collections::HashSet;
        let allowed: HashSet<String> = ["https://app.mailiner.net".into()].into();
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://evil.example".parse().unwrap());
        assert!(!origin_allowed(&headers, &allowed));
        headers.insert("origin", "https://app.mailiner.net".parse().unwrap());
        assert!(origin_allowed(&headers, &allowed));
        // Native client: no Origin.
        assert!(origin_allowed(&HeaderMap::new(), &allowed));
        let any: HashSet<String> = ["*".into()].into();
        headers.insert("origin", "https://evil.example".parse().unwrap());
        assert!(origin_allowed(&headers, &any));
    }

    #[test]
    fn host_allowlist_matches_with_or_without_port() {
        use std::collections::HashSet;
        let allowed: HashSet<String> = ["proxy.example.com".into()].into();
        let mut headers = HeaderMap::new();
        headers.insert("host", "proxy.example.com:9400".parse().unwrap());
        assert!(host_allowed(&headers, &allowed));
        headers.insert("host", "evil.example".parse().unwrap());
        assert!(!host_allowed(&headers, &allowed));
        assert!(!host_allowed(&HeaderMap::new(), &allowed));
        assert!(host_allowed(&HeaderMap::new(), &HashSet::new()));
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

        assert_eq!(upgrade_status(err), 400);
    }

    #[tokio::test]
    async fn test_missing_token_returns_unauthorized() {
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

        assert_eq!(upgrade_status(err), 401);
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

        assert_eq!(upgrade_status(err), 500);
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

        assert_eq!(upgrade_status(err), 401);
    }

    #[test]
    fn far_future_exp_is_rejected() {
        init_logging(slog::Level::Error);
        let secret = Key::<32>::try_new_random().expect("key");
        let key = PasetoSymmetricKey::<V4, Local>::from(secret.clone());
        let far = chrono::Utc::now() + chrono::Duration::days(3650);
        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(ExpirationClaim::try_from(far.to_rfc3339()).unwrap())
            .set_claim(CustomClaim::try_from(("remote", "imap.example.com:993")).unwrap())
            .build(&key)
            .unwrap();
        let log = crate::DEFAULT_LOGGER.get().unwrap().clone();
        let err = super::validate_token(
            &token,
            "imap.example.com:993",
            AuthMode::Paseto,
            &Some(PasetoSymmetricKey::<V4, Local>::from(secret)),
            Duration::from_secs(3600),
            &log,
        );
        assert_eq!(err, Err(axum::http::StatusCode::UNAUTHORIZED));
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
        let (proxy_port, server) = create_servers_with_config(Config {
            ws_idle_timeout: Duration::from_millis(100),
            ..Config::for_tests()
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

    #[tokio::test]
    async fn test_public_auth_allows_missing_token() {
        let (proxy_port, server) = create_servers_with_config(Config {
            auth_mode: AuthMode::Public,
            ..Config::for_tests()
        })
        .await;

        let (mut client, _) = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect("public mode should not require a token");

        let msg = Message::binary(b"ok".as_slice());
        client.send(msg.clone()).await.unwrap();
        let resp = client.next().await.unwrap().unwrap();
        assert_eq!(
            bytes::Bytes::from(resp.into_payload()),
            bytes::Bytes::from(msg.into_payload())
        );
    }

    #[tokio::test]
    async fn test_rejects_disallowed_port() {
        let (proxy_port, server) = create_servers_with_config(Config {
            dest: crate::dest::DestPolicy::default(),
            ..Config::for_tests()
        })
        .await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("random echo port must be rejected");
        assert_eq!(upgrade_status(err), 403);
    }

    #[tokio::test]
    async fn test_rejects_private_destination() {
        let mut dest = crate::dest::DestPolicy::unrestricted();
        dest.allow_private_destinations = false;
        dest.allow_ip_literals = true;
        let (proxy_port, server) = create_servers_with_config(Config {
            dest,
            ..Config::for_tests()
        })
        .await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("loopback must be rejected");
        assert_eq!(upgrade_status(err), 403);
    }

    #[tokio::test]
    async fn test_rejects_ip_literal() {
        let mut dest = crate::dest::DestPolicy::unrestricted();
        dest.allow_ip_literals = false;
        let (proxy_port, server) = create_servers_with_config(Config {
            dest,
            ..Config::for_tests()
        })
        .await;

        let err = Builder::from_uri(
            format!(
                "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
                proxy_port, server.port
            )
            .parse()
            .unwrap(),
        )
        .connect()
        .await
        .expect_err("IP literal must be rejected");
        assert_eq!(upgrade_status(err), 403);
    }

    #[tokio::test]
    async fn test_per_ip_connection_limit() {
        let (proxy_port, server) = create_servers_with_config(Config {
            limits: LimitsConfig {
                max_conns_per_ip: 1,
                ..LimitsConfig::unlimited()
            },
            ..Config::for_tests()
        })
        .await;

        let uri = format!(
            "ws://127.0.0.1:{}/proxy?remote=127.0.0.1:{}&token=testtoken",
            proxy_port, server.port
        );
        let (_first, _) = Builder::from_uri(uri.parse().unwrap())
            .connect()
            .await
            .expect("first connection should succeed");

        let err = Builder::from_uri(uri.parse().unwrap())
            .connect()
            .await
            .expect_err("second connection should be limited");
        assert_eq!(upgrade_status(err), 429);
    }

    #[tokio::test]
    async fn test_byte_cap_closes_session() {
        let (proxy_port, server) = create_servers_with_config(Config {
            max_bytes_per_connection: 8,
            ..Config::for_tests()
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
        .unwrap();

        client
            .send(Message::binary("xxxxxxxxxxxxxxxx"))
            .await
            .expect("send should be accepted by the WS layer");

        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client.next().await {
                    None => return true,
                    Some(Ok(m)) if m.is_close() => return true,
                    Some(Err(_)) => return true,
                    Some(Ok(_)) => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for byte-cap close");
        assert!(closed);
    }

    #[tokio::test]
    async fn test_max_lifetime_closes_session() {
        let (proxy_port, server) = create_servers_with_config(Config {
            max_lifetime: Duration::from_millis(80),
            ..Config::for_tests()
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
        .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;

        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client.next().await {
                    None => return true,
                    Some(Ok(m)) if m.is_close() => return true,
                    Some(Err(_)) => return true,
                    Some(Ok(_)) => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for lifetime close");
        assert!(closed);
    }
}
