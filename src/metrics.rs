use lazy_static::lazy_static;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::time::{Instant, SystemTime};

lazy_static! {
    pub static ref METRICS: Metrics = Metrics::new();
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Error {
    Handshake,
    Read,
    Send,
    Shutdown,
    Timeout
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabels {
    pub error: Error,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum RejectReason {
    Auth,
    InvalidRemote,
    BadPort,
    IpLiteral,
    PrivateIp,
    Dns,
    Connect,
    ConnectRate,
    GlobalConnectRate,
    DistinctDests,
    GlobalFull,
    PerIpFull,
    PerDestFull,
    Proto,
    ByteCap,
    Lifetime,
}

impl From<crate::dest::DestError> for RejectReason {
    fn from(e: crate::dest::DestError) -> Self {
        match e {
            crate::dest::DestError::InvalidRemote => RejectReason::InvalidRemote,
            crate::dest::DestError::BadPort => RejectReason::BadPort,
            crate::dest::DestError::IpLiteral => RejectReason::IpLiteral,
            crate::dest::DestError::PrivateIp => RejectReason::PrivateIp,
            crate::dest::DestError::Dns => RejectReason::Dns,
            crate::dest::DestError::Connect => RejectReason::Connect,
        }
    }
}

impl From<crate::limits::LimitError> for RejectReason {
    fn from(e: crate::limits::LimitError) -> Self {
        match e {
            crate::limits::LimitError::GlobalFull => RejectReason::GlobalFull,
            crate::limits::LimitError::PerIpFull => RejectReason::PerIpFull,
            crate::limits::LimitError::PerDestFull => RejectReason::PerDestFull,
            crate::limits::LimitError::ConnectRate => RejectReason::ConnectRate,
            crate::limits::LimitError::GlobalConnectRate => RejectReason::GlobalConnectRate,
            crate::limits::LimitError::DistinctDests => RejectReason::DistinctDests,
            crate::limits::LimitError::ByteCap => RejectReason::ByteCap,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RejectLabels {
    pub reason: RejectReason,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectionsLabels {
    pub remote: String,
}

pub struct Metrics {
    pub registry: Registry,

    pub active_connections: Gauge,

    pub ws_errors: Family<ErrorLabels, Counter>,
    pub tcp_errors: Family<ErrorLabels, Counter>,

    pub connection_duration: Histogram,

    pub connections: Family<ConnectionsLabels, Counter>,

    pub rejects: Family<RejectLabels, Counter>,

    process_start_time_seconds: Gauge
}

// bucket duration in seconds
static DURATION_BUCKETS: [f64; 12] = [
    1., 5., 10., 30., 60., 120., 300., 600., 1200., 1800., 2700., 3600.,
];

impl Metrics {
    pub fn new() -> Self {
        let mut metrics = Metrics {
            registry: <Registry>::default(),
            active_connections: Gauge::default(),
            ws_errors: Family::<ErrorLabels, Counter>::default(),
            tcp_errors: Family::<ErrorLabels, Counter>::default(),
            connection_duration: Histogram::new(DURATION_BUCKETS.into_iter()),
            connections: Family::<ConnectionsLabels, Counter>::default(),
            rejects: Family::<RejectLabels, Counter>::default(),

            process_start_time_seconds: Gauge::default(),
        };

        metrics.registry.register(
            "active_connections",
            "Number of currently active collections",
            metrics.active_connections.clone(),
        );
        metrics.registry.register(
            "ws_errors",
            "Number of errors that occurred in the WebSocket connection",
            metrics.ws_errors.clone(),
        );
        metrics.registry.register(
            "tcp_errors",
            "Number of errors that occurred in the TCP connection",
            metrics.tcp_errors.clone(),
        );
        metrics.registry.register(
            "connection_duration",
            "Histogram of connection durations",
            metrics.connection_duration.clone(),
        );
        metrics.registry.register(
            "connections",
            "Number of connections to remotes",
            metrics.connections.clone(),
        );
        metrics.registry.register(
            "rejects",
            "Number of rejected proxy attempts by reason",
            metrics.rejects.clone(),
        );
        metrics.registry.register(
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds",
            metrics.process_start_time_seconds.clone(),
        );

        // One of the Prometheus deafult "process" metrics, this one is required by the
        // Prometheus sidecar in GCP
        let now = SystemTime::now();
        let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        metrics.process_start_time_seconds.set(since_epoch.as_secs() as i64);

        metrics
    }

    pub fn inc_tcp_error(&self, error: Error) {
        self.tcp_errors.get_or_create(&ErrorLabels { error }).inc();
    }

    pub fn inc_tcp_timeout(&self, error: Error) {
        self.tcp_errors.get_or_create(&ErrorLabels { error }).inc();
    }

    pub fn inc_ws_error(&self, error: Error) {
        self.ws_errors.get_or_create(&ErrorLabels { error }).inc();
    }

    pub fn inc_reject(&self, reason: RejectReason) {
        self.rejects.get_or_create(&RejectLabels { reason }).inc();
    }

    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry).unwrap();
        buffer
    }
}

pub struct ScopeGauge {
    gauge: &'static Gauge,
}

impl ScopeGauge {
    pub fn new(gauge: &'static Gauge) -> Self {
        gauge.inc();
        ScopeGauge { gauge }
    }
}

impl Drop for ScopeGauge {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

pub struct ScopeDuration {
    histogram: &'static Histogram,
    start: Instant,
}

impl ScopeDuration {
    pub fn new(histogram: &'static Histogram) -> Self {
        ScopeDuration {
            histogram,
            start: Instant::now(),
        }
    }

    pub fn duration(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

impl Drop for ScopeDuration {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        self.histogram.observe(duration);
    }
}
