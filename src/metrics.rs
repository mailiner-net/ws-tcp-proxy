use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::time::Instant;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Error {
    Handshake,
    Read,
    Send,
    Shutdown
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabels {
    pub error: Error
}

pub struct Metrics {
    pub registry: Registry,

    pub active_connections: Gauge,

    pub ws_errors: Family<ErrorLabels, Counter>,
    pub tcp_errors: Family<ErrorLabels, Counter>,

    pub connection_duration: Histogram,
}

// bucket duration in seconds
static DURATION_BUCKETS: [f64; 12] = [1., 5., 10., 30., 60., 120., 300., 600., 1200., 1800., 2700., 3600.];

impl Metrics {
    pub fn new() -> Self {
        let mut metrics = Metrics {
            registry: <Registry>::default(),
            active_connections: Gauge::default(),
            ws_errors: Family::<ErrorLabels, Counter>::default(),
            tcp_errors: Family::<ErrorLabels, Counter>::default(),
            connection_duration: Histogram::new(DURATION_BUCKETS.into_iter())
        };

        metrics.registry.register("active_connections", "Number of currently active collections", metrics.active_connections.clone());
        metrics.registry.register("ws_errors", "Number of errors that occurred in the WebSocket connection", metrics.ws_errors.clone());
        metrics.registry.register("tcp_errors", "Number of errors that occurred in the TCP connection", metrics.tcp_errors.clone());
        metrics.registry.register("connection_duration", "Histogram of connection durations", metrics.connection_duration.clone());

        metrics
    }

    pub fn inc_tcp_error(&self, error: Error) {
        self.tcp_errors.get_or_create(&ErrorLabels { error }).inc();
    }

    pub fn inc_ws_error(&self, error: Error) {
        self.ws_errors.get_or_create(&ErrorLabels { error }).inc();
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
    start: Instant
}

impl ScopeDuration {
    pub fn new(histogram: &'static Histogram) -> Self {
        ScopeDuration { histogram, start: Instant::now() }
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