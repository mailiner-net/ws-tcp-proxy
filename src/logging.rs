use std::str::FromStr;

use slog::{Drain, Logger};

use once_cell::sync::OnceCell;

pub static DEFAULT_LOGGER: OnceCell<Logger> = OnceCell::new();

pub fn parse_log_level(val: &str) -> slog::Level {
    slog::Level::from_str(val).unwrap_or_else(|_| panic!("Invalid log level {}", val))
}

pub fn init_logging(level: slog::Level) {
    DEFAULT_LOGGER.get_or_init(|| {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let drain = slog::LevelFilter::new(drain, level).fuse();
        slog::Logger::root(drain, o!())
    });
}
