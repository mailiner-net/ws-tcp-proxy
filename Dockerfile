FROM rust:1-bookworm AS builder

WORKDIR /usr/src/ws-tcp-proxy
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo install --path . --locked


FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 ws-tcp-proxy

COPY --from=builder /usr/local/cargo/bin/ws-tcp-proxy /usr/local/bin/ws-tcp-proxy

USER 65532:65532

ENV PORT=9400
ENV LOG_LEVEL=info
EXPOSE 9400

CMD ["ws-tcp-proxy"]