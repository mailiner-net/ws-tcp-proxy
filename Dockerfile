FROM rust:1.79 AS builder

WORKDIR /usr/src/ws-tcp-proxy
COPY . .

RUN cargo install --path .


FROM debian:bookworm-slim

COPY --from=builder /usr/local/cargo/bin/ws-tcp-proxy /usr/local/bin/ws-tcp-proxy

ENV PORT=9400

CMD [ "sh", "-c", "ws-tcp-proxy --port ${PORT}" ]