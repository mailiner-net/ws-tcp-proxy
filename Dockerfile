FROM rust:1.79 AS builder

WORKDIR /usr/src/ws-tcp-proxy
COPY . .

RUN cargo install --path .


FROM debian:bookworm-slim

COPY --from=builder /usr/local/cargo/bin/ws-tcp-proxy /usr/local/bin/ws-tcp-proxy

EXPOSE 9400/tcp

ENV MAILINER_PASETO_SECRET=

CMD [ "ws-tcp-proxy" ]