FROM rust:1.79 AS builder

WORKDIR /usr/src/ws-tcp-proxy
COPY . .

RUN cargo install --path .


FROM debian:bookworm-slim

COPY --from=builder /usr/local/cargo/bin/ws-tcp-proxy /usr/local/bin/ws-tcp-proxy

ENV MAILINER_PASETO_SECRET=
ENV PORT=9400

CMD [ "sh", "-c", "MAILINER_PASETO_SECRET=${MAILINER_PASETO_SECRET} ws-tcp-proxy --port ${PORT}" ]