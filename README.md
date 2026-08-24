# WebSocket <-> TCP Proxy

This project is a simple proxy that forwards WebSocket connections to a TCP
server specified in the request URL.

## How to Use

Establish a WebSocket connection to the proxy endpoint:

```
ws://<proxy-host>[:<proxy-port>]/proxy?remote=<host>:<port>&token=<token>
```

* `<proxy-host>`: Hostname or IP of this proxy (e.g. `localhost`, or
  `ws-proxy.dev.mailiner.net`).
* `<proxy-port>`: Listen port (default `9400`). Omit on deployed instances
  that terminate TLS on 443.
* `<host>:<port>`: Upstream mail server. **Hostname + mail port only** by
  default (`143`, `993`, `465`, `587`). Raw IP literals, private/loopback
  addresses, and other ports (including `25`) are rejected. See
  [Anti-abuse](#anti-abuse).
* `<token>`: Required when `MAILINER_AUTH=paseto` (the default). Ignored
  when `MAILINER_AUTH=public`. See [Authentication](#authentication).

Example against a public IMAP host:

```
ws://localhost:9400/proxy?remote=imap.gmail.com:993&token=testtoken
```

`remote=127.0.0.1:993` fails under the default policy. For a loopback
upstream in local debug, set `MAILINER_ALLOW_IP_LITERALS=1` and
`MAILINER_ALLOW_PRIVATE_DESTS=1`.

## Authentication

`MAILINER_AUTH` selects how the `/proxy` endpoint authorizes clients:

* `paseto` (default) — require a [Paseto](https://paseto.io) v4.local token whose
  `remote` claim matches the query string and which has a non-empty `exp`.
* `public` — no token. Destination policy and rate limits are the only gate.
  Use this for a hosted public proxy; do not bake a shared token into the
  Mailiner WASM app.

In release builds with `MAILINER_AUTH=paseto` the following MUST be set:

* `MAILINER_PASETO_SECRET` — shared secret used to sign tokens (32 ASCII characters).

In debug builds the secret is optional and the literal value `testtoken` bypasses
Paseto validation.

## Anti-abuse

The proxy is an untrusted byte pipe. The browser is not an identity. Enforcement
is entirely server-side.

**Destination policy**

* Ports `143`, `993`, `465`, `587` only (not `25`).
* Hostnames only by default — raw IP literals are rejected (including
  dword / hex / octal / short IPv4 forms that `getaddrinfo` would accept).
  Hostnames must be DNS LDH labels, at most 253 bytes.
* After DNS, only globally routable unicast addresses are dialed (loopback,
  RFC1918, link-local, CGNAT, ULA, metadata, Teredo, NAT64/6to4 that embed a
  non-global IPv4, etc. are rejected).
* The TCP connect uses the filtered sockaddr; the name is not resolved again
  (DNS rebinding).

**Limits** (defaults in parentheses; `0` disables a numeric cap)

* Global connections (`5000`)
* Connections per client IP (`16`; IPv6 keyed by `/64`, IPv4 by `/32`)
* Connections per destination host:port (`200`)
* New connects per client IP per minute (`10`)
* Distinct destinations per client IP per minute (`10`)
* Global new connects per second (`20`)
* Bytes per connection (`250 MiB`)
* Bytes per client IP per hour (`1 GiB`)
* Max session lifetime (`86400` seconds)

**Protocol probes** on well-known mail ports (does not decrypt IMAP/SMTP TLS):

* `993` / `465` — first client bytes must be a TLS ClientHello; SNI must match
  the `remote` hostname.
* `143` — server greeting must look like IMAP (`* …`).
* `587` — server greeting must start with `220`.

**Browser origin / Host**

Set `MAILINER_ALLOWED_ORIGINS` to the Mailiner web app origin(s) so a
random website cannot open a WebSocket through a visitor's browser.
Native clients that omit `Origin` are still accepted. `*` disables the
check. `MAILINER_ALLOWED_HOSTS` pins the HTTP `Host` header so the
service is not usable via a raw IP or unexpected name.

When the process sits behind Cloudflare (or another reverse proxy), set
`MAILINER_TRUST_FORWARDED_CLIENT_IP=1` **and**
`MAILINER_TRUSTED_PROXIES` to that proxy's CIDRs so per-IP limits use
`CF-Connecting-IP` (falling back to `X-Real-IP`). Forwarded headers are
ignored unless the TCP peer is in that list — do not publish the origin
and leave the list empty.

Rejected attempts increment `rejects_total{reason=...}` (`bad_port`,
`private_ip`, `ip_literal`, `connect_rate`, `global_full`, `proto`, `byte_cap`,
`lifetime`, …).

### Environment

| Variable | Default |
|---|---|
| `MAILINER_AUTH` | `paseto` |
| `MAILINER_PASETO_SECRET` | required in release + paseto |
| `MAILINER_ALLOWED_PORTS` | `143,993,465,587` (`any` / `*` = unrestricted) |
| `MAILINER_ALLOW_PRIVATE_DESTS` | `0` |
| `MAILINER_ALLOW_IP_LITERALS` | `0` |
| `MAILINER_MAX_GLOBAL_CONNECTIONS` | `5000` |
| `MAILINER_MAX_CONNS_PER_IP` | `16` |
| `MAILINER_MAX_CONNS_PER_DEST` | `200` |
| `MAILINER_CONNECTS_PER_IP_PER_MIN` | `10` |
| `MAILINER_DISTINCT_DESTS_PER_IP_PER_MIN` | `10` |
| `MAILINER_GLOBAL_CONNECTS_PER_SEC` | `20` |
| `MAILINER_MAX_BYTES_PER_CONNECTION` | `262144000` |
| `MAILINER_MAX_BYTES_PER_IP_PER_HOUR` | `1073741824` |
| `MAILINER_LIMIT_IPV4_PREFIX` | `32` (set `24` on the public internet if clients share CGNAT) |
| `MAILINER_LIMIT_IPV6_PREFIX` | `64` |
| `MAILINER_MAX_TRACKED_IPS` | `50000` (`0` = no cap) |
| `MAILINER_MAX_LIFETIME_SECS` | `86400` |
| `MAILINER_DNS_TIMEOUT_SECS` | `5` |
| `MAILINER_WS_MAX_MESSAGE_BYTES` | `1048576` |
| `MAILINER_WS_MAX_FRAME_BYTES` | `262144` |
| `MAILINER_TRUST_FORWARDED_CLIENT_IP` | `0` |
| `MAILINER_TRUSTED_PROXIES` | empty (comma-separated CIDRs; required for forwarded-IP trust) |
| `MAILINER_REQUIRE_PROTOCOL_PROBE` | `1` |
| `MAILINER_ALLOWED_ORIGINS` | empty (no check). Comma-separated, e.g. `https://app.mailiner.net` |
| `MAILINER_ALLOWED_HOSTS` | empty (no check) |
| `METRICS_AUTH_TOKEN` | required in release |
| `MAILINER_UNSAFE` | `0` — release builds refuse `any` ports, private dests, IP literals, disabled probes/caps, public auth without origins, and forwarded-IP trust without CIDRs |
