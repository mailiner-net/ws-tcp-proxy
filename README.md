# WebSocket <-> TCP Proxy

This project is a simple proxy that forwards WebSocket connections to a TCP
server specified in the request URL.

## How to Use

Establish a WebSocket connection to the proxy endpoint:

```
ws://<proxy-host>[:<proxy-port>]/proxy?token=<token>&remote=<tcp-server>:<tcp-port>
```

* `<proxy-host>`: The hostname or IP address where the proxy is running (e.g. localhost
  when running locally, otherwise something like `ws-proxy.dev.mailiner.net`.
* `<proxy-port>`: Optional port where the proxy is listening for incoming WebSocket
  connections (default is 9400). Usually not necessary to specify when connecting to
  deployed instances.
* `<token>`: A [Paseto](https://paseto.io) token that authorizes the connection. The
  token must be signed with a shared secret that's known to the proxy. When the proxy
  is running locally (or in test environment) you can pass a special value `testtoken`
  to bypass the token check.
* `<tcp-server>`: The hostname or IP address of the TCP server to forward the
  WebSocket connection to.
* `<tcp-port>`: The port where the TCP server is listening for incoming connections
  (unlike the `<proxy-port>`,  it is mandatory to specify the TCP port.

## Paseto Token

In release build, the following environemnt variable MUST be set:

* `MAILINER_PASETO_SECRET` - The shared secret used to sign the Paseto token (should
  be 32 ASCII characters long).

In non-release build, the environment variable will still work but is optional. One
can use `testtoken` as the token value to bypass the token check in non-release builds.

Check [Paseto](https://paseto.io) for more information about the Paseto tokens.
