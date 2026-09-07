#!/usr/bin/env bash
# Build ws-tcp-proxy and deploy it to Scaleway Serverless Containers.
#
# Prerequisites:
#   - docker
#   - scw (https://github.com/scaleway/scaleway-cli) configured via `scw init`
#   - python3 (for JSON parsing)
#
# Optional repo-root file `.env.scaleway` (gitignored) is sourced first.
# Required secrets if MAILINER_AUTH=paseto (the default):
#   MAILINER_PASETO_SECRET   exactly 32 bytes
#   METRICS_AUTH_TOKEN       any non-empty string
#
# Usage:
#   ./scripts/deploy-scaleway.sh
#   ./scripts/deploy-scaleway.sh --skip-build      # image already in the registry
#   ./scripts/deploy-scaleway.sh --registry-only   # create the registry namespace and exit
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env.scaleway" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env.scaleway"
  set +a
fi

SKIP_BUILD=0
REGISTRY_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --registry-only) REGISTRY_ONLY=1 ;;
    -h|--help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

REGION="${SCW_DEFAULT_REGION:-${SCALEWAY_REGION:-fr-par}}"
REGISTRY_NS="${SCALEWAY_REGISTRY_NS:-mailiner-ws-tcp-proxy}"
CONTAINER_NS="${SCALEWAY_CONTAINER_NS:-mailiner-dev}"
CONTAINER_NAME="${SCALEWAY_CONTAINER_NAME:-ws-tcp-proxy}"
IMAGE_NAME="${SCALEWAY_IMAGE_NAME:-ws-tcp-proxy}"
IMAGE_TAG="${SCALEWAY_IMAGE_TAG:-latest}"
LISTEN_PORT="${SCALEWAY_PORT:-9400}"
MIN_SCALE="${SCALEWAY_MIN_SCALE:-1}"
MAX_SCALE="${SCALEWAY_MAX_SCALE:-1}"
# Platform max request duration is 60 minutes; close the WS a bit earlier.
MAX_LIFETIME_SECS="${MAILINER_MAX_LIFETIME_SECS:-3540}"
AUTH_MODE="${MAILINER_AUTH:-paseto}"
ALLOWED_ORIGINS="${MAILINER_ALLOWED_ORIGINS:-}"
ALLOWED_HOSTS="${MAILINER_ALLOWED_HOSTS:-}"
# Serverless frontends sit on RFC1918 / CGNAT / link-local. Trust those so
# per-IP limits use X-Forwarded-For instead of the mesh hop.
TRUSTED_PROXIES="${MAILINER_TRUSTED_PROXIES:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fd00::/8}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need python3
if [[ "$SKIP_BUILD" -eq 0 && "$REGISTRY_ONLY" -eq 0 ]]; then
  need docker
fi
if ! command -v scw >/dev/null 2>&1; then
  echo "scw CLI is not installed. Install it, then run \`scw init\`:" >&2
  echo "  curl -s https://raw.githubusercontent.com/scaleway/scaleway-cli/master/scripts/get.sh | sh" >&2
  exit 1
fi

json_get() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

json_first_id_by_name() {
  local want="$1"
  python3 -c '
import json, sys
want = sys.argv[1]
data = json.load(sys.stdin)
if isinstance(data, dict):
    for key in ("namespaces", "containers", "images"):
        if key in data:
            data = data[key]
            break
    else:
        data = [data]
for item in data:
    if item.get("name") == want:
        print(item.get("id", ""))
        break
' "$want"
}

wait_field() {
  local getter="$1"
  local field="$2"
  local expect="$3"
  local i
  for i in $(seq 1 60); do
    local got
    got="$($getter | json_get "$field" 2>/dev/null || true)"
    if [[ "$got" == "$expect" ]]; then
      return 0
    fi
    if [[ "$got" == "error" || "$got" == "locked" ]]; then
      echo "resource entered status=$got" >&2
      $getter >&2 || true
      return 1
    fi
    sleep 5
  done
  echo "timed out waiting for $field=$expect" >&2
  $getter >&2 || true
  return 1
}

REGISTRY_ENDPOINT="rg.${REGION}.scw.cloud/${REGISTRY_NS}"
IMAGE_REF="${REGISTRY_ENDPOINT}/${IMAGE_NAME}:${IMAGE_TAG}"

echo "==> ensuring Container Registry namespace ${REGISTRY_NS} (${REGION})"
REG_ID="$(scw registry namespace list region="$REGION" name="$REGISTRY_NS" -o json | json_first_id_by_name "$REGISTRY_NS")"
if [[ -z "$REG_ID" ]]; then
  REG_ID="$(scw registry namespace create region="$REGION" name="$REGISTRY_NS" is-public=false -o json | json_get id)"
fi
wait_field "scw registry namespace get region=${REGION} ${REG_ID} -o json" status ready

if [[ "$REGISTRY_ONLY" -eq 1 ]]; then
  echo "registry ready: ${REGISTRY_ENDPOINT}"
  exit 0
fi

if [[ "$AUTH_MODE" == "paseto" ]]; then
  if [[ -z "${MAILINER_PASETO_SECRET:-}" ]]; then
    echo "MAILINER_PASETO_SECRET is required (exactly 32 bytes) when MAILINER_AUTH=paseto" >&2
    echo "Generate one with:  python3 -c 'import secrets; print(secrets.token_hex(16))'" >&2
    exit 1
  fi
  if [[ "${#MAILINER_PASETO_SECRET}" -ne 32 ]]; then
    echo "MAILINER_PASETO_SECRET must be exactly 32 bytes (got ${#MAILINER_PASETO_SECRET})" >&2
    exit 1
  fi
fi
if [[ -z "${METRICS_AUTH_TOKEN:-}" ]]; then
  echo "METRICS_AUTH_TOKEN is required in release builds" >&2
  exit 1
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> docker login ${REGISTRY_ENDPOINT}"
  if [[ -z "${SCW_SECRET_KEY:-}" ]]; then
    SCW_SECRET_KEY="$(scw config get secret-key)"
  fi
  printf '%s\n' "$SCW_SECRET_KEY" | docker login "rg.${REGION}.scw.cloud" -u nologin --password-stdin

  echo "==> building and pushing ${IMAGE_REF}"
  docker build --platform linux/amd64 --push -t "$IMAGE_REF" .
fi

echo "==> ensuring Serverless Containers namespace ${CONTAINER_NS}"
NS_ID="$(scw container namespace list region="$REGION" name="$CONTAINER_NS" -o json | json_first_id_by_name "$CONTAINER_NS")"
if [[ -z "$NS_ID" ]]; then
  NS_ID="$(scw container namespace create region="$REGION" name="$CONTAINER_NS" -o json | json_get id)"
fi
wait_field "scw container namespace get region=${REGION} ${NS_ID} -o json" status ready

# scw uses dotted keys for maps. Empty values are omitted.
ENV_ARGS=(
  "environment-variables.MAILINER_AUTH=${AUTH_MODE}"
  "environment-variables.MAILINER_TRUST_FORWARDED_CLIENT_IP=1"
  "environment-variables.MAILINER_TRUSTED_PROXIES=${TRUSTED_PROXIES}"
  "environment-variables.MAILINER_MAX_LIFETIME_SECS=${MAX_LIFETIME_SECS}"
  "environment-variables.LOG_LEVEL=${LOG_LEVEL:-info}"
)
if [[ -n "$ALLOWED_ORIGINS" ]]; then
  ENV_ARGS+=("environment-variables.MAILINER_ALLOWED_ORIGINS=${ALLOWED_ORIGINS}")
fi
if [[ -n "$ALLOWED_HOSTS" ]]; then
  ENV_ARGS+=("environment-variables.MAILINER_ALLOWED_HOSTS=${ALLOWED_HOSTS}")
fi

SECRET_ARGS=(
  "secret-environment-variables.METRICS_AUTH_TOKEN=${METRICS_AUTH_TOKEN}"
)
if [[ -n "${MAILINER_PASETO_SECRET:-}" ]]; then
  SECRET_ARGS+=("secret-environment-variables.MAILINER_PASETO_SECRET=${MAILINER_PASETO_SECRET}")
fi

COMMON_ARGS=(
  "image=${IMAGE_REF}"
  "port=${LISTEN_PORT}"
  "protocol=http1"
  "privacy=public"
  "sandbox=v2"
  "min-scale=${MIN_SCALE}"
  "max-scale=${MAX_SCALE}"
  "timeout=3600s"
  "liveness-probe.http.path=/health"
  "liveness-probe.interval=10s"
  "liveness-probe.timeout=1s"
  "liveness-probe.failure-threshold=3"
  "description=WebSocket to TCP mail proxy"
)

echo "==> creating or updating container ${CONTAINER_NAME}"
CTR_ID="$(scw container container list region="$REGION" name="$CONTAINER_NAME" namespace-id="$NS_ID" -o json | json_first_id_by_name "$CONTAINER_NAME")"
if [[ -z "$CTR_ID" ]]; then
  CTR_ID="$(
    scw container container create region="$REGION" namespace-id="$NS_ID" name="$CONTAINER_NAME" \
      "${COMMON_ARGS[@]}" "${ENV_ARGS[@]}" "${SECRET_ARGS[@]}" \
      https-connections-only=true \
      --wait -o json | json_get id
  )"
else
  scw container container update region="$REGION" "$CTR_ID" \
    "${COMMON_ARGS[@]}" "${ENV_ARGS[@]}" "${SECRET_ARGS[@]}" \
    https-connection-only=true \
    --wait >/dev/null
fi

wait_field "scw container container get region=${REGION} ${CTR_ID} -o json" status ready
ENDPOINT="$(scw container container get region="$REGION" "$CTR_ID" -o json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("public_endpoint") or ("https://"+d.get("domain_name","")))')"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "endpoint=${ENDPOINT}" >> "$GITHUB_OUTPUT"
fi

cat <<EOF

Deployed ${CONTAINER_NAME}
  image:    ${IMAGE_REF}
  endpoint: ${ENDPOINT}
  health:   ${ENDPOINT}/health
  proxy:    ${ENDPOINT/https:/wss:}/proxy?remote=<host>:<port>

Limits of Scaleway Serverless Containers:
  - WebSocket lifetime is capped at 60 minutes (MAILINER_MAX_LIFETIME_SECS=${MAX_LIFETIME_SECS})
  - outbound TCP 25 and 465 are blocked (SMTPS on 465 will fail; use 587)
  - at most 80 concurrent connections per instance (max-scale=${MAX_SCALE})
  - rate limits are in-process; keep max-scale=1 or accept per-replica counters
EOF
