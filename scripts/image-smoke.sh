#!/usr/bin/env bash
# Copyright 2026 3eAI Labs Ltd
# SPDX-License-Identifier: AGPL-3.0-only
#
# image-smoke.sh — start a built image next to a NATS server and check that it comes up.
#
#   1. GET /health/ready on the admin port answers 200 (ready means connected to NATS)
#   2. the image's user is not root
#   3. the gateway's licence texts and the third-party ones are in the image
#
# The image is distroless: it has no shell, wget or id, so every check runs from outside the
# gateway container. The gateway shares the NATS container's network namespace, so its default
# NATS_URL (nats://localhost:4222) reaches NATS without an override; a curl container joins the
# same namespace to reach the admin port (ADMIN_PORT, default 9090).
#
# Usage:  scripts/image-smoke.sh [image]   (default sbi-ha-gateway:dev, as `make image` tags it)

set -euo pipefail

IMAGE="${1:-sbi-ha-gateway:dev}"
NATS_IMAGE="nats:2.10-alpine"
CURL_IMAGE="curlimages/curl:8.11.1"
READY_TIMEOUT=60   # seconds

NATS="sbg-smoke-nats-$$"
GW="sbg-smoke-gw-$$"
LIC="$(mktemp -d)"

cleanup() { docker rm -f "$GW" "$NATS" >/dev/null 2>&1 || true; rm -rf "$LIC"; }
trap cleanup EXIT

fail() {
  echo "image-smoke: FAIL: $*" >&2
  echo "--- gateway logs (last 40 lines) ---" >&2
  docker logs --tail 40 "$GW" >&2 2>&1 || true
  exit 1
}

docker run -d --name "$NATS" "$NATS_IMAGE" >/dev/null
# The gateway is secure by default; the smoke test runs it in cleartext without OAuth, each
# opt-out explicit.
docker run -d --name "$GW" --network "container:$NATS" \
  -e ALLOW_PLAINTEXT_SBI=true -e MTLS_CLIENT_AUTH_MODE=off -e OAUTH_DISABLED=true \
  -e ADMIN_TLS=false -e ADMIN_AUTH_DISABLED=true \
  "$IMAGE" >/dev/null

code=000
for ((i = 0; i < READY_TIMEOUT; i += 2)); do
  [[ "$(docker inspect "$GW" --format '{{.State.Running}}')" == true ]] || fail "container exited"
  code="$(docker run --rm --network "container:$NATS" "$CURL_IMAGE" \
    -s -o /dev/null -w '%{http_code}' http://localhost:9090/health/ready || true)"
  [[ "$code" == 200 ]] && break
  sleep 2
done
[[ "$code" == 200 ]] || fail "/health/ready is HTTP $code after ${READY_TIMEOUT}s"

user="$(docker inspect "$GW" --format '{{.Config.User}}')"
case "$user" in
  "" | root | 0 | root:* | 0:*) fail "image user is '${user:-<unset>}' (root)" ;;
esac

docker cp "$GW:/usr/share/licenses/sbi-ha-gateway/." "$LIC" >/dev/null \
  || fail "/usr/share/licenses/sbi-ha-gateway missing"
grep -q 'GNU AFFERO GENERAL PUBLIC LICENSE' "$LIC/LICENSE" || fail "LICENSE is not the AGPL text"
[[ -s "$LIC/NOTICE" ]] || fail "NOTICE missing"
n="$(find "$LIC/third_party/go" -type f -name 'LICENSE*' | wc -l)"
(( n > 0 )) || fail "no third-party licence texts under third_party/go"

echo "image-smoke: OK ($IMAGE: ready, user $user, licence texts present: $n third-party)"
