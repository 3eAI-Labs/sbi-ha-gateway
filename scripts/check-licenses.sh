#!/usr/bin/env bash
# Copyright 2026 3eAI Labs Ltd
# SPDX-License-Identifier: AGPL-3.0-only
#
# check-licenses.sh — licence gate for the gateway (AGPL-3.0-only) and, when present, the
# client module in client/ (Apache-2.0).
#
#   1. every tracked Go/shell file carries the SPDX header of the tree it belongs to
#   2. every third-party dependency compiled into the gateway has a permissive or MPL-2.0
#      licence: compatible with the AGPL, and still allowing 3eAI Labs to offer the gateway under
#      a commercial licence — which a GPL-family dependency would rule out
#   3. every dependency of the client has a permissive licence — the client is linked into
#      applications of any licence, so a copyleft dependency would defeat its purpose
#   4. the client imports nothing from the gateway module
#
# Usage: scripts/check-licenses.sh        exit 0 = PASS, 1 = FAIL
# GO_LICENSES overrides the go-licenses command (default: go run, pinned version).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
GO_LICENSES="${GO_LICENSES:-go run github.com/google/go-licenses/v2@v2.0.1}"
SERVER_ALLOWED=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
# Each module skips its own packages by path prefix; dependencies are still checked. Listing
# AGPL-3.0 as allowed instead would also admit a third-party AGPL module. The trailing slash
# matters: without it the server prefix also matches sbi-ha-gateway-client, which the server
# depends on as a released module and whose licence must be checked (and shipped) like any other.
OWN_SERVER=github.com/3eAI-Labs/sbi-ha-gateway/
OWN_CLIENT=github.com/3eAI-Labs/sbi-ha-gateway-client
CLIENT_ALLOWED=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC
fail=0
ok() { echo "PASS: $*"; }
ko() { echo "FAIL: $*"; fail=1; }

missing="$(git ls-files '*.go' '*.sh' ':!:client/' | xargs grep -L 'SPDX-License-Identifier: AGPL-3.0-only' || true)"
if [ -z "$missing" ]; then ok "AGPL-3.0-only header on every gateway Go/shell file"
else ko "gateway files without the AGPL-3.0-only header:"; printf '  %s\n' $missing; fi

if $GO_LICENSES check ./... --allowed_licenses="$SERVER_ALLOWED" --ignore "$OWN_SERVER" 2>/dev/null; then
  ok "gateway third-party dependencies are within $SERVER_ALLOWED"
else ko "gateway: a dependency licence is outside $SERVER_ALLOWED — run: $GO_LICENSES report ./..."; fi

if [ -d client ]; then
  missing="$(git ls-files 'client/*.go' | xargs grep -L 'SPDX-License-Identifier: Apache-2.0' || true)"
  if [ -z "$missing" ]; then ok "Apache-2.0 header on every client Go file"
  else ko "client files without the Apache-2.0 header:"; printf '  %s\n' $missing; fi

  if (cd client && $GO_LICENSES check ./... --allowed_licenses="$CLIENT_ALLOWED" --ignore "$OWN_CLIENT" 2>/dev/null); then
    ok "client dependencies are permissive ($CLIENT_ALLOWED)"
  else ko "client: a dependency licence is outside $CLIENT_ALLOWED"; fi

  # A failing `go list` must fail the check, not read as "no gateway imports".
  # Trailing slash: the client's own path (…/sbi-ha-gateway-client) must not match.
  if deps="$(cd client && go list -deps -test ./... 2>&1)"; then
    leaked="$(grep '^github.com/3eAI-Labs/sbi-ha-gateway/' <<<"$deps" || true)"
    if [ -z "$leaked" ]; then ok "client imports nothing from the gateway module"
    else ko "client depends on gateway packages:"; printf '  %s\n' $leaked; fi
  else ko "client: go list failed:"; printf '%s\n' "$deps" | head -5; fi
fi

if [ "$fail" -eq 0 ]; then echo "check-licenses: PASS"; else echo "check-licenses: FAIL"; exit 1; fi
