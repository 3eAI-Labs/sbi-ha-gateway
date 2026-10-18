# Architecture overview

sbi-ha-gateway is one Go binary (`cmd/sbi-gateway`) with two HTTP servers — the SBI port for
network functions and the admin port — and one NATS connection. It keeps no subscriber state: every
SBI request is answered from an application's NATS reply, so any replica can serve any request.

The NATS subjects and messages are a separate Go module, `client/`
([sbi-ha-gateway-client](https://github.com/3eAI-Labs/sbi-ha-gateway-client), Apache-2.0). The
gateway imports it; it never imports the gateway.

## Components

| Package | Role |
|---------|------|
| `internal/server` | Router and middleware chain; TLS 1.3 and client-certificate settings; peer identity from the client certificate; OAuth2 middleware; rate limiter |
| `internal/oauth` | Access-token validation: signature against the JWKS (RS256/ES256), `aud`, `exp`/`nbf`, presence of `iss` and `sub`, scope per service, RFC 8705 certificate binding; cache of valid results |
| `internal/handlers` | One handler per service (UEAU, UECM, MT, and the data services SDM, PP, EE and Nudr); identifier validation; NATS request and HTTP response |
| `internal/nats` | NATS connection; the notification subscriber with callback failover; the SMS subscriber |
| `internal/handlers/outbound` | How a notification reaches a network function: `sbi_direct` (HTTP/2 POST) or `scef_rest` (left to an external adapter) |
| `internal/sbi` | HTTP/2 client for callbacks and SMSF calls, with optional client certificate |
| `internal/handlers/uecm` | Serving-SMSF lookup for the SMS surfaces (a file, or nothing) |
| `internal/audit`, `internal/platform/audit` | Audit events for state-changing operations: SUPI masked to its MCC, key material and tokens redacted, published to NATS |
| `internal/metrics`, `internal/admin` | Prometheus metrics; health and stats on the admin port |
| `internal/config` | Environment variables, read once at start-up |

## Request from a network function

1. The SBI port accepts HTTP/2 (Go's `net/http`): TLS 1.3 with ALPN `h2` when a certificate and key
   are configured, cleartext h2c with prior knowledge otherwise; HTTP/1.1 is accepted too.
2. The middleware chain runs in this order: request ID, access log (JSON through the same logger,
   naming the route pattern rather than the URI), panic recovery, metrics; then
   **peer identity** (the NF instance ID from the client certificate's URI
   SAN, and the certificate's SHA-256 thumbprint); then **OAuth2** (when enabled: the bearer token
   is validated and, if it carries a `cnf` claim, bound to that thumbprint); then the **rate
   limiter**, keyed by the token's `sub` when there is one.
3. The handler checks the subscriber identifier in the path, decodes the body, and sends a core
   NATS request with a `sbiclient` envelope on the operation's subject (README, *Operations
   served*).
4. The reply becomes the HTTP response (`Exchange` in `internal/handlers/base.go`): the result
   object for authentication data, location and data queries, the request's own registration for
   a registration (201), or 204. An error reply, `{"problemDetails": {...}}`, is passed to the
   network function with its status. No reply within `NATS_REQUEST_TIMEOUT`, or no application
   subscribed, gives 504 `TARGET_NF_NOT_REACHABLE`. A reply from JetStream — a stream's publish
   acknowledgement, because a stream captures the subject — or a reply that is not a JSON object
   gives 500 `SYSTEM_FAILURE`.
5. For state-changing operations the handler emits an audit event after a successful reply, and
   none after an error reply or a failure.

## Notification to a network function

The gateway subscribes to `5g.data.notify` with queue group `sbi-gateway`, so one replica handles
each message. It POSTs the message's `changeItem` to `callbackUri`, then to each of
`alternateCallbackUris` in order when one fails with a 5xx, a 429 or a transport error. When every
URI has failed it waits (`RETRY_BASE_DELAY`, doubling: 1 s, then 2 s by default) and starts another
pass, `MAX_RETRIES` passes at most (3 by default). A 4xx from
any URI ends the delivery: the request itself is wrong, and another endpoint would refuse it too.

## SMS surfaces

Enabled with `OTA_ENABLED`. Two NATS surfaces of an SMS platform:

- **Serving-SMSF lookup** (`sbi.outbound.nudm.uecm.request`, core request/reply, queue group
  `sbi-gateway-ota`): the gateway answers from `OTA_RESOLVER_FILE`, or with 404 when it has no
  entry, so the platform can fall back to its 4G/2G path at once.
- **SendSMS** (`sbi.outbound.nsmsf.send.request`): a durable pull consumer, `sbi-gateway-smsf`, on
  the platform's JetStream work-queue stream `OTA_OUTBOUND`. The gateway calls Nsmsf_SMService
  SendSMS on the SMSF named in the message and publishes the result on `ota.delivery.event`. A
  transient failure (5xx, 429, transport error) is reported as `PENDING` and the message is
  redelivered, three deliveries at most; a message that is not JSON is removed from the queue.

## State

None that must survive a restart. Each replica holds its own token-validation cache, its own
rate-limit buckets (so the effective limit grows with the replica count) and its own JWKS copy.

## Configuration and operations

- Environment variables only, read at start-up; a change means a restart (the Helm chart rolls the
  pods). Security settings that would leave the gateway weaker than configured stop it at start-up.
- The gateway starts even when NATS is unreachable and keeps reconnecting; `/health/ready` stays
  503 until the connection is up. With `OTA_ENABLED` it exits instead, because the SendSMS consumer
  cannot be created.
- On SIGTERM it first goes on serving for `SHUTDOWN_DRAIN_DELAY` (5 s) with `/health/ready` at 503,
  so connections that kube-proxy or a balancer still sends to the terminating pod are answered;
  then it stops the NATS subscribers and shuts both HTTP servers down with a 5 s limit.
