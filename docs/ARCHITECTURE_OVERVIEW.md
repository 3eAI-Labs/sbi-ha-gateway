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
| `internal/handlers` | The operation table generated from the 3GPP OpenAPI definitions (`operations_gen.go`) and the one handler that serves it: URI, identifier and body checks; NATS request and HTTP response |
| `internal/nats` | NATS connection; the notification subscriber with callback failover; the SMS subscriber |
| `internal/handlers/outbound` | How a notification reaches a network function: `sbi_direct` (HTTP/2 POST) or `scef_rest` (left to an external adapter) |
| `internal/sbi` | HTTP/2 client for callbacks and SMSF calls, with optional client certificate |
| `internal/handlers/uecm` | Serving-SMSF lookup for the SMS surfaces (a file, or nothing) |
| `internal/audit`, `internal/platform/audit` | Audit events for state-changing operations: SUPI masked to its MCC, key material and tokens redacted, published to NATS |
| `internal/metrics`, `internal/admin` | Prometheus metrics; health and stats on the admin port |
| `internal/config` | Environment variables, read once at start-up |

## Request from a network function

1. The SBI port accepts HTTP/2 (Go's `net/http`): TLS 1.3 with ALPN `h2` when a certificate and key
   are configured, cleartext h2c with prior knowledge only with `ALLOW_PLAINTEXT_SBI` (the gateway
   refuses to start otherwise, as without client certificates or OAuth unless each is switched off
   explicitly; each switched off shows in `sbi_gateway_security_protection`). HTTP/1.1 is refused: TS 29.500
   clause 5.2.1 requires HTTP/2 on the service-based interface. The admin port is HTTP/1.1.
2. The middleware chain runs in this order:
   - request ID;
   - access log: JSON through the same logger, naming the route pattern rather than the URI;
   - metrics;
   - panic recovery: 500 `SYSTEM_FAILURE` as ProblemDetails and one log line with the stack, so a
     panicked request is counted and logged as its 500. A panic after the response began aborts
     the stream;
   - **peer identity:** the NF instance ID from the client certificate's URI SAN, and the
     certificate's SHA-256 thumbprint;
   - **OAuth2,** when enabled: the bearer token is validated and, if it carries a `cnf` claim,
     bound to that thumbprint. A rejection follows TS 29.500 clause 6.7.3: 401 with
     `WWW-Authenticate: Bearer realm="<API URI>"`, and `error="invalid_token"` when a token was
     sent (expired, malformed, for another audience, bound to another certificate); 403
     `error="insufficient_scope"` with the `scope` needed;
   - the **rate limiter**, keyed by the token's `sub` when there is one.
3. The route is the operation of the 3GPP OpenAPI definition (`internal/handlers/operations_gen.go`,
   generated from them). The handler checks the path variables against the identifier kinds their
   schemas name, and the body's media type and JSON. It sends a core NATS request with an
   `sbiclient.Request` on the operation's subject: the operationId, the path variables and the
   body, unchanged (README, *Operations served*).
4. The reply becomes the HTTP response (`internal/handlers/sbi.go`).
   - An `sbiclient.Reply`: its status, if the operation allows it, and its body. `Location` is built
     for a 201 from the request URI, and from the reply's `resourceId` when the 201 creates a
     resource under it.
   - An error reply, `{"problemDetails": {...}}`: passed to the network function with its status.
   - No reply within `NATS_REQUEST_TIMEOUT`, or no application subscribed: 504
     `TARGET_NF_NOT_REACHABLE`.
   - A reply from JetStream (a stream's publish acknowledgement, because a stream captures the
     subject), a reply the operation does not allow, or one that is not a JSON object: 500
     `SYSTEM_FAILURE`.
5. For every operation but a GET the handler emits an audit event, named by the operationId,
   however it ended:
   - `outcome` is `success`, `rejected` (a 4xx: the gateway's check or the application's
     `ErrorReply`) or `failed` (a 5xx, no answer);
   - it carries the HTTP status, the ProblemDetails cause and the request ID;
   - the subscriber is masked and there is never a body.

   An OAuth refusal is audited too (`AccessToken`, `rejected`, the reason), and so are the
   notifications and SMS the gateway sends for applications (`DeliverNotification`,
   `MtForwardSm`; user `nats`, `target` the network function). A publish NATS refuses is counted
   (`sbi_gateway_audit_publish_failures_total`) and logged whole. At shutdown the queue is
   published before the connection closes.

## Notification to a network function

The gateway subscribes to `5g.data.notify` with queue group `sbi-gateway`, so one replica handles
each message. It POSTs the message's `changeItem` to `callbackUri`, then to each of
`alternateCallbackUris` in order when one fails with a 5xx, a 429 or a transport error. When every
URI has failed it waits (`RETRY_BASE_DELAY`, doubling: 1 s, then 2 s by default) and starts another
pass, `MAX_RETRIES` passes at most (3 by default). A 4xx from
any URI ends the delivery: the request itself is wrong, and another endpoint would refuse it too.

- **Concurrency.** `NOTIFY_WORKERS` (32) notifications are delivered at once, so one whose network
  function does not answer holds one worker, not the queue. When all are busy the subscription
  waits and NATS buffers. Order is not kept, as it was not across replicas.
- **Health, per network function** (`scheme://host:port`, shared by the notifications):
  - After 3 transient failures in a row a network function rests, 1 s doubling to 30 s, and the
    other URIs of a notification are tried first. When all of them rest, all are tried.
  - A `Retry-After` is kept to: no request before it. One longer than 30 s ends the delivery.
  - A success forgets the network function.
- **Ends without delivery.** A URI that `OUTBOUND_ALLOWED_DESTINATIONS` refuses is not tried again,
  and an unimplemented `OUTBOUND_PROFILE` ends the delivery. Every notification not delivered is
  published on `5g.data.notify.failed` as a `NotificationFailure`, with the last status and
  ProblemDetails, so the back end can, for example, remove a subscription the network function
  answered 404 for.
- **Shutdown.** The subscription is drained and the deliveries in flight are waited for; any still
  running at the deadline are cancelled and reported with cause `SHUTDOWN`.

## SMS surfaces

Enabled with `OTA_ENABLED`. Two NATS surfaces of an SMS platform:

- **Serving-SMSF lookup** (`sbi.outbound.nudm.uecm.request`, core request/reply, queue group
  `sbi-gateway-ota`): the gateway answers from `OTA_RESOLVER_FILE`, or with 404 when it has no
  entry, so the platform can fall back to its 4G/2G path at once.
- **MT SMS** (`sbi.outbound.nsmsf.send.request`): a durable pull consumer, `sbi-gateway-smsf`, on
  the platform's JetStream work-queue stream `OTA_OUTBOUND`. The gateway calls Nsmsf_SMService
  MtForwardSm (`send-mt-sms`, the RP-DATA as the binary part of a `multipart/related` body) on the
  SMSF named in the message, and publishes the result on `ota.delivery.event`, from the mobile
  station's RP-ACK or RP-ERROR. A transient failure (5xx, 429, transport error) is reported as
  `PENDING` and the message is redelivered, three deliveries at most; on the third it is reported
  `FAILED` (`RETRIES_EXHAUSTED`, the transient cause in `lastCause`) and removed from the queue. A
  message that is not JSON is removed from the queue.

## State

None that must survive a restart. Each replica holds its own token-validation cache, its own
rate-limit buckets (so the effective limit grows with the replica count) and its own JWKS copy.

## Configuration and operations

- Environment variables only, read at start-up; a change means a restart (the Helm chart rolls the
  pods). Security settings that would leave the gateway weaker than configured stop it at start-up.
- The gateway starts even when NATS is unreachable and keeps reconnecting; `/health/ready` stays
  503 until the connection is up, and with OAuth on until the NRF has given it a verification
  key: every token would be rejected meanwhile. With `OTA_ENABLED` it exits instead, because the SMS consumer
  cannot be created.
- On SIGTERM it first goes on serving for `SHUTDOWN_DRAIN_DELAY` (5 s) with `/health/ready` at 503,
  so connections that kube-proxy or a balancer still sends to the terminating pod are answered.
  Then, side by side and within `SHUTDOWN_TIMEOUT` (20 s), the SBI requests in flight finish, the
  notification deliveries finish or are reported, and the SMS being sent finishes and is
  acknowledged; NATS stays connected until all have. SMS fetched but not started are redelivered
  by JetStream. The chart refuses a drain delay plus timeout that does not fit in
  `terminationGracePeriodSeconds`.
