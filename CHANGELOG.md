# Changelog

All notable changes to sbi-ha-gateway are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/) (pre-1.0: a minor version may be breaking).

Versions up to 1.0.0 were released privately. 0.2.0 is the first public release: the version number
goes down on purpose, because the gateway stays below 1.0 until it has carried traffic on a
production network. Its entry describes what changed for an installation of 1.0.0.

## [Unreleased]

## [0.2.1] — 2026-10-18

Fixes found by installing 0.2.0 end to end on Kubernetes. The NATS contract is unchanged. Chart
0.2.1 deploys 0.2.1 and adds `config.shutdown.drainDelay` and `terminationGracePeriodSeconds`; its
other values are those of 0.2.0.

### Fixed

- **A rolling update or a scale-down no longer refuses connections.** On SIGTERM the gateway closed
  its SBI port at once, while kube-proxy went on routing new connections to the terminating pod for a
  moment: deleting a pod under load refused a new connection each time (on kind, one per deletion at
  about 250 requests a second). The
  gateway now goes on serving for `SHUTDOWN_DRAIN_DELAY` (default `5s`, chart
  `config.shutdown.drainDelay`), `/health/ready` answering 503 meanwhile, and only then shuts down.
  The chart sets `terminationGracePeriodSeconds` (default 30), which must exceed the drain delay
  plus the 5 s shutdown.

### Security

- **Subscriber identifiers no longer reach the access log or the metrics.** The access log wrote the
  request URI — the SUPI or GPSI in the path, the query — as a plain-text line per request on
  standard output, outside `LOG_LEVEL`. It is now a JSON line through the gateway's logger that names
  the route pattern (`/nudm-sdm/v1/{supi}/am-data`), the status, the size, the duration and the
  request ID. A path no route matches is `unmatched` in the access log and in the
  `path` label of `sbi_gateway_requests_total` and `sbi_gateway_request_duration_seconds`, where it
  was the path: any client could add a time series per request.

### Changed

- The access line of a request is `debug`, of a 5xx `warn`: at the default `info` the gateway no
  longer writes a line per request. A request whose handler writes no status counts as 200 in the
  metrics, not 0.

## [0.2.0] — 2026-10-18

### Licensing and packaging

- The gateway is licensed under the GNU Affero General Public License v3.0 only. A commercial
  licence is available from 3eAI Labs (`NOTICE`). Contributions require the 3eAI Labs Contributor
  Licence Agreement v1.0 (`CLA.md`).
- The NATS wire contract is a separate module under the Apache License 2.0,
  `github.com/3eAI-Labs/sbi-ha-gateway-client` (package `sbiclient`), so applications can link it
  under any licence. The JSON on every subject is unchanged.
- The image is published as `ghcr.io/3eai-labs/sbi-ha-gateway` (1.0.0 was on
  `registry.3eai-labs.com`). It is based on `gcr.io/distroless/static-debian13:nonroot` and carries
  the licence texts of the gateway and of every Go module compiled into it under
  `/usr/share/licenses/sbi-ha-gateway/`.
- The Go module path is `github.com/3eAI-Labs/sbi-ha-gateway` (it was
  `github.com/3eAI-labs/sbi-ha-gateway`).

### Helm chart 0.2.0

- **Breaking:** `smoke.enabled` and `smoke.natsImage` are removed. In their place, when
  `config.nats.url` is empty the chart deploys a single-replica core NATS (`nats.deploy`, on by
  default) so that an install with the defaults becomes Ready; no application is connected to it.
  With `nats.deploy: false` an empty `config.nats.url` refuses to render.
- **Breaking:** `config.nats.url` defaults to empty; it was `nats://nats-cluster:4222`, an address
  that does not exist in most clusters. Set it to the NATS your applications use.
- `config.ota.enabled` with the bundled NATS refuses to render: the SMS stream is on the
  applications' NATS.
- The pods meet the Kubernetes `restricted` Pod Security Standard: seccomp `RuntimeDefault` on the
  gateway pod. The `smoke` NATS of 0.1.0 also carried the gateway's selector labels, so the
  gateway's Deployment and Service selected its pod; the bundled NATS has labels of its own.
- `image.registry` defaults to `ghcr.io` and `image.repository` to `3eai-labs/sbi-ha-gateway`;
  `image.tag` defaults to the chart's appVersion.

### Fixed

- **A reply from JetStream is no longer taken for the application's reply.** When a stream captures
  a request subject, JetStream answers the gateway's request with its publish acknowledgement before
  the application can. 1.0.0 returned that to the network function as a success — `200 {}` for
  generate-auth-data, 201 for a registration — and emitted an audit event for a change that never
  happened. The gateway now answers 500 (`SYSTEM_FAILURE`), emits no audit event, logs the stream's
  name and counts it as `sbi_gateway_nats_requests_total{status="jetstream_reply"}`.
- **Application errors reach the network function.** An application refuses a request with
  `{"problemDetails": {...}}` (TS 29.571 ProblemDetails) on any request subject; the network
  function gets its status and body, and no audit event is emitted. 1.0.0 ignored the reply on
  `5g.auth.confirm` and `5g.mobility.registration` and answered 201 or 204 whatever it said, and
  decoded any reply on `5g.auth.request` and `5g.mt.loc-info` as a success.
- **`NATS_REQUEST_TIMEOUT` is applied.** 1.0.0 dropped it, and a request to a silent application
  stayed open until the network function gave up. The gateway now answers 504 after the timeout,
  and at once when no application is subscribed.
- **The HTTP servers have timeouts and a body limit.** 1.0.0 set none: a client that never finished
  its request headers held the connection open indefinitely (measured: still open after 20 s; now
  closed at 10 s). Request bodies over 1 MiB are refused with 413. The admin port has timeouts too.
- **A certificate without its key stops the gateway.** 1.0.0 served cleartext h2c instead, and also
  when `MTLS_CLIENT_AUTH_MODE` asked for client certificates without TLS configured.
- `LOG_LEVEL`, `MAX_RETRIES` and `RETRY_BASE_DELAY` are applied: the log level, and the passes and
  backoff of notification delivery (the defaults are 1.0.0's fixed values). 1.0.0 read and ignored
  them. An unknown `LOG_LEVEL` or `MAX_RETRIES` below 1 stops the gateway.
- `sbi_gateway_nats_connection_status` is 0 while the gateway starts without NATS; 1.0.0 reported 1.
- A request body that is not JSON is answered 400 `INVALID_MSG_FORMAT` (TS 29.500); it was
  `INVALID_BODY`.
- A reply that is not a JSON object (`null` among them) is answered 500. 1.0.0 answered it 200 with
  an empty result, or ignored it.

### Security

- Built with Go 1.26.9; `go-chi/chi/v5` 5.3.0, `klauspost/compress` 1.18.7. govulncheck finds no
  vulnerability the gateway's code reaches. With Go 1.25.5 and 1.0.0's modules it reached 31, in
  the standard library, `golang.org/x/net`, `golang.org/x/text` and chi (measured 17 October 2026).
- HTTP/2 comes from Go's `net/http` (server `Protocols`, client `http.Transport`); `golang.org/x/net`
  and `golang.org/x/text` are no longer compiled in. With outbound mTLS configured, an `http://`
  callback URI fails instead of being sent in cleartext — as before, now tested.
- Nothing in a URI can make the application read another resource than the one routed: GPSIs and
  External Group Ids take URI-safe characters only (an escaped `/` in one shifted the resource
  path the application received), an empty identifier (`//`) is invalid rather than absent, empty,
  dot segments and escaped slashes in a data resource are answered 404
  `RESOURCE_URI_STRUCTURE_NOT_FOUND`, and `{pduSessionId}` must be 0–255 (400
  `MANDATORY_IE_INCORRECT`).
- The client address is the TCP peer's. 1.0.0 took it from `X-Forwarded-For`, `X-Real-IP` or
  `True-Client-IP` whoever sent them (chi's `RealIP`, deprecated for that reason); it only keys the
  rate limiter when there is neither an OAuth `sub` nor a `User-Agent`.

### Changed

- **TS 29.503 conformance.**
  - **Breaking for network functions:** `DELETE` on amf-3gpp-access and `PATCH` on
    smsf-3gpp-access are answered 405; the specification has neither. `GET` is served on
    amf-3gpp-access, smsf-3gpp-access, smf-registrations and each SMF registration, through
    `5g.mobility.query`.
  - A registration `PUT` is answered 201 with `Location` when the application created the
    registration, 200 when it replaced one (`{"updated": true}` in the reply); 1.0.0 always
    answered 201 without `Location`.
  - auth-events takes a SUPI only (1.0.0 took a SUCI too) and is answered 201 with the event and
    `Location` ending in the `authEventId` the application returns; 1.0.0 answered `null`.
  - Each URI variable accepts the identifiers its specification gives it: a GPSI on UECM GET,
    Nudr and PP, an External Group Id on PP and EE, `anyUE` on EE. EE took a SUPI only and so
    refused every identifier TS 29.503 allows there. An invalid identifier is answered 400
    `MANDATORY_IE_INCORRECT` with the variable in `invalidParams`; it was `INVALID_QUERY_PARAM`.
  - Served now: SDM `GET /{supi}`, Nudr `GET /subscription-data/{ueId}`,
    `/subscription-data/shared-data` and `/shared-data/{sharedDataId}`; they were 404.
- 204 responses no longer count as an encoding failure in `sbi_gateway_errors_total` nor log an
  error: 1.0.0 tried to write `null` as their body, which net/http refuses.
- **Breaking for applications:** `5g.mobility.query` carries `ueId` (it was `supi`), `resource` and
  `query`; `DataRequest`'s `supi` is `ueId`, since it may hold a GPSI, a group or `anyUE`.
  `5g.auth.confirm` must be answered with `authEventId`.
- **Breaking for applications:** on `5g.data.query` and `5g.data.update`, `DataResponse` has no
  `status` and `code` any more; refuse a request with `problemDetails` instead. 1.0.0 turned
  `"status": "ERROR"` into a 400 with `code` as the cause. Replies on `5g.auth.confirm` and
  `5g.mobility.registration` must be JSON objects (`{}`).
- Problem causes of the gateway's own failures are TS 29.500 names: `TARGET_NF_NOT_REACHABLE`
  (504) when no reply arrives, in place of `TIMEOUT`, `NETWORK_FAILURE` and `BACKEND_TIMEOUT`.
  The problem detail no longer carries the NATS error text.
- **Breaking for applications:** `DataRequest` names the service (`service`) and always carries the
  path after the subscriber in `resource` (`am-data`, `pp-data`, `sdm-subscriptions/9`…); `dataSet`
  is set for Nudr only. The query string is passed in `query`; 1.0.0 dropped it.
- The generate-auth-data request reaches the application whole: `resynchronizationInfo` (RAND and
  AUTS, under its TS 29.503 name `auts`; 1.0.0 read it as `autn` and dropped it), CAG, N5GC, NSWO
  and disaster-roaming indicators. Audit events redact AUTS.
- `sbi_gateway_nats_requests_total` tells `timeout`, `no_responders` and `jetstream_reply` apart from
  `error`.
- The start-up error for OAuth without a JWKS source names the right variable,
  `OAUTH_NRF_JWKS_URL`.

### Known limitations

See [README.md](README.md#known-limitations).
