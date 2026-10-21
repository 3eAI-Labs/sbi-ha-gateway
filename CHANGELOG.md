# Changelog

All notable changes to sbi-ha-gateway are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/) (pre-1.0: a minor version may be breaking).

Versions up to 1.0.0 were released privately. 0.2.0 is the first public release: the version number
goes down on purpose, because the gateway stays below 1.0 until it has carried traffic on a
production network. Its entry describes what changed for an installation of 1.0.0.

## [0.4.1] — 2026-10-21

The four findings of 0.4.0's release, and Go 1.26.10 for a crypto/x509 vulnerability published
after it. Not breaking: the configuration, the chart's defaults and the NATS contract
(`sbi-ha-gateway-client` v0.3.0) are unchanged. An audit consumer sees the peer's NF instance ID
where 0.4.0 wrote `anonymous`. Chart 0.4.1 deploys 0.4.1.

### Fixed

- **The peer's NF instance ID is read from the URI SAN TS 33.310 defines.** The NF certificate
  profile (TS 33.310 clause 6.1.3c.3) carries the NF instance ID as `urn:uuid:<UUID>`. 0.4.0 and
  earlier read only `urn:5g:nf-instance-id:`, which no 3GPP profile defines, so an OAuth refusal of
  a conforming client was audited with user `anonymous`. The URN namespace and the UUID are matched
  case-insensitively and the ID is written in lower case. A certificate carrying only the old form
  is now audited as `anonymous`. The ID is used for that audit field alone; no check changes.
- **`/health/ready` answers `"reasons":[]` when ready,** where 0.4.0 wrote `null`.
- **Chart: Arinna can tune 0.4.0's values.** `config.admin.auth` and `config.admin.tls` are
  high-risk, approval-gated changes like the other protections; `config.admin.tokenSecret` is a
  Secret reference; `metrics.serviceMonitor` and `metrics.prometheusRule` (enabled, interval,
  thresholds) are low-risk. Chart 0.4.0 carried no `x-arinna` on them, so Arinna could install
  only the defaults.
- **Chart: the NetworkPolicy's description no longer says the admin port has no
  authentication;** it has its token and TLS since 0.4.0.

### Security

- **Built with Go 1.26.10,** which fixes GO-2026-6809 ("Distrust compromised intermediate
  certificates in crypto/x509"). 0.4.0 was built with Go 1.26.9, and govulncheck finds the
  gateway's code reaching the affected crypto/x509 code. The SBI port, the admin port and the
  outbound calls all verify certificates with it.

## [0.4.0] — 2026-10-20

The admin port's protection, and the hardening 0.3.0's end-to-end run asked for. Breaking for
installations: the admin port needs its token and TLS. The chart provides both, or each is switched
off explicitly. Audit consumers get refused and failed operations too, with an `outcome`. The NATS
contract is unchanged (`sbi-ha-gateway-client` v0.3.0). Chart 0.4.0 deploys 0.4.0; its new values
are `config.admin` and `metrics`.

### Changed — breaking

- **The admin port is protected by default, like the SBI port.** 0.3.0 served `/metrics` and
  `/admin/stats` to anyone who reached the port, in cleartext. The health endpoints stay open for
  the kubelet.
  - **Token:** `/metrics` and `/admin/*` require a bearer token from `ADMIN_TOKEN_FILE`, re-read
    every 10 s so that a rotated Secret takes effect without a restart. Without one the gateway
    stops at start-up, unless `ADMIN_AUTH_DISABLED=true`.
  - **TLS:** the port is served over TLS with the SBI certificate (`ADMIN_TLS`, default `true`).
    Without a certificate the gateway stops, unless `ADMIN_TLS=false`.
  - **Chart:** `config.admin.auth` and `config.admin.tls` default to `true`. Without
    `config.admin.tokenSecret` the chart creates `<fullname>-admin-token` with a random token,
    kept across upgrades, and `metrics.serviceMonitor` uses it. The probes use HTTPS. A trial
    install without TLS switches admin TLS off itself; any other install without
    `tls.existingSecret` stops at render unless `config.admin.tls=false`.
  - **Migration:** give Prometheus the token (the chart's ServiceMonitor does) and HTTPS, or switch
    each protection off explicitly. Each one off is a WARN at start-up and a 0 in
    `sbi_gateway_security_protection` (`admin_auth`, `admin_tls`).

### Changed

- **Refused and failed operations are audited.** 0.3.0 audited a state-changing operation only
  when it succeeded: one an application refused, that timed out or that the gateway turned away
  left no trace.
  - Every audit event now has `outcome` (`success`, `rejected`, `failed`), `status`, `cause` (the
    ProblemDetails cause) and `request_id`, so a consumer that counted events as changes must read
    `outcome`.
  - OAuth refusals are audited (`AccessToken`, user the client certificate's NF instance ID).
  - The notifications and MT SMS the gateway sends for applications are audited too
    (`DeliverNotification`, `MtForwardSm`, user `nats`, `target` the network function).
  - The fields are additions; events still carry no body.

### Added

- **Metrics:**
  - `tls_certificate_expiry_timestamp_seconds{certificate="sbi"|"outbound"}` and
    `tls_handshake_failures_total{port}`. Handshake errors, one per scanner connection, are now
    logged at debug, where 0.3.0 wrote them at info.
  - `nats_events_total{event}`: disconnected, reconnected, `slow_consumer`. A subscription that
    fell behind lost messages unseen: nats.go had no error handler.
  - `callback_retries_total` counts the attempts after a failed one; 0.3.0 defined it but never
    incremented it.
- **Chart: Prometheus Operator resources, opt-in.**
  - `metrics.serviceMonitor` scrapes `/metrics` with the admin token and TLS when they are set.
  - `metrics.prometheusRule` alerts on: a pod down, no NATS connection, no verification key,
    the 5xx and OAuth rejection ratios, undelivered notifications and SMS, audit loss, a slow
    consumer, a certificate near expiry and a protection switched off. The rules are checked and
    unit-tested with promtool.
- **`/health/ready` says why it is 503:** a JSON body with the reasons (`draining`,
  `nats_disconnected`, `oauth_no_verification_key`), and a log line when readiness changes.

### Fixed

- **A NATS outage no longer writes an error line per request.** 0.3.0 logged "NATS request
  failed" at error level for every SBI request it could not pass on, without the request ID or
  the subject. The line is now written once every 10 s at most, with how many failures went
  unreported, the request ID and the subject; each failure is logged at debug and counted in
  `sbi_gateway_nats_requests_total`.
- **A gateway started while the NRF was down becomes ready within 30 s of the NRF answering.**
  The JWKS cache scheduled the fetch after a failed one at the full `OAUTH_JWKS_REFRESH` (5 m by
  default), so 0.3.0 stayed unready, rejecting every token, for up to that long. While it holds
  no verification key, the gateway now retries the NRF every 30 s.

### Security

- **Audit events reach NATS at shutdown and are not lost silently.** 0.3.0 wrote the events
  still queued at shutdown to the log with two fields, and a publish NATS refused was neither
  counted nor logged in full. The queue is now published before the connection closes. A refusal
  is counted (`sbi_gateway_audit_publish_failures_total`) and logged with every field.
- **An unlisted host name is no longer resolved.** When `OUTBOUND_ALLOWED_DESTINATIONS` has name
  rules alone, a name none matches is refused before any DNS query. 0.3.0 resolved it first, so an
  application able to publish a notification or an SMS could make the gateway query DNS for any
  name. It also retried such a URI in every pass as a transport error, where it is now dropped as
  not allowed. With a CIDR or address rule, or `OUTBOUND_ALLOW_ANY`, names are still resolved:
  the decision is on the address.

## [0.3.0] — 2026-10-19

Conformance to the 3GPP specifications and a secure default. Breaking for applications and for
installations:
- Applications move to `sbi-ha-gateway-client` v0.2.0 or later: the specification's bodies,
  verbatim. v0.3.0 adds the report of undelivered notifications.
- Nudm_SDM and Nudr are served at `v2`; HTTP/1.1 is refused.
- An installation must provide TLS, client certificates and OAuth, or switch each off explicitly.
- Callbacks and SMSF calls need `OUTBOUND_ALLOWED_DESTINATIONS` (or `OUTBOUND_ALLOW_ANY`).

Chart 0.3.0 deploys 0.3.0. Its new values:
- `config.security`, `config.nats.secret`, `config.outbound`, `config.notify` and
  `config.shutdown.timeout`;
- `networkPolicy`, `extraVolumes` and `extraVolumeMounts`.

`config.mtls.clientAuthMode` now defaults to `require` and `config.oauth.disabled` to `false`;
the trial install switches off what it lacks.

### Changed — breaking

- **The NATS contract carries the specification's bodies verbatim** (`sbi-ha-gateway-client` v0.2.0).
  Every request is one `Request`: the API, the operation's operationId, method, path, path variables,
  query, media type and the network function's body, unchanged. Every success reply is one `Reply`:
  status, the created resource's identifier and the body, returned to the network function
  unchanged. 0.2.x decoded bodies into types that re-modelled TS 29.503 by hand and did not match it:
  - the authentication result reached the AUSF as `authVector`/`kAusf`, without `authType` or
    `avType`, where TS 29.503 defines `authenticationVector`/`kausf` and makes both mandatory;
  - information elements the types did not model were dropped (`pei`, `imsVoPs`, `nfSetId`,
    `resetIds` and others);
  - elements the specification defines as objects were strings, so conforming requests got 400;
  - a registration's response was the request, not the application's representation.
- **Nudm_SDM and Nudr_DataRepository are served at `/nudm-sdm/v2` and `/nudr-dr/v2`.** TS 29.503
  clause 6.1.1 ("The <apiVersion> shall be "v2"") and TS 29.504 define these roots. 0.2.x served both
  under `v1`, so a network function calling them got 404. A request to `v1` is now answered 400
  `INVALID_API`, naming the version served.
- Nudr_DataRepository serves subscription data (TS 29.505) only; 0.2.x passed any data set through.
- **Audit events name the operation and carry no request body.**
  - The operation is named by its operationId (`3GppRegistration`, `ConfirmAuth`), not by
    gateway-made names (`REGISTER_AMF`).
  - The body is left out because the gateway no longer interprets bodies, so it cannot tell key
    material from the rest. Nudr's authentication subscription carries `encPermanentKey`, and in a
    JSON Patch a secret sits under `value`.
- **Secure by default.** Without settings the gateway refuses to start and
  names what is missing:
  - TLS: `TLS_CERT_FILE`/`TLS_KEY_FILE`;
  - client certificates: `MTLS_CLIENT_AUTH_MODE` is now `require` by default, with
    `MTLS_CLIENT_CA_FILE`;
  - OAuth: `OAUTH_DISABLED` is now `false` by default; audience and JWKS source required.

  Each protection is switched off only by its own setting: `ALLOW_PLAINTEXT_SBI=true` (new),
  `MTLS_CLIENT_AUTH_MODE=off`, `OAUTH_DISABLED=true`. Each one switched off is a WARN at start-up and
  a 0 in the new gauge `sbi_gateway_security_protection{protection}`.

  The chart follows. With `config.nats.url` set, a missing protection stops the render with what to
  set. A trial install (the bundled NATS) switches off what it lacks, explicitly, so its defaults
  still start. **Upgrading from 0.2.x:** add the certificates and OAuth settings, or the opt-outs.
- **Helm chart: TLS through `tls.existingSecret` works.** In 0.2.x the Secret was mounted root-owned at
  0400, so the gateway (uid 65532) could not read its certificate and a TLS install never became
  Ready (measured on kind). The pod now runs with `fsGroup: 65532` and Secrets mount at 0440.
- **Helm chart:**
  - `config.mtls.outbound{Cert,Key,CA}File` reach the gateway; 0.2.x defined but never rendered
    them.
  - `extraVolumes` and `extraVolumeMounts` mount the files the gateway reads by path: outbound
    TLS, `config.oauth.jwksFile`, `config.ota.resolverFile`.
  - A NetworkPolicy lets the unauthenticated admin port be reached only from the release's
    namespace and `networkPolicy.adminFrom`; the SBI port from `networkPolicy.sbiFrom`, or
    anywhere.
  - The SHACL shapes are inside the chart package (`shapes/`) and follow the secure defaults.
- **Callbacks and SMSF calls reach only allowed destinations.** The URIs come
  from NATS messages; 0.2.x POSTed to any of them.
  - `OUTBOUND_ALLOWED_DESTINATIONS` lists host names, `.domain` suffixes, CIDR blocks and addresses.
    It is checked on the address actually dialled: a name is resolved once and the connection goes
    to a checked address.
  - Empty means none; `OUTBOUND_ALLOW_ANY=true` is the explicit opt-out.
  - Loopback, link-local (cloud metadata), unspecified and multicast addresses are refused unless
    listed by address.
  - A refused SMSF fails the SMS with cause `DESTINATION_NOT_ALLOWED`, without redelivery.
  - Chart: `config.outbound.allowedDestinations`, `config.outbound.allowAny`.
  - **Upgrading:** list the network functions' hosts, or deliveries fail.
- **The SBI port speaks HTTP/2 only** (TS 29.500 clause 5.2.1): ALPN `h2` with TLS, prior-knowledge
  h2c without. 0.2.x also answered HTTP/1.1. The admin port is unchanged.

### Fixed

- **Release artefacts can be verified.**
  - The image and the chart are signed keylessly with cosign (Sigstore), by the release workflow
    at the release tag; README "Verifying a release" gives the commands.
  - The image carries an SPDX SBOM, and the provenance attestation is now requested rather than
    left to a default.
  - The image's `org.opencontainers.image.revision` label and its `sha-` tag name the commit of
    this public repository. 0.2.x named a commit of the private source repository, which nobody
    else can look up.
- **The NRF's JWKS:**
  - Fetched with the `MTLS_OUTBOUND_*` trust anchor and client certificate, as for every 5GC
    peer, and with a 10 s timeout. 0.2.x used Go's default client: no private CA, no
    certificate, and no timeout, so an NRF that accepted the connection and never answered held
    the gateway's start-up indefinitely.
  - With OAuth on, `/health/ready` is 503 until the gateway holds a verification key. 0.2.x was
    ready while it rejected every token.
  - Metrics: `oauth_jwks_keys`, `oauth_jwks_refreshes_total{result}`,
    `oauth_jwks_last_refresh_timestamp_seconds`.
  - `OAUTH_JWKS_REFRESH` below 2 s stopped 0.2.x at start-up, with an error about a 15-minute
    refresh window nobody had set. Down to `1s` now works; below it is refused plainly.
- **OAuth rejections follow TS 29.500 clause 6.7.3.** The `WWW-Authenticate` challenge names
  `realm`, the URI of the API (`https://<host>/<apiName>/<apiVersion>`).
  - Without a token it carries no `error`; 0.2.x sent `error="invalid_token"`.
  - A token for another audience is 401 `invalid_token`; 0.2.x answered 403, which the clause
    keeps for missing scopes.
  - A missing scope is 403 with `error="insufficient_scope"` and the `scope` needed; 0.2.x's 403
    had no challenge.
  - The ProblemDetails `cause` values 0.2.x put on these rejections (`TOKEN_EXPIRED`,
    `INVALID_TOKEN`, `INSUFFICIENT_SCOPES`, `TOKEN_BINDING_FAILED`, `missing_bearer`) are gone.
    No 3GPP specification defines them; the code attributed them to TS 29.500 clause 6.7.5,
    which is about client credentials assertions. `detail` still says what failed.
- **A panic in a handler is answered 500 `SYSTEM_FAILURE` as ProblemDetails.** It is logged as
  one line with its stack and counted in `requests_total`. 0.2.x answered an empty 500, wrote the
  stack to stderr as text and counted nothing. A panic after the response began aborts the HTTP/2
  stream rather than appending to it.
- **Shutdown waits for the work in flight, within `SHUTDOWN_TIMEOUT`.** 0.2.x gave a fixed 5 s
  to everything after the drain delay. It started the drain of its NATS subscriptions without
  waiting for it, so the notifications and the SMS being sent were cut when the process exited.
  JetStream redelivers an SMS cut mid-call, so one the SMSF had already taken could reach the
  subscriber twice.
  - `SHUTDOWN_TIMEOUT` (default `20s`; chart `config.shutdown.timeout`) bounds what follows the
    drain delay. Within it, side by side: the SBI requests in flight finish, the notification
    deliveries finish or are reported, and the SMS being sent finishes and is acknowledged.
  - SMS fetched but not started are redelivered by JetStream, to another replica when there is
    one.
  - The chart refuses `config.shutdown.drainDelay` plus `config.shutdown.timeout` that does not
    fit in `terminationGracePeriodSeconds` (30 by default; 5 s + 20 s fits).
- **A notification that cannot be delivered no longer holds up the others, and is no longer lost
  silently.** 0.2.x delivered notifications one at a time per gateway: one whose network function
  did not answer held every notification behind it for all its attempts (with the defaults, up to
  18 s for one URI). Then it was logged and dropped.
  - `NOTIFY_WORKERS` (32; chart `config.notify.workers`) deliver at once. Their order is not
    kept, as it was not across replicas either.
  - Each undelivered notification is published on `5g.data.notify.failed` as a
    `NotificationFailure` (client v0.3.0): the payload, why (`client_error`, `exhausted`,
    `not_allowed`, `not_implemented`), the last status and ProblemDetails, and the attempts.
  - A network function that failed 3 times in a row rests (1 s, doubling to 30 s): the other URIs
    of a notification go first, and 0.2.x began every notification with the primary. A
    `Retry-After` is kept to (TS 29.500 clause 6.4), remembered for 5 minutes at most; 0.2.x did
    not read it.
  - A URI `OUTBOUND_ALLOWED_DESTINATIONS` refuses is not retried, and the unimplemented
    `mtc_iwf_rest`/`scef_rest_https` profiles end the delivery at once. 0.2.x retried both in
    every pass.
  - On shutdown the deliveries in flight are waited for and those still running at the deadline
    are reported; 0.2.x's drain did not wait.
  - Callback URIs, which carry subscriber identities, are no longer logged: logs name the network
    function (`scheme://host:port`). Per-notification lines are `debug`.
  - Metrics: `outbound_deliveries_total` results `not_allowed` and `not_implemented`;
    `outbound_endpoint_skips_total{reason="resting"|"retry_after"}`.
- **Every SMS ends with `DELIVERED` or `FAILED`.** When the SMSF failed transiently on all three
  deliveries, 0.2.x's last `DeliveryEvent` was `PENDING` and nothing followed; the message stayed in
  the work queue. The last delivery's transient failure is now `FAILED` with cause
  `RETRIES_EXHAUSTED`, the transient cause in `BearerMeta` `lastCause`, and the message is
  acknowledged. Metric `sbi_gateway_ota_smsf_sends_total{result="retries_exhausted"}`.
- **Every operation of the APIs served.** The routes come from the 3GPP Rel-17 OpenAPI definitions:
  249 operations of Nudm_UEAU, UECM, SDM, EE, PP, MT, ReportSMDeliveryStatus and Nudr subscription
  data. Nudm_ReportSMDeliveryStatus is new: an SMS-GMSC reports the outcome of an MT SMS to the UDM
  through it (TS 23.540 clause 5.1.2). 0.2.x lacked, among
  others:
  - the non-3GPP access registrations, the UECM custom operations and IP-SM-GW and NWDAF
    registrations;
  - the other UEAU operations;
  - the SDM sub-resources and shared-data subscriptions;
  - PP's 5G VN groups;
  - MT's UE information.
- **Success statuses and `Location` as the specification gives them.** The application chooses among
  the operation's success statuses: 201 with `Location` for a subscription or a new registration,
  204 for a deletion or a modification without a body. 0.2.x answered every write of SDM, EE, PP and
  Nudr 200.
- **Identifiers as the specification types them.**
  - SDM's `{ueId}` (subscriptions, identifier translation, LCS privacy data) accepts a GPSI.
  - SUPIs may be Global Cable or Line Identifiers.
  - PP accepts only the methods its resources have: 405 elsewhere, as for every resource.
- **Request bodies are checked:** their media type against the operation's (415 otherwise; UECM PATCH
  is `application/merge-patch+json`), and that they are a JSON object or array.
- **Changes on SDM, EE, PP and Nudr are audited**, like those on UEAU, UECM and MT.
- What matches no operation is answered with ProblemDetails (TS 29.500 Table 5.2.7.2-1); 0.2.x
  answered chi's plain text.
- **An MT SMS goes to the SMSF as MtForwardSm.** 0.2.x used UplinkSMS (`sendsms`), which TS 29.540
  Table 5.2.1-1 gives to the AMF, with a JSON body.
  - The SMS now goes out as `send-mt-sms`, the operation of the SMS-GMSC, SMS Router and IP-SM-GW,
    with a `multipart/related` body: TS 29.577 `SmsData` and the RP-DATA as `application/vnd.3gpp.sms`.
  - The delivery event takes its status from the mobile station's RP-ACK or RP-ERROR in the response.
  - The application must send an RP-DATA (client v0.2.0); a bare TPDU fails.
- **Callbacks and SMSF calls to `https://` URIs go out over HTTP/2.** 0.2.x sent them over HTTP/1.1
  when no client certificate was configured; a peer that speaks only HTTP/1.1 is no longer called.
- **`MTLS_OUTBOUND_CA_FILE` alone gives TLS without a client certificate**, trusting that CA; with
  it, `http://` URIs are refused. 0.2.x stopped at start-up unless all three outbound TLS settings
  were set.
- **The gateway authenticates to NATS and can reach it over TLS.**
  - Authentication: user credentials (`NATS_CREDS_FILE`), an nkey seed, a user and password, or a
    token, with secrets read from files.
  - TLS: TLS 1.3 with `NATS_TLS_CA_FILE` and a client certificate.
  - Contradicting settings stop it at start-up.
  - The chart mounts them from `config.nats.secret`.
  - 0.2.x had only `NATS_URL`, so credentials sat in the pod spec.
- **A port that cannot be bound, a TLS certificate that cannot be loaded, or a callback subscriber
  that cannot start stops the gateway at start-up**, naming the cause. 0.2.x logged the error and ran
  on, with `/health/ready` answering 200 and the SBI port closed. A server that fails later stops the
  gateway too.
- **A setting that does not parse stops the gateway**, naming every such variable at once. 0.2.x
  took the default: `OAUTH_DISABLED=fasle` left OAuth off, `RATE_LIMIT_RPS=100/s` switched the rate
  limiter off.
- **The rate limiter's shared counter is no longer a data race.** A request over the limit is
  answered 429 with ProblemDetails, cause `NF_CONGESTION_RISK` (TS 29.500 Table 5.2.7.2-1), and
  `Retry-After`; 0.2.x sent `text/plain` with a cause the table does not have.
- The `method` label of `sbi_gateway_requests_total` and `sbi_gateway_request_duration_seconds` is
  `OTHER` for a method the SBI does not use. In 0.2.x every method a client made up opened a new time
  series, before authentication.

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
