# sbi-ha-gateway

A 5G service-based interface (SBI) gateway. It serves part of the UDM and UDR APIs of a 5G core —
Nudm (UEAU, UECM, SDM, MT, PP, EE) and Nudr DataRepository, 3GPP TS 29.503 and TS 29.504/29.505 —
over HTTP/2, and hands each request to an application over NATS. It also delivers notifications to
network functions' callback URIs and sends SMS through an SMSF (Nsmsf_SMService, TS 29.540) for an
SMS platform.

The gateway keeps no subscriber state. Replicas share the work through NATS queue groups and a
JetStream work queue, so it scales horizontally.

**Status: 0.5.0; 0.2.0 was the first public release.** It has not carried traffic on a production network.
Read [Known limitations](#known-limitations) before relying on it.

## How it works

```
   AMF, AUSF, SMF, SMSF, NEF …                  application (UDM/UDR back end, SMS platform)
            │  HTTP/2 (TLS 1.3 or h2c)                          ▲
            ▼                                                   │ NATS
   ┌──────────────────────────┐   request/reply on 5g.*         │
   │      sbi-ha-gateway      │ ────────────────────────────────┘
   │  OAuth2 · mTLS · limits  │ ◀── 5g.data.notify, sbi.outbound.* (SMS)
   └──────────────────────────┘
            │  HTTP/2 POST to callback URIs, Nsmsf MtForwardSm to the SMSF
            ▼
   network functions, SMSF
```

- **Network function → application.** Each SBI operation becomes a core NATS request on a `5g.*`
  subject. The application's reply becomes the HTTP response.
- **Application → network function.** A message on `5g.data.notify` is POSTed to its callback URI,
  failing over to alternate URIs on 5xx, 429 or transport errors, in up to `MAX_RETRIES` passes
  with backoff. A 4xx ends the delivery. `NOTIFY_WORKERS` notifications go out at once. A network
  function that keeps failing rests while its alternates are tried, and one that answered
  `Retry-After` is not called before then. A notification no network function got is reported on
  `5g.data.notify.failed`, with the last answer.
- **SMS (opt-in, `SMS_ENABLED`).** An SMS platform asks which SMSF serves a subscriber
  (`sbi.outbound.nudm.uecm.request`) and sends SMS through it
  (`sbi.outbound.nsmsf.send.request`, a JetStream work queue); the gateway reports each result on
  `sbi.nsmsf.delivery.event` (`SMS_DELIVERY_EVENT_SUBJECT`). With no stream on the SMS subject,
  the gateway creates one.

- **NRF (opt-in, `NRF_API_ROOT`).** The gateway registers a UDM and/or UDR profile with the NRF
  (TS 29.510), with the APIs it serves, so that network functions can discover it, and heartbeats
  it at the NRF's interval. The installation is one NF instance whatever its replica count: every
  pod registers the same profile, and a stopping pod does not deregister, since the others serve
  on. The chart deregisters it on `helm uninstall`.

The subjects and JSON messages are defined by the Apache-2.0 module
[sbi-ha-gateway-client](https://github.com/3eAI-Labs/sbi-ha-gateway-client), which applications can
link under any licence.

## Operations served

Every operation of these APIs, as the 3GPP Rel-17 OpenAPI definitions give them (TS 29.503 v17.22.0
and earlier corrections per API, TS 29.504 v17.21.0, TS 29.505 v17.13.0):

| API | Root | Operations | NATS subject |
|-----|------|-----------:|--------------|
| Nudm_UEAuthentication | `/nudm-ueau/v1` | 7 | `5g.auth.confirm` for auth-events, `5g.auth.request` for the others |
| Nudm_UEContextManagement | `/nudm-uecm/v1` | 31 | `5g.mobility.query` for reads, `5g.mobility.registration` for changes |
| Nudm_SubscriberDataManagement | `/nudm-sdm/v2` | 35 | `5g.data.query` (GET) or `5g.data.update` |
| Nudm_EventExposure | `/nudm-ee/v1` | 3 | `5g.data.query` (GET) or `5g.data.update` |
| Nudm_ParameterProvision | `/nudm-pp/v1` | 12 | `5g.data.query` (GET) or `5g.data.update` |
| Nudm_MT | `/nudm-mt/v1` | 2 | `5g.mt.loc-info` |
| Nudm_ReportSMDeliveryStatus | `/nudm-rsds/v1` | 1 | `5g.data.update` |
| Nudr_DataRepository, subscription data | `/nudr-dr/v2/subscription-data` | 158 | `5g.data.query` (GET) or `5g.data.update` |

For each call the gateway checks, before NATS is involved:

- **The URI.** An API or API version it does not serve is answered 400 `INVALID_API`, an unknown
  resource of one it serves 404 `RESOURCE_URI_STRUCTURE_NOT_FOUND`, a method the resource does not
  have 405 with `Allow`.
- **The UE identifiers in it**, against the kinds the variable's schema names:
  - a SUPI: `imsi-<5–15 digits>`, `nai-<user>@<realm>`, `gci-…` or `gli-…`;
  - a SUCI;
  - a GPSI: `msisdn-<5–15 digits>` or `extid-<id>@<domain>`;
  - an External Group Id: `extgroupid-<id>@<domain>`;
  - `anyUE`.

  Identifiers take letters, digits and `.`, `_`, `~`, `+`, `-` only, and `{pduSessionId}` is 0–255.
  Anything else is answered 400 `MANDATORY_IE_INCORRECT`, with the variable in `invalidParams`.
  Another path variable with a `.` or `..` segment or an escaped `/` is answered 404.
- **The body:** a JSON object or array of a media type the operation accepts, otherwise:
  - 415 for another media type;
  - 400 `INVALID_MSG_FORMAT` for a body that is not a JSON object or array;
  - 413 above 1 MiB.

The application gets the operation by its operationId with the body unchanged. It answers with the
status, the body and, for a created resource, its identifier. The gateway answers the network function
with that status if the operation allows it, and builds `Location` from the request URI.

An application answers each request with the operation's result or with an error reply,
`{"problemDetails": {...}}`, which the network function receives with its status as the HTTP status
(see the client's README). No reply within `NATS_REQUEST_TIMEOUT`, or no application subscribed, is
answered 504 `TARGET_NF_NOT_REACHABLE`; a reply that is not a JSON object is answered 500
`SYSTEM_FAILURE`.

Applications answer with core NATS subscriptions. Keep the `5g.*` request subjects out of JetStream
streams: a stream that captures one answers every request with its publish acknowledgement before the
application can. The gateway recognises the acknowledgement and answers the network function 500
rather than a success it cannot vouch for, logs the stream's name, and counts it as
`sbi_gateway_nats_requests_total{status="jetstream_reply"}`.

## Try it

The gateway in front of the example back end of the client repository, which answers an AMF
registration, its read-back and the access and mobility subscription data, and 501 for the rest.
Docker, Go and curl, cleartext and without OAuth (a trial, not a deployment):

```bash
docker network create sbi-try
docker run -d --name nats --network sbi-try -p 127.0.0.1:4222:4222 nats:2.10-alpine -js
docker run -d --name sbi --network sbi-try -p 127.0.0.1:8080:8080 \
  -e NATS_URL=nats://nats:4222 -e ALLOW_PLAINTEXT_SBI=true -e MTLS_CLIENT_AUTH_MODE=off \
  -e OAUTH_DISABLED=true -e ADMIN_TLS=false -e ADMIN_AUTH_DISABLED=true \
  ghcr.io/3eai-labs/sbi-ha-gateway:0.5.0

git clone https://github.com/3eAI-Labs/sbi-ha-gateway-client
(cd sbi-ha-gateway-client/example && go run .) &

curl --http2-prior-knowledge http://127.0.0.1:8080/nudm-sdm/v2/imsi-001010000000001/am-data
curl --http2-prior-knowledge -X PUT -H 'Content-Type: application/json' \
  -d '{"amfInstanceId":"2b0e7b3c-1d6a-4f8e-9c2b-7a5d3e1f0c4a","deregCallbackUri":"http://amf.example/dereg","guami":{"plmnId":{"mcc":"001","mnc":"01"},"amfId":"cafe00"},"ratType":"NR"}' \
  http://127.0.0.1:8080/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access
curl --http2-prior-knowledge http://127.0.0.1:8080/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access
curl --http2-prior-knowledge -X POST -H 'Content-Type: application/json' -d '{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}' \
  http://127.0.0.1:8080/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data
```

The first answers 200 with the example's subscription data, the PUT 201 (200 when repeated, with
`Location`), the GET the registration, and the last 501: the example generates no
authentication vectors. Your back end replaces the example: it answers the same subjects (see
the client's README).

## Running it

```bash
make build            # bin/sbi-gateway
make test             # race detector on
make image            # container image sbi-ha-gateway:dev (distroless, non-root)
make image-smoke      # start the image next to NATS and check /health/ready
```

The gateway is configured through environment variables only (below) and needs a NATS server at
`NATS_URL`.

### Helm

```bash
helm install sbi oci://ghcr.io/3eai-labs/charts/sbi-ha-gateway --version <version> \
  --set config.nats.url=nats://nats.example:4222 \
  --set tls.existingSecret=sbi-tls --set config.mtls.clientCAFile=ca.crt \
  --set config.oauth.audience=<nf-instance-id> --set config.oauth.nrfJwksUrl=https://nrf.example/jwks
```

The gateway is secure by default. Its SBI port needs:
- TLS: `tls.existingSecret`, a Secret with `tls.crt`, `tls.key` and `ca.crt`;
- client certificates: `config.mtls.clientAuthMode` `require` with the CA;
- OAuth: `config.oauth`.

Each one is switched off only explicitly, with `config.security.allowPlaintextSbi`,
`config.mtls.clientAuthMode` `off` and `config.oauth.disabled`. A missing one stops the render with
what to set. The admin port is protected too:
- `/metrics` and `/admin/*` take a bearer token, from `config.admin.tokenSecret` or a Secret the
  chart creates;
- the port is served with the SBI certificate.

`config.admin.auth` and `config.admin.tls` switch these off.

Without `config.nats.url` the chart deploys its own single-replica core NATS for a trial install.
It then switches off what it lacks, explicitly, so that its defaults start and become Ready. No
application is connected to that NATS, so every request times out: set `config.nats.url` to the
NATS your applications use. The chart runs under the Kubernetes `restricted` Pod Security Standard.
`values.schema.json` documents every value. The chart adds a NetworkPolicy: the SBI port is open,
the admin port is reachable from the release's namespace and `networkPolicy.adminFrom` (add your
Prometheus). Files the gateway reads by path — outbound TLS, a JWKS file, the SMS resolver — are
mounted with `extraVolumes`.

`config.nrf` registers the gateway with the NRF: its `apiRoot` and `profiles`, one per NF type, each
a TS 29.510 NFProfile with NFService attributes for its services (see `values.yaml`). On
`helm uninstall` a post-delete Job deletes the profiles once no pod heartbeats them; if the NRF
cannot be reached the uninstall fails, and `--no-hooks` skips the Job. With TLS, register an
`fqdn` and serve the SBI on port 443 (`service.sbiPort`), or give `ipEndPoints` the address with the
port: a consumer that builds the URI from the FQDN uses 443, and some NRFs drop an `ipEndPoints`
entry that carries only a port (measured on Open5GS 2.7.6). free5GC's NRF with OAuth on serves a
TLS certificate named `NRF` alone: give `apiRoot` the host name `nrf`, through a Service or an
ExternalName so named, and keep its certificate directory on a persistent volume (see the
changelog). With `config.sms.enabled`, an `SMS_GMSC` profile (no `service`, not in
`config.oauth.audience`) is the instance MT SMS goes to the SMSF as: an SMS that names its SMSF by
instance ID (`routing.smsfInstanceId`) goes to the address the NRF's discovery gives, and when an
SMSF asks for an access token, the gateway obtains that instance's from the NRF, for that SMSF
alone when discovery found it, and sends it over https alone. free5GC's NRF (v4.3.0) refuses a
discovery whose requester is an SMS_GMSC (400, measured): such an SMS fails `DISCOVERY_FAILED`;
Open5GS 2.7.6 answers it. With `config.nrf.notificationApiRoot`, the `{apiRoot}` the NRF reaches
the SBI port at through the Service (with TLS, a name the SBI certificate holds), each pod
subscribes to the SMSFs it discovered: their deregistration, or a change of their profile, makes
it ask the NRF again at the next SMS. The NRF calls `/nrf-notify/v1/…` without an access token,
and a pod hands another pod's notifications to it over NATS (`sbi.internal.nrf.notify.>`, which
the gateway's NATS user must be allowed to publish and subscribe to). Open5GS 2.7.6 notifies a
deregistration but not a profile change (measured).

### Verifying a release

From 0.3.0 the image and the chart are signed keylessly with [cosign](https://docs.sigstore.dev/)
by 3eAI Labs' release workflow, which runs in the gateway's private source repository. The
certificate names that workflow at the release tag:

```bash
v=0.3.0
id="https://github.com/3eAI-Labs/sbi-ha-gateway-internal/.github/workflows/release.yml@refs/tags/v$v"
cosign verify ghcr.io/3eai-labs/sbi-ha-gateway:$v \
  --certificate-identity "$id" --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/3eai-labs/charts/sbi-ha-gateway:<chart version> \
  --certificate-identity "$id" --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image carries an SPDX SBOM and a provenance attestation
(`docker buildx imagetools inspect ghcr.io/3eai-labs/sbi-ha-gateway:$v --format '{{ json .SBOM }}'`).
Its `org.opencontainers.image.revision` label and its `sha-` tag name the commit of this
repository the release was built from.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `SBI_PORT` | `8080` | HTTP/2 port for network functions |
| `ADMIN_PORT` | `9090` | Admin port: `/metrics`, `/health/live`, `/health/ready`, `/admin/stats` |
| `ADMIN_TOKEN_FILE` | empty | File holding the bearer token `/metrics` and `/admin/*` require, read again every 10 s; the health endpoints stay open. Required unless `ADMIN_AUTH_DISABLED=true` |
| `ADMIN_AUTH_DISABLED` | `false` | `true` answers `/metrics` and `/admin/*` without a token (chart `config.admin.auth: false`) |
| `ADMIN_TLS` | `true` | Serve the admin port over TLS with the SBI port's certificate, without client certificates; `false` serves cleartext (chart `config.admin.tls`) |
| `NATS_URL` | `nats://localhost:4222` | NATS server(s). `tls://` for TLS against the system roots. Keep credentials out of it: they show in the environment |
| `NATS_CREDS_FILE`, `NATS_NKEY_SEED_FILE`, `NATS_TOKEN_FILE`, or `NATS_USER` with `NATS_PASSWORD_FILE` | empty | How the gateway authenticates to NATS: one of them; secrets are files. Two at once, or one with credentials in `NATS_URL`, stops the gateway |
| `NATS_TLS_CA_FILE` | empty | CA of the NATS server's certificate; TLS 1.3 |
| `NATS_TLS_CERT_FILE`, `NATS_TLS_KEY_FILE` | empty | Client certificate for NATS; TLS 1.3 |
| `NATS_CONNECT_TIMEOUT` | `5s` | Timeout of each connection attempt; the gateway keeps retrying |
| `NATS_REQUEST_TIMEOUT` | `2s` | Time the gateway waits for an application's reply; then 504 |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | empty | TLS 1.3 with ALPN `h2` on the SBI port; required unless `ALLOW_PLAINTEXT_SBI`. One alone stops the gateway |
| `ALLOW_PLAINTEXT_SBI` | `false` | `true` serves cleartext HTTP/2 (h2c, prior knowledge) without a certificate. HTTP/1.1 is refused either way |
| `MTLS_CLIENT_AUTH_MODE` | `require` | Client certificates on the SBI port: `require` (with `MTLS_CLIENT_CA_FILE`), `optional`, `off` |
| `MTLS_CLIENT_CA_FILE` | empty | CAs that sign network functions' certificates; required with `require` |
| `MTLS_OUTBOUND_CERT_FILE`, `MTLS_OUTBOUND_KEY_FILE`, `MTLS_OUTBOUND_CA_FILE` | empty | TLS for callbacks, SMSF calls and the NRF (its JWKS and the registration). The CA alone: TLS with that trust anchor; with a certificate and its key: mTLS. Any set: `https://` only. None: `https://` against the system roots, `http://` as h2c. Always HTTP/2 |
| `OAUTH_DISABLED` | `false` | An OAuth2 access token (TS 33.501) is required on every SBI request; `true` accepts requests without one |
| `OAUTH_AUDIENCE` | empty | Expected `aud`: this gateway's NF instance ID, or several comma-separated, any of which matches. Required with OAuth on; with NRF registration it must list each profile's `nfInstanceId` |
| `OAUTH_NRF_JWKS_URL` | empty | JWKS endpoint of the NRF; takes precedence over `OAUTH_JWKS_FILE`. Fetched with the `MTLS_OUTBOUND_*` trust anchor and certificate, 10 s at most per fetch |
| `OAUTH_JWKS_FILE` | empty | Static JWKS file |
| `OAUTH_JWKS_REFRESH` | `5m` | JWKS refresh interval, at least `1s`. While the gateway holds no key, the NRF is tried every 30 s |
| `OAUTH_CLOCK_SKEW` | `30s` | Tolerance on `exp` and `nbf` |
| `OAUTH_RESULT_CACHE_TTL` | `60s` | Cache of validated tokens, keyed by token and client certificate; `0` means the default |
| `OAUTH_REQUIRE_CERT_BINDING` | `false` | `true` rejects tokens without an RFC 8705 `cnf` claim. A token that has one is always checked against the client certificate |
| `NRF_API_ROOT` | empty | The NRF's `{apiRoot}` (`https://host[:port][/prefix]`): the gateway registers with it (TS 29.510 Nnrf_NFManagement). Needs `NRF_PROFILES_FILE` |
| `NRF_PROFILES_FILE` | empty | The NF profiles to register, JSON: `{"profiles": [{"profile": {...}, "service": {...}}]}`. `profile` is a TS 29.510 NFProfile, UDM, UDR or SMS_GMSC (`nfInstanceId` a lower-case UUID v4, an address, `udmInfo`, ...); `service` holds NFService attributes added to each service (e.g. `ipEndPoints`). The gateway adds `nfStatus`, `heartBeatTimer` and the services it serves. The SMS_GMSC profile, only with `SMS_ENABLED`, registers no service: MT SMS goes to the SMSF as that instance, with its access tokens, and SMSFs named by instance ID are discovered as it |
| `NRF_HEARTBEAT_TIMER` | empty | Heartbeat interval proposed at registration, whole seconds; empty: the NRF's |
| `NRF_NOTIFICATION_API_ROOT` | empty | The `{apiRoot}` the NRF reaches the SBI port at (`https://` with TLS, else `http://`). Set, each pod subscribes, as the SMS_GMSC, to the SMSFs it discovers, with callbacks under `{apiRoot}/nrf-notify/v1/`; needs the SMS_GMSC profile. Empty: no subscription |
| `RATE_LIMIT_RPS` | `0` | Token bucket per client (OAuth `sub`, else `User-Agent`, else address); `0` disables it |
| `RATE_LIMIT_BURST` | `100` | Bucket size |
| `OUTBOUND_ALLOWED_DESTINATIONS` | empty | Hosts callbacks and SMSF calls may reach: host names, `.domain` suffixes, CIDR blocks, addresses, comma-separated; checked on the address actually dialled. Empty: none. Loopback, link-local (cloud metadata), unspecified and multicast addresses only when listed by address. With name rules alone an unlisted name is refused without a DNS query; a CIDR or address rule makes every name resolved, to be checked |
| `OUTBOUND_ALLOW_ANY` | `false` | `true` allows any destination but the always-refused addresses |
| `OUTBOUND_PROFILE` | `sbi_direct` | `sbi_direct` POSTs notifications to the callback URI; `scef_rest` acknowledges them and leaves delivery to an external adapter |
| `SMS_ENABLED` | `false` | Serve the SMS surfaces. Needs a NATS with JetStream |
| `SMS_RESOLVER_FILE` | empty | JSON map from MSISDN to `{Supi, SmsfFqdn, SmsfInstanceId, SmsfPlmnId}` for the serving-SMSF lookup, with `SmsfFqdn`, `SmsfInstanceId` or both. Empty: every lookup answers 404 |
| `SMS_UECM_TIMEOUT` | `3s` | Time budget of one serving-SMSF lookup |
| `SMS_STREAM` | `SBI_SMSF_SEND` | The stream the gateway creates, a work queue with one replica, when no stream captures `sbi.outbound.nsmsf.send.request`; it uses the one that does, whatever its name |
| `SMS_DELIVERY_EVENT_SUBJECT` | `sbi.nsmsf.delivery.event` | Where each SMS's `DeliveryEvent` goes: through JetStream when a stream captures it, as a core publish otherwise |
| `AUDIT_DISABLED` | `false` | Audit events, with SUPIs masked and no body: every state-changing operation with its outcome (`success`, `rejected`, `failed`), status, cause and request ID; OAuth refusals; the notifications and SMS sent for applications |
| `AUDIT_NATS_SUBJECT` | `audit.events` | Subject of the audit events |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. A line per request is `debug`, a 5xx `warn`; it names the route, not the URI with its SUPI |
| `MAX_RETRIES` | `3` | Passes over a notification's callback URIs, the first included, before it is reported on `5g.data.notify.failed` |
| `NOTIFY_WORKERS` | `32` | Notifications delivered at once; one whose network function does not answer holds one worker. Their order is not kept |
| `RETRY_BASE_DELAY` | `1s` | Wait after the first failed pass; it doubles after each further one |
| `SHUTDOWN_DRAIN_DELAY` | `5s` | After SIGTERM the SBI port goes on serving this long, `/health/ready` answering 503, before it closes; `0` closes at once |
| `SHUTDOWN_TIMEOUT` | `20s` | Then the time the requests in flight, the notification deliveries and the SMS being sent have to finish. Drain delay plus this must stay below the pod's `terminationGracePeriodSeconds` |

Invalid settings stop the gateway at start-up rather than weakening it or running otherwise than
asked: no TLS without `ALLOW_PLAINTEXT_SBI`, OAuth on without an audience or a JWKS source,
`require` without a CA file, a certificate
without its key (or the reverse), client-certificate settings without TLS, an incomplete outbound
certificate, an NRF profile file that does not check out, an unknown `OUTBOUND_PROFILE` or `LOG_LEVEL`, `MAX_RETRIES` or `NOTIFY_WORKERS` below
1, a negative `SHUTDOWN_DRAIN_DELAY`, a `SHUTDOWN_TIMEOUT` that is not positive.

The SBI port drops a connection whose request headers take over 10 s, limits each stream to 30 s of
reading and to the NATS request timeout plus 10 s (at least 30 s) of writing, closes connections idle
for 2 minutes, and refuses request bodies over 1 MiB with 413.

## Observability

Prometheus metrics under `sbi_gateway_` on the admin port: requests and their durations by route
pattern, NATS requests, OAuth validations, notification deliveries and failover position, SMS
lookups and sends, audit events, the NRF's JWKS (`oauth_jwks_keys`, `oauth_jwks_refreshes_total`,
`oauth_jwks_last_refresh_timestamp_seconds`), the NRF registration (`nrf_registered`,
`nrf_requests_total`, `nrf_last_contact_timestamp_seconds`, `nrf_notifications_total`), certificate expiry
(`tls_certificate_expiry_timestamp_seconds`), TLS handshakes not completed
(`tls_handshake_failures_total`) and NATS connection events (`nats_events_total`: disconnected,
reconnected, slow_consumer). The chart can add a Prometheus Operator ServiceMonitor
(`metrics.serviceMonitor`, with the admin token and TLS) and a PrometheusRule
(`metrics.prometheusRule`) alerting on:
- a pod down, no NATS connection, no OAuth verification key;
- the 5xx and OAuth rejection ratios;
- undelivered notifications and SMS, audit loss, a slow consumer;
- a profile no pod holds registered with the NRF, a pod that cannot reach the NRF, a pod whose
  SMSF discoveries all fail, a pod whose subscriptions to the SMSFs all fail;
- a certificate near expiry, a protection switched off. `/health/ready` is 200 while the NATS connection is up and, with OAuth on,
the gateway holds a verification key; 503 otherwise, and from SIGTERM on, with the reasons in its
JSON body (`draining`, `nats_disconnected`, `oauth_no_verification_key`) and a log line when they
change. Logs are JSON on standard
output.

## Known limitations

- **Not all of TS 29.503 is served.**
  - Nudm_NIDDAuthorisation, Nudm_ServiceSpecificAuthorisation and Nudm_UEIdentifier are not
    routed: they are answered 400 `INVALID_API`.
  - Nudr_DataRepository serves subscription data only.
  - Identifiers outside the formats above are refused, though TS 29.571's patterns admit any string.
- **NRF: registration, access tokens, SMSF discovery and subscriptions only.** The gateway
  registers its profiles and heartbeats them, obtains access tokens from the NRF for NFManagement
  and for MT SMS, when the NRF or the SMSF asks for one, discovers an SMSF that an SMS names by
  instance ID, and, with `NRF_NOTIFICATION_API_ROOT`, subscribes to the SMSFs it discovered. A
  discovered address serves for the NRF's `validityPeriod`, and longer while the NRF does not
  answer; a notified deregistration or profile change ends it sooner. Without the setting, or
  with an NRF that does not notify (Open5GS 2.7.6 notifies no profile change), the
  `validityPeriod` alone bounds it. The NRF's notifications are not authenticated: the random key
  in the callback URI guards them, and they only make the gateway ask the NRF again.
  Notifications the gateway sends carry no token: their callbacks state no security in the 3GPP
  OpenAPI definitions.

## Roadmap

Next, as users ask for them:
- the gateway as the SMSF's service-based interface (Nsmsf_SMService towards the AMF);
- the Nudm APIs not served (NIDDAuthorisation, ServiceSpecificAuthorisation, UEIdentifier) and
  Nudr data beyond subscription data;
- OAuth2: an `iss` check and reloading a JWKS file;
- the NRF's notifications over TLS with client certificates, measured; SCP and SEPP routing.

Open an issue for what your network needs.

## Licence

The gateway is licensed under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0-only). A commercial licence without the AGPL's obligations is available from 3eAI Labs
([NOTICE](NOTICE)). The wire-contract client is a separate work under the Apache License 2.0.
Contributions require the [3eAI Labs Contributor Licence Agreement](CLA.md); see
[CONTRIBUTING.md](CONTRIBUTING.md).
