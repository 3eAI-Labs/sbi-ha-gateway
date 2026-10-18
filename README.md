# sbi-ha-gateway

A 5G service-based interface (SBI) gateway. It serves part of the UDM and UDR APIs of a 5G core —
Nudm (UEAU, UECM, SDM, MT, PP, EE) and Nudr DataRepository, 3GPP TS 29.503 and TS 29.504/29.505 —
over HTTP/2, and hands each request to an application over NATS. It also delivers notifications to
network functions' callback URIs and sends SMS through an SMSF (Nsmsf_SMService, TS 29.540) for an
SMS platform.

The gateway keeps no subscriber state. Replicas share the work through NATS queue groups and a
JetStream work queue, so it scales horizontally.

**Status: 0.2.0, the first public release.** It has not carried traffic on a production network.
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
            │  HTTP/2 POST to callback URIs, Nsmsf SendSMS to the SMSF
            ▼
   network functions, SMSF
```

- **Network function → application.** Each SBI operation becomes a core NATS request on a `5g.*`
  subject. The application's reply becomes the HTTP response.
- **Application → network function.** A message on `5g.data.notify` is POSTed to its callback URI,
  failing over to alternate URIs on 5xx, 429 or transport errors, in up to `MAX_RETRIES` passes
  with backoff. A 4xx ends the delivery.
- **SMS (opt-in, `OTA_ENABLED`).** An SMS platform asks which SMSF serves a subscriber
  (`sbi.outbound.nudm.uecm.request`) and sends SMS through it
  (`sbi.outbound.nsmsf.send.request`, a JetStream work queue); the gateway reports each result on
  `ota.delivery.event`.

The subjects and JSON messages are defined by the Apache-2.0 module
[sbi-ha-gateway-client](https://github.com/3eAI-Labs/sbi-ha-gateway-client), which applications can
link under any licence.

## Operations served

| Service | Method and path | NATS subject |
|---------|-----------------|--------------|
| Nudm_UEAU | `POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data` | `5g.auth.request` |
| Nudm_UEAU | `POST /nudm-ueau/v1/{supi}/auth-events` | `5g.auth.confirm` |
| Nudm_UECM | `GET /nudm-uecm/v1/{ueId}/registrations` | `5g.mobility.query` |
| Nudm_UECM | `GET`, `PUT`, `PATCH /nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access` | `5g.mobility.query` (GET) or `5g.mobility.registration` |
| Nudm_UECM | `GET /nudm-uecm/v1/{ueId}/registrations/smf-registrations` | `5g.mobility.query` |
| Nudm_UECM | `GET`, `PUT`, `PATCH`, `DELETE /nudm-uecm/v1/{ueId}/registrations/smf-registrations/{pduSessionId}` | `5g.mobility.query` (GET) or `5g.mobility.registration` |
| Nudm_UECM | `GET`, `PUT`, `DELETE /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access` | `5g.mobility.query` (GET) or `5g.mobility.registration` |
| Nudm_MT | `POST /nudm-mt/v1/{supi}/loc-info/provide-loc-info` | `5g.mt.loc-info` |
| Nudm_SDM | `GET /nudm-sdm/v1/{supi}`, `GET /nudm-sdm/v1/{supi}/{dataSet}`, `GET /nudm-sdm/v1/shared-data` | `5g.data.query` |
| Nudm_SDM | any method on `/nudm-sdm/v1/{supi}/sdm-subscriptions…` | `5g.data.query` (GET) or `5g.data.update` |
| Nudm_PP | any method on `/nudm-pp/v1/{ueId}/pp-data` | `5g.data.query` (GET) or `5g.data.update` |
| Nudm_EE | any method on `/nudm-ee/v1/{ueIdentity}/ee-subscriptions…` | `5g.data.query` (GET) or `5g.data.update` |
| Nudr_DR | `GET /nudr-dr/v1/{dataSet}/{ueId}`, `GET …/shared-data`, `GET …/shared-data/{sharedDataId}`, any method on `/nudr-dr/v1/{dataSet}/{ueId}/…` | `5g.data.query` (GET) or `5g.data.update` |

Each URI variable accepts the identifiers TS 29.503 and TS 29.505 give it: a SUPI (`imsi-<5–15
digits>` or `nai-<user>@<realm>`) for `{supi}`; a SUPI or a SUCI for `{supiOrSuci}`; for `{ueId}`
a SUPI (UECM PUT, PATCH, DELETE), a SUPI or a GPSI (`msisdn-<5–15 digits>`, `extid-<id>@<domain>`;
UECM GET, Nudr), or also an External Group Id (`extgroupid-<id>@<domain>`; PP); for `{ueIdentity}`
a GPSI, an External Group Id or `anyUE` (EE). `<id>` and `<domain>` take letters, digits and
`.`, `_`, `~`, `+`, `-` only, and `{pduSessionId}` is 0–255. Anything else is answered 400
`MANDATORY_IE_INCORRECT`, with the variable in `invalidParams`, before NATS is involved; a data
resource path with a `.` or `..` segment or an escaped `/` is answered 404.

A PUT of a registration is answered 201 with `Location` when the application created it, 200 when
it replaced one; auth-events is answered 201 with `Location` ending in the `authEventId` the
application assigned.

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
helm install sbi oci://ghcr.io/3eai-labs/charts/sbi-ha-gateway --version 0.2.0 \
  --set config.nats.url=nats://nats.example:4222
```

Without `config.nats.url` the chart deploys its own single-replica core NATS so that a trial install
becomes Ready. No application is connected to it, so every request then times out — set
`config.nats.url` to the NATS your applications use. The chart runs under the Kubernetes `restricted`
Pod Security Standard. `values.schema.json` documents every value.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `SBI_PORT` | `8080` | HTTP/2 port for network functions |
| `ADMIN_PORT` | `9090` | Admin port: `/metrics`, `/health/live`, `/health/ready`, `/admin/stats` |
| `NATS_URL` | `nats://localhost:4222` | NATS server. Credentials and TLS only through the URL (see [SECURITY.md](SECURITY.md)) |
| `NATS_CONNECT_TIMEOUT` | `5s` | Timeout of each connection attempt; the gateway keeps retrying |
| `NATS_REQUEST_TIMEOUT` | `2s` | Time the gateway waits for an application's reply; then 504 |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | empty | Both set: TLS 1.3 with ALPN `h2`. Neither: cleartext HTTP/2 (h2c). One alone stops the gateway |
| `MTLS_CLIENT_AUTH_MODE` | `off` | Client certificates on the SBI port: `off`, `optional`, `require` |
| `MTLS_CLIENT_CA_FILE` | empty | CAs that sign network functions' certificates; required with `require` |
| `MTLS_OUTBOUND_CERT_FILE`, `MTLS_OUTBOUND_KEY_FILE`, `MTLS_OUTBOUND_CA_FILE` | empty | Client certificate for callbacks and SMSF calls; all three or none |
| `OAUTH_DISABLED` | `true` | `false` requires an OAuth2 access token (TS 33.501) on every SBI request |
| `OAUTH_AUDIENCE` | empty | Expected `aud`: this gateway's NF instance ID. Required with OAuth on |
| `OAUTH_NRF_JWKS_URL` | empty | JWKS endpoint of the NRF; takes precedence over `OAUTH_JWKS_FILE` |
| `OAUTH_JWKS_FILE` | empty | Static JWKS file |
| `OAUTH_JWKS_REFRESH` | `5m` | JWKS refresh interval |
| `OAUTH_CLOCK_SKEW` | `30s` | Tolerance on `exp` and `nbf` |
| `OAUTH_RESULT_CACHE_TTL` | `60s` | Cache of validated tokens, keyed by token and client certificate; `0` means the default |
| `OAUTH_REQUIRE_CERT_BINDING` | `false` | `true` rejects tokens without an RFC 8705 `cnf` claim. A token that has one is always checked against the client certificate |
| `RATE_LIMIT_RPS` | `0` | Token bucket per client (OAuth `sub`, else `User-Agent`, else address); `0` disables it |
| `RATE_LIMIT_BURST` | `100` | Bucket size |
| `OUTBOUND_PROFILE` | `sbi_direct` | `sbi_direct` POSTs notifications to the callback URI; `scef_rest` acknowledges them and leaves delivery to an external adapter |
| `OTA_ENABLED` | `false` | Serve the SMS surfaces. Needs JetStream and the application's stream `OTA_OUTBOUND` |
| `OTA_RESOLVER_FILE` | empty | JSON map from MSISDN to `{Supi, SmsfFqdn, SmsfPlmnId}` for the serving-SMSF lookup. Empty: every lookup answers 404 |
| `OTA_UECM_TIMEOUT` | `3s` | Time budget of one serving-SMSF lookup |
| `AUDIT_DISABLED` | `false` | Audit events for state-changing operations, with SUPIs masked and key material redacted |
| `AUDIT_NATS_SUBJECT` | `audit.events` | Subject of the audit events |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `MAX_RETRIES` | `3` | Passes over a notification's callback URIs, the first included, before it is dropped |
| `RETRY_BASE_DELAY` | `1s` | Wait after the first failed pass; it doubles after each further one |

Invalid settings stop the gateway at start-up rather than weakening it or running otherwise than
asked: OAuth on without an audience or a JWKS source, `require` without a CA file, a certificate
without its key (or the reverse), client-certificate settings without TLS, an incomplete outbound
certificate, an unknown `OUTBOUND_PROFILE` or `LOG_LEVEL`, `MAX_RETRIES` below 1.

The SBI port drops a connection whose request headers take over 10 s, limits each stream to 30 s of
reading and to the NATS request timeout plus 10 s (at least 30 s) of writing, closes connections idle
for 2 minutes, and refuses request bodies over 1 MiB with 413.

## Observability

Prometheus metrics under `sbi_gateway_` on the admin port: requests and their durations by route
pattern, NATS requests, OAuth validations, notification deliveries and failover position, SMS
lookups and sends, audit events. `/health/ready` is 200 while the NATS connection is up and 503
otherwise. Logs are JSON on standard output.

## Known limitations

These are open in 0.2.0.

- **Not all of TS 29.503 is served.** Among the operations the table above does not list: AMF and
  SMSF registrations for non-3GPP access, the UECM custom operations (dereg-amf, pei-update,
  roaming-info-update, send-routing-info-sm), updating an auth event
  (`PUT …/auth-events/{authEventId}`), and the services other than UEAU, UECM, SDM, PP, EE and MT.
  They are answered 404 or 405. Identifiers outside the formats above are refused, though TS
  29.571's patterns admit any string.
- **NATS has no TLS or authentication settings of its own.** See [SECURITY.md](SECURITY.md).

## Licence

The gateway is licensed under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0-only). A commercial licence without the AGPL's obligations is available from 3eAI Labs
([NOTICE](NOTICE)). The wire-contract client is a separate work under the Apache License 2.0.
Contributions require the [3eAI Labs Contributor Licence Agreement](CLA.md); see
[CONTRIBUTING.md](CONTRIBUTING.md).
