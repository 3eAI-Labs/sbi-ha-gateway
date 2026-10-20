# Security Policy

## Supported versions

Only the most recent release receives fixes. There are no long-term support branches.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/3eAI-Labs/sbi-ha-gateway/security/advisories/new).
The report stays private between you and the maintainers until a fix is published.

Useful things to include, roughly in order of how much they help:

- Version (container image tag or commit) and the affected component (SBI API, OAuth2 token
  validation, mTLS, rate limiting, NATS bridge, notification delivery, SMS surfaces, audit, admin
  port, Helm chart)
- What an attacker gains — the impact matters more than the mechanism
- A reproduction: a failing test, or the exact HTTP requests or NATS messages. Strip real subscriber
  identities (SUPI, SUCI, GPSI, MSISDN), authentication vectors, tokens and operator NF identities
  before attaching anything
- The relevant configuration (environment variables or Helm values), credentials removed

You will get an acknowledgement, and an honest estimate rather than a promised deadline. If a
report turns out to be a plain bug rather than a vulnerability, you will be told so and asked to
move it to a public issue.

## Scope

In scope — anything in this repository that lets an attacker:

- get a request accepted that the configuration should refuse: an access token not signed by a key
  in the configured JWKS, or with the wrong audience, scope or expiry, a token bound (RFC 8705) to
  another client certificate, a client certificate the configured CA did not sign while
  `MTLS_CLIENT_AUTH_MODE=require`
- read or alter subscriber data (SUPI, location, registrations, authentication vectors) that should
  not reach them, including through logs, metrics, audit events or NATS subjects
- crash the gateway or exhaust its memory with crafted HTTP/2 requests or NATS messages
- get a notification or an SMS delivered somewhere other than where the application asked
- obtain secrets from a deployment that followed the Helm chart's documented production settings

Out of scope, because the gateway does not claim to handle them:

- **Protections switched off on purpose.** The gateway requires TLS, client certificates and
  OAuth2 by default. It refuses to start without them, unless each is switched off explicitly:
  `ALLOW_PLAINTEXT_SBI`, `MTLS_CLIENT_AUTH_MODE` `off`/`optional`, `OAUTH_DISABLED`.
  - Each one switched off is logged at start-up and shows as 0 in `sbi_gateway_security_protection`.
  - Rate limiting is off by default.
- **The admin port** (`ADMIN_PORT`, default 9090: `/metrics`, `/health/*`, `/admin/stats`):
  - By default `/metrics` and `/admin/*` require a bearer token (`ADMIN_TOKEN_FILE`), and the
    port is served with the SBI certificate (`ADMIN_TLS`). `ADMIN_AUTH_DISABLED=true` and
    `ADMIN_TLS=false` switch these off explicitly.
  - The chart's NetworkPolicy admits only the release's namespace and `networkPolicy.adminFrom`.
  - The health endpoints always answer without a token: the kubelet probes them.
  - When either protection is off, a WARN at start-up and `sbi_gateway_security_protection`
    (`admin_auth`, `admin_tls`) say so.
- **NATS.** Whoever can publish on the gateway's subjects can make it answer network functions,
  send POST requests to a callback URI or SMSF address in their message, and send SMS. Those
  requests reach only the hosts `OUTBOUND_ALLOWED_DESTINATIONS` lists. The check runs on the
  address actually dialled, and loopback, link-local and metadata addresses are refused unless
  listed by address.
  - The gateway authenticates to NATS with user credentials, an nkey, a user and password, or a
    token, and can use TLS 1.3 with its own CA and a client certificate (`NATS_*` settings,
    secrets as files).
  - Use them, and give the gateway's NATS user only the subjects it needs. The permissions, and
    the NATS server itself, are the deployment's responsibility.
- **Client identity for rate limiting without OAuth.** The key is then the `User-Agent` header,
  which the client chooses; without one it is the TCP peer's address (forwarding headers are not
  believed). The limiter is a guard against misbehaving peers, not against an attacker, unless
  OAuth is on.
- Weaknesses of the 5G SBI protocols themselves that the standards leave to operators — the
  gateway is not a substitute for a SEPP or an API firewall at the network edge.
- The Helm chart's trial defaults (the bundled NATS), which the chart documents as unsuitable for
  production.
