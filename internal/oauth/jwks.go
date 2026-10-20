// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwksFetchTimeout bounds one fetch of the NRF's JWKS when JWKSConfig.HTTPClient is nil: an
// NRF that accepts the connection and never answers must not hold the gateway's start-up,
// nor a refresh, indefinitely.
var jwksFetchTimeout = 10 * time.Second

// allowedAlgs is the JWS algorithm allowlist, applied at JWKS-fetch time so
// disallowed keys never reach the verifier. Carrier guidance (TS 33.501 §6.7
// + GSMA FS.40 §4.2) limits NF authn signatures to RS256 / ES256.
//
// Adding HS* would be a key-confusion footgun (symmetric key shared between
// signer/verifier). Adding `none` would defeat the entire authN. Both stay
// out of this map by design.
var allowedAlgs = map[jwa.SignatureAlgorithm]struct{}{
	jwa.RS256: {},
	jwa.ES256: {},
}

// JWKSConfig describes where to fetch verification keys from. NRFURL takes
// precedence; FilePath is used only without it (CI, air-gapped), read once at start-up,
// never as a fallback when the NRF fails. At least one must be set.
type JWKSConfig struct {
	NRFURL          string        // e.g. https://nrf.5gc.local/oauth2/jwks
	FilePath        string        // local JSON JWKS, used when NRFURL is empty
	RefreshInterval time.Duration // foreground TTL, default 5m
	NegativeTTL     time.Duration // retry interval while no key is held, default 30s
	// HTTPClient fetches from NRFURL: the NRF's trust anchor, the gateway's client
	// certificate, a timeout. nil: system roots, no certificate, a 10 s timeout.
	HTTPClient *http.Client
}

func (c *JWKSConfig) defaults() {
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = 5 * time.Minute
	}
	if c.NegativeTTL <= 0 {
		c.NegativeTTL = 30 * time.Second
	}
}

// keySource is the minimal interface the validator needs from the JWKS layer.
// It hides whether keys came from NRF discovery or a static file behind one
// surface, which keeps the validator straightforward and the test doubles tiny.
type keySource interface {
	keys() jwk.Set
	// held is the number of verification keys the source has, 0 before the NRF first
	// answered with one.
	held() int64
}

type cachedKeySource struct {
	cache *jwk.Cache
	url   string
	count atomic.Int64 // keys of the last successful fetch
}

func (c *cachedKeySource) keys() jwk.Set {
	return jwk.NewCachedSet(c.cache, c.url)
}

func (c *cachedKeySource) held() int64 { return c.count.Load() }

// fetched filters a fetched set and records what it holds: every successful fetch ends here.
// A failure is counted where it surfaces: the error sink, or the start-up Refresh.
func (c *cachedKeySource) fetched(u string, in jwk.Set) (jwk.Set, error) {
	out, err := filterByAlg(u, in)
	if err != nil {
		return nil, err
	}
	c.count.Store(int64(out.Len()))
	metrics.RecordJWKSRefresh(true)
	metrics.SetJWKSKeys(out.Len())
	return out, nil
}

// retryWhileKeyless fetches from the NRF every retry while the source holds no key, until ctx
// ends. httprc schedules the fetch after a failed one at the full refresh interval: a gateway
// started while the NRF was down would otherwise stay unready, rejecting every token, for
// OAUTH_JWKS_REFRESH (5 m by default).
func (c *cachedKeySource) retryWhileKeyless(ctx context.Context, retry time.Duration, log *slog.Logger) {
	tick := time.NewTicker(retry)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if c.held() > 0 {
			continue
		}
		if _, err := c.cache.Refresh(ctx, c.url); err != nil && ctx.Err() == nil {
			metrics.RecordJWKSRefresh(false)
			log.Warn("NRF JWKS fetch failed; no verification key yet", slog.String("url", c.url), slog.Any("error", err))
		}
	}
}

type staticKeySource struct{ set jwk.Set }

func (s *staticKeySource) keys() jwk.Set { return s.set }

func (s *staticKeySource) held() int64 { return int64(s.set.Len()) }

// loadKeySource constructs the right keySource for cfg. With NRFURL it sets
// up a background-refreshed cache + algorithm-allowlist post-fetcher. With
// FilePath it loads once and filters in-memory. Errors come back wrapped so
// the operator can tell *which* source failed at startup.
func loadKeySource(ctx context.Context, cfg JWKSConfig, log *slog.Logger) (keySource, error) {
	cfg.defaults()

	if cfg.NRFURL != "" {
		// RefreshWindow controls how often the cache scans for due
		// refreshes. The default is 15m which silently bumps any
		// per-URL RefreshInterval below 15m to 15m — exactly the
		// "1-hour blast radius on key rotation" we explicitly rejected.
		// Pin it to 30s so a 5m foreground TTL is honoured.
		// httprc replaces a window under 1 s with its 15 m default, and then refuses the
		// registration: the window is kept within [1 s, 30 s], the interval at 1 s at least.
		if cfg.RefreshInterval < time.Second {
			return nil, fmt.Errorf("OAUTH_JWKS_REFRESH (%s) must be at least 1s", cfg.RefreshInterval)
		}
		window := min(max(cfg.RefreshInterval/2, time.Second), 30*time.Second)
		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: jwksFetchTimeout}
		}
		src := &cachedKeySource{url: cfg.NRFURL}
		src.cache = jwk.NewCache(ctx,
			jwk.WithErrSink(jwkErrSink{log: log}),
			jwk.WithRefreshWindow(window),
		)
		err := src.cache.Register(
			cfg.NRFURL,
			jwk.WithHTTPClient(client),
			jwk.WithMinRefreshInterval(cfg.RefreshInterval),
			jwk.WithRefreshInterval(cfg.RefreshInterval),
			jwk.WithPostFetcher(jwk.PostFetchFunc(src.fetched)),
		)
		if err != nil {
			return nil, fmt.Errorf("register NRF JWKS %q: %w", cfg.NRFURL, err)
		}
		// Prime the cache so the first incoming request doesn't pay the
		// fetch latency. A failure here is not fatal — the cache will
		// retry in the background; the validator will reject all tokens
		// until a refresh succeeds, which is the correct fail-closed
		// behaviour for a security middleware. Readiness says so meanwhile (Ready).
		if _, err := src.cache.Refresh(ctx, cfg.NRFURL); err != nil {
			metrics.RecordJWKSRefresh(false) // the error sink sees only background refreshes
			log.Warn("initial NRF JWKS fetch failed; validator will fail-closed until next refresh",
				slog.String("url", cfg.NRFURL),
				slog.Any("error", err),
			)
		}
		go src.retryWhileKeyless(ctx, cfg.NegativeTTL, log)
		return src, nil
	}

	if cfg.FilePath != "" {
		set, err := loadJWKSFile(cfg.FilePath)
		if err != nil {
			return nil, fmt.Errorf("load JWKS file %q: %w", cfg.FilePath, err)
		}
		metrics.SetJWKSKeys(set.Len())
		return &staticKeySource{set: set}, nil
	}

	return nil, errors.New("oauth: JWKS misconfigured — set OAUTH_NRF_JWKS_URL or OAUTH_JWKS_FILE")
}

func loadJWKSFile(path string) (jwk.Set, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- OAUTH_JWKS_FILE, set by the operator, never by a request
	if err != nil {
		return nil, err
	}
	parsed, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	filtered, err := filterByAlg(path, parsed)
	if err != nil {
		return nil, err
	}
	if filtered.Len() == 0 {
		return nil, errors.New("no keys with allowed algorithm (RS256/ES256) in file")
	}
	return filtered, nil
}

// filterByAlg drops any key whose `alg` attribute is missing or not in the
// allowlist. Runs after every successful refresh — a rotated NRF that adds an
// HS256 key by mistake will not poison this validator.
func filterByAlg(_ string, in jwk.Set) (jwk.Set, error) {
	out := jwk.NewSet()
	for i := 0; i < in.Len(); i++ {
		key, ok := in.Key(i)
		if !ok {
			continue
		}
		algRaw := key.Algorithm()
		alg, ok := algRaw.(jwa.SignatureAlgorithm)
		if !ok {
			// Key has no `alg` or non-signature alg (e.g. encryption) — drop.
			continue
		}
		if _, allowed := allowedAlgs[alg]; !allowed {
			continue
		}
		if err := out.AddKey(key); err != nil {
			return nil, fmt.Errorf("add filtered key: %w", err)
		}
	}
	return out, nil
}

// jwkErrSink routes background-refresh errors from the jwk.Cache into our
// structured logger. Without this, those failures vanish into stderr and the
// only signal that NRF is unreachable is "every token rejected".
type jwkErrSink struct{ log *slog.Logger }

func (s jwkErrSink) Error(err error) {
	metrics.RecordJWKSRefresh(false)
	s.log.Warn("JWKS background refresh failed", slog.Any("error", err))
}
