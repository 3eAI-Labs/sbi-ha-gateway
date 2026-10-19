// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/admin"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/config"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/uecm"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/oauth"
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/logger"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/server"
)

func main() {
	if err := Run(); err != nil {
		slog.Error("Application failed", slog.Any("error", err))
		os.Exit(1)
	}
}

// Run starts the application with OS signal handling for graceful shutdown
func Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	return RunWithContext(ctx)
}

// RunWithContext starts the application with the given context for shutdown control
func RunWithContext(ctx context.Context) error {
	// 1. Load Configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	// 2. Initialize Logger. An unknown LOG_LEVEL stops the gateway rather than
	//    logging at a level nobody asked for.
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("LOG_LEVEL %q: want debug, info, warn or error", cfg.LogLevel)
	}
	log := logger.InitLogger("sbi-ha-gateway", level)
	if cfg.MaxRetries < 1 || cfg.RetryBaseDelay <= 0 || cfg.NotifyWorkers < 1 {
		return fmt.Errorf("MAX_RETRIES (%d) and NOTIFY_WORKERS (%d) must be at least 1 and RETRY_BASE_DELAY (%s) positive",
			cfg.MaxRetries, cfg.NotifyWorkers, cfg.RetryBaseDelay)
	}
	// Secure by default: cleartext is an explicit choice.
	if !cfg.TLSEnabled() && !cfg.AllowPlaintextSBI {
		return errors.New("the SBI port needs TLS: set TLS_CERT_FILE and TLS_KEY_FILE, " +
			"or ALLOW_PLAINTEXT_SBI=true to serve cleartext h2c")
	}
	// The SBI port's TLS configuration (server.BuildTLSConfig: TLS 1.3 and the client
	// certificate modes), checked before anything connects. Misconfiguration is fatal.
	tlsCfg, err := server.BuildTLSConfig(server.TLSOptions{
		CertFile:       cfg.TLSCertFile,
		KeyFile:        cfg.TLSKeyFile,
		ClientCAFile:   cfg.MTLSClientCAFile,
		ClientAuthMode: server.ClientAuthMode(cfg.MTLSClientAuthMode),
	})
	if err != nil {
		log.Error("TLS config build failed", slog.Any("error", err))
		return err
	}
	if cfg.ShutdownDrainDelay < 0 || cfg.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_DRAIN_DELAY (%s) must not be negative and SHUTDOWN_TIMEOUT (%s) must be positive",
			cfg.ShutdownDrainDelay, cfg.ShutdownTimeout)
	}
	log.Info("Starting SBI HA Gateway...",
		slog.String("sbi_port", cfg.SBIPort),
		slog.String("admin_port", cfg.AdminPort),
	)

	// 3. Initialize NATS
	natsSec := nats.Security{
		CredsFile: cfg.NatsCredsFile, NkeySeedFile: cfg.NatsNkeySeedFile,
		User: cfg.NatsUser, PasswordFile: cfg.NatsPasswordFile, TokenFile: cfg.NatsTokenFile,
		CAFile: cfg.NatsTLSCAFile, CertFile: cfg.NatsTLSCertFile, KeyFile: cfg.NatsTLSKeyFile,
	}
	natsAuth, natsTransport := natsSec.Describe(cfg.NatsURL)
	log.Info("Connecting to NATS", slog.String("authentication", natsAuth), slog.String("transport", natsTransport))
	nc, err := nats.NewClientWithSecurity(cfg.NatsURL, log, cfg.NatsConnectTimeout, natsSec)
	if err != nil {
		log.Error("Failed to connect to NATS", slog.Any("error", err))
		return err
	}
	defer nc.Close()

	// 3.1 Wire the audit publisher to NATS. Tear-down on shutdown.
	if !cfg.AuditDisabled {
		cgaudit.SetPublisher(nc.GetConn(), cfg.AuditNATSSubject)
		log.Info("Audit publisher wired",
			slog.String("subject", cfg.AuditNATSSubject),
		)
		defer cgaudit.SetPublisher(nil, "")
	} else {
		log.Warn("Audit DISABLED — state-changing operations will not be audited (AUDIT_DISABLED=true)")
	}

	// 4. Setup Router & Handlers
	sbiH := handlers.NewSBIHandler(log, nc, cfg.NatsRequestTimeout)

	// 4.0 Build OAuth validator (or nil when disabled). Failing here is
	// fatal: a misconfigured auth subsystem must not silently degrade to
	// open-access. The only way to start without OAuth is OAUTH_DISABLED=true.
	oauthValidator, err := buildOAuthValidator(ctx, cfg, log)
	if err != nil {
		log.Error("OAuth validator init failed", slog.Any("error", err))
		return err
	}
	if oauthValidator != nil {
		log.Info("OAuth2 NF token authentication enabled",
			slog.String("audience", cfg.OAuthAudience),
			slog.String("nrf_jwks_url", cfg.OAuthNRFJWKSURL),
			slog.String("jwks_file", cfg.OAuthJWKSFile),
		)
	}
	reportSecurity(log, cfg)

	r := server.NewRouter(server.RouterConfig{
		SBI:            sbiH,
		OAuthValidator: oauthValidator,
		RateLimitRPS:   cfg.RateLimitRPS,
		RateLimitBurst: cfg.RateLimitBurst,
		Logger:         log,
	})

	// 4.1 Build outbound HTTP/2 client. mTLS config is fatal-on-partial
	// (cert without key, etc.) — see sbi.buildOutboundTLS.
	amfCfg := sbi.DefaultAmfClientConfig()
	amfCfg.TLSCertFile = cfg.MTLSOutboundCertFile
	amfCfg.TLSKeyFile = cfg.MTLSOutboundKeyFile
	amfCfg.TLSCAFile = cfg.MTLSOutboundCAFile
	// Where callbacks and SMSF calls may go, checked on the dialled
	// address.
	amfCfg.Destinations, err = sbi.ParseDestinations(cfg.OutboundAllowedDestinations, cfg.OutboundAllowAny)
	if err != nil {
		return err
	}
	amfClient, err := sbi.NewAmfClientWithConfig(amfCfg)
	if err != nil {
		log.Error("Outbound HTTP client init failed", slog.Any("error", err))
		return err
	}
	if cfg.MTLSOutboundCertFile != "" {
		log.Info("Outbound mTLS enabled",
			slog.String("cert", cfg.MTLSOutboundCertFile),
			slog.String("ca", cfg.MTLSOutboundCAFile),
		)
	}

	// 4.2 Build the outbound client for OUTBOUND_PROFILE. Invalid profile is fatal —
	// silently coercing to a default would mask a typo and the operator
	// would discover at first delivery (or never).
	outClient, err := outbound.New(outbound.Profile(cfg.OutboundProfile), amfClient)
	if err != nil {
		log.Error("Outbound profile init failed", slog.Any("error", err))
		return err
	}
	log.Info("Outbound delivery profile configured",
		slog.String("profile", cfg.OutboundProfile))

	// 4.3 Start NATS Subscriber (Callback Listener) with HA failover.
	sub := nats.NewSubscriberWithOutbound(nc.GetConn(), log, outClient, nats.DefaultCallbackTimeout).
		WithRetry(cfg.MaxRetries, cfg.RetryBaseDelay).
		WithWorkers(cfg.NotifyWorkers)
	if err := sub.Start(); err != nil {
		log.Error("Failed to start NATS subscriber", slog.Any("error", err))
		return err
	}
	log.Info("NATS Subscriber started (Listening for Callbacks with HA failover)")

	// 4.4 Start the SMS (OTA) subscriber: serving-SMSF lookup and SendSMS. Opt-in via
	// OTA_ENABLED — when off, the UECM / SMSF subjects are not consumed
	// and OTA's probe budget naturally times out (the documented graceful
	// fallback to Diameter / MAP).
	var otaSub *nats.OTASubscriber
	if cfg.OTAEnabled {
		resolver, err := uecm.NewFromFile(cfg.OTAResolverFile)
		if err != nil {
			log.Error("OTA resolver init failed", slog.Any("error", err))
			return err
		}
		js, err := nc.JetStream()
		if err != nil {
			log.Error("OTA JetStream init failed", slog.Any("error", err))
			return err
		}
		otaSub = nats.NewOTASubscriber(nc.GetConn(), js, log, nats.OTAConfig{
			Resolver:    resolver,
			Outbound:    outClient,
			UecmTimeout: cfg.OTAUecmTimeout,
		})
		if err := otaSub.Start(ctx); err != nil {
			log.Error("OTA subscriber start failed", slog.Any("error", err))
			return err
		}
		log.Info("OTA subscriber started",
			slog.String("resolver_file", cfg.OTAResolverFile),
			slog.Duration("uecm_timeout", cfg.OTAUecmTimeout),
		)
	}

	adminSrv := admin.NewAdminServer(nc)
	if oauthValidator != nil {
		// Without a verification key every token is rejected: not ready until the NRF answers.
		adminSrv.AddReadinessCheck(func() bool { return oauth.Ready(oauthValidator) })
	}
	adminHTTPSrv := adminSrv.HTTPServer(":" + cfg.AdminPort)
	srv := sbiServer(":"+cfg.SBIPort, cfg.NatsRequestTimeout, tlsCfg != nil)
	srv.Handler = r
	srv.TLSConfig = tlsCfg

	// 6. Open both ports before serving either: a port that cannot be bound stops the
	//    gateway instead of leaving a process whose readiness says it serves.
	adminLn, err := net.Listen("tcp", adminHTTPSrv.Addr)
	if err != nil {
		return fmt.Errorf("admin port: %w", err)
	}
	sbiLn, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		_ = adminLn.Close()
		return fmt.Errorf("SBI port: %w", err)
	}

	// A server that stops on its own — a certificate file that cannot be read, a listener
	// that fails — stops the gateway the same way.
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	var serveErr error
	var serveErrOnce sync.Once
	failed := func(name string, err error) {
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}
		serveErrOnce.Do(func() { serveErr = fmt.Errorf("%s: %w", name, err) })
		log.Error("Server failed", slog.String("server", name), slog.Any("error", err))
		stopServing()
	}
	go func() {
		log.Info("Admin server starting", slog.String("port", cfg.AdminPort))
		failed("admin server", adminHTTPSrv.Serve(adminLn))
	}()
	go func() {
		if tlsCfg != nil {
			log.Info("SBI Gateway listening (TLS 1.3)",
				slog.String("port", cfg.SBIPort),
				slog.String("client_auth", cfg.MTLSClientAuthMode),
			)
			failed("SBI server", srv.ServeTLS(sbiLn, "", "")) // TLSConfig.Certificates is loaded
			return
		}
		log.Info("SBI Gateway listening (h2c, no TLS)", slog.String("port", cfg.SBIPort))
		failed("SBI server", srv.Serve(sbiLn))
	}()

	// 7. Wait for the shutdown signal, or for a server to fail.
	<-serveCtx.Done()

	if serveErr == nil {
		// A terminating pod leaves the Service's endpoints, but kube-proxy and any balancer
		// in front route to it for a moment longer: closing the listener now would refuse
		// those connections. Serve on for the drain delay, answering not ready meanwhile.
		log.Info("Shutting down gracefully...", slog.Duration("drain_delay", cfg.ShutdownDrainDelay))
		adminSrv.Drain()
		time.Sleep(cfg.ShutdownDrainDelay)
	}

	// The SBI requests in flight, the notification deliveries and the SMS being sent finish
	// side by side within SHUTDOWN_TIMEOUT; NATS stays connected until all have (the deferred
	// Close flushes what they published).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	var stopping sync.WaitGroup
	var sbiErr error
	stopping.Go(func() { sbiErr = srv.Shutdown(shutdownCtx) })
	stopping.Go(func() { _ = sub.Stop(shutdownCtx) }) // logs its own outcome
	if otaSub != nil {
		stopping.Go(func() { _ = otaSub.Stop(shutdownCtx) })
	}
	stopping.Wait()

	if err := adminHTTPSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("Admin server did not shut down cleanly", slog.Any("error", err))
	}
	if sbiErr != nil {
		return sbiErr
	}
	return serveErr
}

// reportSecurity logs each SBI protection an explicit setting switched off and sets its
// gauge, so that a weakened pod shows in its log and can be alerted on.
func reportSecurity(log *slog.Logger, cfg *config.Config) {
	for _, p := range []struct {
		name, setting string
		on            bool
	}{
		{"tls", "ALLOW_PLAINTEXT_SBI=true: the SBI port serves cleartext h2c", cfg.TLSEnabled()},
		{"client_certificate", "MTLS_CLIENT_AUTH_MODE=" + cfg.MTLSClientAuthMode +
			": client certificates are not required", cfg.MTLSClientAuthMode == "require"},
		{"oauth", "OAUTH_DISABLED=true: SBI requests are accepted without an access token", !cfg.OAuthDisabled},
		{"outbound_destinations", "OUTBOUND_ALLOW_ANY=true: callbacks and SMSF calls may reach any host " +
			"but loopback, link-local, unspecified and multicast addresses", !cfg.OutboundAllowAny},
	} {
		metrics.SetSecurityProtection(p.name, p.on)
		if !p.on {
			log.Warn("SBI protection off", slog.String("protection", p.name), slog.String("setting", p.setting))
		}
	}
	if !cfg.OutboundAllowAny && strings.TrimSpace(cfg.OutboundAllowedDestinations) == "" {
		log.Warn("No outbound destination allowed: notifications and SMS fail until " +
			"OUTBOUND_ALLOWED_DESTINATIONS lists their hosts")
	}
}

// sbiServer returns the SBI port's server: HTTP/2 over TLS (ALPN h2) when tls, else
// unencrypted HTTP/2 with prior knowledge (h2c). Never HTTP/1.1: TS 29.500 clause 5.2.1
// requires HTTP/2 on the service-based interface.
// Slow or idle peers must not hold connections. With HTTP/2 the read and write
// timeouts apply per stream; the write timeout covers the wait for the application's
// reply, natsRequestTimeout.
func sbiServer(addr string, natsRequestTimeout time.Duration, tls bool) *http.Server {
	var protocols http.Protocols
	if tls {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	return &http.Server{
		Addr:              addr,
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      max(30*time.Second, natsRequestTimeout+10*time.Second),
		IdleTimeout:       120 * time.Second,
	}
}

// jwksHTTPClient fetches the NRF's JWKS with the gateway's outbound TLS identity
// (MTLS_OUTBOUND_*: the NRF is one more 5GC peer) and a bound on each fetch.
func jwksHTTPClient(cfg *config.Config) (*http.Client, error) {
	tlsCfg, err := sbi.OutboundTLS(cfg.MTLSOutboundCertFile, cfg.MTLSOutboundKeyFile, cfg.MTLSOutboundCAFile)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, nil
}

// buildOAuthValidator constructs the OAuth2 validator from config. Returns
// (nil, nil) when OAUTH_DISABLED=true — the only path to a running server
// without authentication, deliberately explicit.
func buildOAuthValidator(ctx context.Context, cfg *config.Config, log *slog.Logger) (oauth.Validator, error) {
	if cfg.OAuthDisabled {
		return nil, nil
	}
	client, err := jwksHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return oauth.New(ctx, oauth.Config{
		JWKS: oauth.JWKSConfig{
			NRFURL:          cfg.OAuthNRFJWKSURL,
			FilePath:        cfg.OAuthJWKSFile,
			RefreshInterval: cfg.OAuthJWKSRefresh,
			HTTPClient:      client,
		},
		Audience:           cfg.OAuthAudience,
		ClockSkew:          cfg.OAuthClockSkew,
		ResultCacheTTL:     cfg.OAuthResultCacheTTL,
		RequireCertBinding: cfg.OAuthRequireCertBinding,
	}, log)
}
