// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/admin"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/config"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/uecm"
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
	cfg := config.Load()

	// 2. Initialize Logger. An unknown LOG_LEVEL stops the gateway rather than
	//    logging at a level nobody asked for.
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("LOG_LEVEL %q: want debug, info, warn or error", cfg.LogLevel)
	}
	log := logger.InitLogger("sbi-ha-gateway", level)
	if cfg.MaxRetries < 1 || cfg.RetryBaseDelay <= 0 {
		return fmt.Errorf("MAX_RETRIES (%d) must be at least 1 and RETRY_BASE_DELAY (%s) positive",
			cfg.MaxRetries, cfg.RetryBaseDelay)
	}
	log.Info("Starting SBI HA Gateway...",
		slog.String("sbi_port", cfg.SBIPort),
		slog.String("admin_port", cfg.AdminPort),
	)

	// 3. Initialize NATS
	nc, err := nats.NewClientWithTimeout(cfg.NatsURL, log, cfg.NatsConnectTimeout)
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
	authH := handlers.NewAuthHandler(log, nc, cfg.NatsRequestTimeout)
	mobH := handlers.NewMobilityHandler(log, nc, cfg.NatsRequestTimeout)
	dataH := handlers.NewDataHandler(log, nc, cfg.NatsRequestTimeout)
	mtH := handlers.NewMTHandler(log, nc, cfg.NatsRequestTimeout)

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
	} else {
		log.Warn("OAuth2 NF token authentication DISABLED — gateway will accept unauthenticated SBI requests")
	}

	r := server.NewRouter(server.RouterConfig{
		AuthHandler:    authH,
		MobH:           mobH,
		DataH:          dataH,
		MtH:            mtH,
		OAuthValidator: oauthValidator,
		RateLimitRPS:   cfg.RateLimitRPS,
		RateLimitBurst: cfg.RateLimitBurst,
	})

	// 4.1 Build outbound HTTP/2 client. mTLS config is fatal-on-partial
	// (cert without key, etc.) — see sbi.buildOutboundTLS.
	amfCfg := sbi.DefaultAmfClientConfig()
	amfCfg.TLSCertFile = cfg.MTLSOutboundCertFile
	amfCfg.TLSKeyFile = cfg.MTLSOutboundKeyFile
	amfCfg.TLSCAFile = cfg.MTLSOutboundCAFile
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
		WithRetry(cfg.MaxRetries, cfg.RetryBaseDelay)
	if err := sub.Start(); err != nil {
		log.Error("Failed to start NATS subscriber", slog.Any("error", err))
	} else {
		log.Info("NATS Subscriber started (Listening for Callbacks with HA failover)")
	}

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

	// 5. Start Admin Server
	adminHTTPSrv := admin.NewAdminServer(nc).HTTPServer(":" + cfg.AdminPort)
	go func() {
		log.Info("Admin server starting", slog.String("port", cfg.AdminPort))
		if err := adminHTTPSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Admin server failed", slog.Any("error", err))
		}
	}()

	// 6. Start Main HTTP/2 Server. TLS config now centralised in
	//    server.BuildTLSConfig — handles plain TLS 1.3 + the mTLS auth
	//    modes (off/optional/require). Misconfiguration is fatal here.
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
	srv := sbiServer(":"+cfg.SBIPort, cfg.NatsRequestTimeout, tlsCfg != nil)
	srv.Handler = r
	srv.TLSConfig = tlsCfg

	go func() {
		if tlsCfg != nil {
			log.Info("SBI Gateway listening (TLS 1.3)",
				slog.String("port", cfg.SBIPort),
				slog.String("client_auth", cfg.MTLSClientAuthMode),
			)
			if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Error("HTTPS server failed", slog.Any("error", err))
			}
			return
		}

		log.Info("SBI Gateway listening (h2c, no TLS)", slog.String("port", cfg.SBIPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server failed", slog.Any("error", err))
		}
	}()

	// 7. Wait for shutdown signal via context
	<-ctx.Done()

	log.Info("Shutting down gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop NATS subscribers first (drain in-flight messages)
	if otaSub != nil {
		if err := otaSub.Stop(); err != nil {
			log.Warn("Failed to stop OTA subscriber cleanly", slog.Any("error", err))
		}
	}
	if err := sub.Stop(); err != nil {
		log.Warn("Failed to stop NATS subscriber cleanly", slog.Any("error", err))
	}

	if err := adminHTTPSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("Admin server did not shut down cleanly", slog.Any("error", err))
	}
	return srv.Shutdown(shutdownCtx)
}

// sbiServer returns the SBI port's server: HTTP/2 over TLS (ALPN h2) when tls, else
// unencrypted HTTP/2 with prior knowledge (h2c); HTTP/1.1 is served too, as before.
// Slow or idle peers must not hold connections. With HTTP/2 the read and write
// timeouts apply per stream; the write timeout covers the wait for the application's
// reply, natsRequestTimeout.
func sbiServer(addr string, natsRequestTimeout time.Duration, tls bool) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
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

// buildOAuthValidator constructs the OAuth2 validator from config. Returns
// (nil, nil) when OAUTH_DISABLED=true — the only path to a running server
// without authentication, deliberately explicit.
func buildOAuthValidator(ctx context.Context, cfg *config.Config, log *slog.Logger) (oauth.Validator, error) {
	if cfg.OAuthDisabled {
		return nil, nil
	}
	return oauth.New(ctx, oauth.Config{
		JWKS: oauth.JWKSConfig{
			NRFURL:          cfg.OAuthNRFJWKSURL,
			FilePath:        cfg.OAuthJWKSFile,
			RefreshInterval: cfg.OAuthJWKSRefresh,
		},
		Audience:           cfg.OAuthAudience,
		ClockSkew:          cfg.OAuthClockSkew,
		ResultCacheTTL:     cfg.OAuthResultCacheTTL,
		RequireCertBinding: cfg.OAuthRequireCertBinding,
	}, log)
}
