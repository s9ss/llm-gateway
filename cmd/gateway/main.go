package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s9ss/llm-gateway/internal/audit"
	"github.com/s9ss/llm-gateway/internal/config"
	"github.com/s9ss/llm-gateway/internal/keys"
	"github.com/s9ss/llm-gateway/internal/proxy"
)

// build is the s9ss marker. It shows up in /__gw/health and in every audit
// record, so a binary found somewhere can be traced back to this repo.
const build = "s9ss/llm-gateway"

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("%s: %v", build, err)
	}

	logger, err := audit.Open(cfg.AuditPath, build)
	if err != nil {
		log.Fatalf("%s: audit log: %v", build, err)
	}
	defer logger.Close()

	store := keys.New(cfg.Keys)
	srv, err := proxy.New(cfg, store, logger)
	if err != nil {
		log.Fatalf("%s: %v", build, err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // streams run as long as the model does
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Eventf("listening on %s, upstream %s, %d keys", cfg.Listen, cfg.Upstream, len(cfg.Keys))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("%s: %v", build, err)
	case <-sig:
		logger.Eventf("shutting down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Eventf("shutdown: %v", err)
	}
}
