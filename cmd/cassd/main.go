package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/bindatype/cassandra/internal/agent"
	"github.com/bindatype/cassandra/internal/env"
)

func main() {
	cfg, err := agent.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// A long-running service, so this is said once at startup rather than
	// per request. It goes through log like everything else here: the agent's
	// output is a journal, not a terminal, and a bare stderr write would be
	// the one line in it without a timestamp.
	var legacy strings.Builder
	if env.ReportLegacy(&legacy) {
		log.Print(strings.TrimSpace(legacy.String()))
	}

	auditor, err := agent.NewAuditor(cfg.AuditPath)
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer auditor.Close()

	service := agent.NewService(cfg, auditor)
	server := newHTTPServer(cfg, agent.NewHandler(service, cfg))

	log.Printf("cassd listening on %s", cfg.BindAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func newHTTPServer(cfg agent.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}
