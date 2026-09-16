package main

import (
	"log"
	"net/http"

	"github.com/bindatype/cassandra/internal/agent"
)

func main() {
	cfg, err := agent.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	auditor, err := agent.NewAuditor(cfg.AuditPath)
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer auditor.Close()

	service := agent.NewService(cfg, auditor)
	server := newHTTPServer(cfg, agent.NewHandler(service, cfg))

	log.Printf("cass-agent listening on %s", cfg.BindAddr)
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
