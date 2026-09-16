package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/agent"
)

func TestNewHTTPServerAppliesConfig(t *testing.T) {
	cfg := agent.Config{
		BindAddr:          "127.0.0.1:18081",
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      4 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	server := newHTTPServer(cfg, handler)
	if server.Addr != cfg.BindAddr || server.Handler == nil {
		t.Fatalf("server did not retain address and handler: %+v", server)
	}
	if server.ReadHeaderTimeout != cfg.ReadHeaderTimeout || server.ReadTimeout != cfg.ReadTimeout ||
		server.WriteTimeout != cfg.WriteTimeout || server.IdleTimeout != cfg.IdleTimeout {
		t.Fatalf("server did not apply configured timeouts: %+v", server)
	}
}
