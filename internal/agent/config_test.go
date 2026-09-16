package agent

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromEnvRequiresAuthToken(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "")
	t.Setenv("CASS_AUTH_TOKENS", "")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error when auth token env vars are unset")
	}
	if !strings.Contains(err.Error(), "auth token") {
		t.Fatalf("expected auth token error, got %v", err)
	}
}

func TestLoadConfigFromEnvLoadsDistinctAuthTokens(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "primary-token")
	t.Setenv("CASS_AUTH_TOKENS", "rotated-token, primary-token , canary-token")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	want := []string{"primary-token", "rotated-token", "canary-token"}
	if !reflect.DeepEqual(cfg.AuthTokens, want) {
		t.Fatalf("expected auth tokens %v, got %v", want, cfg.AuthTokens)
	}
}

func TestLoadConfigFromEnvUsesHardenedHTTPDefaults(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_BIND_ADDR", "")
	t.Setenv("CASS_MAX_REQUEST_BYTES", "")
	t.Setenv("CASS_READ_HEADER_TIMEOUT", "")
	t.Setenv("CASS_READ_TIMEOUT", "")
	t.Setenv("CASS_WRITE_TIMEOUT", "")
	t.Setenv("CASS_IDLE_TIMEOUT", "")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddr != "127.0.0.1:8080" {
		t.Fatalf("expected loopback bind, got %q", cfg.BindAddr)
	}
	if cfg.MaxRequestBytes != 65536 {
		t.Fatalf("expected 65536 max request bytes, got %d", cfg.MaxRequestBytes)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.ReadTimeout != 15*time.Second ||
		cfg.WriteTimeout != 30*time.Second || cfg.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected HTTP timeouts: %+v", cfg)
	}
}

func TestLoadConfigFromEnvLoadsHTTPOverrides(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_BIND_ADDR", "[::]:18081")
	t.Setenv("CASS_MAX_REQUEST_BYTES", "4096")
	t.Setenv("CASS_READ_HEADER_TIMEOUT", "2s")
	t.Setenv("CASS_READ_TIMEOUT", "3s")
	t.Setenv("CASS_WRITE_TIMEOUT", "4s")
	t.Setenv("CASS_IDLE_TIMEOUT", "5s")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddr != "[::]:18081" || cfg.MaxRequestBytes != 4096 {
		t.Fatalf("unexpected HTTP overrides: %+v", cfg)
	}
	if cfg.ReadHeaderTimeout != 2*time.Second || cfg.ReadTimeout != 3*time.Second ||
		cfg.WriteTimeout != 4*time.Second || cfg.IdleTimeout != 5*time.Second {
		t.Fatalf("unexpected timeout overrides: %+v", cfg)
	}
}

func TestLoadConfigFromEnvUsesSafeOperationDefaults(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	unsetEnv(t, "CASS_ENABLED_OPERATIONS")
	unsetEnv(t, "CASS_HOST_INFO_FIELDS")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if containsName(cfg.EnabledOperations, operationProcessList) {
		t.Fatalf("process.list must be disabled by default: %v", cfg.EnabledOperations)
	}
	if !reflect.DeepEqual(cfg.HostInfoFields, defaultHostInfoFields()) {
		t.Fatalf("unexpected default host info fields: %v", cfg.HostInfoFields)
	}
}

func TestLoadConfigFromEnvLoadsExplicitSecurityPolicy(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_ENABLED_OPERATIONS", "host.info,process.list,host.info")
	t.Setenv("CASS_HOST_INFO_FIELDS", "arch,uptime_seconds")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if want := []string{"host.info", "process.list"}; !reflect.DeepEqual(cfg.EnabledOperations, want) {
		t.Fatalf("expected enabled operations %v, got %v", want, cfg.EnabledOperations)
	}
	if want := []string{"arch", "uptime_seconds"}; !reflect.DeepEqual(cfg.HostInfoFields, want) {
		t.Fatalf("expected host info fields %v, got %v", want, cfg.HostInfoFields)
	}
}

func TestLoadConfigFromEnvRejectsUnknownOperation(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_ENABLED_OPERATIONS", "filesystem.read,shell.execute")

	_, err := LoadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "unsupported value") {
		t.Fatalf("expected unsupported operation error, got %v", err)
	}
}

func TestLoadConfigFromEnvRejectsUnknownHostInfoField(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_HOST_INFO_FIELDS", "arch,environment")

	_, err := LoadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "unsupported value") {
		t.Fatalf("expected unsupported host info field error, got %v", err)
	}
}

func TestLoadConfigFromEnvRequiresFieldsWhenHostInfoEnabled(t *testing.T) {
	t.Setenv("CASS_AUTH_TOKEN", "test-token")
	t.Setenv("CASS_ENABLED_OPERATIONS", "host.info")
	t.Setenv("CASS_HOST_INFO_FIELDS", "")

	_, err := LoadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "host.info requires") {
		t.Fatalf("expected host info field error, got %v", err)
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	value, exists := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if exists {
			_ = os.Setenv(key, value)
			return
		}
		_ = os.Unsetenv(key)
	})
}
