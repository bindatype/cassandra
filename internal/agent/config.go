package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/env"
)

const (
	defaultBindAddr          = "127.0.0.1:8080"
	defaultMaxRequestBytes   = 65536
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
)

type Config struct {
	BindAddr          string
	AuthTokens        []string
	AllowedRoots      []string
	ProcRoot          string
	EnabledOperations []string
	HostInfoFields    []string
	MaxRequestBytes   int64
	MaxReadBytes      int64
	MaxTailBytes      int64
	MaxListEntries    int
	MaxProcessEntries int
	AuditPath         string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

func LoadConfigFromEnv() (Config, error) {
	enabledOperations, err := loadConfiguredNames(
		"CASS_ENABLED_OPERATIONS",
		defaultEnabledOperations(),
		knownOperations,
	)
	if err != nil {
		return Config{}, err
	}
	hostInfoFields, err := loadConfiguredNames(
		"CASS_HOST_INFO_FIELDS",
		defaultHostInfoFields(),
		knownHostInfoFields,
	)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		BindAddr:          envOrDefault("CASS_BIND_ADDR", defaultBindAddr),
		AuthTokens:        loadAuthTokensFromEnv(),
		ProcRoot:          envOrDefault("CASS_PROC_ROOT", "/proc"),
		EnabledOperations: enabledOperations,
		HostInfoFields:    hostInfoFields,
		AuditPath:         envOrDefault("CASS_AUDIT_PATH", "runtime/audit.log"),
		MaxRequestBytes:   envInt64("CASS_MAX_REQUEST_BYTES", defaultMaxRequestBytes),
		MaxReadBytes:      envInt64("CASS_MAX_READ_BYTES", 65536),
		MaxTailBytes:      envInt64("CASS_MAX_TAIL_BYTES", 65536),
		MaxListEntries:    int(envInt64("CASS_MAX_LIST_ENTRIES", 256)),
		MaxProcessEntries: int(envInt64("CASS_MAX_PROCESS_ENTRIES", 256)),
		ReadHeaderTimeout: envDuration("CASS_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout),
		ReadTimeout:       envDuration("CASS_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:      envDuration("CASS_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:       envDuration("CASS_IDLE_TIMEOUT", defaultIdleTimeout),
	}

	roots := strings.Split(envOrDefault("CASS_ALLOWED_ROOTS", "/workspace,/tmp,/var/log/cass"), ",")
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		if !filepath.IsAbs(root) {
			return Config{}, fmt.Errorf("allowed root must be absolute: %q", root)
		}
		cfg.AllowedRoots = append(cfg.AllowedRoots, filepath.Clean(root))
	}
	if len(cfg.AllowedRoots) == 0 {
		return Config{}, fmt.Errorf("at least one allowed root is required")
	}
	if len(cfg.AuthTokens) == 0 {
		return Config{}, fmt.Errorf("at least one auth token is required")
	}
	if !filepath.IsAbs(cfg.ProcRoot) {
		return Config{}, fmt.Errorf("proc root must be absolute: %q", cfg.ProcRoot)
	}
	if containsName(cfg.EnabledOperations, operationHostInfo) && len(cfg.HostInfoFields) == 0 {
		return Config{}, fmt.Errorf("host.info requires at least one configured host info field")
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func loadAuthTokensFromEnv() []string {
	values := []string{}
	if single := strings.TrimSpace(env.Get("CASS_AUTH_TOKEN")); single != "" {
		values = append(values, single)
	}
	if multi := env.Get("CASS_AUTH_TOKENS"); multi != "" {
		for _, value := range strings.Split(multi, ",") {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				values = append(values, trimmed)
			}
		}
	}

	tokens := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		tokens = append(tokens, value)
	}
	return tokens
}

func loadConfiguredNames(key string, defaults []string, known map[string]struct{}) ([]string, error) {
	raw, configured := os.LookupEnv(key)
	if !configured {
		return append([]string(nil), defaults...), nil
	}

	names := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range strings.Split(raw, ",") {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("%s contains unsupported value %q", key, name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

func containsName(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}
