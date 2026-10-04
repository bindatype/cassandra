package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	policyVersion      = 1
	maxResourceNameLen = 64
	maxHostSelectorLen = 253
	maxPolicyReadBytes = 65536
	maxPolicyListItems = 256
)

func LoadPolicy(r io.Reader) (Policy, error) {
	var policy Policy
	if err := decodeOneJSON(r, &policy); err != nil {
		return Policy{}, fmt.Errorf("decode broker policy: %w", err)
	}
	return policy, nil
}

func DecodeRouteRequest(r io.Reader) (RouteRequest, error) {
	var request RouteRequest
	if err := decodeOneJSON(r, &request); err != nil {
		return RouteRequest{}, fmt.Errorf("decode route request: %w", err)
	}
	return request, nil
}

func decodeOneJSON(r io.Reader, destination any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validatePolicy(policy Policy) error {
	if policy.Version != policyVersion {
		return fmt.Errorf("policy version must be %d", policyVersion)
	}
	if policy.LiveHosts == nil {
		return fmt.Errorf("live_hosts must be present")
	}
	if policy.Resources == nil {
		return fmt.Errorf("resources must be present")
	}

	for name, resource := range policy.Resources {
		if err := validateResourceName(name); err != nil {
			return fmt.Errorf("resource %q: %w", name, err)
		}
		if err := validateResource(resource); err != nil {
			return fmt.Errorf("resource %q: %w", name, err)
		}
	}

	for host, hostPolicy := range policy.LiveHosts {
		if err := validateHostSelector(host); err != nil {
			return fmt.Errorf("live host %q: %w", host, err)
		}
		seen := make(map[string]struct{}, len(hostPolicy.Resources))
		for _, resourceName := range hostPolicy.Resources {
			if _, ok := policy.Resources[resourceName]; !ok {
				return fmt.Errorf("live host %q references unknown resource %q", host, resourceName)
			}
			if _, ok := seen[resourceName]; ok {
				return fmt.Errorf("live host %q repeats resource %q", host, resourceName)
			}
			seen[resourceName] = struct{}{}
		}
	}
	return nil
}

func validateResourceName(name string) error {
	if name == "" || len(name) > maxResourceNameLen {
		return fmt.Errorf("name must contain 1-%d characters", maxResourceNameLen)
	}
	for _, char := range name {
		if unicode.IsLower(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("name may contain only lowercase letters, digits, dot, dash, and underscore")
	}
	return nil
}

// RT logins here are email addresses, which can run to the full 254.
const maxOwnerSelectorLen = 254

func validateOwnerSelector(owner string) error {
	if owner == "" || len(owner) > maxOwnerSelectorLen || strings.TrimSpace(owner) != owner {
		return fmt.Errorf("owner must be one RT login of 1-%d characters with no spaces", maxOwnerSelectorLen)
	}
	for _, char := range owner {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune(".-_@+", char) {
			continue
		}
		return fmt.Errorf("owner contains an unsupported character; it accepts only letters, digits, " +
			"'.', '-', '_', '@', and '+', and exactly one RT login per call -- to ask about several " +
			"owners, call this once per owner rather than combining them")
	}
	return nil
}

const (
	maxQueueSelectorLen = 64
	maxQueueSelectors   = 20
)

// validateQueueSelectors checks the shape of requested queue names. Whether
// each is allowlisted is the connector's check: the allowlist is its
// configuration, not the broker's.
func validateQueueSelectors(queues []string) error {
	if len(queues) > maxQueueSelectors {
		return fmt.Errorf("at most %d queues per call", maxQueueSelectors)
	}
	seen := make(map[string]bool, len(queues))
	for _, queue := range queues {
		if queue == "" || len(queue) > maxQueueSelectorLen || strings.TrimSpace(queue) != queue {
			return fmt.Errorf("each queue must be one RT queue name of 1-%d characters, as a separate list item", maxQueueSelectorLen)
		}
		for _, char := range queue {
			if unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune(" .-_", char) {
				continue
			}
			return fmt.Errorf("queue %q contains an unsupported character; give each queue as its own list item, "+
				"using only letters, digits, spaces, '.', '-' and '_'", queue)
		}
		key := strings.ToLower(queue)
		if seen[key] {
			return fmt.Errorf("queue %q is listed twice", queue)
		}
		seen[key] = true
	}
	return nil
}

func validateHostSelector(host string) error {
	if host == "" || len(host) > maxHostSelectorLen || strings.TrimSpace(host) != host {
		return fmt.Errorf("host must contain 1-%d non-whitespace characters", maxHostSelectorLen)
	}
	for _, char := range host {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			continue
		}
		// Usually a model joining several hosts into one string. Say "one host
		// per call" outright, or it bisects the list by trial and error.
		return fmt.Errorf("host contains an unsupported character; it accepts only letters, digits, " +
			"'.', '-', and '_', and exactly one hostname per call -- to ask about several hosts, " +
			"call this once per host rather than combining them")
	}
	return nil
}

// OperationTakesTarget reports whether a broker-routable operation addresses a
// path.
//
// Machine-fact operations such as host.info do not. Validation, route
// construction and the connector all use this one predicate, so they can't
// disagree.
func OperationTakesTarget(operation string) bool {
	switch operation {
	case "host.info", "host.uptime", "host.diskfree", "host.network",
		"host.listeners", "kernel.messages", "host.gpu", "capabilities.describe":
		// Facts about the machine, not a file. The command-backed ones also
		// pass only compile-time arguments, so a caller's value has nowhere to
		// land.
		return false
	default:
		return true
	}
}

func validateResource(resource Resource) error {
	// Operation before path: the path rules depend on it.
	if !routableOperations[resource.Operation] {
		return fmt.Errorf("operation %q is not broker-routable", resource.Operation)
	}

	if OperationTakesTarget(resource.Operation) {
		if !filepath.IsAbs(resource.Path) {
			return fmt.Errorf("path must be absolute")
		}
		if filepath.Clean(resource.Path) != resource.Path {
			return fmt.Errorf("path must be canonical")
		}
	} else if resource.Path != "" {
		// Rejected rather than ignored, so a discarded path doesn't read as
		// honoured.
		return fmt.Errorf("%s addresses no path; remove the path field", resource.Operation)
	}

	params := OperationParams{}
	if resource.Params != nil {
		params = *resource.Params
	}
	if params.Offset < 0 || params.MaxBytes < 0 || params.MaxEntries < 0 {
		return fmt.Errorf("operation limits must not be negative")
	}

	switch resource.Operation {
	case "filesystem.list":
		if params.MaxEntries < 1 || params.MaxEntries > maxPolicyListItems {
			return fmt.Errorf("filesystem.list requires max_entries between 1 and %d", maxPolicyListItems)
		}
		if params.Offset != 0 || params.MaxBytes != 0 {
			return fmt.Errorf("filesystem.list accepts only max_entries")
		}
	case "filesystem.stat":
		if params != (OperationParams{}) {
			return fmt.Errorf("filesystem.stat does not accept parameters")
		}
	case "filesystem.read":
		if params.MaxBytes < 1 || params.MaxBytes > maxPolicyReadBytes {
			return fmt.Errorf("filesystem.read requires max_bytes between 1 and %d", maxPolicyReadBytes)
		}
		if params.MaxEntries != 0 {
			return fmt.Errorf("filesystem.read does not accept max_entries")
		}
	case "filesystem.tail":
		if params.MaxBytes < 1 || params.MaxBytes > maxPolicyReadBytes {
			return fmt.Errorf("filesystem.tail requires max_bytes between 1 and %d", maxPolicyReadBytes)
		}
		if params.Offset != 0 || params.MaxEntries != 0 {
			return fmt.Errorf("filesystem.tail accepts only max_bytes")
		}
	case "host.info":
		// The fields it may report are the agent's own configuration
		// (CASS_HOST_INFO_FIELDS), not the policy's to narrow, so there is
		// nothing here to bound.
		if params != (OperationParams{}) {
			return fmt.Errorf("host.info does not accept parameters")
		}
	case "host.uptime", "host.diskfree", "host.network", "host.listeners", "kernel.messages", "host.gpu":
		// Command-backed operations take no parameters: every argument is
		// compiled in, which removes the injection class. There is nothing to
		// bound.
		if params != (OperationParams{}) {
			return fmt.Errorf("%s does not accept parameters", resource.Operation)
		}
	default:
		return fmt.Errorf("operation %q is not broker-routable", resource.Operation)
	}
	return nil
}

// routableOperations is what a policy resource may ask an endpoint agent for.
// The agent implements more -- process.list among them -- and implementing an
// operation is not the same as exposing it through the broker.
var routableOperations = map[string]bool{
	"filesystem.list": true,
	"filesystem.stat": true,
	"filesystem.read": true,
	"filesystem.tail": true,
	"host.info":       true,
	"host.uptime":     true,
	"host.diskfree":   true,
	"host.network":    true,
	"host.listeners":  true,
	"kernel.messages": true,
	"host.gpu":        true,
}
