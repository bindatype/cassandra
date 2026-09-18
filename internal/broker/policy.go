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

func validateHostSelector(host string) error {
	if host == "" || len(host) > maxHostSelectorLen || strings.TrimSpace(host) != host {
		return fmt.Errorf("host must contain 1-%d non-whitespace characters", maxHostSelectorLen)
	}
	for _, char := range host {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("host contains an unsupported character")
	}
	return nil
}

// OperationTakesTarget reports whether a broker-routable operation addresses a
// path.
//
// Every operation did, until host.info: it reports facts about the machine
// rather than about a file, so there is nothing for a path to name. Keeping
// that as one predicate rather than a condition repeated in three places is
// deliberate -- validation, route construction and the connector each need to
// know, and three copies of a list is how they come to disagree.
func OperationTakesTarget(operation string) bool {
	switch operation {
	case "host.info", "host.uptime", "host.diskfree", "host.network",
		"host.listeners", "kernel.messages", "capabilities.describe":
		// These report facts about the machine rather than about a file. The
		// command-backed ones take no target for a second reason as well: every
		// argument they pass is a compile-time constant, so there is no place
		// for a caller-supplied value to land.
		return false
	default:
		return true
	}
}

func validateResource(resource Resource) error {
	// The operation is checked before the path, because the path rules depend
	// on it and because "path must be absolute" is a confusing complaint about
	// an operation that is not routable at all.
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
		// Rejected rather than ignored. A path that is silently discarded
		// reads, to whoever wrote it, as a path that is being honoured.
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
	case "host.uptime", "host.diskfree", "host.network", "host.listeners", "kernel.messages":
		// Command-backed operations take no parameters at all: every argument
		// they pass is compiled in, which is the property that removes the
		// injection class. A policy that tried to bound them would be
		// describing a knob that does not exist.
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
}
