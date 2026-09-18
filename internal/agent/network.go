package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// host.network used to run `ip addr show` and `ip route show`. It cannot.
//
// /usr/sbin/ip is labelled ifconfig_exec_t, so executing it triggers an SELinux
// domain transition to ifconfig_t. DynamicUser=yes implies NoNewPrivileges=yes,
// and NNP forbids a domain transition that is not bounded, so the exec is
// denied with nnp_transition and the service exits 203 before `ip` runs at all.
// Measured on sgtstubby 2026-09-18, under enforcing:
//
//	avc: denied { nnp_transition } scontext=init_t tcontext=ifconfig_t
//
// It passed every test because the tests ran the agent as an ordinary user
// rather than as a hardened unit, which is the one difference that decided it.
//
// Go's net package speaks netlink from inside this process. No child, no
// transition, no NNP problem -- and the same data. Routes come from /proc/net,
// which are ordinary readable files. The result is both correct under enforcing
// and one fewer external dependency.

type networkInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	State     string   `json:"state"`
	Flags     []string `json:"flags,omitempty"`
	Hardware  string   `json:"hardware_address,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

type networkRoute struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// hostNetwork reports interfaces with their addresses, and the routing tables,
// together. An address without its route explains nothing: a reachable-looking
// interface with no route to the peer is the common case worth seeing.
func (s *Service) hostNetwork() (any, bool, *APIError) {
	interfaces, err := readInterfaces()
	if err != nil {
		return nil, false, newAPIError(500, "network_read_failed", err.Error())
	}
	if len(interfaces) == 0 {
		// A host always has at least a loopback. None means we could not look.
		return nil, false, newAPIError(500, "network_read_failed",
			"no interfaces were visible at all, which is not a state a running host can be in")
	}

	routes, routeWarnings := readRoutes(s.cfg.ProcRoot)

	payload := map[string]any{
		"interfaces": interfaces,
		"routes":     routes,
	}
	notes := []string{
		"addresses and interface state come from netlink; routes come from /proc/net. " +
			"No external program is run, so this reflects the kernel directly.",
	}
	// A routing table that could not be read is named, not omitted. An empty
	// route list and an unreadable one must not look alike.
	notes = append(notes, routeWarnings...)
	payload["notes"] = notes
	return payload, false, nil
}

func readInterfaces() ([]networkInterface, error) {
	found, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	result := make([]networkInterface, 0, len(found))
	for _, iface := range found {
		record := networkInterface{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			State: "down",
		}
		if iface.Flags&net.FlagUp != 0 {
			record.State = "up"
		}
		for name, flag := range map[string]net.Flags{
			"up": net.FlagUp, "broadcast": net.FlagBroadcast, "loopback": net.FlagLoopback,
			"point-to-point": net.FlagPointToPoint, "multicast": net.FlagMulticast,
		} {
			if iface.Flags&flag != 0 {
				record.Flags = append(record.Flags, name)
			}
		}
		sort.Strings(record.Flags)
		if iface.HardwareAddr != nil {
			record.Hardware = iface.HardwareAddr.String()
		}
		// An interface whose addresses cannot be read keeps its entry: the
		// interface existing is itself a fact, and dropping it would make a
		// partial read look like a shorter machine.
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				record.Addresses = append(record.Addresses, addr.String())
			}
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index < result[j].Index })
	return result, nil
}

// readRoutes returns both families, and a warning for each table it could not
// read. On an IPv6-mostly estate the v6 table is the one that matters, so a
// missing v4 table is unremarkable and a missing v6 table is not -- naming
// which one is absent is the whole point.
func readRoutes(procRoot string) ([]networkRoute, []string) {
	var routes []networkRoute
	var warnings []string

	v4, err := os.ReadFile(filepath.Join(procRoot, "net", "route"))
	if err != nil {
		warnings = append(warnings, "the IPv4 routing table could not be read: "+err.Error())
	} else {
		routes = append(routes, parseIPv4Routes(string(v4))...)
	}

	v6, err := os.ReadFile(filepath.Join(procRoot, "net", "ipv6_route"))
	if err != nil {
		warnings = append(warnings, "the IPv6 routing table could not be read: "+err.Error())
	} else {
		routes = append(routes, parseIPv6Routes(string(v6))...)
	}
	return routes, warnings
}

// parseIPv4Routes reads /proc/net/route, whose addresses are little-endian hex.
func parseIPv4Routes(content string) []networkRoute {
	var routes []networkRoute
	for i, line := range strings.Split(content, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		destination := hexLEToIPv4(fields[1])
		mask := hexLEToIPv4(fields[7])
		if destination == nil || mask == nil {
			continue
		}
		ones, _ := net.IPMask(mask.To4()).Size()
		route := networkRoute{
			Family:      "ipv4",
			Destination: fmt.Sprintf("%s/%d", destination, ones),
			Interface:   fields[0],
		}
		if gateway := hexLEToIPv4(fields[2]); gateway != nil && !gateway.IsUnspecified() {
			route.Gateway = gateway.String()
		}
		if len(fields) > 6 {
			route.Metric, _ = strconv.Atoi(fields[6])
		}
		if destination.IsUnspecified() && ones == 0 {
			route.Destination = "default"
		}
		routes = append(routes, route)
	}
	return routes
}

// parseIPv6Routes reads /proc/net/ipv6_route: 32 hex digits of destination, a
// hex prefix length, then source, next hop, and metric.
func parseIPv6Routes(content string) []networkRoute {
	var routes []networkRoute
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		destination := hexToIPv6(fields[0])
		if destination == nil {
			continue
		}
		prefix, err := strconv.ParseInt(fields[1], 16, 32)
		if err != nil {
			continue
		}
		route := networkRoute{
			Family:      "ipv6",
			Destination: fmt.Sprintf("%s/%d", destination, prefix),
			Interface:   fields[9],
		}
		if nextHop := hexToIPv6(fields[4]); nextHop != nil && !nextHop.IsUnspecified() {
			route.Gateway = nextHop.String()
		}
		if metric, err := strconv.ParseInt(fields[5], 16, 32); err == nil {
			route.Metric = int(metric)
		}
		if destination.IsUnspecified() && prefix == 0 {
			route.Destination = "default"
		}
		routes = append(routes, route)
	}
	return routes
}

func hexLEToIPv4(field string) net.IP {
	raw, err := hex.DecodeString(field)
	if err != nil || len(raw) != 4 {
		return nil
	}
	value := binary.BigEndian.Uint32(raw)
	out := make(net.IP, 4)
	binary.LittleEndian.PutUint32(out, value)
	return out
}

func hexToIPv6(field string) net.IP {
	raw, err := hex.DecodeString(field)
	if err != nil || len(raw) != 16 {
		return nil
	}
	return net.IP(raw)
}
