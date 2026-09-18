package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real shapes, taken from a running RHEL 9 host. Addresses in /proc/net/route
// are little-endian hex, which is the part that is easy to get backwards.
const procNetRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enp1s0	00000000	FE8FFDA1	0003	0	0	100	00000000	0	0	0
enp1s0	008FFDA1	00000000	0001	0	0	100	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

const procNetIPv6Route = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000026463fffe0c0001 00000400 00000001 00000000 00000003 enp1s0
2606069c901010060000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 enp1s0
`

func writeProcNet(t *testing.T, route, ipv6Route string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if route != "" {
		if err := os.WriteFile(filepath.Join(root, "net", "route"), []byte(route), 0o644); err != nil {
			t.Fatalf("write route: %v", err)
		}
	}
	if ipv6Route != "" {
		if err := os.WriteFile(filepath.Join(root, "net", "ipv6_route"), []byte(ipv6Route), 0o644); err != nil {
			t.Fatalf("write ipv6_route: %v", err)
		}
	}
	return root
}

func TestIPv4RoutesAreDecodedFromLittleEndianHex(t *testing.T) {
	routes := parseIPv4Routes(procNetRoute)
	if len(routes) != 3 {
		t.Fatalf("got %d routes, want 3", len(routes))
	}
	if routes[0].Destination != "default" {
		t.Errorf("destination = %q, want default (0.0.0.0/0 is the default route)", routes[0].Destination)
	}
	// FE8FFDA1 little-endian is 161.253.143.254 -- the real gateway. Reading it
	// big-endian would give 254.143.253.161, which is plausible and wrong.
	if routes[0].Gateway != "161.253.143.254" {
		t.Errorf("gateway = %q, want 161.253.143.254 (byte order is reversed)", routes[0].Gateway)
	}
	if routes[1].Destination != "161.253.143.0/24" {
		t.Errorf("destination = %q, want 161.253.143.0/24", routes[1].Destination)
	}
	if routes[1].Gateway != "" {
		t.Errorf("a directly-connected route reported gateway %q, want none", routes[1].Gateway)
	}
	if routes[0].Metric != 100 {
		t.Errorf("metric = %d, want 100", routes[0].Metric)
	}
}

func TestIPv6RoutesAreDecoded(t *testing.T) {
	routes := parseIPv6Routes(procNetIPv6Route)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0].Destination != "default" {
		t.Errorf("destination = %q, want default", routes[0].Destination)
	}
	if routes[0].Gateway != "fe80::264:63ff:fe0c:1" {
		t.Errorf("gateway = %q, want fe80::264:63ff:fe0c:1", routes[0].Gateway)
	}
	if routes[0].Interface != "enp1s0" {
		t.Errorf("interface = %q, want enp1s0", routes[0].Interface)
	}
	if !strings.HasSuffix(routes[1].Destination, "/64") {
		t.Errorf("destination = %q, want a /64 prefix", routes[1].Destination)
	}
}

// An unreadable routing table is named, not omitted. An empty route list and a
// table that could not be read must not look alike -- on an IPv6-mostly estate
// a silently missing v6 table is the one that would mislead.
func TestAnUnreadableRoutingTableIsNamed(t *testing.T) {
	root := writeProcNet(t, procNetRoute, "") // v4 present, v6 absent
	routes, warnings := readRoutes(root)
	if len(routes) == 0 {
		t.Error("the readable table was dropped along with the unreadable one")
	}
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1", len(warnings))
	}
	if !strings.Contains(warnings[0], "IPv6") {
		t.Errorf("warning = %q, want it to name which table is missing", warnings[0])
	}
}

func TestBothRoutingTablesAreReadWhenPresent(t *testing.T) {
	root := writeProcNet(t, procNetRoute, procNetIPv6Route)
	routes, warnings := readRoutes(root)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	var v4, v6 int
	for _, route := range routes {
		switch route.Family {
		case "ipv4":
			v4++
		case "ipv6":
			v6++
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Errorf("got %d v4 and %d v6 routes; both families must be reported", v4, v6)
	}
}

// The operation reports interfaces and routes together, because an address
// without its route explains nothing.
func TestHostNetworkReportsInterfacesAndRoutesTogether(t *testing.T) {
	service := NewService(Config{
		EnabledOperations: []string{operationHostNetwork},
		ProcRoot:          writeProcNet(t, procNetRoute, procNetIPv6Route),
	}, nil)

	data, _, apiErr := service.hostNetwork()
	if apiErr != nil {
		t.Fatalf("hostNetwork() error = %+v", apiErr)
	}
	payload, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected payload %#v", data)
	}
	interfaces, ok := payload["interfaces"].([]networkInterface)
	if !ok || len(interfaces) == 0 {
		t.Fatal("no interfaces reported; a host always has at least loopback")
	}
	if _, present := payload["routes"]; !present {
		t.Error("routes are absent; an address without its route explains nothing")
	}
	if _, present := payload["notes"]; !present {
		t.Error("notes are absent; the source of this data is not self-evident")
	}

	// Loopback is the one interface every host has, so it is the safe assertion.
	var sawLoopback bool
	for _, iface := range interfaces {
		for _, flag := range iface.Flags {
			if flag == "loopback" {
				sawLoopback = true
			}
		}
	}
	if !sawLoopback {
		t.Error("no loopback interface was reported")
	}
}
