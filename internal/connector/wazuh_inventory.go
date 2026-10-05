package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

// The inventory actions read Wazuh syscollector for one agent: what the host
// reported running and listening. Three properties of that data shape
// everything here, all measured against the live manager on 2026-10-05:
//
//   - A row's scan.time is when it last changed, not when it was last
//     checked. A process that has run since July carries a July time while
//     the agent reports hourly, so only the newest row dates the inventory.
//   - A disconnected agent keeps its last inventory. zabbixproxy01, silent
//     since 2026-07-17, still returned 4,403 processes, with nothing in the
//     rows to say they were old.
//   - Userland process rows carry cmd, the full command line, which can hold
//     a password. It is never requested, and never decoded if sent anyway.
const (
	// inventoryItemCap bounds the rows returned. A process row here is about
	// 150 bytes, so 200 stays well inside the 64 KB evidence cap; Wazuh's own
	// totals say how much was left out, and match is how to narrow.
	inventoryItemCap = 200
	// inventoryStaleAfter is twice the 1-hour syscollector interval set at RTS.
	inventoryStaleAfter = 2 * time.Hour
	// The fields requested. cmd and argvs are deliberately absent.
	inventoryProcessFields = "name,pid,ppid,euser,state,start_time,scan.time"
	inventoryPortFields    = "local.ip,local.port,protocol,process,pid,state,scan.time"
)

// wazuhNumber decodes a value Wazuh sends as a string in one table and a
// number in another: pid is "2270" for processes and 2284 for ports.
type wazuhNumber string

func (n *wazuhNumber) UnmarshalJSON(raw []byte) error {
	*n = wazuhNumber(strings.Trim(string(raw), `"`))
	return nil
}

type wazuhScan struct {
	Time string `json:"time"`
}

// The typed rows are the second barrier for command lines: a field not named
// here is dropped by the decoder even if Wazuh ignores select.
type wazuhProcess struct {
	Name      string      `json:"name"`
	PID       wazuhNumber `json:"pid"`
	PPID      wazuhNumber `json:"ppid"`
	EUser     string      `json:"euser"`
	State     string      `json:"state"`
	StartTime int64       `json:"start_time"`
	Scan      wazuhScan   `json:"scan"`
}

type wazuhPort struct {
	Local struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"local"`
	Protocol string      `json:"protocol"`
	Process  string      `json:"process"`
	PID      wazuhNumber `json:"pid"`
	State    string      `json:"state"`
	Scan     wazuhScan   `json:"scan"`
}

type wazuhPage[T any] struct {
	Data struct {
		AffectedItems      []T `json:"affected_items"`
		TotalAffectedItems int `json:"total_affected_items"`
	} `json:"data"`
}

// getPage is get for syscollector tables. It shares getRaw, so the size bound
// and Wazuh's in-body error check apply here as on every other path.
func getPage[T any](ctx context.Context, c *WazuhConnector, path string, query url.Values) (wazuhPage[T], error) {
	body, err := c.getRaw(ctx, path, query)
	if err != nil {
		return wazuhPage[T]{}, err
	}
	var page wazuhPage[T]
	if err := json.Unmarshal(body, &page); err != nil {
		return wazuhPage[T]{}, newConnectorError("decode_response", err.Error())
	}
	return page, nil
}

func (c *WazuhConnector) executeInventory(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Host == "" {
		return Evidence{}, newConnectorError("missing_host", step.Action+" requires a host")
	}
	requestedAt := time.Now().UTC()

	// Syscollector is addressed by agent ID. An unknown name is an error: an
	// empty inventory would read as a host running nothing.
	lookup := url.Values{}
	lookup.Set("select", wazuhAgentFields)
	lookup.Set("name", step.Host)
	agents, err := c.get(ctx, "/agents", lookup)
	if err != nil {
		return Evidence{}, err
	}
	if len(agents.Data.AffectedItems) == 0 {
		return Evidence{}, newConnectorError("unknown_agent", fmt.Sprintf(
			"Wazuh has no agent named %q; inventory is per agent, so the name must match exactly", step.Host))
	}
	agent := agents.Data.AffectedItems[0]

	table := "processes"
	if step.Action == "syscollector.listeners" {
		table = "ports"
	}
	base := "/syscollector/" + agent.ID + "/" + table

	evidence := Evidence{
		Source:      string(broker.SourceWazuhAPI),
		Action:      step.Action,
		Endpoint:    redactEndpoint(c.endpoint),
		Host:        step.Host,
		Match:       step.Match,
		RequestedAt: requestedAt,
	}
	if table == "processes" {
		err = c.fillProcesses(ctx, base, agent.Name, step.Match, &evidence)
	} else {
		err = c.fillListeners(ctx, base, agent.Name, step.Match, &evidence)
	}
	if err != nil {
		return Evidence{}, err
	}

	// Dated from the whole table, not the filtered rows: a match on one
	// long-running process would otherwise date the inventory to its start.
	newest, err := getPage[struct {
		Scan wazuhScan `json:"scan"`
	}](ctx, c, base, url.Values{"sort": {"-scan.time"}, "limit": {"1"}, "select": {"scan.time"}})
	if err != nil {
		return Evidence{}, err
	}
	if step.Match != "" && evidence.ItemCount == 0 {
		evidence.Notes = append(evidence.Notes, emptyMatchNote(step.Action, step.Match))
	}
	var warnings []string
	if agent.Status != "active" {
		warnings = append(warnings, fmt.Sprintf(
			"agent %s is %s (last contact %s): this inventory is what it reported before then, not its current state",
			agent.Name, agent.Status, agent.LastKeepAlive))
	}
	if len(newest.Data.AffectedItems) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"Wazuh holds no %s inventory for %s; syscollector may be off or may never have run there, "+
				"so this is not evidence that nothing is running", table, agent.Name))
	} else {
		stamp := newest.Data.AffectedItems[0].Scan.Time
		changed, parseErr := time.Parse(time.RFC3339, stamp)
		if parseErr != nil {
			warnings = append(warnings, fmt.Sprintf("the inventory time %q could not be read, so its age is unknown", stamp))
		} else {
			age := requestedAt.Sub(changed)
			evidence.Summary["newest_change_age_minutes"] = int(age.Minutes())
			evidence.Notes = append(evidence.Notes, fmt.Sprintf(
				"inventory as of its newest change, %s (%s ago); Wazuh records when a row last changed, "+
					"not when it was last checked, so rows for long-running processes carry older times",
				changed.UTC().Format(time.RFC3339), age.Round(time.Minute)))
			if age > inventoryStaleAfter {
				warnings = append(warnings, fmt.Sprintf(
					"the newest inventory change for %s is %s old, past the %s expected of an hourly collection; "+
						"it may not describe the host as it is now", agent.Name, age.Round(time.Minute), inventoryStaleAfter))
			}
		}
	}
	evidence.Warnings = warnings
	evidence.DurationMS = time.Since(requestedAt).Milliseconds()
	return evidence, nil
}

// emptyMatchNote says what an empty filtered result does and does not mean.
// Without it, "no rows" reads as "nothing there" when it only means nothing
// matched the filter as Wazuh applied it.
func emptyMatchNote(action, match string) string {
	filtered := "process names containing"
	if action == "syscollector.listeners" {
		filtered = "listeners whose owning process name contains"
		if _, isPort := broker.InventoryMatchPort(match); isPort {
			filtered = "listeners on port"
		}
	}
	return fmt.Sprintf("match filtered on %s %q and nothing matched: that means nothing matched that filter "+
		"in this inventory, not that nothing is running or listening", filtered, match)
}

func (c *WazuhConnector) fillProcesses(ctx context.Context, base, host, match string, evidence *Evidence) error {
	query := url.Values{
		"select": {inventoryProcessFields},
		"sort":   {"+name"},
		"limit":  {strconv.Itoa(inventoryItemCap)},
	}
	if match != "" {
		query.Set("q", "name~"+match)
	}
	page, err := getPage[wazuhProcess](ctx, c, base, query)
	if err != nil {
		return err
	}
	items := make([]EvidenceItem, 0, len(page.Data.AffectedItems))
	for _, p := range page.Data.AffectedItems {
		fields := map[string]string{
			"pid":     string(p.PID),
			"ppid":    string(p.PPID),
			"user":    p.EUser,
			"changed": p.Scan.Time,
		}
		if p.StartTime > 0 {
			fields["started"] = time.Unix(p.StartTime, 0).UTC().Format(time.RFC3339)
		}
		items = append(items, EvidenceItem{
			ID: string(p.PID), Host: host, Description: p.Name, State: p.State, Fields: fields,
		})
	}
	total := page.Data.TotalAffectedItems
	evidence.Items = items
	evidence.ItemCount = len(items)
	evidence.TotalAvailable = total
	evidence.Truncated = total > len(items)
	evidence.Summary = map[string]int{"returned": len(items), "total_matching": total}
	return nil
}

// fillListeners merges TCP sockets in the listening state with every bound
// UDP socket, since UDP has no listening state to filter on. Each query is
// filtered by Wazuh, so established connections, by far the larger share on a
// busy host, never cross the wire.
func (c *WazuhConnector) fillListeners(ctx context.Context, base, host, match string, evidence *Evidence) error {
	filters := []struct {
		name string
		q    string
	}{
		{"tcp_listening", "state=listening"},
		{"udp", "protocol=udp"},
		{"udp6", "protocol=udp6"},
	}
	summary := map[string]int{}
	var ports []wazuhPort
	total := 0
	narrow := ""
	if match != "" {
		narrow = ";process~" + match
		if _, isPort := broker.InventoryMatchPort(match); isPort {
			narrow = ";local.port=" + match
		}
	}
	for _, filter := range filters {
		q := filter.q + narrow
		page, err := getPage[wazuhPort](ctx, c, base, url.Values{
			"select": {inventoryPortFields},
			"sort":   {"+local.port"},
			"limit":  {strconv.Itoa(inventoryItemCap)},
			"q":      {q},
		})
		if err != nil {
			return err
		}
		summary[filter.name] = page.Data.TotalAffectedItems
		total += page.Data.TotalAffectedItems
		ports = append(ports, page.Data.AffectedItems...)
	}
	summary["udp_bound"] = summary["udp"] + summary["udp6"]
	delete(summary, "udp")
	delete(summary, "udp6")

	sort.SliceStable(ports, func(i, j int) bool { return ports[i].Local.Port < ports[j].Local.Port })
	if len(ports) > inventoryItemCap {
		ports = ports[:inventoryItemCap]
	}
	items := make([]EvidenceItem, 0, len(ports))
	withoutProcess := 0
	for i, p := range ports {
		if p.Process == "" {
			withoutProcess++
		}
		port := strconv.Itoa(p.Local.Port)
		items = append(items, EvidenceItem{
			ID:          strconv.Itoa(i),
			Host:        host,
			Description: strings.TrimSpace(p.Protocol + " " + p.Local.IP + ":" + port + " " + p.Process),
			State:       p.State,
			Fields: map[string]string{
				"protocol": p.Protocol,
				"address":  p.Local.IP,
				"port":     port,
				"process":  p.Process,
				"pid":      string(p.PID),
				"changed":  p.Scan.Time,
			},
		})
	}
	summary["returned"] = len(items)
	summary["total_matching"] = total
	summary["returned_without_process"] = withoutProcess
	evidence.Items = items
	evidence.ItemCount = len(items)
	evidence.TotalAvailable = total
	evidence.Truncated = total > len(items)
	evidence.Summary = summary
	return nil
}
