package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

// The question that prompted this path -- "what groups are there and how many
// nodes in each" -- was answered from a capped page of agent records, so the
// model reported a sample of 60 out of 276 and refused to give counts. The
// group census exists so the counts come from Wazuh instead.
func TestWazuhGroupsReturnsCountsWithoutTallyingAgents(t *testing.T) {
	var groupPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
			io.WriteString(w, "jwt-token-value\n")
		case r.URL.Path == "/groups":
			groupPath = r.URL.Path
			if got := r.Header.Get("Authorization"); got != "Bearer jwt-token-value" {
				t.Errorf("Authorization = %q", got)
			}
			io.WriteString(w, `{"data":{"affected_items":[
				{"name":"Viper","count":3},
				{"name":"Pegasus","count":199},
				{"name":"RTS_Ops","count":14}
			],"total_affected_items":3,"total_failed_items":0},"message":"ok","error":0}`)
		case r.URL.Path == "/agents":
			t.Error("groups.list must not fetch agent records; the counts come from /groups")
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	evidence, err := newTestWazuh(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "groups.list",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if groupPath != "/groups" {
		t.Fatalf("groups.list queried %q, want /groups", groupPath)
	}
	if evidence.Truncated {
		t.Error("a three-group census is not truncated; reporting it as such reintroduces the hedge this path removes")
	}
	if len(evidence.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(evidence.Items))
	}

	// Largest first: a reader asking about group sizes wants the big ones.
	if evidence.Items[0].ID != "Pegasus" || evidence.Items[0].Fields["agents"] != "199" {
		t.Errorf("first item = %q/%q, want Pegasus/199", evidence.Items[0].ID, evidence.Items[0].Fields["agents"])
	}
	if evidence.Items[2].ID != "Viper" {
		t.Errorf("last item = %q, want Viper (smallest)", evidence.Items[2].ID)
	}

	// Every item states its own count, so no answer depends on the model adding.
	for _, item := range evidence.Items {
		if item.Fields["agents"] == "" {
			t.Errorf("item %q carries no agent count", item.ID)
		}
	}

	if evidence.Summary["groups_total"] != 3 {
		t.Errorf("groups_total = %d, want 3", evidence.Summary["groups_total"])
	}
	// 3+199+14. Named as memberships because an agent in two groups is in both.
	if evidence.Summary["group_memberships_total"] != 216 {
		t.Errorf("group_memberships_total = %d, want 216", evidence.Summary["group_memberships_total"])
	}
	if _, present := evidence.Summary["agents_total"]; present {
		t.Error("summary must not name a fleet total: overlapping groups make the sum larger than the fleet")
	}
}

// Group membership is current state. A time bound would filter nothing and
// imply a window the answer does not have -- the same trap fleet.inventory
// refuses.
func TestWazuhGroupsRefusesTimeBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a bounded groups.list must be refused before any request is made")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := newTestWazuh(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "groups.list",
		Since:  "2026-09-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("bounded groups.list was accepted")
	}
	if !strings.Contains(err.Error(), "since or until") {
		t.Errorf("error = %v, want it to name the bound it refuses", err)
	}
}

// A Wazuh application error arrives inside an HTTP 200 body. The groups path
// shares getRaw precisely so this check is not one the new path could skip.
func TestWazuhGroupsHonoursWazuhErrorEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
			io.WriteString(w, "jwt-token-value\n")
		default:
			io.WriteString(w, `{"data":{"affected_items":[],"total_affected_items":0},"message":"permission denied","error":4000}`)
		}
	}))
	defer server.Close()

	_, err := newTestWazuh(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "groups.list",
	})
	if err == nil {
		t.Fatal("an error envelope inside HTTP 200 was treated as success")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v, want the wazuh message carried through", err)
	}
}
