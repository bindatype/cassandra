package orchestrator

import (
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

func TestTicketBoundContradictionCatchesAnInvertedAge(t *testing.T) {
	open := broker.IntentTicketsOpen
	cases := []struct {
		name     string
		question string
		request  broker.RouteRequest
		refused  bool
	}{
		// The live case, 2026-10-02.
		{"less than N days old sent as until", "what is the oldest open ticket for each owner? list the top 20 oldest overall that are less than 365 days old",
			broker.RouteRequest{Intent: open, Until: "365d"}, true},
		{"less than N days old sent as since", "list each owner's oldest ticket less than 365 days old",
			broker.RouteRequest{Intent: open, Since: "365d"}, false},
		{"in the last N days sent as until", "which open tickets were created in the last 30 days?",
			broker.RouteRequest{Intent: open, Until: "30d"}, true},
		{"older than sent as until", "how many open tickets are older than 60 days?",
			broker.RouteRequest{Intent: open, Until: "60d"}, false},
		{"older than sent as since", "how many open tickets are older than 60 days?",
			broker.RouteRequest{Intent: open, Since: "60d"}, true},
		{"oldest alone is not a direction", "which are the oldest open tickets?",
			broker.RouteRequest{Intent: open, Until: "30d"}, false},
		{"both directions asked", "tickets older than 30 days but created in the last 90 days",
			broker.RouteRequest{Intent: open, Until: "30d"}, false},
		{"a window is two-sided", "tickets created in the last 90 days",
			broker.RouteRequest{Intent: open, Since: "90d", Until: "30d"}, false},
		{"not a ticket intent", "problems in the last 3 days",
			broker.RouteRequest{Intent: broker.IntentMonitoringHistory, Until: "3d"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ticketBoundContradiction(tc.question, tc.request)
			if (err != nil) != tc.refused {
				t.Fatalf("refused = %v (%v), want %v", err != nil, err, tc.refused)
			}
			if err != nil && !strings.Contains(err.Error(), "instead") {
				t.Errorf("message %q does not say what to send instead", err)
			}
		})
	}
}
