package broker

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// DefaultMonitoringLimit is the page size when a request does not ask for
	// one. It is deliberately small: most questions are answered by the
	// aggregates rather than by the rows.
	DefaultMonitoringLimit = 25

	// MaxMonitoringLimit is as large a page as the 64 KB evidence cap holds
	// (an event is a couple of hundred bytes). Over the cap the whole result
	// is discarded, not shortened.
	MaxMonitoringLimit = 200

	// maxMatchLen bounds the substring filter. It selects rows; it does not
	// compose a query, and no legitimate problem name needs more.
	maxMatchLen = 96
)

// severityFloors maps the severity names evidence already speaks in to the
// numeric priorities Zabbix stores. A request names "high"; nothing outside
// this file should have to know that Zabbix calls it 4.
//
// The names match what evidence shows, so the model already knows them.
var severityFloors = map[string]int{
	"not classified": 0,
	"information":    1,
	"warning":        2,
	"average":        3,
	"high":           4,
	"disaster":       5,
}

// SeverityNames lists the accepted severity floors, weakest first, for error
// messages and for the tool schema.
func SeverityNames() []string {
	return []string{"not classified", "information", "warning", "average", "high", "disaster"}
}

// SeverityFloor resolves a severity name to its numeric Zabbix priority.
func SeverityFloor(name string) (int, bool) {
	level, ok := severityFloors[normalizeSeverity(name)]
	return level, ok
}

func normalizeSeverity(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(name))), " ")
}

// Problem states a request may select. "problem" and "resolved" are the two
// values the Zabbix event log records; asking for both is the default and is
// spelled by leaving State empty.
const (
	StateProblem  = "problem"
	StateResolved = "resolved"
)

// validateMatch checks the substring filter.
//
// Zabbix binds the value into a LIKE, so the risk is not injection but a
// filter that silently matches nothing. Control characters and blank values
// are rejected so a malformed filter can't read as "no results".
func validateMatch(match string) error {
	if strings.TrimSpace(match) != match {
		return fmt.Errorf("match must not begin or end with whitespace")
	}
	if match == "" {
		return fmt.Errorf("match must not be empty; omit it to match every problem")
	}
	if len(match) > maxMatchLen {
		return fmt.Errorf("match must be at most %d characters", maxMatchLen)
	}
	for _, char := range match {
		if unicode.IsControl(char) {
			return fmt.Errorf("match must not contain control characters")
		}
	}
	return nil
}

// validateSeverity checks the severity floor.
func validateSeverity(severity string) error {
	if _, ok := SeverityFloor(severity); !ok {
		return fmt.Errorf("severity must be one of %s", strings.Join(SeverityNames(), ", "))
	}
	return nil
}

// validateState checks the problem-state selector.
func validateState(state string) error {
	switch normalizeSeverity(state) {
	case StateProblem, StateResolved:
		return nil
	}
	return fmt.Errorf("state must be %q or %q; omit it for both", StateProblem, StateResolved)
}

// resolveLimit turns a requested page size into the one a step will carry.
//
// An over-large request is refused, naming the cap, rather than silently
// clamped: a caller who asked for 2,000 rows must not mistake 200 for all.
func resolveLimit(requested int) (int, error) {
	switch {
	case requested == 0:
		return DefaultMonitoringLimit, nil
	case requested < 0:
		return 0, fmt.Errorf("limit must be positive")
	case requested > MaxMonitoringLimit:
		return 0, fmt.Errorf(
			"limit must be at most %d; a larger page would exceed the evidence budget and be discarded whole. "+
				"To characterize a result larger than that, narrow it with match, severity, state, or a tighter "+
				"window, and read the totals in summary rather than counting rows",
			MaxMonitoringLimit)
	default:
		return requested, nil
	}
}

// monitoringSelectors validates the filters shared by the two monitoring
// intents and returns them normalized.
func monitoringSelectors(request RouteRequest, allowState bool) (match, severity, state string, limit int, err error) {
	if request.Match != "" {
		if err := validateMatch(request.Match); err != nil {
			return "", "", "", 0, newRouteError("invalid_match", err.Error())
		}
		match = request.Match
	}
	if request.Severity != "" {
		if err := validateSeverity(request.Severity); err != nil {
			return "", "", "", 0, newRouteError("invalid_severity", err.Error())
		}
		severity = normalizeSeverity(request.Severity)
	}
	if request.State != "" {
		if !allowState {
			// monitoring.problems returns only firing triggers, so a state
			// filter there would be silently ignored.
			return "", "", "", 0, newRouteError("invalid_request",
				"monitoring.problems returns only problems that are currently firing and takes no state; "+
					"use monitoring.history to ask what has resolved")
		}
		if err := validateState(request.State); err != nil {
			return "", "", "", 0, newRouteError("invalid_state", err.Error())
		}
		state = normalizeSeverity(request.State)
	}
	limit, limitErr := resolveLimit(request.Limit)
	if limitErr != nil {
		return "", "", "", 0, newRouteError("invalid_limit", limitErr.Error())
	}
	return match, severity, state, limit, nil
}
