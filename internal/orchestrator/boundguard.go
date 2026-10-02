package orchestrator

import (
	"fmt"
	"regexp"

	"github.com/bindatype/cassandra/internal/broker"
)

// The model inverts ticket age bounds ("less than 365 days old" sent as
// until: 365d, i.e. older than a year), and the prompt rule against it did
// not hold. The question is in hand here, so the contradiction is checked in
// code.
var (
	asksNewer = regexp.MustCompile(`(?i)\b(?:less|fewer) than \d+ ?(?:day|week|month|year)s? old\b|` +
		`\bunder \d+ ?(?:day|week|month|year)s? old\b|\b(?:younger|newer) than\b|` +
		`\b(?:within|in) the (?:last|past) \d+|\b(?:last|past) \d+ ?(?:day|week|month|year)s?\b|` +
		`\b(?:created|opened) (?:after|since)\b`)
	asksOlder = regexp.MustCompile(`(?i)\bolder than\b|\b(?:more|greater) than \d+ ?(?:day|week|month|year)s? old\b|` +
		`\bover \d+ ?(?:day|week|month|year)s? old\b|\bat least \d+ ?(?:day|week|month|year)s? old\b|` +
		`\b(?:created|opened) before\b`)
)

// ticketBoundContradiction reports a ticket request whose one-sided age bound
// points the opposite way from an unambiguous question. Questions that ask in
// both directions, or in neither, are left alone.
func ticketBoundContradiction(question string, request broker.RouteRequest) error {
	if request.Intent != broker.IntentTicketsOpen && request.Intent != broker.IntentTicketsByHost {
		return nil
	}
	newer, older := asksNewer.MatchString(question), asksOlder.MatchString(question)
	switch {
	case newer && !older && request.Until != "" && request.Since == "":
		return fmt.Errorf("the question asks for tickets NEWER than a bound (created within it), but until: %q "+
			"selects tickets OLDER than that bound. Use since: %q instead, and order: oldest_first if the "+
			"oldest of those are wanted", request.Until, request.Until)
	case older && !newer && request.Since != "" && request.Until == "":
		return fmt.Errorf("the question asks for tickets OLDER than a bound, but since: %q selects tickets "+
			"created AFTER it. Use until: %q instead", request.Since, request.Since)
	}
	return nil
}
