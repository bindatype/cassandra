package broker

import (
	"fmt"
	"strings"
	"time"
)

// maxSinceAge bounds how far back a request may reach. A window of years is
// not a filter, and asking a source for everything since 2019 is the same
// unbounded query the limits exist to prevent.
const maxSinceAge = 400 * 24 * time.Hour

// ParseSince validates a time bound and returns it in UTC.
//
// Accepted forms are RFC 3339, a plain date, and a relative window such as
// "24h" or "7d", because a model asked for "today" reaches for the shortest
// thing that could work and a parser that accepts only one form turns a
// well-formed question into a denial.
func ParseSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if len(value) > 64 {
		return time.Time{}, fmt.Errorf("since is too long")
	}

	// The words a question about a time period reaches for first. A model asked
	// "did anything alert today" wrote since: "today", and rejecting that turns
	// a well-formed question into a denial over vocabulary.
	//
	// Built in the caller's zone, then compared as an instant. This used to
	// take the calendar date from a local clock and stamp it midnight UTC,
	// which is not a day in either zone: at 20:07 EDT on 3 September it made
	// "today" begin at 8pm on the 2nd, a 28-hour window. An operator asking
	// what happened today got four hours of yesterday evening as well, and no
	// part of the answer said so.
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "today":
		return bound(midnight, now)
	case "yesterday":
		return bound(midnight.AddDate(0, 0, -1), now)
	}

	if moment, err := time.Parse(time.RFC3339, value); err == nil {
		return bound(moment.UTC(), now)
	}
	if day, err := time.ParseInLocation("2006-01-02", value, now.Location()); err == nil {
		return bound(day, now)
	}
	if days, err := parseDays(value); err == nil {
		return bound(now.Add(-days).UTC(), now)
	}
	if window, err := time.ParseDuration(value); err == nil {
		if window <= 0 {
			return time.Time{}, fmt.Errorf("since must be a past window")
		}
		return bound(now.Add(-window).UTC(), now)
	}
	return time.Time{}, fmt.Errorf("since must be RFC 3339, a date such as 2026-08-28, a window such as 24h or 7d, or today or yesterday")
}

// parseDays handles the "7d" form, which time.ParseDuration does not accept.
func parseDays(value string) (time.Duration, error) {
	if len(value) < 2 || value[len(value)-1] != 'd' {
		return 0, fmt.Errorf("not a day window")
	}
	days, err := time.ParseDuration(value[:len(value)-1] + "h")
	if err != nil {
		return 0, err
	}
	return days * 24, nil
}

// bound validates a resolved instant and returns it in UTC.
//
// The zone matters while a day boundary is being computed and must not survive
// into the result. Plan writes these into a step with Format, and Verify
// re-plans and compares with reflect.DeepEqual: the same instant carried as
// "2026-07-05T00:00:00-04:00" by one path and "2026-07-05T04:00:00Z" by
// another is equal as a time and unequal as a plan, and the plan is rejected
// as unauthorized.
func bound(moment, now time.Time) (time.Time, error) {
	if moment.After(now.Add(time.Minute)) {
		return time.Time{}, fmt.Errorf("since is in the future")
	}
	if now.Sub(moment) > maxSinceAge {
		return time.Time{}, fmt.Errorf("since reaches further back than %d days", int(maxSinceAge.Hours()/24))
	}
	return moment.UTC(), nil
}

// ParseUntil closes the window ParseSince opens. It accepts the same forms and
// treats a plain date as the end of that day rather than its start, because
// "until May 21st" means through the 21st, not up to its first second.
func ParseUntil(value string, ref time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if day, err := time.ParseInLocation("2006-01-02", value, ref.Location()); err == nil {
		return day.AddDate(0, 0, 1).UTC(), nil
	}
	midnight := time.Date(ref.Year(), ref.Month(), ref.Day(), 0, 0, 0, 0, ref.Location())
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "today":
		return midnight.AddDate(0, 0, 1).UTC(), nil
	case "yesterday":
		return midnight.UTC(), nil
	}
	// ParseSince words its errors for since; this one is reporting on until.
	moment, err := ParseSince(value, ref)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s", strings.Replace(err.Error(), "since", "until", 1))
	}
	return moment, nil
}
