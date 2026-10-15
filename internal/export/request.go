package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Request is what a caller asks for. Dates, never epochs: the exporter
// computes the boundaries, so a caller cannot hand it a window a year off.
type Request struct {
	Source           string   `json:"source"`
	Window           Window   `json:"window"`
	Fields           []string `json:"fields"`
	Deliver          string   `json:"deliver"`
	Identity         string   `json:"identity"`
	AllowUnavailable bool     `json:"allow_unavailable"`
	Purpose          string   `json:"purpose"`
}

type Window struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Timezone string `json:"timezone"`
}

const (
	DeliverRaw        = "raw"
	DeliverNormalized = "normalized"

	IdentityPseudonymous = "pseudonymous"
	IdentityNetid        = "netid"
)

// Plan is a validated request: the computed window and the fields split by
// whether they can be delivered.
type Plan struct {
	Request     Request
	RequestHash string
	Location    *time.Location
	StartEpoch  int64
	EndEpoch    int64
	Deliverable []Field // requested and recorded or derived, in request order
	Unavailable []Field // requested and not recorded
}

// Issue is one reason a request was refused.
type Issue struct {
	Field   string `json:"field"`
	Problem string `json:"problem"`
}

// RequestError refuses a request before anything is extracted. Every problem
// is reported at once, so a caller fixes them in one round.
type RequestError struct {
	Issues []Issue `json:"issues"`
}

func (e *RequestError) Error() string {
	parts := make([]string, 0, len(e.Issues))
	for _, issue := range e.Issues {
		parts = append(parts, issue.Field+": "+issue.Problem)
	}
	return "request refused: " + strings.Join(parts, "; ")
}

var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// DecodeRequest reads one request and rejects unknown keys, so a caller who
// sends "start_epoch" is told it is not part of the contract rather than
// having it silently ignored.
func DecodeRequest(raw []byte) (Request, error) {
	var req Request
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return Request{}, &RequestError{Issues: []Issue{{Field: "request", Problem: "not a valid export request: " + err.Error() +
			". Give source, window {start, end, timezone} as dates, fields, deliver, identity, allow_unavailable and purpose; epochs are computed by the exporter, never supplied"}}}
	}
	return req, nil
}

// Validate checks a request against the definitions and computes its window.
// canIdentify says whether the caller may receive netids.
func (d *Definitions) Validate(req Request, canIdentify bool) (*Plan, error) {
	var issues []Issue
	add := func(field, problem string) { issues = append(issues, Issue{Field: field, Problem: problem}) }

	if req.Source != "pegasus" {
		add("source", fmt.Sprintf("%q is not supported; the only source is \"pegasus\"", req.Source))
	}

	var location *time.Location
	if req.Window.Timezone == "" {
		add("window.timezone", "required: an IANA time zone name such as America/New_York")
	} else if strings.EqualFold(req.Window.Timezone, "local") {
		add("window.timezone", "\"Local\" depends on the machine; name the zone, such as America/New_York")
	} else if loc, err := time.LoadLocation(req.Window.Timezone); err != nil {
		add("window.timezone", fmt.Sprintf("%q is not a known IANA time zone", req.Window.Timezone))
	} else {
		location = loc
	}
	start, startOK := parseDate(req.Window.Start, "window.start", location, add)
	end, endOK := parseDate(req.Window.End, "window.end", location, add)
	if startOK && endOK && !end.After(start) {
		add("window.end", "must be after window.start; the window is [start, end), end excluded")
	}

	switch req.Deliver {
	case DeliverRaw, DeliverNormalized:
	default:
		add("deliver", fmt.Sprintf("%q is not supported; use \"raw\" or \"normalized\"", req.Deliver))
	}
	switch req.Identity {
	case IdentityPseudonymous:
	case IdentityNetid:
		if !canIdentify {
			add("identity", "netid requires the identify permission, which this caller does not have; use \"pseudonymous\"")
		}
	default:
		add("identity", fmt.Sprintf("%q is not supported; use \"pseudonymous\" or \"netid\"", req.Identity))
	}
	if strings.TrimSpace(req.Purpose) == "" {
		add("purpose", "required: say what the export is for; it is written to the audit log")
	}

	plan := &Plan{Request: req, Location: location}
	if len(req.Fields) == 0 {
		add("fields", "required: name at least one field; valid fields are "+strings.Join(d.Names(), ", "))
	}
	seen := map[string]bool{}
	for _, name := range req.Fields {
		if seen[name] {
			add("fields", fmt.Sprintf("%s is named twice", name))
			continue
		}
		seen[name] = true
		field, ok := d.Lookup(name)
		if !ok {
			add("fields", fmt.Sprintf("%q is not a defined field; valid fields are %s", name, strings.Join(d.Names(), ", ")))
			continue
		}
		if field.Status == StatusNotRecorded {
			plan.Unavailable = append(plan.Unavailable, field)
			if !req.AllowUnavailable {
				add(name, "not recorded: "+field.Reason+
					" Remove it, or set allow_unavailable to true to export without it and have the omission listed in the manifest")
			}
			continue
		}
		plan.Deliverable = append(plan.Deliverable, field)
	}
	if len(plan.Deliverable) == 0 && len(req.Fields) > 0 {
		add("fields", "none of the requested fields is recorded, so there is nothing to export")
	}

	if len(issues) > 0 {
		return nil, &RequestError{Issues: issues}
	}
	plan.StartEpoch, plan.EndEpoch = start.Unix(), end.Unix()
	canonical, _ := json.Marshal(req)
	sum := sha256.Sum256(canonical)
	plan.RequestHash = hex.EncodeToString(sum[:])
	return plan, nil
}

// parseDate accepts a calendar date only and returns its midnight in loc.
// A time of day, an offset or an epoch is refused: the window is whole days
// in a named zone, and the exporter alone turns it into instants.
func parseDate(value, field string, loc *time.Location, add func(string, string)) (time.Time, bool) {
	if !datePattern.MatchString(value) {
		add(field, fmt.Sprintf("%q is not a date; give YYYY-MM-DD (whole days, no time, no epoch)", value))
		return time.Time{}, false
	}
	day, err := time.Parse("2006-01-02", value)
	if err != nil {
		add(field, fmt.Sprintf("%q is not a calendar date", value))
		return time.Time{}, false
	}
	if loc == nil {
		return time.Time{}, false
	}
	return time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc), true
}
