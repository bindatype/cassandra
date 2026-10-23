package connector

import (
	"strings"
	"time"
)

// localTimeLayout names the zone by its abbreviation for that date, so a time
// either side of a daylight-saving change carries the right one.
const localTimeLayout = "2006-01-02 15:04:05 MST"

// LocalizeTimes adds the deployment's local time beside every UTC time in the
// evidence: since_local and until_local for the applied window, and a
// <field>_local twin for each RFC 3339 field of each item. On 2026-10-23 a
// summary labelled UTC times as EDT and dropped events inside the window;
// converting in code means the model copies a time instead of computing one.
// A nil location leaves the evidence unchanged.
func LocalizeTimes(evidence *Evidence, location *time.Location) {
	if location == nil {
		return
	}
	evidence.LocalZone = location.String()
	evidence.SinceLocal = localTime(evidence.Since, location)
	evidence.UntilLocal = localTime(evidence.Until, location)
	for i := range evidence.Items {
		localizeFields(evidence.Items[i].Fields, location)
	}
	for _, group := range evidence.Earliest {
		for key, item := range group {
			if item.Fields != nil {
				localizeFields(item.Fields, location)
				group[key] = item
			}
		}
	}
}

func localizeFields(fields map[string]string, location *time.Location) {
	for key, value := range fields {
		if strings.HasSuffix(key, "_local") {
			continue
		}
		if local := localTime(value, location); local != "" {
			fields[key+"_local"] = local
		}
	}
}

// localTime renders an RFC 3339 time in the location, or returns "" for
// anything that is not one: a relative window such as 24h is left alone.
func localTime(value string, location *time.Location) string {
	if len(value) < len("2006-01-02T15:04:05Z") {
		return ""
	}
	moment, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return ""
	}
	return moment.In(location).Format(localTimeLayout)
}
