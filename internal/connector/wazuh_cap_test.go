package connector

import (
	"encoding/json"
	"testing"
)

// The orchestrator rejects an oversized evidence payload *whole* rather than
// trimming it, so a cap set too high does not degrade an answer -- it removes
// the evidence entirely and the answer arrives with none. This asserts the cap
// stays on the safe side of that cliff, with room for a second source in the
// same turn.
//
// It exists because the cap was nearly raised to 300 on the reasoning that
// "276 hosts fit, so 300 is about right". 300 records is ~66 KB against a
// 64 KB tripwire: the number that looked safe was the first one over.
func TestFleetItemCapLeavesRoomUnderTheEvidenceTripwire(t *testing.T) {
	// Mirrors what the orchestrator's tripwire is set to. Duplicated rather
	// than imported because connector must not depend on orchestrator.
	const evidenceTripwire = 64 * 1024

	// A worst-case-shaped record: full IPv6 address, long hostname, two groups.
	sample := EvidenceItem{
		ID:          "042",
		Host:        "pegasus-login001.arc.gwu.edu",
		Description: "Wazuh agent Wazuh v4.14.0",
		State:       "active",
		Fields: map[string]string{
			"ip":              "2606:69c0:9010:1006:e273:e7ff:fe0c:fdbb",
			"last_keep_alive": "2026-09-18T07:45:11Z",
			"groups":          "default,Pegasus",
		},
	}
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	perRecord := len(encoded)
	atCap := perRecord * fleetItemCap

	if atCap >= evidenceTripwire {
		t.Fatalf("fleetItemCap = %d at ~%d bytes/record is %d bytes, at or over the %d byte tripwire: "+
			"a full fleet listing would be discarded whole and the answer would carry no fleet evidence",
			fleetItemCap, perRecord, atCap, evidenceTripwire)
	}

	// Headroom for a second source in the same turn. A cap that only fits when
	// it is the sole evidence makes every cross-source question fragile.
	if atCap > evidenceTripwire*3/4 {
		t.Errorf("fleetItemCap = %d uses %d of %d bytes (>75%%), leaving no room for a second source "+
			"in a cross-source question", fleetItemCap, atCap, evidenceTripwire)
	}
}
