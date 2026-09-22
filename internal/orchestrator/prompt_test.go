package orchestrator

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

// The prompt is English the compiler cannot check, but parts of it are load
// bearing: it names the tool, it enumerates the intents, and several of its
// claims exist because getting them wrong produced a confidently wrong answer.
// These assert the couplings that would otherwise drift silently.

func TestPromptNamesTheTool(t *testing.T) {
	if !strings.Contains(systemPrompt, toolName) {
		t.Errorf("prompt does not mention %q; a renamed tool would leave the model calling one that does not exist", toolName)
	}
}

func TestPromptDescribesEveryIntent(t *testing.T) {
	for _, intent := range broker.AllIntents() {
		if !strings.Contains(systemPrompt, string(intent)) {
			t.Errorf("prompt does not describe intent %q; a model offered an intent it was never told about has to guess its arguments", intent)
		}
	}
}

// The prompt announces how many channels exist before listing them, and the
// two drifted: it said five while listing six, in a document whose entire job
// is to be precise about what the model may ask for.
func TestPromptCountsItsOwnChannels(t *testing.T) {
	spelled := map[int]string{
		4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
	}
	want, ok := spelled[len(broker.AllIntents())]
	if !ok {
		t.Fatalf("no spelling for %d intents; extend this table", len(broker.AllIntents()))
	}
	// The count is stated twice, at the top as channels and in the closing
	// contract as intents. Only the first was guarded, and on 2026-09-03 the
	// prompt said eight channels in one place and five intents in the other --
	// two instructions to the same model in the same document, disagreeing.
	// Every place the number appears has to be checked, or guarding one of
	// them just moves the staleness somewhere unwatched.
	for _, phrase := range []string{
		"these " + want + " evidence channels",
		"these " + want + " intents",
	} {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt does not say %q, but the broker offers %d intents",
				phrase, len(broker.AllIntents()))
		}
	}
}

func TestPromptDescribesEveryToolParameter(t *testing.T) {
	// A field absent from the prompt is a field the model infers the name of.
	// database.query was usable only by accident until "query" was declared.
	definition := ToolDefinition([]string{"database.query"}).(map[string]any)
	function := definition["function"].(map[string]any)
	parameters := function["parameters"].(map[string]any)
	properties := parameters["properties"].(map[string]any)

	for name := range properties {
		if !strings.Contains(systemPrompt, name) {
			t.Errorf("tool parameter %q is never mentioned in the prompt", name)
		}
	}
}

func TestPromptRetainsItsHardWonRules(t *testing.T) {
	// Each of these is in the prompt because its absence produced a specific
	// wrong answer. Removing one should require deleting a test and saying why.
	// Needles name the substance of a rule, not a sentence. The prompt was
	// rewritten once and every phrase-tied needle fired, which is the test
	// working -- but a needle pinned to wording has to be relaxed on every
	// edit until it stops meaning anything.
	rules := []struct {
		needle string
		why    string
	}{
		{"authoritative job outcome",
			"using DerivedExitCode reported 26 failures against a true 496"},
		{"UNIX_TIMESTAMP",
			"comparing an integer column to a datetime silently matched zero rows"},
		{"total_matching",
			"without comparing it to returned, a truncated result reads as complete"},
		{"proof of absence",
			"an empty Zabbix result was reported as 'no critical CVEs'"},
		{"reassur",
			"the same failure, stated as a reassurance rather than a finding"},
		{"NOT LIKE 'CANCELLED%'",
			"State <> 'CANCELLED' keeps suffixed cancellations and shifts wait times by 5%"},
		{"information_schema",
			"the prompt previously implied its own table list was exhaustive"},
		{"collapse rows",
			"an uncollapsed window function filled the result with duplicates"},
		{"breakdown.events_by_host",
			"asked which systems were degraded, a model read a host list off the 25-row page and implied the rest were fine"},
		{"appears twice in the event log",
			"counting event rows without a state filter double-counts every incident that opened and closed in the window"},
		{"Lead with the broken thing",
			"a literally-true \"no host has lost its agent since 05:00\" led an answer whose body reported 19 hosts down"},
		{"total_ignoring_time_bound",
			"a bound on monitoring.problems returned 0 agent-down triggers while 19 were firing, and 0 was reported as an all-clear"},
		{"is not in the event log for the window",
			"the event log had 0 agent-down rows since 05:00 while 19 hosts had the agent down right then"},
		{"not answered by asking for more rows",
			"a large result is characterized by the aggregates; raising the limit past the budget returns nothing at all"},
	}
	for _, rule := range rules {
		if !strings.Contains(systemPrompt, rule.needle) {
			t.Errorf("prompt lost %q\n     it was there because: %s", rule.needle, rule.why)
		}
	}
}

func TestPromptAndEvidenceLeaveRoomToAnswer(t *testing.T) {
	// The prompt and a maximal evidence payload both travel on the synthesis
	// turn, so together they must leave room for the question, the tool call
	// and an answer of useful length. Three quarters is the line.
	//
	// This used to hardcode `32000 * 4`, with a comment that every model on
	// the gateway was capped at 32k tokens regardless of its native context.
	// That was true, and stopped being true when the backend moved to vLLM.
	// servedContextTokens was re-measured to 131072 and this was not, so the
	// guard went on enforcing a ceiling four times lower than the real one --
	// the same two-copies-of-a-number drift this project keeps finding.
	//
	// Deriving it from servedContextTokens and the measured character ratios
	// means the two cannot disagree again, and it counts tokens rather than
	// bytes, which is what the window is actually denominated in. Prose and
	// JSON are counted at their own ratios because a byte of evidence costs
	// nearly twice a byte of prompt.
	promptTokens := int(float64(len(systemPrompt)) / proseCharsPerToken)
	evidenceBytes := maxEvidenceJSON
	evidenceTokens := int(float64(evidenceBytes) / jsonCharsPerToken)
	used := promptTokens + evidenceTokens + answerReserveTokens

	if used > servedContextTokens*3/4 {
		t.Errorf("prompt (%d tokens) plus max evidence (%d tokens) plus the answer reserve (%d) "+
			"is %d of %d served tokens, past the three-quarter line",
			promptTokens, evidenceTokens, answerReserveTokens, used, servedContextTokens)
	}
}

func TestEvidenceBudgetExceedsWhatConnectorsReturn(t *testing.T) {
	// A connector allowed to return more than this will produce a query that
	// succeeds against the database and is then rejected here, which reads to
	// the caller as a failure of the query rather than of the configuration.
	const largestConnectorPayload = 48 * 1024 // pegasusMaxTotalBytes
	if maxEvidenceJSON <= largestConnectorPayload {
		t.Errorf("evidence budget %d does not exceed the largest connector payload %d",
			maxEvidenceJSON, largestConnectorPayload)
	}
}

// TestPromptTeachesTicketAgeDirection guards the mapping the model got wrong
// in the field on 2026-09-02: "older than N days" is an `until`, not a
// `since`, and it stands alone. The prompt told the model to ask RT for an
// exact count with the bound applied, and separately that a lone `since` is a
// ray; it never said which field carries ticket age. The model sent no bound,
// got 100 of 428 tickets, and tallied dates and owners off the page.
//
// This asserts the guidance is present, not that a model follows it. Only an
// eval can show the second, and there is no RT eval harness yet.
func TestPromptTeachesTicketAgeDirection(t *testing.T) {
	required := []string{
		"`until` bounds the older side",
		"`until: 60d`",
		"breakdown.tickets_by_owner",
	}
	for _, phrase := range required {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt no longer teaches ticket age direction: missing %q", phrase)
		}
	}
}

// TestPromptTeachesEndpointEvidence guards the rule that arrived with the
// endpoint connector. live.evidence is the only channel whose result lands in
// `data` rather than `items`, which puts a countable array directly in front
// of a model that is told everywhere else never to count arrays. Without this
// paragraph the model has a raw list, a prohibition, and no stated way to
// answer "how many" that is neither a refusal nor a violation.
func TestPromptTeachesEndpointEvidence(t *testing.T) {
	for _, phrase := range []string{
		"Counts still come from `summary`, never from `data`",
		"`summary.entries`",
		"supports no population claim",
	} {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt no longer tells the model how to read endpoint evidence: missing %q", phrase)
		}
	}
}

// pricedRules are the rules with an incident behind them. Each names the
// marker that delimits it and a phrase that must survive any rewrite.
//
// The prompt has ~128 rules and, before this, three guards. A defensive
// rewrite in August cut it from 12,376 to 10,706 bytes, scored the same on
// the head-to-head suite, and silently dropped three rules -- the runTBL2
// column list cost about two hours of guessed column names before anyone
// worked out why. The lesson recorded then was that a fixed suite only
// measures the shapes it contains. These are the shapes it did not contain.
var pricedRules = []struct {
	marker string
	phrase string
	cost   string
}{
	{"grouped-truncation", "leaves no visible trace",
		"a grouped result loses half its groups with every returned row still well formed"},
	{"runtbl2-columns", "groupName",
		"the model guessed a Hostname column; one wasted turn per host question for ~2 hours"},
	{"unrun-check-not-allclear", "reads as an",
		"\"no critical agents are disconnected\" was posted while five were down"},
	{"lead-with-broken", "people skim",
		"a reader who stops after one sentence gets the opposite impression"},
	{"counts-from-summary", "Never count the `items` list by hand",
		"275 records tallied as 55 against a true 52; a total reported as the page limit"},
	{"no-cve-source", "vulnerabilities or CVEs",
		"a CVE question answered from Zabbix triggers, reporting no critical CVEs for a host that did not exist"},
	{"oldruntbl-compressed", "compressed form",
		"LIKE '%cpu004%' silently misses jobs recorded as cpu[004-005]"},
	{"ingestion-lag", "ingestion frontier",
		"CURDATE() selects a partial day and reports a fraction of it as a total"},
	{"time-bound-contract", "refuse a bound rather than ignore it",
		"live.evidence accepted a bound and dropped it until c9f4c3f"},
	{"rt-metadata-only", "never the ticket body",
		"RT tickets routinely carry user PII and credentials pasted into a support request"},
	{"ticket-age-direction", "bounds the older side",
		"an unbounded fetch tallied 100 of 428 rows by hand, 2026-09-02"},
	// Added after the eleven above, because selecting them from the incident
	// record missed the rule governing the worst-performing case in the suite.
	// Every rule guarded above covers a case scoring 3/3; this one covers the
	// only case that does not, at 1/3 and 2/3 across both arms of an A/B.
	{"ongoing-not-in-log", "wrote nothing between those hours",
		"monitoring.history since 05:00 matched 0 events while 19 hosts had the agent down right now, " +
			"and zero rows read as an all-clear"},
}

// TestPricedRulesSurvive fails if a rule with a known cost has been reworded
// away. String presence is a weak assertion and that is the point: it is cheap
// enough to keep one per rule, and a rewrite cannot drop the rule without
// turning this red.
func TestPricedRulesSurvive(t *testing.T) {
	for _, rule := range pricedRules {
		if !strings.Contains(systemPrompt, rule.phrase) {
			t.Errorf("the %s rule is gone (%q). What it cost last time: %s",
				rule.marker, rule.phrase, rule.cost)
		}
	}
}

// TestPricedRulesAreMarkedForAblation asserts each is delimited, so its worth
// can be measured by removing it rather than argued about. The markers are
// stripped before the model sees them.
func TestPricedRulesAreMarkedForAblation(t *testing.T) {
	raw := rawPromptForTest(t)
	for _, rule := range pricedRules {
		marker := "<!-- rule:" + rule.marker + " -->"
		if !strings.Contains(raw, marker) {
			t.Errorf("%s carries no ablation marker, so its cost cannot be measured", rule.marker)
			continue
		}
		// A marker not at the start of a line is invisible to the harness
		// regex, which is how one rule was reported removed while its text
		// stayed in place.
		if !strings.Contains(raw, "\n"+marker+"\n") {
			t.Errorf("%s marker is not alone on its own line; the ablation harness will not see it", rule.marker)
		}
	}
}

// TestPromptCarriesNoMarkersIntoTheModel asserts the stripping works. A model
// reading "<!-- rule:grouped-truncation -->" is being handed a name for a rule
// it is supposed to follow, not notice.
func TestPromptCarriesNoMarkersIntoTheModel(t *testing.T) {
	if strings.Contains(systemPrompt, "<!-- rule:") || strings.Contains(systemPrompt, "<!-- /rule -->") {
		t.Error("ablation markers reached the assembled prompt; they must be stripped before the model sees them")
	}
}

// rawPromptForTest reads prompt.md from disk, markers intact. systemPrompt has
// been stripped, so a marker assertion has to read the source.
func rawPromptForTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("prompt.md")
	if err != nil {
		t.Fatalf("read prompt.md: %v", err)
	}
	return string(raw)
}

// TestSafetyRulesCannotBeAblated asserts the rules whose loss would turn an
// absence of evidence into a reassurance are named in eval_ablate.py's
// protected list.
//
// That protection used to be the absence of an ablation marker. On 2026-09-03
// eleven rules were marked so their loss could be guarded -- correct in
// itself -- and four of them were safety rules, so the protection silently
// ended in the same commit that improved the guarding. A safeguard that holds
// only while nobody does the obvious thing is not a safeguard.
//
// The harness scores against a pegasusdb suite, so for most of these it would
// report "removal costs nothing" while being structurally incapable of seeing
// the failure. That is not a null result; it is a wrong one, and it would read
// as permission to delete the rule that exists because a false all-clear was
// posted while five critical agents were down.
func TestSafetyRulesCannotBeAblated(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/eval_ablate.py")
	if err != nil {
		t.Fatalf("read eval_ablate.py: %v", err)
	}
	harness := string(raw)

	// Rules that must never be removed on the strength of a score.
	safety := []string{
		"grouped-truncation", "unrun-check-not-allclear", "ongoing-not-in-log",
		"no-cve-source", "lead-with-broken", "counts-from-summary",
		"rt-metadata-only", "oldruntbl-compressed", "ingestion-lag",
	}
	for _, name := range safety {
		if !strings.Contains(harness, `"`+name+`"`) {
			t.Errorf("%s is not in the ablation harness's protected list; a run could remove it "+
				"and report that removal costs nothing", name)
		}
	}

	// A protected name that no longer exists in the prompt protects nothing,
	// and would do it quietly.
	promptText := rawPromptForTest(t)
	for _, name := range safety {
		if !strings.Contains(promptText, "<!-- rule:"+name+" -->") {
			t.Errorf("%s is protected in the harness but no longer marked in the prompt; "+
				"the protection now applies to nothing", name)
		}
	}
}

// TestContextBudgetIsNotAlreadyExceeded is the arithmetic nobody had done.
//
// maxEvidenceJSON caps one result. Nothing capped the total, and every result
// stays in the message history, so five are sent together on the final turn.
//
// Under the previous backend that overflow was silent: the gateway discarded
// the head and kept the tail, and the head is the system prompt, so the safety
// rules were the first thing lost exactly when the context was largest. The
// current backend refuses with HTTP 400 instead, which is survivable but still
// a failed answer, so the arithmetic is still worth asserting.
//
// The numbers move when the backend moves. They are held in one place, in
// session.go, with the measurement that produced each; this test does the sums
// so that a change there cannot quietly stop adding up.
func TestContextBudgetIsNotAlreadyExceeded(t *testing.T) {
	promptTokens := int(float64(len(systemPrompt)) / proseCharsPerToken)
	schema, err := json.Marshal(ToolDefinition([]string{"monitoring.problems"}))
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	schemaTokens := int(float64(len(schema)) / jsonCharsPerToken)
	oneResult := int(float64(evidenceBudget()) / jsonCharsPerToken)

	fixed := promptTokens + schemaTokens + answerReserveTokens
	t.Logf("prompt %d + schema %d + answer reserve %d = %d tokens fixed cost",
		promptTokens, schemaTokens, answerReserveTokens, fixed)
	t.Logf("one full evidence result: %d tokens; served context: %d", oneResult, servedContextTokens)

	if fixed >= servedContextTokens {
		t.Fatalf("the prompt and schema alone reach %d of %d tokens; no evidence fits at all",
			fixed, servedContextTokens)
	}
	if fixed+oneResult <= servedContextTokens {
		return
	}
	// Not a failure: it is the finding. A single maximum-size result does not
	// fit, so maxEvidenceJSON is larger than the window can carry and the
	// cumulative guard is what stops it reaching the gateway.
	t.Logf("NOTE: one maximum-size result (%d) plus fixed cost (%d) = %d, over the %d served context. "+
		"The per-result cap alone would overflow; roomForMore is what prevents it.",
		oneResult, fixed, fixed+oneResult, servedContextTokens)
}

// TestRoomForMoreRefusesBeforeTheGatewayTruncates asserts the guard fires while
// there is still a window to protect, rather than after the request is already
// too big to serve -- and that it does not fire so early it refuses work that
// fits.
func TestRoomForMoreRefusesBeforeTheGatewayTruncates(t *testing.T) {
	tools := []any{ToolDefinition([]string{"monitoring.problems"})}
	messages := []Message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: "how many?"}}

	if _, ok := roomForMore(messages, tools, 4*1024); !ok {
		t.Error("a 4 KB result was refused on an empty history; the guard is too tight to be usable")
	}

	// A real result, not the synthetic maximum: an unbounded tickets.open
	// against the live instance measured 36,666 bytes.
	const realResult = 36666
	if _, ok := roomForMore(messages, tools, realResult); !ok {
		t.Error("a result the size of a real ticket search was refused on an empty history; " +
			"the guard is too tight to be usable")
	}

	// A full run of real-size results must stay inside the window. Whether the
	// guard closes before maxToolCalls is a property of the window, not of the
	// guard: against the 32,768 this once assumed it closed on the second
	// result, and asserting that it must close made the test fail when the
	// backend got bigger. The invariant is that the history never passes what
	// the gateway serves.
	added := 0
	for i := 0; i < maxToolCalls; i++ {
		if _, ok := roomForMore(messages, tools, realResult); !ok {
			break
		}
		messages = append(messages, Message{Role: "tool", Content: strings.Repeat("x", realResult)})
		added++
	}
	if got := estimatedTokens(messages, tools); got > servedContextTokens {
		t.Errorf("the guard let the history reach %d tokens, past the %d the gateway serves", got, servedContextTokens)
	}
	t.Logf("%d of %d real-size result(s) accepted; history estimated at %d of %d tokens",
		added, maxToolCalls, estimatedTokens(messages, tools), servedContextTokens)

	// The guard's actual job, exercised independently of how large the window
	// happens to be: keep feeding it until it says no. It must say no, and it
	// must say no while the request is still servable.
	flood := []Message{{Role: "system", Content: systemPrompt}}
	closed := false
	for i := 0; i < 1000; i++ {
		if _, ok := roomForMore(flood, tools, evidenceBudget()); !ok {
			closed = true
			break
		}
		flood = append(flood, Message{Role: "tool", Content: strings.Repeat("x", evidenceBudget())})
	}
	if !closed {
		t.Fatal("the guard never refused, even after 1000 maximum-size results")
	}
	if got := estimatedTokens(flood, tools); got > servedContextTokens {
		t.Errorf("the guard refused only after the history reached %d tokens, past the %d served",
			got, servedContextTokens)
	}
	t.Logf("guard refused with %d maximum-size result(s) held, at %d of %d tokens",
		len(flood)-1, estimatedTokens(flood, tools), servedContextTokens)

	// The per-result cap is larger than the window can deliver, which is a
	// finding rather than a failure: it means a maximum-size result can never
	// be returned, and this guard is what turns that into a refusal with a
	// reason instead of a silently decapitated request.
	fits := int(float64(servedContextTokens-estimatedTokens(
		[]Message{{Role: "system", Content: systemPrompt}}, tools)) * jsonCharsPerToken)
	if evidenceBudget() > fits {
		t.Logf("NOTE: maxEvidenceJSON is %d bytes but at most about %d bytes of evidence fit "+
			"alongside the prompt; a maximum-size result cannot be delivered", evidenceBudget(), fits)
	}
}

// TestWithheldEvidenceIsDisclosed asserts a truncated-for-context answer says
// so even when the model does not.
func TestWithheldEvidenceIsDisclosed(t *testing.T) {
	if got := discloseWithheldEvidence("There are 12 problems.", false); strings.Contains(got, "incomplete") {
		t.Error("added a limitation to an answer that had none to add")
	}
	got := discloseWithheldEvidence("There are 12 problems.", true)
	if !strings.Contains(strings.ToLower(got), "incomplete") {
		t.Errorf("a partial answer did not say it was partial: %q", got)
	}
	already := "This is incomplete because evidence was withheld."
	if discloseWithheldEvidence(already, true) != already {
		t.Error("repeated a limitation the model had already stated")
	}
}

// TestSchemaNamesThePolicysLiveTargets pins the fix for three consecutive
// refusals that were each correct and none of them useful: asked to list a
// directory on a host it had been told about by name, the model proposed host
// "sgtstubby" against a policy saying "sgtstubby.arc.gwu.edu", then resource
// "/var/log" and "var_log" against a policy saying "log-dir".
func TestSchemaNamesThePolicysLiveTargets(t *testing.T) {
	hosts := []string{"sgtstubby.arc.gwu.edu"}
	resources := []string{"log-dir", "log-dir-metadata"}

	encoded, err := json.Marshal(toolDefinition([]string{"live.evidence"}, hosts, resources))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	schema := string(encoded)

	// The resource field is closed: a resource alias means nothing to any
	// other intent, so guessing one is never the right behaviour.
	for _, want := range resources {
		if !strings.Contains(schema, want) {
			t.Errorf("schema does not offer resource %q; the model can only guess it", want)
		}
	}
	if !strings.Contains(schema, `"enum":["log-dir","log-dir-metadata"]`) {
		t.Error("resource is not an enum; a free-form string invites the path that was tried three times")
	}

	// The host field names the authorized hosts but is NOT closed. host is
	// also a Wazuh agent name and an RT subject; an enum here would refuse
	// agent.status for every host without an endpoint agent.
	if !strings.Contains(schema, "sgtstubby.arc.gwu.edu") {
		t.Error("schema does not name the authorized live host")
	}
	if strings.Contains(schema, `"enum":["sgtstubby.arc.gwu.edu"]`) {
		t.Error("host was closed to the live hosts; agent.status for any other host would now be refused")
	}
}

// TestSchemaStaysOpenWithoutAPolicy asserts the degenerate case does not
// produce an empty enum, which is a schema permitting nothing.
func TestSchemaStaysOpenWithoutAPolicy(t *testing.T) {
	encoded, err := json.Marshal(toolDefinition([]string{"fleet.inventory"}, nil, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), `"enum":[]`) {
		t.Error("empty enum emitted; that permits no value at all")
	}
}
