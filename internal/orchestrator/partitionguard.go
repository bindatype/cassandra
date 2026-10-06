package orchestrator

import (
	"fmt"
	"regexp"

	"github.com/bindatype/cassandra/internal/broker"
)

// A generic GPU or CPU count is a workload class, not a partition-name
// pattern. Observed 2026-10-05: a Hermes run counted GPU jobs with
// `partition` LIKE '%gpu%', which silently dropped superChip and viz and put
// them, with nano and the staff partitions, into its CPU bucket. The
// definition now lives in the runTBL2_workload view; this refuses the pattern
// that bypasses it. Explicit partition names, and family patterns that do not
// name gpu or cpu (LIKE 'superChip%'), pass.
var partitionClassPattern = regexp.MustCompile(
	"(?is)`?partition`?\\s+(?:not\\s+)?(?:like|rlike|regexp)\\s+'[^']*(?:gpu|cpu)[^']*'")

// partitionPatternFilter reports a database query that filters partitions by
// a gpu or cpu name pattern.
func partitionPatternFilter(request broker.RouteRequest) error {
	if request.Intent != broker.IntentDatabaseQuery || !partitionClassPattern.MatchString(request.Query) {
		return nil
	}
	return fmt.Errorf("this query filters partitions by a gpu or cpu name pattern, which misclassifies jobs: " +
		"superChip and viz have no gpu in their names, and from 9 May 2026 a GPU job is one that requested " +
		"a GPU, on any partition. For generic GPU or CPU jobs use the runTBL2_workload view with " +
		"workload = 'gpu' or workload = 'cpu'. If the question names a partition, filter on exactly that " +
		"name: `partition` = 'gpu'")
}
