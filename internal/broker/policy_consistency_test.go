package broker

import "testing"

// The comment on OperationTakesTarget says three copies of a list is how they
// come to disagree. There are four: routableOperations, OperationTakesTarget,
// the parameter-validation switch, and the agent's own catalog. Adding
// host.uptime, host.diskfree and host.network to the first two and forgetting
// the third produced "operation is not broker-routable" for an operation that
// was, in fact, in routableOperations -- a complaint that named the wrong
// cause and cost a debugging cycle.
//
// This walks every routable operation through the validator so the lists
// cannot drift apart silently again.
func TestEveryRoutableOperationPassesParameterValidation(t *testing.T) {
	for operation := range routableOperations {
		resource := Resource{Operation: operation}
		if OperationTakesTarget(operation) {
			resource.Path = "/var/log"
			// Path-taking operations need whatever bounds their own case
			// demands; supply the ones the validator asks for.
			switch operation {
			case "filesystem.read", "filesystem.tail":
				resource.Params = &OperationParams{MaxBytes: 4096}
			case "filesystem.list":
				resource.Params = &OperationParams{MaxEntries: 16}
			}
		}
		if err := validateResource(resource); err != nil {
			t.Errorf("operation %q is in routableOperations but validateResource rejects it: %v\n"+
				"  a routable operation with no case in the parameter switch fails with "+
				"\"not broker-routable\", which names the wrong cause", operation, err)
		}
	}
}

// The inverse: an operation that takes no target must be rejected if a policy
// gives it one, so a stray path cannot ride along unnoticed.
func TestTargetlessOperationsRejectAPath(t *testing.T) {
	for operation := range routableOperations {
		if OperationTakesTarget(operation) {
			continue
		}
		err := validateResource(Resource{Operation: operation, Path: "/etc/shadow"})
		if err == nil {
			t.Errorf("operation %q takes no target but a policy path was accepted", operation)
		}
	}
}
