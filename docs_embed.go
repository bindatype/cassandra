// Package cassandra embeds the project's public documentation so the tool can
// answer questions about itself.
//
// The embed lives at the repository root because go:embed cannot read above
// its own package directory, and copying the files into internal/ would create
// exactly the drift this is meant to avoid: documentation that describes a
// version of the tool nobody is running. These are the real files, and a test
// fails if they stop naming every intent the broker offers.
//
// Only user-facing documentation belongs here. Not configuration, not the
// deployment units, and nothing from the Obsidian vault -- those carry host
// detail and security analysis that is not this tool's to recite on request.
package cassandra

import "embed"

//go:embed README.md docs/onboarding.md docs/cassd-capabilities.md docs/adding-a-connector.md
var Docs embed.FS

// DocFiles is the read order, most generally useful first. A question about
// what the tool can do is usually answered by the README; the rest are for
// questions that survive it.
var DocFiles = []string{
	"README.md",
	"docs/onboarding.md",
	"docs/cassd-capabilities.md",
	"docs/adding-a-connector.md",
}
