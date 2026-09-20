package orchestrator

import (
	"context"
	"fmt"
	"strings"

	cassandra "github.com/bindatype/cassandra"
)

// Answering "how does this work?" from the documentation is a different act
// from answering "how many agents are disconnected?" from a source, and the
// difference has to survive into the answer. Evidence is measured; this is the
// project describing itself.
//
// It is reached only where the alternative is a flat refusal. Nothing routes a
// question here: the loop runs first, and the documentation is consulted only
// when no intent was used and none failed -- that is, when the model looked at
// what it could reach and judged that none of it applied. A question that got
// evidence never sees this path, so documentation can never displace a
// measurement. A question whose evidence call *failed* never sees it either,
// because replacing a broken source with prose would hide the breakage.
const docsSystemPrompt = `You are answering a question about Cassandra itself, using only the
documentation below.

Rules:
- Answer ONLY from the documentation provided. It is the whole of what you know here.
- If the documentation does not answer the question, say so plainly and do not fill the gap.
- Never describe a capability the documentation does not state. This tool is describing
  itself, so an invented feature is worse than an admitted gap.
- Do not answer questions about live infrastructure from this text. The documentation
  describes what Cassandra can do; it does not contain current data about any host,
  ticket, alert, or job. If the question wanted live data, say that the evidence sources
  did not cover it.
- Mention "askcass -help" when the question is about running the tool.
- End with a Scope line reading exactly: "Scope: Cassandra documentation (not live evidence)."`

// answerFromDocs runs one extra turn with the documentation in context.
func (s *Session) answerFromDocs(ctx context.Context, question string) (string, error) {
	corpus, err := loadDocs()
	if err != nil {
		return "", err
	}

	messages := []Message{
		{Role: "system", Content: docsSystemPrompt},
		{Role: "user", Content: "Documentation follows.\n\n" + corpus + "\n\nQuestion: " + question},
	}

	// No tools. This turn cannot reach a source, which is the point: it is
	// bounded to the text it was given.
	choice, err := s.client.Complete(ctx, messages, nil, "")
	if err != nil {
		return "", fmt.Errorf("documentation lookup: %w", err)
	}
	answer := strings.TrimSpace(choice.Message.Content)
	if answer == "" {
		return "", fmt.Errorf("documentation lookup returned nothing")
	}
	return answer, nil
}

// loadDocs concatenates the embedded documentation, each part labelled so the
// model can attribute what it says to a file rather than to the project in
// general.
func loadDocs() (string, error) {
	var builder strings.Builder
	for _, name := range cassandra.DocFiles {
		content, err := cassandra.Docs.ReadFile(name)
		if err != nil {
			return "", fmt.Errorf("read embedded %s: %w", name, err)
		}
		fmt.Fprintf(&builder, "===== %s =====\n%s\n\n", name, content)
	}
	if builder.Len() == 0 {
		// An empty corpus would produce an answer sourced from nothing while
		// claiming to come from the documentation.
		return "", fmt.Errorf("no documentation is embedded")
	}
	return builder.String(), nil
}
