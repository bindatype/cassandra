package orchestrator

import (
	"strings"
	"testing"

	cassandra "github.com/bindatype/cassandra"
	"github.com/bindatype/cassandra/internal/broker"
)

func TestEmbeddedDocsLoad(t *testing.T) {
	corpus, err := loadDocs()
	if err != nil {
		t.Fatalf("loadDocs() error = %v", err)
	}
	if len(corpus) < 10_000 {
		t.Errorf("corpus is %d bytes; the documentation is larger than that, so something is not embedded", len(corpus))
	}
	// Each part is labelled so the model can attribute a claim to a file.
	for _, name := range cassandra.DocFiles {
		if !strings.Contains(corpus, "===== "+name+" =====") {
			t.Errorf("%s is not labelled in the corpus", name)
		}
	}
}

// The tool describing itself is only as good as the description. A capability
// list that has gone stale makes askcass confidently advertise something it no
// longer has -- worse than refusing, because it is the tool vouching for
// itself. TestPromptDescribesEveryIntent does this for the prompt; the
// documentation needs the same discipline.
func TestDocumentationNamesEveryIntent(t *testing.T) {
	corpus, err := loadDocs()
	if err != nil {
		t.Fatalf("loadDocs() error = %v", err)
	}
	for _, intent := range broker.AllIntents() {
		if !strings.Contains(corpus, string(intent)) {
			t.Errorf("intent %q appears in no embedded document. askcass now answers "+
				"questions about itself from this text, so an intent missing here is a "+
				"capability the tool will deny having", intent)
		}
	}
}

// The documentation must not become a second, quieter copy of the answer
// contract. These are the properties a reader relies on, and a doc answer that
// contradicts them is worse than none.
func TestDocsPromptRefusesToInventOrToAnswerLiveQuestions(t *testing.T) {
	for _, required := range []string{
		"ONLY from the documentation",
		"does not answer the question, say so",
		"does not contain current data",
		"askcass -help",
		"Scope: Cassandra documentation (not live evidence)",
	} {
		if !strings.Contains(docsSystemPrompt, required) {
			t.Errorf("the documentation prompt no longer says %q", required)
		}
	}
}

// Only user-facing documentation is embedded. Configuration, deployment units
// and the vault carry host detail and security analysis that this tool should
// not recite on request.
func TestOnlyPublicDocumentationIsEmbedded(t *testing.T) {
	for _, name := range cassandra.DocFiles {
		if strings.HasPrefix(name, "deploy/") || strings.HasPrefix(name, "configs/") {
			t.Errorf("%s is embedded; deployment and configuration are not public documentation", name)
		}
		if !strings.HasSuffix(name, ".md") {
			t.Errorf("%s is embedded and is not a markdown document", name)
		}
	}
	corpus, err := loadDocs()
	if err != nil {
		t.Fatalf("loadDocs() error = %v", err)
	}
	// A credential reaching this corpus would be recited to anyone who asks.
	//
	// The patterns are assembled rather than written out: verify.sh scans
	// tracked files for exactly these shapes, and a test that spells one
	// literally fails that scan. Which is the scanner behaving correctly --
	// it should not have to judge intent -- but it means the check for a
	// secret cannot itself look like one.
	forbidden := []string{
		"CASS_AUTH_TOKENS" + "=",
		"password" + "=",
		"Bearer " + "mr2_",
		"hooks." + "zoom" + ".us",
	}
	for _, forbidden := range forbidden {
		if strings.Contains(corpus, forbidden) {
			t.Errorf("the embedded documentation contains %q, which askcass would now read out on request", forbidden)
		}
	}
}
