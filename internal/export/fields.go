// Package export extracts Pegasus job requests to files, deterministically:
// no model writes the SQL, chooses the window or interprets a column. A
// request names logical fields from fields.json, the one authoritative list of
// what each field means, where it comes from and whether it is recorded at
// all. The export reports three outcomes separately, so none can be read as
// another: whether the raw extraction is complete, whether normalization was
// validated, and whether the original request was fulfilled.
//
// It exists because of 2026-10-07: an agent asked for this data, invented a
// window a year off, read allocated nodes as requested ones, assumed a GPU
// type and a memory scope the database does not record, failed to write its
// files, and reported the result as verified.
package export

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed fields.json
var fieldsJSON []byte

// Field status values.
const (
	StatusRecorded    = "recorded"
	StatusDerived     = "derived"
	StatusNotRecorded = "not_recorded"
)

type Field struct {
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Sources     []string `json:"sources"`
	Unit        string   `json:"unit,omitempty"`
	Rule        string   `json:"rule,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Assumptions []string `json:"assumptions,omitempty"`
}

type Assumption struct {
	Name      string   `json:"name"`
	Fields    []string `json:"fields"`
	Statement string   `json:"statement"`
}

type Definitions struct {
	Version string `json:"version"`
	Source  struct {
		Database   string `json:"database"`
		Relation   string `json:"relation"`
		TimeColumn string `json:"time_column"`
		Definition string `json:"definition"`
	} `json:"source"`
	NullMarker  string            `json:"null_marker"`
	Assumptions []Assumption      `json:"assumptions"`
	Flags       map[string]string `json:"flags"`
	Fields      []Field           `json:"fields"`

	byName map[string]Field
	sha256 string
	raw    []byte
}

// LoadDefinitions parses the embedded definitions and checks they are
// internally consistent; a broken file fails here, not halfway through an
// export.
func LoadDefinitions() (*Definitions, error) {
	return parseDefinitions(fieldsJSON)
}

func parseDefinitions(raw []byte) (*Definitions, error) {
	var defs Definitions
	if err := json.Unmarshal(raw, &defs); err != nil {
		return nil, fmt.Errorf("field definitions: %w", err)
	}
	sum := sha256.Sum256(raw)
	defs.sha256 = hex.EncodeToString(sum[:])
	defs.raw = raw
	defs.byName = map[string]Field{}
	assumptions := map[string]bool{}
	for _, a := range defs.Assumptions {
		assumptions[a.Name] = true
	}
	for _, f := range defs.Fields {
		if _, dup := defs.byName[f.Name]; dup {
			return nil, fmt.Errorf("field definitions: %s is defined twice", f.Name)
		}
		switch f.Status {
		case StatusRecorded, StatusDerived:
			if f.Rule == "" {
				return nil, fmt.Errorf("field definitions: %s has no rule", f.Name)
			}
		case StatusNotRecorded:
			if f.Reason == "" {
				return nil, fmt.Errorf("field definitions: %s is not recorded but gives no reason", f.Name)
			}
		default:
			return nil, fmt.Errorf("field definitions: %s has unknown status %q", f.Name, f.Status)
		}
		for _, a := range f.Assumptions {
			if !assumptions[a] {
				return nil, fmt.Errorf("field definitions: %s names unknown assumption %s", f.Name, a)
			}
		}
		defs.byName[f.Name] = f
	}
	return &defs, nil
}

// Lookup returns a field by its logical name.
func (d *Definitions) Lookup(name string) (Field, bool) {
	f, ok := d.byName[name]
	return f, ok
}

// SHA256 is the hash of the definitions file as embedded, recorded in every
// manifest so a reader knows exactly which definitions produced the data.
func (d *Definitions) SHA256() string { return d.sha256 }

// Raw returns the definitions file exactly as embedded.
func (d *Definitions) Raw() []byte { return d.raw }

// Names lists the defined fields, in definition order.
func (d *Definitions) Names() []string {
	names := make([]string, 0, len(d.Fields))
	for _, f := range d.Fields {
		names = append(names, f.Name)
	}
	return names
}

func (d *Definitions) sortedFlags() []string {
	names := make([]string, 0, len(d.Flags))
	for name := range d.Flags {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
