package export

import "time"

// ManifestVersion changes when the manifest's meaning changes; the verifier
// refuses a version it does not know.
const ManifestVersion = 1

// Raw extraction states.
const (
	RawComplete   = "complete"
	RawIncomplete = "incomplete"
)

// Normalization states.
const (
	NormValidated        = "validated"
	NormFailedValidation = "failed_validation"
	NormNotRequested     = "not_requested"
	NormNotRun           = "not_run" // the raw extraction was incomplete
)

// Fulfillment states, judged against the request as received.
const (
	Fulfilled          = "fulfilled"
	PartiallyFulfilled = "partially_fulfilled"
	NotFulfilled       = "not_fulfilled"
)

// Manifest is written last. A directory without one is not an export.
type Manifest struct {
	ManifestVersion  int              `json:"manifest_version"`
	ExportID         string           `json:"export_id"`
	CreatedAt        time.Time        `json:"created_at"`
	Tool             ToolInfo         `json:"tool"`
	Caller           string           `json:"caller"`
	Request          Request          `json:"request"`
	RequestSHA256    string           `json:"request_sha256"`
	FieldDefinitions DefinitionsInfo  `json:"field_definitions"`
	Source           SourceInfo       `json:"source"`
	Window           WindowInfo       `json:"window"`
	AsOf             time.Time        `json:"as_of"`
	QueryFile        string           `json:"query_file"`
	QuerySHA256      string           `json:"query_sha256"`
	Files            []FileInfo       `json:"files"`
	Raw              RawOutcome       `json:"raw"`
	Normalization    NormOutcome      `json:"normalization"`
	Fulfillment      FulfillOutcome   `json:"fulfillment"`
	Unavailable      []UnavailableRef `json:"unavailable_fields"`
	Assumptions      []Assumption     `json:"assumptions"`
	Warnings         []string         `json:"warnings"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DefinitionsInfo struct {
	File    string `json:"file"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type WindowInfo struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	Timezone   string `json:"timezone"`
	StartEpoch int64  `json:"start_epoch"`
	EndEpoch   int64  `json:"end_epoch"`
	Interval   string `json:"interval"`
}

type FileInfo struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Rows   *int64 `json:"rows,omitempty"` // data rows, for the CSV files
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// RawOutcome: was every job in the window extracted, verbatim, and written
// intact?
type RawOutcome struct {
	State        string   `json:"state"`
	File         string   `json:"file"`
	Columns      []string `json:"columns"`
	RowsExpected int64    `json:"rows_expected"`
	RowsWritten  int64    `json:"rows_written"`
	CountAfter   int64    `json:"count_after"`
	Checks       []Check  `json:"checks"`
	Reason       string   `json:"reason,omitempty"`
}

// NormOutcome: were the logical fields derived and every validation check
// passed? A normalized file exists only when this is validated.
type NormOutcome struct {
	State   string   `json:"state"`
	File    string   `json:"file,omitempty"`
	Columns []string `json:"columns,omitempty"`
	Rows    int64    `json:"rows"`
	Checks  []Check  `json:"checks"`
	Reason  string   `json:"reason,omitempty"`
}

// FulfillOutcome: did the delivered files answer the request as asked?
type FulfillOutcome struct {
	State   string         `json:"state"`
	Deliver string         `json:"deliver_requested"`
	Fields  []FieldOutcome `json:"fields"`
	Reason  string         `json:"reason,omitempty"`
}

type FieldOutcome struct {
	Field       string   `json:"field"`
	DeliveredAs string   `json:"delivered_as"` // normalized_column, raw_source_columns, unavailable, not_delivered
	Columns     []string `json:"columns,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type UnavailableRef struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Fulfillment derives the fulfillment outcome from the other two and the
// request. The verifier recomputes it the same way and refuses a manifest
// whose claim disagrees.
func Fulfillment(req Request, raw, norm string, unavailable int) (string, string) {
	switch {
	case raw != RawComplete:
		return NotFulfilled, "the raw extraction is " + raw + ", so no file can be relied on"
	case req.Deliver == DeliverNormalized && norm != NormValidated:
		return NotFulfilled, "normalized data was requested and normalization is " + norm + "; only the raw file is usable"
	case unavailable > 0:
		return PartiallyFulfilled, "every deliverable field was delivered; requested fields that are not recorded were omitted, as allow_unavailable permitted"
	}
	return Fulfilled, ""
}
