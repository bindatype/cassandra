package export

// Summary is what a caller sees first: the three outcomes, side by side and
// never merged, and how to verify them.
type Summary struct {
	ExportID      string           `json:"export_id"`
	Directory     string           `json:"directory,omitempty"`
	AsOf          string           `json:"as_of"`
	Window        WindowInfo       `json:"window"`
	Raw           string           `json:"raw"`
	RawRows       int64            `json:"raw_rows"`
	RawReason     string           `json:"raw_reason,omitempty"`
	Normalization string           `json:"normalization"`
	NormReason    string           `json:"normalization_reason,omitempty"`
	Fulfillment   string           `json:"fulfillment"`
	FulfillReason string           `json:"fulfillment_reason,omitempty"`
	Unavailable   []UnavailableRef `json:"unavailable_fields"`
	Assumptions   []string         `json:"assumptions"`
	Files         []string         `json:"files"`
	Verify        string           `json:"verify"`
}

// VerifyInstruction is the completion rule, stated wherever an export is
// reported.
const VerifyInstruction = "Download every listed file and manifest.json into one empty directory and run " +
	"`python3 verify_export.py <directory>`. Report the export as done only if it exits 0; exit 3 means the " +
	"files are intact but the request was not fully met (report the fulfillment state and reason); exit 1 means " +
	"the files do not support the manifest and must not be used. VERIFIER.md lists what is and is not checked."

func Summarize(m *Manifest, dir string) Summary {
	s := Summary{
		ExportID: m.ExportID, Directory: dir, AsOf: m.AsOf.Format("2006-01-02T15:04:05Z"), Window: m.Window,
		Raw: m.Raw.State, RawRows: m.Raw.RowsWritten, RawReason: m.Raw.Reason,
		Normalization: m.Normalization.State, NormReason: m.Normalization.Reason,
		Fulfillment: m.Fulfillment.State, FulfillReason: m.Fulfillment.Reason,
		Unavailable: m.Unavailable, Assumptions: []string{}, Files: []string{ManifestFile}, Verify: VerifyInstruction,
	}
	for _, a := range m.Assumptions {
		s.Assumptions = append(s.Assumptions, a.Name+": "+a.Statement)
	}
	for _, f := range m.Files {
		s.Files = append(s.Files, f.Name)
	}
	return s
}
