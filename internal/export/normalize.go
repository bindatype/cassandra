package export

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // time zones from the binary, not whatever the host has installed
)

// Text is a nullable string column. Null and empty are different facts in
// this database (an empty TRESReq_gres_gpu on a recorded job means no GPU; a
// null one before TRES means unknown), so they are never merged.
type Text struct {
	Value string
	Valid bool
}

// Int is a nullable integer column.
type Int struct {
	Value int64
	Valid bool
}

// SourceRow is one job as the source returns it: the raw columns every field
// is derived from, plus the view's own derived columns, used only to check
// the exporter's conversions against an independent implementation.
type SourceRow struct {
	JobID          Text
	Netid          Text
	GroupName      Text
	SubmitTime     int64
	Partition      Text
	State          Text
	ReqCPUS        Int
	TRESReqCPU     Text
	TRESReqNode    Text
	TRESReqGresGPU Text
	TRESReqMem     Text
	TimelimitRaw   Text

	ViewMemReqGB     Text // runTBL2_jobs.mem_req_gb, DECIMAL as text
	ViewTimelimitMin Int
	ViewGpusReq      Int
	ViewNodesReq     Int
}

// Value is one normalized cell: a string, or null.
type Value struct {
	Text  string
	Valid bool
}

func some(s string) Value { return Value{Text: s, Valid: true} }

var null = Value{}

// Normalized is one job's logical fields and the flags each one raised.
type Normalized struct {
	Values map[string]Value
	Flags  map[string][]string // field -> flags it raised
}

var (
	plainJobID = regexp.MustCompile(`^[0-9]+$`)
	arrayJobID = regexp.MustCompile(`^([0-9]+)_([0-9]+)$`)
	memValue   = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([MGT])$`)
	wholeNum   = regexp.MustCompile(`^[0-9]+$`)
)

var memShift = map[string]uint{"M": 20, "G": 30, "T": 40}

// Normalizer derives logical fields from a SourceRow.
type Normalizer struct {
	Location *time.Location
	Identity string
	Salt     []byte
}

// ResearcherKey is the pseudonymous identity for a netid.
func ResearcherKey(salt []byte, netid string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(netid))
	return "r_" + hex.EncodeToString(mac.Sum(nil))[:16]
}

func (n Normalizer) identity(netid string) string {
	if n.Identity == IdentityNetid {
		return netid
	}
	return ResearcherKey(n.Salt, netid)
}

// tresRecorded is the test for whether this job's TRES request was recorded
// at all: TRESReq_mem is set for every job from 22 January 2026 and for none
// before. The view uses the same test.
func tresRecorded(row SourceRow) bool {
	return row.TRESReqMem.Valid && strings.TrimSpace(row.TRESReqMem.Value) != ""
}

// Normalize derives every recorded or derived field for one row. It never
// turns a missing value into zero: every null it returns carries a flag
// saying why.
func (n Normalizer) Normalize(row SourceRow) Normalized {
	out := Normalized{Values: map[string]Value{}, Flags: map[string][]string{}}
	flag := func(field string, flags ...string) { out.Flags[field] = append(out.Flags[field], flags...) }
	set := func(field string, v Value) { out.Values[field] = v }

	// Identity of the job.
	set("job_id", textValue(row.JobID))
	switch {
	case row.JobID.Valid && plainJobID.MatchString(row.JobID.Value):
		set("array_parent_id", null)
		set("array_task_index", null)
	case row.JobID.Valid && arrayJobID.MatchString(row.JobID.Value):
		m := arrayJobID.FindStringSubmatch(row.JobID.Value)
		set("array_parent_id", some(m[1]))
		set("array_task_index", some(m[2]))
	default:
		set("array_parent_id", null)
		set("array_task_index", null)
		flag("array_parent_id", "jobid_malformed")
		flag("array_task_index", "jobid_malformed")
	}

	if row.Netid.Valid && strings.TrimSpace(row.Netid.Value) != "" {
		set("researcher_key", some(n.identity(row.Netid.Value)))
	} else {
		set("researcher_key", null)
		flag("researcher_key", "netid_missing")
	}
	set("account", textValue(row.GroupName))

	// Time, in the request's zone, computed here rather than by the database.
	submitted := time.Unix(row.SubmitTime, 0).In(n.Location)
	set("submit_epoch", some(strconv.FormatInt(row.SubmitTime, 10)))
	set("submit_local", some(submitted.Format(time.RFC3339)))
	set("submit_month", some(submitted.Format("2006-01")))

	set("partition_raw", textValue(row.Partition))
	if !row.Partition.Valid || row.Partition.Value == "" {
		flag("partition_raw", "partition_missing")
	} else if strings.Contains(row.Partition.Value, "_") {
		flag("partition_raw", "partition_unresolved")
	}
	set("state", textValue(row.State))

	// CPUs.
	if row.ReqCPUS.Valid {
		set("req_cpus", some(strconv.FormatInt(row.ReqCPUS.Value, 10)))
		if row.TRESReqCPU.Valid && row.TRESReqCPU.Value != "" && row.TRESReqCPU.Value != strconv.FormatInt(row.ReqCPUS.Value, 10) {
			flag("req_cpus", "cpu_tres_mismatch")
		}
	} else {
		set("req_cpus", null)
		flag("req_cpus", "cpus_missing")
	}

	recorded := tresRecorded(row)

	// Nodes requested: TRESReq_node, never NNodes.
	switch {
	case !recorded:
		set("req_nodes", null)
		flag("req_nodes", "tres_unrecorded")
	case !row.TRESReqNode.Valid || row.TRESReqNode.Value == "":
		set("req_nodes", null)
		flag("req_nodes", "nodes_missing")
	case wholeNum.MatchString(row.TRESReqNode.Value):
		set("req_nodes", some(trimZeros(row.TRESReqNode.Value)))
	default:
		set("req_nodes", null)
		flag("req_nodes", "nodes_invalid")
	}

	// GPUs requested: zero only where the record says none were asked for.
	switch {
	case !recorded:
		set("req_gpus", null)
		flag("req_gpus", "tres_unrecorded")
	case !row.TRESReqGresGPU.Valid || row.TRESReqGresGPU.Value == "":
		set("req_gpus", some("0"))
	case wholeNum.MatchString(row.TRESReqGresGPU.Value):
		set("req_gpus", some(trimZeros(row.TRESReqGresGPU.Value)))
	default:
		set("req_gpus", null)
		flag("req_gpus", "gpus_invalid")
	}

	// Memory.
	set("req_mem_raw", textValue(row.TRESReqMem))
	if bytes, flags := memBytes(row.TRESReqMem); bytes != "" {
		set("req_mem_bytes", some(bytes))
		flag("req_mem_bytes", flags...)
	} else {
		set("req_mem_bytes", null)
		flag("req_mem_bytes", flags...)
	}

	// Wall time.
	set("req_walltime_raw", textValue(row.TimelimitRaw))
	switch {
	case !row.TimelimitRaw.Valid || strings.TrimSpace(row.TimelimitRaw.Value) == "":
		set("req_walltime_s", null)
		flag("req_walltime_s", "walltime_missing")
	case row.TimelimitRaw.Value == "UNLIMITED":
		set("req_walltime_s", null)
		flag("req_walltime_s", "walltime_unlimited")
	case row.TimelimitRaw.Value == "Partition":
		set("req_walltime_s", null)
		flag("req_walltime_s", "walltime_partition_default")
	case wholeNum.MatchString(row.TimelimitRaw.Value):
		minutes, err := strconv.ParseInt(row.TimelimitRaw.Value, 10, 64)
		if err != nil {
			set("req_walltime_s", null)
			flag("req_walltime_s", "walltime_invalid")
			break
		}
		set("req_walltime_s", some(strconv.FormatInt(minutes*60, 10)))
	default:
		set("req_walltime_s", null)
		flag("req_walltime_s", "walltime_invalid")
	}
	return out
}

// QualityFlags joins the flags raised by the delivered fields.
func (n Normalized) QualityFlags(fields []Field) string {
	set := map[string]bool{}
	for _, f := range fields {
		for _, flag := range n.Flags[f.Name] {
			set[flag] = true
		}
	}
	flags := make([]string, 0, len(set))
	for flag := range set {
		flags = append(flags, flag)
	}
	sort.Strings(flags)
	return strings.Join(flags, ";")
}

// memBytes converts a memory request to bytes. It returns "" with the reason
// when no byte value can be defended.
func memBytes(raw Text) (string, []string) {
	if !raw.Valid || strings.TrimSpace(raw.Value) == "" {
		return "", []string{"mem_missing"}
	}
	m := memValue.FindStringSubmatch(raw.Value)
	if m == nil {
		return "", []string{"mem_invalid"}
	}
	amount, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return "", []string{"mem_invalid"}
	}
	if amount.Sign() == 0 {
		return "", []string{"mem_special"}
	}
	amount.Mul(amount, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), memShift[m[2]])))
	return roundHalfUp(amount).String(), []string{"mem_scope_assumed_job_total"}
}

// roundHalfUp rounds a non-negative rational to the nearest integer, halves up.
func roundHalfUp(r *big.Rat) *big.Int {
	doubled := new(big.Rat).Mul(r, big.NewRat(2, 1))
	doubled.Add(doubled, big.NewRat(1, 1))
	q := new(big.Int).Quo(doubled.Num(), doubled.Denom())
	return q.Rsh(q, 1)
}

func textValue(t Text) Value {
	if !t.Valid {
		return null
	}
	return some(t.Value)
}

// trimZeros writes "007" as "7", so a count reads as a number.
func trimZeros(s string) string {
	trimmed := strings.TrimLeft(s, "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}
