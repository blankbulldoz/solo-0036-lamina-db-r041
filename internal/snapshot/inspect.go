package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Demand is a single operator requirement checked against the image's
// verified reachability scope. Demands never weaken validation: a broken
// envelope fails regardless of the demands supplied.
type Demand struct {
	// Kind is "read", "change" or "journal_id".
	Kind string `json:"kind"`
	// Relation is required for read demands.
	Relation string `json:"relation,omitempty"`
	// Sequence is the "at" snapshot (read) or "after" cursor (change).
	Sequence uint64 `json:"sequence,omitempty"`
	// JournalID is the expected lineage for journal_id demands.
	JournalID string `json:"journal_id,omitempty"`
}

// DemandVerdict reports one demand against the shared reachability rules.
type DemandVerdict struct {
	Demand    Demand `json:"demand"`
	Satisfied bool   `json:"satisfied"`
	Reason    string `json:"reason,omitempty"`
}

// RelationReach is the verified boundary of one relation.
type RelationReach struct {
	Created         uint64 `json:"created"`
	EarliestVersion uint64 `json:"earliest_retained_version"`
}

// Report is the complete precheck result. Everything in it is derived from
// a single sequential read of the file; no second copy is materialized on
// disk and no live database is opened.
type Report struct {
	Path string `json:"path"`
	// Digest is the observed SHA-256 of the envelope payload. Pin this
	// exact value at install time (-expect-digest) to close the gap between
	// preview and installation.
	Digest        string       `json:"digest"`
	Bytes         int64        `json:"bytes"`
	Checks        CheckResults `json:"checks"`
	Valid         bool         `json:"valid"`
	IdentityKnown bool         `json:"identity_known"`
	Origin        *Origin      `json:"origin,omitempty"`
	// Head is the image's committed sequence; Horizon is the enforced lower
	// bound for historical reads. Retained interval is Horizon..Head.
	Head       uint64                   `json:"head,omitempty"`
	Horizon    uint64                   `json:"horizon,omitempty"`
	ChangeBase uint64                   `json:"change_base,omitempty"`
	Relations  map[string]RelationReach `json:"relations,omitempty"`
	Demands    []DemandVerdict          `json:"demands"`
	// VerifiedScope states in plain terms what the report actually proves.
	VerifiedScope []string `json:"verified_scope"`
	// NotVerified states what a precheck deliberately cannot establish.
	NotVerified []string `json:"not_verified"`
}

// ExitCode maps the report to a process status:
//   - 2: image unreadable or structurally invalid (unsafe to install)
//   - 1: image valid, but at least one explicit demand is unsatisfied
//   - 0: image valid and every explicit demand is satisfied
func (r *Report) ExitCode() int {
	if !r.Valid {
		return 2
	}
	for _, d := range r.Demands {
		if !d.Satisfied {
			return 1
		}
	}
	return 0
}

// Inspect reads a backup image once and decides, against the same
// reachability rules the running engine enforces, whether it can serve the
// operator's intended historical reads and change catch-up.
//
// Cost: one file read plus one in-memory decode bounded by MaxImage. The
// image is never expanded into a data directory, so the extra footprint is
// at most one image — matching the single spare image-sized space budget.
func Inspect(path string, demands []Demand) (*Report, error) {
	report := &Report{
		Path:          path,
		Demands:       []DemandVerdict{},
		Relations:     map[string]RelationReach{},
		VerifiedScope: []string{},
		NotVerified:   []string{},
	}
	info, err := statRegularFile(path)
	if err != nil {
		return failReport(report, "file", err)
	}
	report.Bytes = info.Size()
	if info.Size() > MaxImage {
		return failReport(report, "file", fmt.Errorf("image exceeds limit"))
	}
	f, err := os.Open(path)
	if err != nil {
		return failReport(report, "file", err)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxImage+1))
	f.Close()
	if err != nil {
		return failReport(report, "file", err)
	}
	if len(b) > MaxImage {
		return failReport(report, "file", fmt.Errorf("image exceeds limit"))
	}

	// Stage 1: envelope digest. Nothing below this line is trustworthy if
	// the digest fails, so stop immediately.
	claimed, actual, formatOK, err := PayloadDigest(b)
	report.Digest = actual
	report.VerifiedScope = []string{
		"file read once; payload SHA-256 recomputed over the exact bytes offered for install",
	}
	if err != nil || !formatOK || claimed != actual {
		report.Checks.FailureStage = "envelope_digest"
		if err != nil {
			report.Checks.FailureReason = err.Error()
		} else if !formatOK {
			report.Checks.FailureReason = "unsupported envelope format"
		} else {
			report.Checks.FailureReason = "payload digest mismatch"
		}
		report.NotVerified = []string{"payload contents were not parsed: a failed digest cannot establish any structural or reachability fact"}
		return report, nil
	}
	report.Checks.EnvelopeDigest = true

	// Stage 2: decode payload.
	var env Envelope
	if err = json.Unmarshal(b, &env); err != nil {
		return failReport(report, "envelope", err)
	}
	var image Image
	if err = json.Unmarshal(env.Payload, &image); err != nil {
		return failReport(report, "payload_json", err)
	}

	// Stages 3..7: structural validation with the same functions install
	// uses, staged so the report says how far verification reached.
	report.Checks = StagedValidate(image)
	report.Checks.EnvelopeDigest = true
	if report.Checks.FailureStage != "" {
		report.NotVerified = []string{
			"reachability was not evaluated because structural validation stopped at " + report.Checks.FailureStage,
		}
		return report, nil
	}

	report.Valid = true
	report.Head = image.Sequence
	report.Horizon = image.Horizon
	report.Origin = image.Origin
	report.IdentityKnown = image.Origin != nil && image.Origin.JournalID != ""
	sc := image.Scope()
	report.ChangeBase = sc.ChangeBase
	for name, rel := range sc.Relations {
		report.Relations[name] = RelationReach{Created: rel.Created, EarliestVersion: rel.EarliestVersion}
	}

	report.VerifiedScope = []string{
		"envelope format and payload SHA-256 digest",
		fmt.Sprintf("header: retained snapshot interval %d..%d, change history begins at %d", sc.Horizon, sc.Head, sc.ChangeBase),
		"catalog schemas, index metadata and per-relation creation sequences",
		"every version chain: ordering, sequence bounds, row types and primary-key encoding",
		"unique-index constraints over the head snapshot",
	}
	if report.IdentityKnown {
		report.VerifiedScope = append(report.VerifiedScope, "source journal lineage identity carried inside the digest-protected payload")
	}
	report.NotVerified = []string{
		"digest integrity is not authentication: the image is not bound to a trusted publisher",
		"contents of future source commits after capture; the image is an immutable frozen state",
		"disk space or exclusive-lock availability of the target directory at install time",
	}
	if !report.IdentityKnown {
		report.NotVerified = append(report.NotVerified, "source journal lineage: legacy image without origin metadata")
	}

	// Demands are judged by the shared reach package — the exact code the
	// engine runs for /query and /changes after restore.
	for _, demand := range demands {
		verdict := DemandVerdict{Demand: demand}
		switch demand.Kind {
		case "read":
			if err = sc.CanRead(demand.Relation, demand.Sequence); err != nil {
				verdict.Reason = err.Error()
			} else {
				verdict.Satisfied = true
			}
		case "change":
			if err = sc.CanChange(demand.Sequence); err != nil {
				verdict.Reason = err.Error()
			} else {
				verdict.Satisfied = true
			}
		case "journal_id":
			if !report.IdentityKnown {
				verdict.Reason = "image carries no source journal identity"
			} else if image.Origin.JournalID != demand.JournalID {
				verdict.Reason = fmt.Sprintf("lineage mismatch: image journal_id=%s, expected=%s", image.Origin.JournalID, demand.JournalID)
			} else {
				verdict.Satisfied = true
			}
		default:
			verdict.Reason = fmt.Sprintf("unknown demand kind %s", demand.Kind)
		}
		report.Demands = append(report.Demands, verdict)
	}
	return report, nil
}

func failReport(report *Report, stage string, err error) (*Report, error) {
	report.Checks.FailureStage = stage
	report.Checks.FailureReason = err.Error()
	return report, nil
}
