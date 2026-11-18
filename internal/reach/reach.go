// Package reach owns one fact: which historical snapshots and change
// cursors are actually reachable from a retained image or a live database.
//
// Both restore precheck (snapshot.Inspect) and the running engine's query
// and change endpoints must answer reachability with the same rules, so
// the logic lives here instead of being approximated by a sequence number
// comparison at each call site. A newer head sequence never implies that
// older versions are still retained: vacuum can have pruned them, and a
// restored journal starts a new change history at the image base.
package reach

import (
	"fmt"
	"lamina/internal/catalog"
	"lamina/internal/versions"
)

// Error carries an engine-compatible code so callers translate it without
// re-interpreting the message.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Scope is an immutable snapshot of everything that bounds reachability.
// It is cheap to construct and never mutates the catalog or store passed in.
type Scope struct {
	// Horizon is the lowest sequence at which a historical read is
	// accepted. Versions strictly before it have been vacuumed away.
	Horizon uint64
	// Head is the highest committed sequence contained in the state.
	Head uint64
	// ChangeBase is the first sequence at which change records can be
	// served. A portable image carries no source journal frames, so after
	// restore change history begins at Head; checkpoints keep their base.
	ChangeBase uint64
	Relations  map[string]Relation
}

// Relation captures the per-relation reachability boundary.
type Relation struct {
	Created uint64
	// EarliestVersion is the smallest retained version sequence across the
	// relation's chains. It is informational: Horizon remains the enforced
	// read boundary, but it lets precheck report how deep retention really
	// goes rather than only echoing the requested horizon.
	EarliestVersion uint64
}

// From builds a Scope from live catalog/store structures.
func From(horizon, head, changeBase uint64, c *catalog.Catalog, s *versions.Store) Scope {
	sc := Scope{Horizon: horizon, Head: head, ChangeBase: changeBase, Relations: map[string]Relation{}}
	for name, r := range c.Relations {
		rel := Relation{Created: r.Created}
		earliest := uint64(0)
		for _, chain := range s.Tables[name] {
			for _, v := range chain {
				if earliest == 0 || v.Sequence < earliest {
					earliest = v.Sequence
				}
			}
		}
		rel.EarliestVersion = earliest
		sc.Relations[name] = rel
	}
	return sc
}

// CanRead applies exactly the same test as an engine historical query:
// the snapshot must sit inside the retained interval and the relation must
// already have existed at that sequence.
func (sc Scope) CanRead(relation string, at uint64) error {
	if at < sc.Horizon || at > sc.Head {
		return fail("snapshot", "snapshot %d unavailable; retained interval %d..%d", at, sc.Horizon, sc.Head)
	}
	rel, ok := sc.Relations[relation]
	if !ok {
		return fail("invalid", "unknown relation %s", relation)
	}
	if at < rel.Created {
		return fail("snapshot", "relation %s did not exist at snapshot %d (created at %d)", relation, at, rel.Created)
	}
	return nil
}

// CanChange applies exactly the same test as GET /changes: cursors before
// the journal base are gone forever; cursors past the observed head cannot
// yet be served.
func (sc Scope) CanChange(after uint64) error {
	if after < sc.ChangeBase {
		return fail("snapshot", "change history begins at %d; cursor %d predates it", sc.ChangeBase, after)
	}
	if after > sc.Head {
		return fail("invalid", "cursor %d is ahead of head %d", after, sc.Head)
	}
	return nil
}
