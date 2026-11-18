package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lamina/internal/index"
	"lamina/internal/journal"
	"lamina/internal/snapshot"
	"lamina/internal/versions"
	"os"
	"path/filepath"
	"time"
)

func (d *DB) image() snapshot.Image {
	return snapshot.Image{
		Format:   1,
		Sequence: d.sequence,
		Horizon:  d.horizon,
		Origin:   d.origin(),
		Catalog:  d.catalog.Clone(),
		Store:    d.store.Clone(),
	}
}

// origin records the current journal lineage. On a fresh database this is
// the node's own journal id; after restore it stays the source lineage
// until the captured state, while new commits run under the new journal id
// exposed via stats and changes.
func (d *DB) origin() *snapshot.Origin {
	id := d.wal.IDHex()
	if id == "" && d.originJournal == "" {
		return nil
	}
	return &snapshot.Origin{
		JournalID:  firstNonEmpty(d.originJournal, id),
		Base:       d.wal.Base,
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (d *DB) Checkpoint() (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return 0, err
	}
	if err := snapshot.Write(filepath.Join(d.dir, "checkpoint.lmi"), d.image()); err != nil {
		return 0, fault("unavailable", "checkpoint: %s", err)
	}
	return d.sequence, nil
}
func (d *DB) Backup() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.usable(); err != nil {
		return nil, err
	}
	b, err := snapshot.Encode(d.image())
	if err != nil {
		return nil, err
	}
	if len(b) > snapshot.MaxImage {
		return nil, fault("capacity", "backup exceeds 128MiB")
	}
	return b, nil
}

// Restore installs a validated backup into a new data directory.
//
// All validation happens before anything is created on disk:
//  1. the file is read once as a regular file and its envelope digest
//     recomputed,
//  2. expectDigest (when supplied from a prior precheck) must equal the
//     observed digest — any change between preview and install aborts,
//  3. full structural validation runs through the same code as precheck,
//
// only then is the target directory created. A failure removes every
// partial artifact, so an aborted install never pollutes the target path.
func Restore(dir, backupPath, expectDigest string) error {
	image, observed, err := snapshot.LoadVerified(backupPath)
	if err != nil {
		return fmt.Errorf("restore precheck failed: %w", err)
	}
	if expectDigest != "" {
		if _, err = hex.DecodeString(expectDigest); err != nil || len(expectDigest) != sha256.Size*2 {
			return fmt.Errorf("invalid expected digest")
		}
		if expectDigest != observed {
			return fmt.Errorf("backup changed since precheck: observed digest %s, expected %s; install refused", observed, expectDigest)
		}
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("restore requires a new directory: %w", err)
	}
	installed := false
	defer func() {
		if !installed {
			os.Remove(filepath.Join(dir, "checkpoint.lmi"))
			os.Remove(filepath.Join(dir, "journal.lmw"))
			os.Remove(filepath.Join(dir, "lamina.lock"))
			os.Remove(dir)
		}
	}()
	// The restored journal is a brand-new lineage: its header gets a fresh
	// random id, while the source lineage remains recorded in the image
	// origin and in the origin_journal_id stat.
	w, err := journal.Open(dir, image.Sequence)
	if err != nil {
		return err
	}
	if err = snapshot.Write(filepath.Join(dir, "checkpoint.lmi"), image); err != nil {
		w.Close()
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	installed = true
	return nil
}
func (d *DB) Vacuum(requested uint64) (versions.VacuumResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return versions.VacuumResult{}, err
	}
	if requested > d.sequence || requested < d.horizon {
		return versions.VacuumResult{}, fault("invalid", "vacuum horizon outside retained interval")
	}
	horizon := requested
	for _, tx := range d.transactions {
		if tx.Snapshot < horizon {
			horizon = tx.Snapshot
		}
	}
	beforeKeys, beforeVersions := d.store.Count()
	_ = beforeKeys
	if err := d.publish(journal.Record{Kind: "vacuum", Horizon: horizon}); err != nil {
		return versions.VacuumResult{}, err
	}
	_, remaining := d.store.Count()
	d.indexes = index.Build(d.catalog, d.store)
	return versions.VacuumResult{Horizon: horizon, Removed: beforeVersions - remaining, Retained: remaining, Pinned: horizon < requested}, nil
}
