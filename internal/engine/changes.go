package engine

import "lamina/internal/journal"

type ChangePage struct {
	Records         []journal.Record `json:"records"`
	Cursor          uint64           `json:"cursor"`
	Head            uint64           `json:"head"`
	HistoryBase     uint64           `json:"history_base"`
	JournalID       string           `json:"journal_id"`
	OriginJournalID string           `json:"origin_journal_id,omitempty"`
	More            bool             `json:"more"`
}

func (d *DB) Changes(after uint64, limit int) (ChangePage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := ChangePage{
		Records:         []journal.Record{},
		Cursor:          after,
		Head:            d.sequence,
		HistoryBase:     d.wal.Base,
		JournalID:       d.wal.IDHex(),
		OriginJournalID: d.originJournal,
	}
	if err := d.usable(); err != nil {
		return out, err
	}
	// Same cursor rule the restore precheck applies to the image scope.
	if err := reachFault(d.scope().CanChange(after)); err != nil {
		return out, err
	}
	if limit < 1 || limit > 1000 {
		return out, fault("invalid", "invalid change cursor or limit")
	}
	for _, r := range d.wal.Records {
		if r.Sequence <= after {
			continue
		}
		if len(out.Records) >= limit {
			out.More = true
			break
		}
		out.Records = append(out.Records, r)
		out.Cursor = r.Sequence
	}
	return out, nil
}
