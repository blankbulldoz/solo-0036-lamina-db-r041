package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lamina/internal/catalog"
	"lamina/internal/reach"
	"lamina/internal/versions"
	"os"
)

const MaxImage = 128 << 20

// Origin records the journal lineage an image was captured from. It is
// covered by the payload digest, so an envelope whose digest verifies
// necessarily carries the origin its source database wrote. A digest alone
// cannot prove lineage continuity across two different files; operators
// compare origin.journal_id against the source they expect.
type Origin struct {
	// JournalID is the 16-byte hex identifier of the source journal at
	// capture time. Empty only for legacy images written before identity.
	JournalID string `json:"journal_id"`
	// Base is the source journal's change-history base when captured.
	Base uint64 `json:"base"`
	// CapturedAt is an RFC3339 UTC timestamp for human inspection.
	CapturedAt string `json:"captured_at"`
}

type Image struct {
	Format   int              `json:"format"`
	Sequence uint64           `json:"sequence"`
	Horizon  uint64           `json:"horizon"`
	Origin   *Origin          `json:"origin,omitempty"`
	Catalog  *catalog.Catalog `json:"catalog"`
	Store    *versions.Store  `json:"store"`
}
type Envelope struct {
	Format  int             `json:"format"`
	Digest  string          `json:"sha256"`
	Payload json.RawMessage `json:"payload"`
}

func Encode(image Image) ([]byte, error) {
	image.Format = 1
	b, err := json.Marshal(image)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return json.Marshal(Envelope{Format: 1, Digest: hex.EncodeToString(h[:]), Payload: b})
}
func Decode(b []byte) (Image, error) {
	var image Image
	var env Envelope
	if len(b) > MaxImage {
		return image, fmt.Errorf("image exceeds limit")
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return image, err
	}
	h := sha256.Sum256(env.Payload)
	if env.Format != 1 || hex.EncodeToString(h[:]) != env.Digest {
		return image, fmt.Errorf("image format or digest mismatch")
	}
	if err := json.Unmarshal(env.Payload, &image); err != nil {
		return image, err
	}
	if err := Validate(image); err != nil {
		return image, err
	}
	return image, nil
}

// PayloadDigest recomputes the SHA-256 of an envelope payload and reports
// whether it matches the claimed digest, plus the envelope format. It is
// the first gate: nothing past it (unmarshal, validation, reachability)
// may be trusted when the digest does not verify.
func PayloadDigest(b []byte) (claimed string, actual string, formatOK bool, err error) {
	var env Envelope
	if err = json.Unmarshal(b, &env); err != nil {
		return "", "", false, err
	}
	h := sha256.Sum256(env.Payload)
	return env.Digest, hex.EncodeToString(h[:]), env.Format == 1, nil
}

// statRegularFile rejects symlinks and non-regular files. Lstat is
// required because Stat follows symlinks and would report the target's
// regular mode, defeating the check. This is what lets a precheck digest
// be meaningfully pinned to the same path at install time.
func statRegularFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("backup path must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup must be a regular file, got mode %s", info.Mode())
	}
	return info, nil
}

// LoadVerified reads an image file through every trust gate up to full
// validation and returns the decoded image together with the file's
// observed digest. It never writes anything and never expands the image
// onto disk: the in-memory copy is bounded by MaxImage.
//
// Symlinks and non-regular files are rejected so a precheck digest can be
// meaningfully pinned to a later install of the same path.
func LoadVerified(path string) (Image, string, error) {
	info, err := statRegularFile(path)
	if err != nil {
		return Image{}, "", err
	}
	if info.Size() > MaxImage {
		return Image{}, "", fmt.Errorf("image exceeds limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return Image{}, "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxImage+1))
	if err != nil {
		return Image{}, "", err
	}
	if len(b) > MaxImage {
		return Image{}, "", fmt.Errorf("image exceeds limit")
	}
	image, err := Decode(b)
	if err != nil {
		return Image{}, "", err
	}
	_, digest, _, err := PayloadDigest(b)
	if err != nil {
		return Image{}, "", err
	}
	return image, digest, nil
}

func Read(path string) (Image, error) {
	image, _, err := LoadVerified(path)
	return image, err
}

// CheckResults reports how far validation got. Earlier stages gate later
// ones, so a false stage means subsequent stages were not attempted.
type CheckResults struct {
	EnvelopeDigest bool   `json:"envelope_digest"`
	Header         bool   `json:"header"`
	Catalog        bool   `json:"catalog"`
	VersionChains  bool   `json:"version_chains"`
	UniqueIndexes  bool   `json:"unique_indexes"`
	Origin         bool   `json:"origin"`
	FailureStage   string `json:"failure_stage,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
}

// Validate runs every structural gate. Inspect uses the staged variants to
// report the verified scope; install keeps using the combined function.
func Validate(image Image) error {
	if err := checkHeader(image); err != nil {
		return err
	}
	if err := checkCatalog(image); err != nil {
		return err
	}
	if err := checkChains(image); err != nil {
		return err
	}
	if err := checkUnique(image); err != nil {
		return err
	}
	return checkOrigin(image)
}

func checkHeader(image Image) error {
	if image.Format != 1 || image.Horizon > image.Sequence || image.Catalog == nil || image.Store == nil || image.Catalog.Relations == nil || image.Catalog.Indexes == nil || image.Store.Tables == nil {
		return fmt.Errorf("invalid image header")
	}
	return nil
}
func checkCatalog(image Image) error {
	for name, r := range image.Catalog.Relations {
		if name != r.Name || r.Created == 0 || r.Created > image.Sequence {
			return fmt.Errorf("invalid catalog sequence")
		}
		if err := r.Validate(); err != nil {
			return err
		}
	}
	for name, definition := range image.Catalog.Indexes {
		relation, ok := image.Catalog.Relations[definition.Relation]
		if !ok || name != definition.Name || !catalog.ValidName(name) || definition.Created < relation.Created || definition.Created > image.Sequence {
			return fmt.Errorf("invalid index metadata")
		}
		if _, ok := relation.Column(definition.Column); !ok {
			return fmt.Errorf("invalid index column")
		}
	}
	return nil
}
func checkChains(image Image) error {
	for name, rows := range image.Store.Tables {
		r, ok := image.Catalog.Relations[name]
		if !ok {
			return fmt.Errorf("image references unknown relation")
		}
		for key, chain := range rows {
			var last uint64
			if len(chain) == 0 {
				return fmt.Errorf("empty version chain")
			}
			for _, v := range chain {
				if v.Sequence <= last || v.Sequence > image.Sequence || v.Sequence <= r.Created {
					return fmt.Errorf("invalid version order")
				}
				last = v.Sequence
				if !v.Deleted {
					row, err := r.Normalize(v.Row)
					if err != nil || r.Key(row) != key {
						return fmt.Errorf("invalid stored tuple")
					}
				}
			}
		}
	}
	return nil
}
func checkUnique(image Image) error {
	for _, definition := range image.Catalog.Indexes {
		if !definition.Unique {
			continue
		}
		seen := map[string]bool{}
		for _, chain := range image.Store.Tables[definition.Relation] {
			version, exists := versions.Visible(chain, image.Sequence)
			if !exists {
				continue
			}
			value := version.Row[definition.Column]
			if value.Null() {
				continue
			}
			if seen[value.Key()] {
				return fmt.Errorf("image violates unique index %s", definition.Name)
			}
			seen[value.Key()] = true
		}
	}
	return nil
}

// checkOrigin validates lineage metadata when present. Legacy images
// without an origin remain structurally valid; Inspect reports their
// identity as unknown rather than failing them.
func checkOrigin(image Image) error {
	if image.Origin == nil {
		return nil
	}
	o := image.Origin
	if o.JournalID != "" {
		raw, err := hex.DecodeString(o.JournalID)
		if err != nil || len(raw) != 16 {
			return fmt.Errorf("invalid origin journal id")
		}
	}
	if o.Base > image.Sequence {
		return fmt.Errorf("origin base beyond image sequence")
	}
	return nil
}

// StagedValidate runs the same gates as Validate in order and records how
// far verification reached, so precheck can state the verified scope even
// when a later stage fails.
func StagedValidate(image Image) CheckResults {
	c := CheckResults{}
	stage := func(name string, fn func(Image) error) bool {
		if err := fn(image); err != nil {
			c.FailureStage = name
			c.FailureReason = err.Error()
			return false
		}
		return true
	}
	if !stage("header", checkHeader) {
		return c
	}
	c.Header = true
	if !stage("catalog", checkCatalog) {
		return c
	}
	c.Catalog = true
	if !stage("version_chains", checkChains) {
		return c
	}
	c.VersionChains = true
	if !stage("unique_indexes", checkUnique) {
		return c
	}
	c.UniqueIndexes = true
	if image.Origin != nil {
		if !stage("origin", checkOrigin) {
			return c
		}
	}
	c.Origin = image.Origin != nil
	return c
}

// Scope derives the shared reachability scope from a validated image.
// A portable image contains no source journal frames, so change history on
// the restored node begins at the image head even though the source origin
// may record an older journal base.
func (image Image) Scope() reach.Scope {
	return reach.From(image.Horizon, image.Sequence, image.Sequence, image.Catalog, image.Store)
}
