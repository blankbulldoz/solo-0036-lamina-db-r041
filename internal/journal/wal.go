package journal

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	MaxFrame = 16 << 20

	magicV1       = "LMW1"
	headerV1Bytes = 16
	magicV2       = "LMW2"
	headerV2Bytes = 32
)

type WAL struct {
	Base          uint64
	ID            [16]byte
	file          *os.File
	lock          *os.File
	Records       []Record
	RecoveredTail int64
	Poisoned      bool
}

// IDHex returns the durable journal lineage identifier. An empty string
// means the journal predates identity headers (LMW1) and has no known ID.
func (w *WAL) IDHex() string {
	if w.ID == ([16]byte{}) {
		return ""
	}
	return hex.EncodeToString(w.ID[:])
}

func Open(dir string, base uint64) (*WAL, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lamina.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("data directory already open: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "journal.lmw"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		lock.Close()
		return nil, err
	}
	w := &WAL{file: f, lock: lock, Base: base}
	info, err := f.Stat()
	if err != nil {
		w.Close()
		return nil, err
	}
	if info.Size() == 0 {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			w.Close()
			return nil, err
		}
		header := make([]byte, headerV2Bytes)
		copy(header[:4], magicV2)
		binary.BigEndian.PutUint64(header[4:12], base)
		copy(header[12:28], id[:])
		binary.BigEndian.PutUint32(header[28:], crc32.ChecksumIEEE(header[:28]))
		if _, err = f.Write(header); err == nil {
			err = f.Sync()
		}
		if err != nil {
			w.Close()
			return nil, err
		}
	}
	directory, syncErr := os.Open(dir)
	if syncErr != nil {
		w.Close()
		return nil, syncErr
	}
	syncErr = directory.Sync()
	directory.Close()
	if syncErr != nil {
		w.Close()
		return nil, syncErr
	}
	if _, err = f.Seek(0, 0); err != nil {
		w.Close()
		return nil, err
	}
	if err = w.recover(); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}
func (w *WAL) recover() error {
	// Read the 4-byte magic first so a legacy 16-byte LMW1 header is not
	// rejected by a fixed-size probe for the 32-byte LMW2 header.
	var magic [4]byte
	if _, err := io.ReadFull(w.file, magic[:]); err != nil {
		return fmt.Errorf("journal header: %w", err)
	}
	var headerLen int64
	switch string(magic[:]) {
	case magicV1:
		var rest [12]byte
		if _, err := io.ReadFull(w.file, rest[:]); err != nil {
			return fmt.Errorf("journal header: %w", err)
		}
		if crc32.ChecksumIEEE(append(magic[:], rest[:8]...)) != binary.BigEndian.Uint32(rest[8:12]) {
			return fmt.Errorf("invalid journal header")
		}
		headerLen = headerV1Bytes
		actualBase := binary.BigEndian.Uint64(rest[0:8])
		if actualBase > w.Base {
			return fmt.Errorf("journal requires newer checkpoint")
		}
		w.Base = actualBase
	case magicV2:
		var rest [28]byte
		if _, err := io.ReadFull(w.file, rest[:]); err != nil {
			return fmt.Errorf("journal header: %w", err)
		}
		if crc32.ChecksumIEEE(append(magic[:], rest[:24]...)) != binary.BigEndian.Uint32(rest[24:28]) {
			return fmt.Errorf("invalid journal header")
		}
		headerLen = headerV2Bytes
		copy(w.ID[:], rest[8:24])
		actualBase := binary.BigEndian.Uint64(rest[0:8])
		if actualBase > w.Base {
			return fmt.Errorf("journal requires newer checkpoint")
		}
		w.Base = actualBase
	default:
		return fmt.Errorf("invalid journal header")
	}
	if _, err := w.file.Seek(headerLen, io.SeekStart); err != nil {
		return err
	}
	offset := headerLen
	last := w.Base
	for {
		var head [8]byte
		n, err := io.ReadFull(w.file, head[:])
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			w.RecoveredTail = int64(n)
			break
		}
		if err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(head[:4])
		if length == 0 || length > MaxFrame {
			return fmt.Errorf("invalid journal length at %d", offset)
		}
		payload := make([]byte, length)
		n, err = io.ReadFull(w.file, payload)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			w.RecoveredTail = int64(8 + n)
			break
		}
		if err != nil {
			return err
		}
		if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(head[4:8]) {
			return fmt.Errorf("journal checksum mismatch at %d", offset)
		}
		var r Record
		if err = json.Unmarshal(payload, &r); err != nil {
			return fmt.Errorf("journal json at %d: %w", offset, err)
		}
		if r.Format != 1 || r.Sequence != last+1 {
			return fmt.Errorf("journal sequence or format mismatch at %d", offset)
		}
		w.Records = append(w.Records, r)
		last = r.Sequence
		offset += int64(8 + length)
	}
	if w.RecoveredTail > 0 {
		if err := w.file.Truncate(offset); err != nil {
			return err
		}
		if err := w.file.Sync(); err != nil {
			return err
		}
	}
	_, err := w.file.Seek(0, io.SeekEnd)
	return err
}
func (w *WAL) Append(r Record) error {
	if w.Poisoned {
		return fmt.Errorf("journal is unavailable; restart required")
	}
	if r.Sequence != w.Base+uint64(len(w.Records))+1 {
		return fmt.Errorf("noncontiguous journal sequence")
	}
	r.Format = 1
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrame {
		return fmt.Errorf("commit exceeds journal frame limit")
	}
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], crc32.ChecksumIEEE(payload))
	copy(frame[8:], payload)
	if _, err = w.file.Write(frame); err != nil {
		w.Poisoned = true
		return err
	}
	if err = w.file.Sync(); err != nil {
		w.Poisoned = true
		return err
	}
	w.Records = append(w.Records, r)
	return nil
}
func (w *WAL) Close() error {
	err := w.file.Close()
	w.lock.Close()
	return err
}
