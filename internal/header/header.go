package header

import (
	"fmt"
	"os"

	"nestedaes/internal/aesx"
	"nestedaes/internal/mu"
)

const EntrySize = aesx.KeySize * 2

// The first heeader entry does not have a kek -- that entry is zero'd
type Entry struct {
	KEK [aesx.KeySize]byte
	DEK [aesx.KeySize]byte
}

func NewEntry(kek, dek []byte) *Entry {
	ent := &Entry{}
	ent.SetKEK(kek)
	ent.SetDEK(dek)
	return ent
}

func (ent *Entry) SetKEK(kek []byte) {
	if len(kek) != len(ent.KEK) {
		mu.Panicf("bad KEK key size (%d)", len(kek))
	}
	copy(ent.KEK[:], kek)
}

func (ent *Entry) SetDEK(dek []byte) {
	if len(dek) != len(ent.DEK) {
		mu.Panicf("bad DEK key size (%d)", len(dek))
	}
	copy(ent.DEK[:], dek)
}

func (ent *Entry) ToBytes() []byte {
	totSize := len(ent.KEK) + len(ent.DEK)
	data := make([]byte, totSize)
	copy(data[:len(ent.KEK)], ent.KEK[:])
	copy(data[len(ent.KEK):], ent.DEK[:])
	return data
}

func ReadFileRaw(path string) ([]byte, int, error) {
	hdr, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("can't read header file: %v", err)
	}

	hdrSize := len(hdr)
	numEntries := hdrSize / EntrySize
	if numEntries == 0 {
		return nil, 0, fmt.Errorf("malformed header: header too small")
	}
	partial := hdrSize % EntrySize
	if partial != 0 {
		return nil, 0, fmt.Errorf("malformed header: header size not multiple of entry size")
	}

	return hdr, numEntries, nil
}
