package nestedaes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/nestedaes/internal/aesx"
)

const HeaderEntrySize = aesx.KeySize * 2

type HeaderEntry struct {
	KEK [aesx.KeySize]byte
	DEK [aesx.KeySize]byte
}

func NewHeaderEntry(kek, dek []byte) *HeaderEntry {
	e := &HeaderEntry{}
	e.SetKEK(kek)
	e.SetDEK(dek)
	return e
}

func (e *HeaderEntry) SetKEK(kek []byte) {
	if len(kek) != len(e.KEK) {
		mu.Panicf("bad KEK size: expected %d, got %d", len(e.KEK), len(kek))
	}
	copy(e.KEK[:], kek)
}

func (e *HeaderEntry) SetDEK(dek []byte) {
	if len(dek) != len(e.DEK) {
		mu.Panicf("bad DEK size: expected %d, got %d", len(e.DEK), len(dek))
	}
	copy(e.DEK[:], dek)
}

func (e *HeaderEntry) String() string {
	return fmt.Sprintf("{KEK: %x DEK: %x}", e.KEK, e.DEK)
}

func (e *HeaderEntry) Marshal() []byte {
	b := new(bytes.Buffer)
	b.Write(e.KEK[:])
	b.Write(e.DEK[:])
	return b.Bytes()
}

func UnmarshalHeaderEntry(data []byte) (*HeaderEntry, error) {
	if len(data) < HeaderEntrySize {
		return nil, fmt.Errorf("failed to unmarshal HeaderEntry: expected %d bytes, got %d", HeaderEntrySize, len(data))
	}

	e := &HeaderEntry{}
	r := bytes.NewReader(data)
	_, err := r.Read(e.KEK[:])
	if err != nil {
		return nil, err
	}
	_, err = r.Read(e.DEK[:])
	if err != nil {
		return nil, err
	}
	return e, nil
}

type PlainHeader struct {
	Size   uint32
	BaseIV [aesx.IVSize]byte
}

type EncryptedHeader struct {
	Tag     [aesx.TagSize]byte
	Entries []HeaderEntry
}

type Header struct {
	PlainHeader
	EncryptedHeader
}

// String satisfies the [fmt.Stringer] interface.
func (h *Header) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "\tsize: %d,\n", h.Size)
	fmt.Fprintf(&b, "\tBaseIV: %x,\n", h.BaseIV)
	fmt.Fprintf(&b, "\tTag: %x,\n", h.Tag)
	fmt.Fprintf(&b, "\tEntries: %x\n", h.Tag)
	for i := 0; i < len(h.Entries); i++ {
		fmt.Fprintf(&b, "\t\t%d: %v,\n", i, h.Entries[i])
	}
	fmt.Fprintf(&b, "\t]\n")
	fmt.Fprintf(&b, "}")

	return b.String()
}

// New creates a new [Header] and initializes the BaseIV and Tag.  Note that
// the returned header does not have any entries, and the caller is responsible
// for invoking the [AddEntry] method.
// TODO: should this return an error instead of panic on bad iv/tag lengths?
func NewHeader(iv []byte, tag []byte) *Header {
	h := &Header{}
	if len(iv) != len(h.BaseIV) {
		mu.Panicf("bad IV size: expected %d, got %d", len(h.BaseIV), len(iv))
	}
	copy(h.BaseIV[:], iv)

	if len(tag) != len(h.Tag) {
		mu.Panicf("bad Tag size: expected %d, got %d", len(h.Tag), len(tag))
	}
	copy(h.Tag[:], tag)

	h.Size = uint32(4 + len(h.BaseIV) + len(h.Tag)) // 4 for the Size field
	return h
}

// AddEntry addes a new key entry to the header.
func (h *Header) AddEntry(e *HeaderEntry) {
	h.Size += HeaderEntrySize
	h.Entries = append(h.Entries, *e)
}

// Marshal marshals the header to a []byte.  As part of marshaling, this method
// takes care of encrypting the "encrypted" portion of the header.
func (h *Header) Marshal(kek []byte) ([]byte, error) {
	if len(kek) != aesx.KeySize {
		return nil, fmt.Errorf("header.Marshal failed: expected KEK size of %d, but got %d", aesx.KeySize, kek)
	}

	if len(h.Entries) == 0 {
		return nil, fmt.Errorf("header.Marshal failed: header has zero entries")
	}

	// write the plaintext data for what will become the encrypted part of the
	// header
	ct := new(bytes.Buffer)
	ct.Write(h.Tag[:])
	for _, e := range h.Entries {
		ct.Write(e.Marshal())
	}

	// encrypt it
	enc := ct.Bytes()
	eidx := len(h.Tag) + HeaderEntrySize
	numEntries := len(h.Entries)

	iv := aesx.NewIV(h.BaseIV[:])
	for i := 1; i < numEntries; i++ {
		curKEK := h.Entries[i].KEK
		aesx.CTREncrypt(enc[:eidx], curKEK[:], iv[:])
		eidx += HeaderEntrySize
		iv.Inc()
	}

	// encrypt with last KEK
	aesx.CTREncrypt(enc[:eidx], kek, iv[:])

	// write the plain portion of the header and concatenate the encryption
	// portion
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, h.Size)
	b.Write(h.BaseIV[:])
	b.Write(enc)

	return b.Bytes(), nil
}

// Unmarshal takes a marshalled version of the header and the current Key
// Encryption Key (KEK) and deserializes and decrypts the header.
func UnmarshalHeader(data []byte, kek []byte) (*Header, error) {
	if len(kek) != aesx.KeySize {
		return nil, fmt.Errorf("UnmarshalHeader failed: expected KEK size of %d, but got %d", aesx.KeySize, kek)
	}

	h := &Header{}
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &h.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: can't read Size field: %w", err)
	}

	if h.Size != uint32(len(data)) {
		return nil, fmt.Errorf("failed to unmarshal header: header size field is %d but marshalled data is %d bytes", h.Size, len(data))
	}

	n, err := r.Read(h.BaseIV[:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: can't read BaseIV: %w", err)
	}
	if n != len(h.BaseIV) {
		return nil, fmt.Errorf("failed to unmarshal header: can't read BaseIV")
	}

	enc := data[int(r.Size())-r.Len():]
	mod := (len(enc) - len(h.Tag)) % HeaderEntrySize
	if mod != 0 {
		return nil, fmt.Errorf("failed to unmarshal header: header has a partial entry")
	}
	numEntries := (len(enc) - len(h.Tag)) / HeaderEntrySize
	if numEntries <= 0 {
		return nil, fmt.Errorf("failed to unmarshal header: header has 0 entries")
	}

	curKEK := kek
	iv := aesx.NewIV(h.BaseIV[:])
	iv.Add(numEntries - 1) // fast-forward to largest IV
	eidx := len(enc)

	for eidx != len(h.Tag) {
		aesx.CTRDecrypt(enc[:eidx], curKEK, iv[:])

		entryStart := eidx - HeaderEntrySize
		entry, err := UnmarshalHeaderEntry(enc[entryStart : entryStart+2*aesx.KeySize])
		if err != nil {
			return nil, err
		}
		h.Entries = slices.Insert(h.Entries, 0, *entry)

		eidx = entryStart
		curKEK = entry.KEK[:]
		iv.Dec()
	}

	copy(h.Tag[:], enc[:len(h.Tag)])

	return h, nil
}
