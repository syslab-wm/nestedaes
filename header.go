package nestedaes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/nestedaes/internal/aesx"
)

// DEK only
const HeaderEntrySize = aesx.KeySize;

type PlainHeader struct {
	Size      uint32
	HeaderTag [aesx.TagSize]byte
	BaseIV    [aesx.IVSize]byte
}

type EncryptedHeader struct {
	DataTag [aesx.TagSize]byte
	Entries [][HeaderEntrySize]byte // array of data keys
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
	fmt.Fprintf(&b, "\tHeaderTag: %x,\n", h.HeaderTag)
	fmt.Fprintf(&b, "\tBaseIV: %x,\n", h.BaseIV)
	fmt.Fprintf(&b, "\tDataTag: %x,\n", h.DataTag)
	fmt.Fprintf(&b, "\tEntries (%d): [\n", len(h.Entries))
	for i := 0; i < len(h.Entries); i++ {
		fmt.Fprintf(&b, "\t\t%d: %v,\n", i, h.Entries[i])
	}
	fmt.Fprintf(&b, "\t]\n")
	fmt.Fprintf(&b, "}")

	return b.String()
}

// New creates a new [Header] and initializes the BaseIV, DataTag, and first
// DEK entry.
// TODO: should this return an error instead of panic on bad iv/tag lengths?
func NewHeader(iv []byte, dataTag []byte, dek *[aesx.KeySize]byte) *Header {
	h := &Header{}
	if len(iv) != len(h.BaseIV) {
		mu.Panicf("bad IV size: expected %d, got %d", len(h.BaseIV), len(iv))
	}
	copy(h.BaseIV[:], iv)

	if len(dataTag) != len(h.DataTag) {
		mu.Panicf("bad Tag size: expected %d, got %d", len(h.DataTag), len(dataTag))
	}
	copy(h.DataTag[:], dataTag)

	h.Entries = make([][HeaderEntrySize]byte, 1)
	copy(h.Entries[0][:], dek[:])

	h.Size = uint32(4 + len(h.HeaderTag) + len(h.BaseIV) + len(h.DataTag) + HeaderEntrySize) // 4 for the Size field
	return h
}

// AddEntry addes a new data key entry to the header.
func (h *Header) AddEntry(e *[HeaderEntrySize]byte) {
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
	ct.Write(h.DataTag[:])
	for _, dek := range h.Entries {
		ct.Write(dek[:])
	}

	// encrypt it
	numEntries := len(h.Entries)
	iv := aesx.NewIV(h.BaseIV[:])
	iv.Add(numEntries - 1)
	// encrypt with current KEK
	// TODO: should size or anything else be verified as additional data?
	gcmRet := aesx.GCMEncrypt(ct.Bytes(), kek, iv[:], nil)
	enc, tag, _ := aesx.SplitCiphertextTag(gcmRet)
	copy(h.HeaderTag[:], tag)

	// write the plain portion of the header and concatenate the encryption
	// portion
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, h.Size)
	b.Write(h.HeaderTag[:])
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

	n, err := r.Read(h.HeaderTag[:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: can't read HeaderTag: %w", err)
	}
	if n != len(h.HeaderTag) {
		return nil, fmt.Errorf("failed to unmarshal header: can't read HeaderTag")
	}

	n, err = r.Read(h.BaseIV[:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: can't read BaseIV: %w", err)
	}
	if n != len(h.BaseIV) {
		return nil, fmt.Errorf("failed to unmarshal header: can't read BaseIV")
	}

	enc := data[int(r.Size())-r.Len():]
	mod := (len(enc) - len(h.DataTag)) % HeaderEntrySize
	if mod != 0 {
		return nil, fmt.Errorf("failed to unmarshal header: header has a partial entry")
	}
	numEntries := (len(enc) - len(h.DataTag)) / HeaderEntrySize
	if numEntries <= 0 {
		return nil, fmt.Errorf("failed to unmarshal header: header has 0 entries")
	}

	iv := aesx.NewIV(h.BaseIV[:])
	iv.Add(numEntries - 1)
	gcmArg := append(enc, h.HeaderTag[:]...)
	dec, err := aesx.GCMDecrypt(gcmArg, kek, iv[:], nil)
	h.Entries = make([][HeaderEntrySize]byte, numEntries)

	for i := 0; i < numEntries; i++ {
		n = copy(h.Entries[i][:], dec[len(h.DataTag)+i*HeaderEntrySize:])
		if n != HeaderEntrySize {
			return nil, fmt.Errorf("failed to unmarshal header: can't read key %d/%d", i, numEntries)
		}
	}

	copy(h.DataTag[:], dec[:len(h.DataTag)])

	return h, nil
}
