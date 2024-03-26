package header

import (
    "bytes"
	"fmt"
    "encoding/binary"
    "slices"
    "strings"

	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/nestedaes/internal/aesx"
)

const EntrySize = aesx.KeySize * 2

func NewEntry(kek, dek []byte) *Entry {
	e := &Entry{}
	e.SetKEK(kek)
	e.SetDEK(dek)
	return e
}

type Entry struct {
	KEK [aesx.KeySize]byte
	DEK [aesx.KeySize]byte
}

func (e *Entry) SetKEK(kek []byte) {
	if len(kek) != len(e.KEK) {
		mu.Panicf("bad KEK size: expected %d, got %d", len(e.KEK), len(kek))
	}
	copy(e.KEK[:], kek)
}

func (e *Entry) SetDEK(dek []byte) {
	if len(dek) != len(e.DEK) {
        mu.Panicf("bad DEK size: expected %d, got %d", len(e.DEK), len(dek))
	}
	copy(e.DEK[:], dek)
}

func (e *Entry) String() string {
    return fmt.Sprintf("{KEK: %x DEK: %x}", e.KEK, e.DEK)
}

func (e *Entry) Marshal() []byte {
    b := new(bytes.Buffer)
    b.Write(e.KEK[:])
    b.Write(e.DEK[:])
    return b.Bytes()
}

func UnmarshalEntry(data []byte) (*Entry, error) {
    e := &Entry{}
    r := bytes.NewReader(data)

    // TODO check return values
    r.Read(e.KEK[:])
    r.Read(e.DEK[:])

    return e, nil
}

type PlainHeader struct {
    // cleartext
    // Size -- only present on disk, a uint32be
    Size uint32
    BaseIV [aesx.IVSize]byte
}

type EncryptedHeader struct {
    Tag [aesx.TagSize]byte
    Entries []Entry
}

type Header struct {
    PlainHeader
    EncryptedHeader
}

func (h *Header) String() string {
    var b strings.Builder

    fmt.Fprintf(&b, "{\n")
    fmt.Fprintf(&b, "\tsize: %d,\n", h.Size)
    fmt.Fprintf(&b, "\tBaseIV: %x,\n", h.BaseIV)
    fmt.Fprintf(&b, "\tTag: %x,\n", h.Tag)
    fmt.Fprintf(&b, "\tEntries: [\n", h.Tag)
    for i := 0; i < len(h.Entries); i++ {
        fmt.Fprintf(&b, "\t\t%d: %v,\n", i, h.Entries[i])
    }
    fmt.Fprintf(&b, "\t]\n")
    fmt.Fprintf(&b, "}")

    return b.String()    
}

func New(iv []byte, tag []byte) *Header {
    h := &Header{}
	if len(iv) != len(h.BaseIV) {
		mu.Panicf("bad IV size: expected, got %d", len(h.BaseIV), len(iv))
	}
    copy(h.BaseIV[:], iv)

	if len(tag) != len(h.Tag) {
		mu.Panicf("bad Tag size: expected, got %d", len(h.Tag), len(tag))
	}
	copy(h.Tag[:], tag)

    h.Size = uint32(4 + len(h.BaseIV) + len(h.Tag))  // 4 for the Size field
    return h
}

func (h *Header) AddEntry(e *Entry) {
    h.Size += EntrySize
    h.Entries = append(h.Entries, *e)
}

func (h *Header) Marshal(kek []byte) []byte {
    ct := new(bytes.Buffer)

    // TODO: check len(kek)? 

    if len(h.Entries) == 0 {
        mu.Panicf("marshal header tag field: header has zero entries")
    }

    // write the plaintext data for what will be the "payload"
    // (the encrypted part of the header)
    ct.Write(h.Tag[:])
    for _, e := range h.Entries {
        ct.Write(e.Marshal())
    }

    // encrypt it
    payload := ct.Bytes()
    eidx := len(h.Tag) + EntrySize
    numEntries := len(h.Entries)

    iv := aesx.NewIV(h.BaseIV[:])
    for i := 1; i < numEntries; i++ {
        curKEK := h.Entries[i].KEK
        aesctr := aesx.NewCTR(curKEK[:], iv[:])
        aesctr.XORKeyStream(payload[:eidx], payload[:eidx])
        eidx = eidx + EntrySize
        iv.Inc()
    }

    // encrypt with last KEK
    aesctr := aesx.NewCTR(kek, iv[:])
    aesctr.XORKeyStream(payload[:eidx], payload[:eidx])

    b := new(bytes.Buffer)
    binary.Write(b, binary.BigEndian, h.Size)
    b.Write(h.BaseIV[:])
    b.Write(payload)

    return b.Bytes()
}

func Unmarshal(data []byte, kek []byte) (*Header, error) {
    h := &Header{}
    r := bytes.NewReader(data)

    err := binary.Read(r, binary.BigEndian, &h.Size)
    if err != nil {
        return nil, fmt.Errorf("can't unmarshal header: %w", err)
    }

    if h.Size != uint32(len(data)) {
        return nil, fmt.Errorf("can't unmarshal header: header size field is %d but input data is %d bytes", h.Size, len(data))
    }

    _, err = r.Read(h.BaseIV[:])
    if err != nil {
        fmt.Errorf("can't unmarshal header: %w", err)
    }

    payload := data[int(r.Size())-r.Len():]
    mod := (len(payload) - len(h.Tag)) % EntrySize
    if mod != 0 {
        fmt.Errorf("can't unmarshal header: header has a partial entry")
    }
    numEntries := (len(payload) - len(h.Tag)) / EntrySize
    if numEntries <= 0 {
        fmt.Errorf("can't unmarshal header: header has 0 entries")
    }

    eidx := len(payload) 
    curKEK := kek
    iv := aesx.NewIV(h.BaseIV[:])
    iv.Add(numEntries - 1) // fast-forward to largest IV

    for eidx != len(h.Tag) {
        aesctr := aesx.NewCTR(curKEK, iv[:])
        aesctr.XORKeyStream(payload[:eidx], payload[:eidx])

        entryStart := eidx - EntrySize
        kek := payload[entryStart:entryStart+aesx.KeySize]
        dek := payload[entryStart+aesx.KeySize:entryStart+(2*aesx.KeySize)]
        entry := NewEntry(kek, dek)
        h.Entries = slices.Insert(h.Entries, 0, *entry)

        eidx = entryStart
        curKEK = kek
        iv.Dec()
    }


    copy(h.Tag[:], payload[:len(h.Tag)])

    return h, nil
}
