package nestedaes

import (
	"bytes"
	"fmt"
	"testing"
)

func compareHeader(h1, h2 *Header) error {
	if h1.Size != h2.Size {
		return fmt.Errorf("expected header Size of %d, got %d", h1.Size, h2.Size)
	}

	/*if bytes.Compare(h1.HeaderTag[:], h2.HeaderTag[:]) != 0 {
		return fmt.Errorf("expected header DataTag to be %x, got %x", h1.HeaderTag, h2.HeaderTag)
	}*/

	if bytes.Compare(h2.BaseIV[:], h2.BaseIV[:]) != 0 {
		return fmt.Errorf("expected header BaseIV to be %x, got %x", h1.BaseIV, h2.BaseIV)
	}

	if bytes.Compare(h1.DataTag[:], h2.DataTag[:]) != 0 {
		return fmt.Errorf("expected header DataTag to be %x, got %x", h1.DataTag, h2.DataTag)
	}

	if len(h1.Entries) != len(h2.Entries) {
		return fmt.Errorf("expected header to have %d entries, got %d", len(h1.Entries), len(h2.Entries))
	}

	/* TODO: compare entries */

	return nil
}

func TestHeader(t *testing.T) {
	deks := [][KeySize]byte{
		[KeySize]byte([]byte("11111111111111111111111111111111")), [KeySize]byte([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		[KeySize]byte([]byte("22222222222222222222222222222222")), [KeySize]byte([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
		[KeySize]byte([]byte("33333333333333333333333333333333")), [KeySize]byte([]byte("cccccccccccccccccccccccccccccccc")),
		[KeySize]byte([]byte("44444444444444444444444444444444")), [KeySize]byte([]byte("dddddddddddddddddddddddddddddddd")),
		[KeySize]byte([]byte("55555555555555555555555555555555")), [KeySize]byte([]byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")),
	}

	iv := []byte("abcdefghijklmnop")
	tag := []byte("qrstuvwxyzABCDEF")
	h := NewHeader(iv, tag, &deks[0])
	for _, dek := range deks[1:] {
		h.AddEntry(&dek)
	}

	if len(deks) != len(h.Entries) {
		t.Fatalf("expected %d entries, got %d", len(deks), len(h.Entries))
	}

	kek := []byte("66666666666666666666666666666666")
	hData, err := h.Marshal(kek)
	if err != nil {
		t.Fatalf("h.Marshal failed: %v", err)
	}

	if h.Size != uint32(len(hData)) {
		t.Fatalf("expected marshalled header to have size of %d bytes, got %d", h.Size, len(hData))
	}

	h2, err := UnmarshalHeader(hData, kek)
	if err != nil {
		t.Fatalf("h.Unmarshal failed: %v", err)
	}

	if err := compareHeader(h, h2); err != nil {
		t.Fatalf("h.Unmarshal: %v", err)
	}
}
