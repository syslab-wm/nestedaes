package header

import (
    "bytes"
    "fmt"
	"testing"
)

func compareHeader(h1, h2 *Header) error {
    if h1.Size != h2.Size {
        return fmt.Errorf("expected header Size of %d, got %d", h1.Size, h2.Size)
    }

    if bytes.Compare(h2.BaseIV[:], h2.BaseIV[:]) != 0 {
        return fmt.Errorf("expected header BaseIV to be %x, got %x", h1.BaseIV, h2.BaseIV)
    }

    if bytes.Compare(h1.Tag[:], h2.Tag[:]) != 0 {
        return fmt.Errorf("expected header Tag to be %x, got %x", h1.Tag, h2.Tag)
    }

    if len(h1.Entries) != len(h2.Entries) {
        return fmt.Errorf("expected header to have %d entries, got %d", len(h1.Entries), len(h2.Entries))
    }

    /* TODO: compare entries */

    return nil
}

func TestHeader(t *testing.T) {
    keyTuples := []struct {
        KEK []byte
        DEK []byte
    } {
        {[]byte("11111111111111111111111111111111"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        {[]byte("22222222222222222222222222222222"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
        {[]byte("33333333333333333333333333333333"), []byte("cccccccccccccccccccccccccccccccc")},
        {[]byte("44444444444444444444444444444444"), []byte("dddddddddddddddddddddddddddddddd")},
        {[]byte("55555555555555555555555555555555"), []byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")},
    }

    iv := []byte("abcdefghijklmnop")
    tag := []byte("qrstuvwxyzABCDEF")
    h := New(iv, tag)
    for _, tup := range keyTuples {
        e := NewEntry(tup.KEK, tup.DEK)
        h.AddEntry(e)
    }

    if len(keyTuples) != len(h.Entries) {
        t.Fatalf("expected %d entries, got %d", len(keyTuples), len(h.Entries))
    }

    kek := []byte("66666666666666666666666666666666")
    hData, err := h.Marshal(kek)
    if err != nil {
        t.Fatalf("h.Marshal failed: %v", err)
    }

    if h.Size != uint32(len(hData)) {
        t.Fatalf("expected marshalled header to have size of %d bytes, got %d", h.Size, len(hData))
    }

    h2, err := Unmarshal(hData, kek)
    if err != nil {
        t.Fatalf("h.Unmarshal failed: %v", err)
    }

    if err := compareHeader(h, h2); err != nil {
        t.Fatalf("h.Unmarshal: %v", err)
    }
}
