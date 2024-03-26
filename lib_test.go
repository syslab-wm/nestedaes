package nestedaes

import (
    "bytes"
    "testing"

    "github.com/syslab-wm/nestedaes/internal/aesx"
)

func TestEncryptOnce(t *testing.T) {
    plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aesx.GenRandomKey()
    iv := aesx.GenRandomIV()
    blob, err := Encrypt(plain, kek, iv[:])
    if err != nil {
		t.Fatal(err)
    }

    got, err := Decrypt(blob, kek)
    if err != nil {
		t.Fatal(err)
    }

    if bytes.Compare(plain, got) != 0 {
        t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
    }
}

func TestReencryptOnce(t *testing.T) {
    plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aesx.GenRandomKey()
    iv := aesx.GenRandomIV()
    blob, err := Encrypt(plain, kek, iv[:])
    if err != nil {
		t.Fatal(err)
    }

    blob, kek, err = Reencrypt(blob, kek)
    if err != nil {
		t.Fatal(err)
    }

    got, err := Decrypt(blob, kek)
    if err != nil {
		t.Fatal(err)
    }

    if bytes.Compare(plain, got) != 0 {
        t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
    }
}

func TestReencryptMany(t *testing.T) {
    plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aesx.GenRandomKey()
    iv := aesx.GenRandomIV()
    blob, err := Encrypt(plain, kek, iv[:])
    if err != nil {
		t.Fatal(err)
    }

    for i := 0; i < 100; i++ {
        blob, kek, err = Reencrypt(blob, kek)
        if err != nil {
            t.Fatalf("reencrypt #%d failed: %v", i, err)
        }
    }

    got, err := Decrypt(blob, kek)
    if err != nil {
		t.Fatal(err)
    }

    if bytes.Compare(plain, got) != 0 {
        t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
    }
}
