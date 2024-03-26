package nestedaes

import (
    "bytes"
    "encoding/binary"
    "fmt"

	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/nestedaes/header"
	"github.com/syslab-wm/nestedaes/internal/aesx"
)

func SplitHeaderPayload(blob []byte) ([]byte, []byte, error) {
    var hSize uint32
    r := bytes.NewReader(blob)
    binary.Read(r, binary.BigEndian, &hSize)

    if hSize >= uint32(len(blob)) {
        return nil, nil, fmt.Errorf("header size (%d bytes) is >= blob size (%d bytes)", hSize, len(blob))
    }

    return blob[:int(hSize)], blob[int(hSize):], nil
}

// Encrypt encrypts the plaintext and returns two outputs:
// 1. The ciphertext blob
// 2. The Key Encryption Key (KEK)
//
// The format of the ciphertext blob is:
//
//  ciphertext blob := header ciphertext
//  header := size iv encrtyped_header
//  encrypted_header := tag wrappedkeys
func Encrypt(plaintext, iv []byte) ([]byte, []byte) {
    // encrypt the plaintext
	dek := aesx.GenRandomKey()
	aesgcm := aesx.NewGCM(dek)
	nonce := aesx.GenZeroNonce()
	ciphertext := aesgcm.Seal(plaintext[:0], nonce, plaintext, nil)

	// separate the ciphertext from the AEAD tag
    ciphertext, tag, err := aesx.SplitCiphertextTag(ciphertext)
    if err != nil {
        mu.Panicf("nestedaes.Encrypt: %v", err)
    }

	// create the ciphertext header
    h := header.New(iv, tag)
	kek := aesx.GenRandomKey()
    entry := &header.Entry{}
    entry.SetDEK(dek)   // note that first entry only has a dek, and not a kek
    h.AddEntry(entry)

    // concat header and ciphertext
    b := new(bytes.Buffer)

    b.Write(h.Marshal(kek))
    b.Write(ciphertext)

    return b.Bytes(), kek
}


// output: new blob, new kek, error
func Reencrypt(blob, kek []byte) ([]byte, []byte, error) {
    hData, payload, err := SplitHeaderPayload(blob)
    if err != nil {
        return nil, nil, err
    }

    h, err := header.Unmarshal(hData, kek)
    if err != nil {
        return nil, nil, err
    }

    newKEK := aesx.GenRandomKey()
    dek := aesx.GenRandomKey()

    e := header.NewEntry(kek, dek)
    h.AddEntry(e)

    iv := aesx.NewIV(h.BaseIV[:])
    iv.Add(len(h.Entries) - 1)

    aesctr := aesx.NewCTR(dek, iv[:])
    aesctr.XORKeyStream(payload, payload)

    w := new(bytes.Buffer)
    w.Write(h.Marshal(newKEK))
    w.Write(payload)

    return w.Bytes(), newKEK, nil
}

// decrypted payload, and error
func Decrypt(blob, kek []byte) ([]byte, error) {
    hData, payload, err := SplitHeaderPayload(blob)
    if err != nil {
        return nil, err
    }

    h, err := header.Unmarshal(hData, kek)
    if err != nil {
        return nil, err
    }

    iv := aesx.NewIV(h.BaseIV[:])
    iv.Add(len(h.Entries) - 1) // fast-forward to largest IV

    var dek [aesx.KeySize]byte
    for i := len(h.Entries)-1; i > 0; i-- {
        dek = h.Entries[i].DEK
        aesctr := aesx.NewCTR(dek[:], iv[:])
        aesctr.XORKeyStream(payload, payload)
        iv.Dec()
    }

    aesgcm := aesx.NewGCM(dek[:])
	nonce := aesx.GenZeroNonce()
    payload = append(payload, h.Tag[:]...)
	plaintext, err := aesgcm.Open(payload[:0], nonce, payload, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
