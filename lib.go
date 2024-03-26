// The format of a blob is:
//
//  BLOB := HEADER || PAYLOAD
//  HEADER := PLAIN_HEADER || ENCRYPTED_HEADER
//  PLAIN_HEADER := SIZE || IV
//  ENCRYPTED_HEADER := TAG || ENTRIES...
//  ENTRY := KEK || DEK
//  
// The PAYLOAD is encrypted plaintext.
package nestedaes


import (
    "bytes"
    "encoding/binary"
    "fmt"

	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/nestedaes/header"
	"github.com/syslab-wm/nestedaes/internal/aesx"
)

// SplitHeaderPayload takes a slice of the Blob of returns
// it's two components: the Header bytes and the Payload bytes.
func SplitHeaderPayload(blob []byte) ([]byte, []byte, error) {
    var hSize uint32
    r := bytes.NewReader(blob)
    binary.Read(r, binary.BigEndian, &hSize)

    if hSize >= uint32(len(blob)) {
        return nil, nil, fmt.Errorf("header size (%d bytes) is >= blob size (%d bytes)", hSize, len(blob))
    }

    return blob[:int(hSize)], blob[int(hSize):], nil
}

// Encrypt encrypts the plaintext and returns the Blob.  The function encrypts
// the plaintext with a randomly generated Data Encryptoin Key (KEK), and uses
// the input Key Encryption Key (KEK) to encrypt the DEK in the Blob's header.
// The iv is the BaseIV.  The caller should randomly generate it; each
// subsequent layer of encryption uses a different IV derived from the BaseIV.
// TODO: does Encrypt modify the plaintext input?
func Encrypt(plaintext, kek, iv []byte) ([]byte, error) {
    // encrypt the plaintext
	dek := aesx.GenRandomKey()
	aesgcm := aesx.NewGCM(dek)
	nonce := aesx.GenZeroNonce()
	payload := aesgcm.Seal(plaintext[:0], nonce, plaintext, nil)

	// separate the ciphertext from the AEAD tag
    payload, tag, err := aesx.SplitCiphertextTag(payload)
    if err != nil {
        mu.Panicf("nestedaes.Encrypt: %v", err)
    }

	// create the ciphertext header
    h := header.New(iv, tag)
    entry := &header.Entry{}
    entry.SetDEK(dek)   // note that first entry only has a dek, and not a kek
    h.AddEntry(entry)

    // concat header and payload
    b := new(bytes.Buffer)

    hData, err := h.Marshal(kek)
    if err != nil {
        return nil, err
    }
    b.Write(hData)
    b.Write(payload)

    return b.Bytes(), nil
}


// output: new blob, new kek, error
// TODO: does Rencrypt moidfy the blob and kek inputs?
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
    hData, err = h.Marshal(newKEK)
    if err != nil {
        return nil, nil, err
    }
    w.Write(hData)
    w.Write(payload)

    return w.Bytes(), newKEK, nil
}

// decrypted payload, and error
// TODO: does Decrypt modify the blob and kek inputs?
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
    i := len(h.Entries) - 1
    for i > 0 {
        dek := h.Entries[i].DEK
        aesctr := aesx.NewCTR(dek[:], iv[:])
        aesctr.XORKeyStream(payload, payload)
        iv.Dec()
        i--
    }

    dek := h.Entries[i].DEK
    aesgcm := aesx.NewGCM(dek[:])
	nonce := aesx.GenZeroNonce()
    payload = append(payload, h.Tag[:]...)
	plaintext, err := aesgcm.Open(payload[:0], nonce, payload, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
