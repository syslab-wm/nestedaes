package aesx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
    "fmt"

	"github.com/syslab-wm/mu"
)

const KeySize = 32
const NonceSize = 12
const TagSize = 16

func GenRandomKey() []byte {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		mu.Panicf("failed to generate an AES-256 key: %v", err)
	}
	return key
}

func NewCTR(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		mu.Panicf("aes.NewCipher failed: %v", err)
	}
	return cipher.NewCTR(block, iv)
}

func GenZeroNonce() []byte {
	return make([]byte, NonceSize)
}

func NewGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		mu.Panicf("aes.NewCipher failed: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		mu.Panicf("cipher.NewGCM failed: %v", err)
	}

	return aesgcm
}

// SplitCiphertextTag takes as input an AES-GCM encrypted ciphertext
// and returns the two components of the ciphertext: the ciphertext proper, and
// the authentication tag (which is conventionally appended to the ciphertext).
func SplitCiphertextTag(ciphertext []byte) ([]byte, []byte, error) {
    if len(ciphertext) <= TagSize {
        return nil, nil, fmt.Errorf("ciphertext (%d bytes) <= AES GCM tag size (%d)", len(ciphertext), TagSize)
    }

	tag := ciphertext[len(ciphertext) - TagSize:]
	ciphertext = ciphertext[:len(ciphertext) - TagSize]
    return ciphertext, tag, nil
}

