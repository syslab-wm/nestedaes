package aesx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"nestedaes/internal/mu"
)

const KeySize = 32
const NonceSize = 12
const TagSize = 16
const IVSize = 16

const bufSize = 8192

func GenKey() []byte {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		mu.Panicf("failed to generate an AES-256 key: %v", err)
	}
	return key
}

func ReadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read AES key file: %v", err)
	}

	keySize := len(data)
	if keySize != KeySize {
		return nil, fmt.Errorf("can't read AES key file %q has bad size (expected %d, got %d)", KeySize, keySize)
	}

	return data, nil
}

func GenIVWithValue(v uint64) []byte {
	buf := make([]byte, IVSize)
	iv := bytes.NewBuffer(buf[:0])
	err := binary.Write(iv, binary.LittleEndian, v)
	if err != nil {
		mu.Panicf("failed to generate an IV with value %d: %v", v, err)
	}
	return buf
}

func NewCTR(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		mu.Panicf("aes.NewCipher failed: %v", err)
	}
	return cipher.NewCTR(block, iv)
}

func CTREncryptFile(key, iv []byte, inFile, outFile string) error {
	buf := make([]byte, bufSize)
	aesctr := NewCTR(key, iv)

	inf, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("can't open input ciphertext file: %v", err)
	}
	defer inf.Close()

	outf, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("can't open output plaintext file: %v", err)
	}
	defer outf.Close()

	for {
		n, err := inf.Read(buf)
		if err != nil {
			if err == io.EOF {
				// if io.EOF, then n == 0
				break
			}
			return fmt.Errorf("error reading from input ciphertext file: %v", err)
		}
		aesctr.XORKeyStream(buf[:n], buf[:n])
		mu.WriteAll(outf, buf[:n])
	}

	return nil
}

func CTRDecryptFile(key, iv []byte, inFile, outFile string) error {
	return CTREncryptFile(key, iv, inFile, outFile)
}

func CTRDecrypt(key, iv, msg []byte) {
	aesctr := NewCTR(key, iv)
	aesctr.XORKeyStream(msg, msg)
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

func ReadTagFile(path string) ([]byte, error) {
	tag, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read tag key file: %v", err)
	}

	tagSize := len(tag)
	if tagSize != TagSize {
		return nil, fmt.Errorf("bad tag size: expected %d, got %d", TagSize, tagSize)
	}

	return tag, nil
}
