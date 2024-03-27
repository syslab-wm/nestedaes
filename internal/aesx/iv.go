package aesx

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const IVSize = 16

type IV [IVSize]byte

var maxIV *big.Int

func init() {
	a := [IVSize]byte{}
	for i := 0; i < len(a); i++ {
		a[i] = 0xff
	}
	maxIV = new(big.Int)
	maxIV = maxIV.SetBytes(a[:])
	maxIV.Add(maxIV, big.NewInt(1))
}

func GenRandomIV() *IV {
	var iv IV
	_, err := rand.Read(iv[:])
	if err != nil {
		panic(fmt.Sprintf("rand.Read failed: %v", err))
	}
	return &iv
}

func NewIV(data []byte) *IV {
	var iv IV
	copy(iv[:], data)
	return &iv
}

func (iv *IV) String() string {
	return fmt.Sprintf("%#x", *iv)
}

func (iv *IV) IsZero() bool {
	for b := range iv {
		if b != 0 {
			return false
		}
	}
	return true
}

func (iv *IV) ToBigInt() *big.Int {
	z := new(big.Int)
	z.SetBytes(iv[:])
	return z
}

func (iv *IV) Add(x int) {
	z := iv.ToBigInt()
	y := big.NewInt(int64(x))
	z.Add(z, y)
	z.Mod(z, maxIV) // This should always be positive
	z.FillBytes(iv[:])
}

func (iv *IV) Dec() {
	iv.Add(-1)
}

func (iv *IV) Inc() {
	iv.Add(1)
}
