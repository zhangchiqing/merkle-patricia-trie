package mpt

import "golang.org/x/crypto/sha3"

// Keccak256 returns the Keccak256 hash of data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}
