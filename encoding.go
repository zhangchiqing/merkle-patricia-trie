package main

import "encoding/hex"

func fromString(s string) []byte {
	return []byte(s)
}

func fromHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
