package main

import (
	"fmt"
)

type Nibble byte

func IsNibble(nibble byte) bool {
	n := int(nibble)
	return n >= 0 && n < 16
}

func FromByte(n byte) (Nibble, error) {
	if !IsNibble(n) {
		return 0, fmt.Errorf("non-nibble byte: %v", n)
	}
	return Nibble(n), nil
}

func FromBytes(nibbles []byte) ([]Nibble, error) {
	ns := make([]Nibble, 0, len(nibbles))
	for _, n := range nibbles {
		nibble, err := FromByte(n)
		if err != nil {
			return nil, fmt.Errorf("contains non-nibble byte: %w", err)
		}
		ns = append(ns, nibble)
	}
	return ns, nil
}

func ToPrefixed(ns []Nibble, isLeafNode bool) []byte {
	// create prefix
	var prefixBytes []byte
	// odd number of nibbles
	if len(ns)%2 > 0 {
		prefixBytes = []byte{1}
	} else {
		// even number of nibbles
		prefixBytes = []byte{0, 0}
	}

	// append prefix to all nibble bytes
	prefixed := make([]byte, 0, len(prefixBytes)+len(ns))
	prefixed = append(prefixed, prefixBytes...)
	for _, n := range ns {
		prefixed = append(prefixed, byte(n))
	}

	// update prefix if is leaf node
	if isLeafNode {
		prefixed[0] += 2
	}

	return prefixed
}
