package mpt

import (
	"fmt"
)

type Nibble byte

func IsNibble(nibble byte) bool {
	n := int(nibble)
	// 0-9 && a-f
	return n >= 0 && n < 16
}

func FromNibbleByte(n byte) (Nibble, error) {
	if !IsNibble(n) {
		return 0, fmt.Errorf("non-nibble byte: %v", n)
	}
	return Nibble(n), nil
}

func FromNibbleBytes(nibbles []byte) ([]Nibble, error) {
	ns := make([]Nibble, 0, len(nibbles))
	for _, n := range nibbles {
		nibble, err := FromNibbleByte(n)
		if err != nil {
			return nil, fmt.Errorf("contains non-nibble byte: %w", err)
		}
		ns = append(ns, nibble)
	}
	return ns, nil
}

func NibblesFromByte(b byte) []Nibble {
	return []Nibble{
		Nibble(byte(b >> 4)),
		Nibble(byte(b % 16)),
	}
}

func NibblesFromBytes(bs []byte) []Nibble {
	ns := make([]Nibble, 0, len(bs)*2)
	for _, b := range bs {
		ns = append(ns, NibblesFromByte(b)...)
	}
	return ns
}

func FromString(s string) []Nibble {
	return NibblesFromBytes([]byte(s))
}

// AppendPrefixToNibbles add nibble prefix to a slice of nibbles to make its length even
// the prefix indicts whether a node is a leaf node.
func AppendPrefixToNibbles(ns []Nibble, isLeafNode bool) []Nibble {
	// create prefix
	var prefixBytes []Nibble
	// odd number of nibbles
	if len(ns)%2 > 0 {
		prefixBytes = []Nibble{1}
	} else {
		// even number of nibbles
		prefixBytes = []Nibble{0, 0}
	}

	// append prefix to all nibble bytes
	prefixed := make([]Nibble, 0, len(prefixBytes)+len(ns))
	prefixed = append(prefixed, prefixBytes...)
	for _, n := range ns {
		prefixed = append(prefixed, Nibble(n))
	}

	// update prefix if is leaf node
	if isLeafNode {
		prefixed[0] += 2
	}

	return prefixed
}

// RemovePrefixFromNibbles removes nibble prefix from a slice of nibbles and
//tells if the nibbles belong to a leaf node
func RemovePrefixFromNibbles(ns []Nibble) (noPrefixNs []Nibble, isLeafNode bool) {

	// From https://eth.wiki/fundamentals/patricia-tree:
	//
	// 	hex char    bits    |    node type partial     path length
	// ----------------------------------------------------------
	//    0        0000    |       extension              even
	//    1        0001    |       extension              odd
	//    2        0010    |   terminating (leaf)         even
	//    3        0011    |   terminating (leaf)         odd

	if ns[0] == 1 {
		return ns[1:], false
	}

	if ns[0] == 3 {
		return ns[1:], true
	}

	if ns[0] == 0 {
		return ns[2:], false
	}

	if ns[0] == 2 {
		return ns[2:], true
	}

	panic("invalid nibble prefix")
}

// NibblesToBytes converts a slice of nibbles to a byte slice
// assuming the nibble slice has even number of nibbles.
func NibblesToBytes(ns []Nibble) []byte {
	buf := make([]byte, 0, len(ns)/2)

	for i := 0; i < len(ns); i += 2 {
		b := byte(ns[i]<<4) + byte(ns[i+1])
		buf = append(buf, b)
	}

	return buf
}

// [0,1,2,3], [0,1,2] => 3
// [0,1,2,3], [0,1,2,3] => 4
// [0,1,2,3], [0,1,2,3,4] => 4
func PrefixMatchedLen(node1 []Nibble, node2 []Nibble) int {
	matched := 0
	for i := 0; i < len(node1) && i < len(node2); i++ {
		n1, n2 := node1[i], node2[i]
		if n1 == n2 {
			matched++
		} else {
			break
		}
	}

	return matched
}
