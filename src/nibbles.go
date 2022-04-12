package mpt

import (
	"fmt"
)

// Nibble is an alias of byte which enforces by construction (NewNibblesFromByte & NewNibblesFromBytes) that
// its value is between 0 (inclusive) and 16 (non-inclusive). This corresponds to the range of values that a
// hexadecimal number (4 bits) can take.
type Nibble byte

// NewNibblesFromByte converts a single byte (8 bits, 2^8 possible values) to a slice containing two nibbles:
// (2 * 4 bits, 2^4*2 = 2^8 possible values).
func NewNibblesFromByte(b byte) []Nibble {
	return []Nibble{
		Nibble(byte(b >> 4)),
		Nibble(byte(b % 16)),
	}
}

// NewNibblesFromBytes generalizes NewNibblesFromByte for slice-of-bytes inputs.
func NewNibblesFromBytes(bs []byte) []Nibble {
	ns := make([]Nibble, 0, len(bs)*2)
	for _, b := range bs {
		ns = append(ns, NewNibblesFromByte(b)...)
	}
	return ns
}

// ByteAsNibble casts nibble (a byte) into a value of type Nibble (which is just an alias of type byte)
// /without/ changing the underlying value. This is in contrast to `NewNibblesFromByte`, which actually
// returns a different underlying value.
//
// ByteAsNibble returns an error if n is not a valid Nibble (i.e., it's not a value of type byte that
// is greater or equal to 0 and less than 16).
func ByteAsNibble(nibble byte) (Nibble, error) {
	if !IsNibble(nibble) {
		return 0, fmt.Errorf("non-nibble byte: %v", nibble)
	}
	return Nibble(nibble), nil
}

// BytesAsNibbles generalizes ByteAsNibble for slice-of-bytes inputs.
func BytesAsNibbles(nibbles []byte) ([]Nibble, error) {
	ns := make([]Nibble, 0, len(nibbles))
	for _, n := range nibbles {
		nibble, err := ByteAsNibble(n)
		if err != nil {
			return nil, fmt.Errorf("contains non-nibble byte: %w", err)
		}
		ns = append(ns, nibble)
	}
	return ns, nil
}

// NibblesAsBytes converts a slice of nibbles to a byte slice assuming the nibble slice has even
// number of nibbles.
func NibblesAsBytes(ns []Nibble) []byte {
	buf := make([]byte, 0, len(ns)/2)

	for i := 0; i < len(ns); i += 2 {
		b := byte(ns[i]<<4) + byte(ns[i+1])
		buf = append(buf, b)
	}

	return buf
}

// AppendPrefixToNibbles add nibble prefix to a slice of nibbles to make its length even.
// The prefix disambiguates whether a deserialization of a node corresponds to a LeafNode or an ExtensionNode.
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
// tells if the nibbles belong to a leaf node
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

func IsNibble(nibble byte) bool {
	n := int(nibble)
	// 0-9 && a-f
	return n >= 0 && n < 16
}
