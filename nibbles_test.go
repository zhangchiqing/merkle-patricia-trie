package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsNibble(t *testing.T) {
	for i := 0; i < 20; i++ {
		isNibble := i >= 0 && i < 16
		require.Equal(t, isNibble, IsNibble(byte(i)), i)
	}
}

func TestToPrefixed(t *testing.T) {
	cases := []struct {
		ns         []Nibble
		isLeafNode bool
		expected   []Nibble
	}{
		{
			[]Nibble{1},
			false,
			[]Nibble{1, 1},
		},
		{
			[]Nibble{1, 2},
			false,
			[]Nibble{0, 0, 1, 2},
		},
		{
			[]Nibble{1},
			true,
			[]Nibble{3, 1},
		},
		{
			[]Nibble{1, 2},
			true,
			[]Nibble{2, 0, 1, 2},
		},
		{
			[]Nibble{5, 0, 6},
			true,
			[]Nibble{3, 5, 0, 6},
		},
		{
			[]Nibble{14, 3},
			false,
			[]Nibble{0, 0, 14, 3},
		},
		{
			[]Nibble{9, 3, 6, 5},
			true,
			[]Nibble{2, 0, 9, 3, 6, 5},
		},
		{
			[]Nibble{1, 3, 3, 5},
			true,
			[]Nibble{2, 0, 1, 3, 3, 5},
		},
		{
			[]Nibble{7},
			true,
			[]Nibble{3, 7},
		},
	}

	for _, c := range cases {
		require.Equal(t,
			c.expected,
			ToPrefixed(c.ns, c.isLeafNode))
	}
}

func TestFromBytes(t *testing.T) {
	// [1, 100] -> ['0x01', '0x64']
	require.Equal(t, []Nibble{0, 1, 6, 4}, FromBytes([]byte{1, 100}))
}

func TestToBytes(t *testing.T) {
	bytes := []byte{0, 1, 2, 3}
	require.Equal(t, bytes, ToBytes(FromBytes(bytes)))
}

func TestPrefixMatchedLen(t *testing.T) {
	require.Equal(t, 3, PrefixMatchedLen([]Nibble{0, 1, 2, 3}, []Nibble{0, 1, 2}))
	require.Equal(t, 4, PrefixMatchedLen([]Nibble{0, 1, 2, 3}, []Nibble{0, 1, 2, 3}))
	require.Equal(t, 4, PrefixMatchedLen([]Nibble{0, 1, 2, 3}, []Nibble{0, 1, 2, 3, 4}))
}
