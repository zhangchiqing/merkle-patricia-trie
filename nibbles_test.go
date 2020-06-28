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
		ns         []byte
		isLeafNode bool
		expected   []byte
	}{
		{
			[]byte{1},
			false,
			[]byte{1, 1},
		},
		{
			[]byte{1, 2},
			false,
			[]byte{0, 0, 1, 2},
		},
		{
			[]byte{1},
			true,
			[]byte{3, 1},
		},
		{
			[]byte{1, 2},
			true,
			[]byte{2, 0, 1, 2},
		},
	}

	for _, c := range cases {
		ns, err := FromBytes(c.ns)
		require.NoError(t, err)
		require.Equal(t,
			c.expected,
			ToPrefixed(ns, c.isLeafNode))
	}
}
