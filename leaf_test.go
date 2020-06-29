package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIteration(t *testing.T) {
	require.Equal(t, "01020304", fmt.Sprintf("%x", []byte{1, 2, 3, 4}))
	require.Equal(t, "76657262", fmt.Sprintf("%x", []byte("verb")))

	// "buffer to nibbles
	require.Equal(t, "0001000200030004", fmt.Sprintf("%x", FromBytes([]byte{1, 2, 3, 4})))

	// ToPrefixed
	require.Equal(t, "02000001000200030004", fmt.Sprintf("%x", ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true)))

	// ToBuffer
	require.Equal(t, "2001020304", fmt.Sprintf("%x", ToBytes(ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true))))
}

func TestLeafNode(t *testing.T) {
	nibbles, value := []byte{1, 2, 3, 4}, []byte("verb")
	l, err := NewLeafNodeFromBytes(nibbles, value)
	require.NoError(t, err)
	expected, err := fromHex("2bafd1eef58e8707569b7c70eb2f91683136910606ba7e31d07572b8b67bf5c6")
	require.NoError(t, err)
	require.Equal(t, expected, l.Hash())
}
