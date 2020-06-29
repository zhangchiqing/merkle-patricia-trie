package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeafNode(t *testing.T) {
	fmt.Printf("%x, %x\n", []byte{1, 2, 3, 4}, []byte("verb"))                      // 01020304, 76657262
	fmt.Printf("buffer to nibbles: %x\n", FromBytes([]byte{1, 2, 3, 4}))            // 0001000200030004
	fmt.Printf("ToPrefixed: %x\n", ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true)) // 02000001000200030004
	fmt.Printf("Tobuffer: %x\n", ToBytes(ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true)))
	nibbles, value := []byte{1, 2, 3, 4}, []byte("verb")
	l, err := NewLeafNodeFromBytes(nibbles, value)
	require.NoError(t, err)
	expected, err := fromHex("2bafd1eef58e8707569b7c70eb2f91683136910606ba7e31d07572b8b67bf5c6")
	require.NoError(t, err)
	require.Equal(t, expected, l.Hash())
}
