package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeafNode(t *testing.T) {
	nibbles, value := []byte{1, 2, 3, 4}, []byte("verb")
	fmt.Println(nibbles)
	fmt.Printf("%v-%v\n", nibbles, value)
	l, err := NewLeafNode(nibbles, value)
	require.NoError(t, err)
	expected, err := fromHex("2bafd1eef58e8707569b7c70eb2f91683136910606ba7e31d07572b8b67bf5c6")
	require.NoError(t, err)
	require.Equal(t, expected, l.Hash())
}
