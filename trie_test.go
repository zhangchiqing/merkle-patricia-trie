package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPut(t *testing.T) {
	trie := NewTrie()
	require.Equal(t, EmptyNodeHash, trie.Hash())
	trie.put([]byte{0, 1, 0, 2, 0, 3, 0, 4}, []byte("hello"))
	ns := NewLeafNodeFromBytes([]byte{0, 1, 0, 2, 0, 3, 0, 4}, []byte("hello"))
	require.Equal(t, ns.Hash(), trie.Hash())
}
