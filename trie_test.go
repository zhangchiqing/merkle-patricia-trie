package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPut(t *testing.T) {
	trie := NewTrie()
	require.Equal(t, EmptyNodeHash, trie.Hash())
	trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
	ns := NewLeafNodeFromBytes([]byte{1, 2, 3, 4}, []byte("hello"))
	require.Equal(t, ns.Hash(), trie.Hash())
}

func TestPutLeafShorter(t *testing.T) {
	trie := NewTrie()
	trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
	trie.Put([]byte{1, 2, 3}, []byte("world"))

	leaf := NewLeafNodeFromNibbles([]Nibble{4}, []byte("hello"))

	branch := NewBranchNode()
	branch.SetBranch(Nibble(0), leaf)
	branch.SetValue([]byte("world"))

	ext := NewExtensionNode([]Nibble{0, 1, 0, 2, 0, 3}, branch)

	require.Equal(t, ext.Hash(), trie.Hash())
}

func TestPutLeafAllMatched(t *testing.T) {
	trie := NewTrie()
	trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
	trie.Put([]byte{1, 2, 3, 4}, []byte("world"))

	ns := NewLeafNodeFromBytes([]byte{1, 2, 3, 4}, []byte("world"))
	require.Equal(t, ns.Hash(), trie.Hash())
}

func TestPutLeafMore(t *testing.T) {
	trie := NewTrie()
	trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
	trie.Put([]byte{1, 2, 3, 4, 5, 6}, []byte("world"))

	leaf := NewLeafNodeFromNibbles([]Nibble{5, 0, 6}, []byte("world"))

	branch := NewBranchNode()
	branch.SetValue([]byte("hello"))
	branch.SetBranch(Nibble(0), leaf)

	ext := NewExtensionNode([]Nibble{0, 1, 0, 2, 0, 3, 0, 4}, branch)

	require.Equal(t, ext.Hash(), trie.Hash())
}

func TestPutOrder(t *testing.T) {
	trie1, trie2 := NewTrie(), NewTrie()

	trie1.Put([]byte{1, 2, 3, 4, 5, 6}, []byte("world"))
	trie1.Put([]byte{1, 2, 3, 4}, []byte("hello"))

	trie2.Put([]byte{1, 2, 3, 4}, []byte("hello"))
	trie2.Put([]byte{1, 2, 3, 4, 5, 6}, []byte("world"))

	require.Equal(t, trie1.Hash(), trie2.Hash())
}
