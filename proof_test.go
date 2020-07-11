package main

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
)

func TestEthProof(t *testing.T) {
	mpt := new(trie.Trie)
	mpt.Update([]byte{1, 2, 3}, []byte("hello"))
	mpt.Update([]byte{1, 2, 3, 4, 5}, []byte("world"))
	w := NewProofDB()
	err := mpt.Prove([]byte{1, 2, 3}, 0, w)
	require.NoError(t, err)
	rootHash := mpt.Hash()
	val, err := trie.VerifyProof(rootHash, []byte{1, 2, 3}, w)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), val)
	fmt.Printf("root hash: %x\n", rootHash)
}

func TestMyTrie(t *testing.T) {
	tr := NewTrie()
	tr.Put([]byte{1, 2, 3}, []byte("hello"))
	tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))
	n0, ok := tr.root.(*ExtensionNode)
	require.True(t, ok)
	n1, ok := n0.Next.(*BranchNode)
	require.True(t, ok)
	fmt.Printf("n0 hash: %x, Serialized: %x\n", n0.Hash(), n0.Serialize())
	fmt.Printf("n1 hash: %x, Serialized: %x\n", n1.Hash(), n1.Serialize())
}

func TestProveAndVerifyProof(t *testing.T) {
	tr := NewTrie()
	tr.Put([]byte{1, 2, 3}, []byte("hello"))
	tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))

	key := []byte{1, 2, 3}
	proof, ok := tr.Prove(key)
	require.True(t, ok)

	val, err := VerifyProof(tr.Hash(), key, proof)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), val)
}
