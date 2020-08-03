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
	t.Run("should not generate proof for non-exist key", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))
		notExistKey := []byte{1, 2, 3, 4}
		_, ok := tr.Prove(notExistKey)
		require.False(t, ok)
	})

	t.Run("should generate a proof for an existing key, the proof can be verified with the merkle root hash", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))

		key := []byte{1, 2, 3}
		proof, ok := tr.Prove(key)
		require.True(t, ok)

		rootHash := tr.Hash()

		// verify the proof with the root hash, the key in question and its proof
		val, err := VerifyProof(rootHash, key, proof)
		require.NoError(t, err)

		// when the verification has passed, it should return the correct value for the key
		require.Equal(t, []byte("hello"), val)
	})

	t.Run("should fail the verification of the trie was updated", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))

		// the hash was taken before the trie was updated
		rootHash := tr.Hash()

		// the proof was generated after the trie was updated
		tr.Put([]byte{5, 6, 7}, []byte("trie"))
		key := []byte{1, 2, 3}
		proof, ok := tr.Prove(key)
		require.True(t, ok)

		// should fail the verification since the merkle root hash doesn't match
		_, err := VerifyProof(rootHash, key, proof)
		require.Error(t, err)
	})
}
