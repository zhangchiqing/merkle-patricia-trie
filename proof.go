package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie"
)

type Proof interface {
	// Put inserts the given value into the key-value data store.
	Put(key []byte, value []byte) error

	// Delete removes the key from the key-value data store.
	Delete(key []byte) error

	// Has retrieves if a key is present in the key-value data store.
	Has(key []byte) (bool, error)

	// Get retrieves the given key if it's present in the key-value data store.
	Get(key []byte) ([]byte, error)

	// Serialize returns the serialized proof
	Serialize() [][]byte
}

type ProofDB struct {
	kv map[string][]byte
}

func NewProofDB() *ProofDB {
	return &ProofDB{
		kv: make(map[string][]byte),
	}
}

func (w *ProofDB) Put(key []byte, value []byte) error {
	keyS := fmt.Sprintf("%x", key)
	w.kv[keyS] = value
	fmt.Printf("put key: %x, value: %x\n", key, value)
	return nil
}

func (w *ProofDB) Delete(key []byte) error {
	keyS := fmt.Sprintf("%x", key)
	delete(w.kv, keyS)
	return nil
}
func (w *ProofDB) Has(key []byte) (bool, error) {
	keyS := fmt.Sprintf("%x", key)
	_, ok := w.kv[keyS]
	return ok, nil
}

func (w *ProofDB) Get(key []byte) ([]byte, error) {
	keyS := fmt.Sprintf("%x", key)
	val, ok := w.kv[keyS]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return val, nil
}

func (w *ProofDB) Serialize() [][]byte {
	nodes := make([][]byte, 0, len(w.kv))
	for _, value := range w.kv {
		nodes = append(nodes, value)
	}
	return nodes
}

// Prove returns the merkle proof for the given key, which is
func (t *Trie) Prove(key []byte) (Proof, bool) {
	proof := NewProofDB()
	node := t.root
	nibbles := FromBytes(key)

	for {
		proof.Put(Hash(node), Serialize(node))

		if IsEmptyNode(node) {
			return nil, false
		}

		if leaf, ok := node.(*LeafNode); ok {
			matched := PrefixMatchedLen(leaf.Path, nibbles)
			if matched != len(leaf.Path) || matched != len(nibbles) {
				return nil, false
			}

			return proof, true
		}

		if branch, ok := node.(*BranchNode); ok {
			if len(nibbles) == 0 {
				return proof, branch.HasValue()
			}

			b, remaining := nibbles[0], nibbles[1:]
			nibbles = remaining
			node = branch.Branches[b]
			continue
		}

		if ext, ok := node.(*ExtensionNode); ok {
			matched := PrefixMatchedLen(ext.Path, nibbles)
			// E 01020304
			//   010203
			if matched < len(ext.Path) {
				return nil, false
			}

			nibbles = nibbles[matched:]
			node = ext.Next
			continue
		}

		panic("not found")
	}
}

// VerifyProof verify the proof for the given key under the given root hash using go-ethereum's VerifyProof implementation.
// It returns the value for the key if the proof is valid, otherwise error will be returned
func VerifyProof(rootHash []byte, key []byte, proof Proof) (value []byte, err error) {
	return trie.VerifyProof(common.BytesToHash(rootHash), key, proof)
}
