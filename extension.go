package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type ExtensionNode struct {
	Path []Nibble
	Next Node
}

func NewExtensionNode(nibbles []Nibble, next Node) *ExtensionNode {
	return &ExtensionNode{
		Path: nibbles,
		Next: next,
	}
}

func (e ExtensionNode) Hash() []byte {
	return crypto.Keccak256(e.Serialize())
}

func (e ExtensionNode) Raw() []interface{} {
	hashes := make([]interface{}, 2)
	hashes[0] = ToBytes(ToPrefixed(e.Path, false))
	if len(e.Next.Serialize()) >= 32 {
		hashes[1] = e.Next.Hash()
	} else {
		hashes[1] = e.Next.Raw()
	}
	return hashes
}

func (e ExtensionNode) Serialize() []byte {
	raw := e.Raw()

	extRLP, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return extRLP
}
