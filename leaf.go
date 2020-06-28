package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type LeafNode struct {
	Path  []Nibble
	Value []byte
}

func NewLeafNode(nibbles []byte, value []byte) (*LeafNode, error) {
	ns, err := FromBytes(nibbles)
	if err != nil {
		return nil, fmt.Errorf("could not create leaf node: %w", err)
	}

	return &LeafNode{
		Path:  ns,
		Value: value,
	}, nil
}

func (l LeafNode) Hash() []byte {
	path := ToPrefixed(l.Path, true)
	raw := []interface{}{path, l.Value}
	leafRLP, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return crypto.Keccak256(leafRLP)
}
