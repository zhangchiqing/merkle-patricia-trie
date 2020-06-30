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

func NewLeafNodeFromNibbleBytes(nibbles []byte, value []byte) (*LeafNode, error) {
	ns, err := FromNibbleBytes(nibbles)
	if err != nil {
		return nil, fmt.Errorf("could not leaf node from nibbles: %w", err)
	}

	return NewLeafNodeFromNibbles(ns, value)
}

func NewLeafNodeFromNibbles(nibbles []Nibble, value []byte) (*LeafNode, error) {
	return &LeafNode{
		Path:  nibbles,
		Value: value,
	}, nil
}

func NewLeafNodeFromKeyValue(key, value string) (*LeafNode, error) {
	return NewLeafNodeFromBytes([]byte(key), []byte(value))
}

func NewLeafNodeFromBytes(key, value []byte) (*LeafNode, error) {
	return NewLeafNodeFromNibbles(FromBytes(key), value)
}

func (l LeafNode) Hash() []byte {
	raw := l.Raw()
	leafRLP, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return crypto.Keccak256(leafRLP)
}

func (l LeafNode) Raw() []interface{} {
	path := ToBytes(ToPrefixed(l.Path, true))
	raw := []interface{}{path, l.Value}
	return raw
}
