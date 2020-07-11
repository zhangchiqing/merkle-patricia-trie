package main

import "github.com/ethereum/go-ethereum/rlp"

type Node interface {
	Hash() []byte // common.Hash
	Raw() []interface{}
}

func Hash(node Node) []byte {
	if IsEmptyNode(node) {
		return EmptyNodeHash
	}
	return node.Hash()
}

func Serialize(node Node) []byte {
	var raw interface{}

	if IsEmptyNode(node) {
		raw = EmptyNodeRaw
	} else {
		raw = node.Raw()
	}

	rlp, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return rlp
}
