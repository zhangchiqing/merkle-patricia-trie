package main

import "github.com/ethereum/go-ethereum/rlp"

type Node interface {
	Hash() []byte // common.Hash
	Raw() []interface{}
}

func Serialize(node Node) []byte {
	raw := node.Raw()

	rlp, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return rlp
}
