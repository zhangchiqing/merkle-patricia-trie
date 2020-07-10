package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type BranchNode struct {
	Branches [16]Node
	Value    []byte
}

func NewBranchNode() *BranchNode {
	return &BranchNode{
		Branches: [16]Node{},
	}
}

func (b BranchNode) Hash() []byte {
	return crypto.Keccak256(b.Serialize())
}

func (b *BranchNode) SetBranch(nibble Nibble, node Node) {
	b.Branches[int(nibble)] = node
}

func (b *BranchNode) RemoveBranch(nibble Nibble) {
	b.Branches[int(nibble)] = nil
}

func (b *BranchNode) SetValue(value []byte) {
	b.Value = value
}

func (b *BranchNode) RemoveValue() {
	b.Value = nil
}

func (b BranchNode) Raw() []interface{} {
	hashes := make([]interface{}, 17)
	for i := 0; i < 16; i++ {
		if b.Branches[i] == nil {
			hashes[i] = EmptyNodeRaw
		} else {
			node := b.Branches[i]
			hashes[i] = node.Hash()
			// if len(node.Serialize()) >= 32 {
			// 	hashes[i] = node.Hash()
			// } else {
			// 	// if node can be serialized to less than 32 bits, then
			// 	// use Serialized directly
			// 	// has to be ">=", rather than ">",
			// 	// so that when deserialized, the content can be distinguished
			// 	// by length
			// 	hashes[i] = node.Raw()
			// }
		}
	}

	hashes[16] = b.Value
	return hashes
}

func (b BranchNode) Serialize() []byte {
	raw := b.Raw()
	fmt.Printf("branch raw: %v\n", raw)

	branchRLP, err := rlp.EncodeToBytes(raw)
	fmt.Printf("branch rlp: %x\n", branchRLP)
	if err != nil {
		panic(err)
	}

	return branchRLP
}

func (b BranchNode) HasValue() bool {
	return b.Value != nil
}
