package main

type Node interface {
	Hash() []byte // common.Hash
}

type BranchNode struct {
	Branches [16]Node
	Value    []byte
	HasValue bool
}

type ExtensionNode struct {
	Path []Nibble
	Next Node
}

func (e ExtensionNode) Hash() []byte {
	return nil
}
