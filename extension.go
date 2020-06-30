package main

type ExtensionNode struct {
	Path []Nibble
	Next Node
}

func (e ExtensionNode) Hash() []byte {
	return nil
}
