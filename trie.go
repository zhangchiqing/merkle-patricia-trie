package main

type Trie struct {
	root Node
}

func NewTrie() {
}

func (t *Trie) Hash() []byte {
	if t.root == nil {
		return EmptyNodeHash
	}
	return t.root.Hash()
}
