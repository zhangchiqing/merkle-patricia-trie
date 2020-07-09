package main

import "fmt"

type Trie struct {
	root Node
}

func NewTrie() *Trie {
	return &Trie{}
}

func (t *Trie) Hash() []byte {
	if IsEmptyNode(t.root) {
		return EmptyNodeHash
	}
	return t.root.Hash()
}

func (t *Trie) Get(key []byte) ([]byte, bool) {
	node := t.root
	nibbles := FromBytes(key)
	fmt.Printf("nibbles: %v\n", nibbles)
	for len(nibbles) > 0 {
		fmt.Printf("get nibble: %v\n", nibbles[0])
		if IsEmptyNode(node) {
			fmt.Printf("empty node: %v\n", node)
			return nil, false
		}

		if leaf, ok := node.(*LeafNode); ok {
			fmt.Printf("leaf node: %v\n", leaf)
			matched := PrefixMatchedLen(leaf.Path, nibbles)
			if matched != len(leaf.Path) || matched != len(nibbles) {
				return nil, false
			}
			return leaf.Value, true
		}

		if branch, ok := node.(*BranchNode); ok {
			fmt.Printf("branch node: %v\n", branch)
			if len(nibbles) == 0 {
				return branch.Value, branch.HasValue()
			}

			b, remaining := nibbles[0], nibbles[1:]
			nibbles = remaining
			node = branch.Branches[b]
			continue
		}

		if ext, ok := node.(*ExtensionNode); ok {
			fmt.Printf("ext node: %v\n", ext)
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

	return nil, false
}

// 80 "aa"
// 01 "bb"
// 0

// In general, when inserting into a MPT
// if you stopped at an empty node, you add a new leaf node with the remaining path and replace the empty node with the hash of the new leaf node
// if you stopped at a leaf node, you need to convert it to an extension node and add a new branch and a new leaf node
// if you stopped at an extension node, you convert it to another extension node with shorter path and create a new branch a leaves
func (t *Trie) Put(key []byte, value []byte) {
	// need to use pointer, so that I can update root in place without
	// keeping trace of the parent node
	node := &t.root
	nibbles := FromBytes(key)
	fmt.Printf("put nibbles: %v, values: %x\n", nibbles, value)
	for i := 0; i < len(nibbles); {
		if IsEmptyNode(*node) {
			fmt.Printf("i: %v, nibbles[i]: %v, put empty node: %v\n", i, nibbles[i], node)
			leaf := NewLeafNodeFromBytes(key[i:], value)
			*node = leaf
			return
		}

		if leaf, ok := (*node).(*LeafNode); ok {
			fmt.Printf("i: %v, nibbles[i]: %v, put leaf node: %v\n", i, nibbles[i], leaf)
			matched := PrefixMatchedLen(leaf.Path, nibbles)
			if matched < len(leaf.Path) {
				// have dismatched
				// L 01020304 hello
				// + 010203   world

				// 01020304, 0, 4
				extNibbles, branchNibble, leafNibbles := leaf.Path[:matched], leaf.Path[matched], leaf.Path[matched+1:]
				newLeaf := NewLeafNodeFromNibbles(leafNibbles, leaf.Value) // not :matched+1
				branch := NewBranchNode()
				branch.SetBranch(branchNibble, newLeaf)
				branch.SetValue(value)
				if matched > 0 {
					// create an extension node for the shared nibbles
					ext := NewExtensionNode(extNibbles, branch)
					*node = ext
				} else {
					// when there is nothing matched, there is no need to keep the extension node
					*node = branch
				}
				return
			} else if matched == len(nibbles) { // matched can only be == leaf.Path, can't be > leaf.Path
				// all matched, update value even if the value are equal
				newLeaf := NewLeafNodeFromNibbles(leaf.Path, value)
				*node = newLeaf
				return
			} else if matched < len(nibbles) {
				// L 01020304 hello
				// + 010203040 world

				// L 01020304 hello
				// + 010203040506 world
				extNibbles, branchNibble, leafNibbles := nibbles[:matched], nibbles[matched], nibbles[matched+1:]
				newLeaf := NewLeafNodeFromNibbles(leafNibbles, value)
				branch := NewBranchNode()
				branch.SetBranch(branchNibble, newLeaf)
				branch.SetValue(leaf.Value)
				ext := NewExtensionNode(extNibbles, branch)
				*node = ext
				return
			} else {
				panic("bug")
			}
		}

		if branch, ok := (*node).(*BranchNode); ok {
			fmt.Printf("i: %v, nibbles[i]: %v, put branch node: %v\n", i, nibbles[i], branch)
			if len(nibbles) == 0 {
				branch.SetValue(value)
				return
			}

			b, remaining := nibbles[0], nibbles[1:]
			nibbles = remaining
			node = &branch.Branches[b]
			i++
			continue
		}

		// E 01020304
		// B 0 hello
		// L 506 world
		// + 010203 good
		if ext, ok := (*node).(*ExtensionNode); ok {
			fmt.Printf("i: %v, nibbles[i]: %v, put ext node: %v\n", i, nibbles[i], ext)
			matched := PrefixMatchedLen(ext.Path, nibbles)
			if matched < len(ext.Path) {
				// E 01020304
				// + 010203 good
				extNibbles, branchNibble, extRemainingnibbles := ext.Path[:matched], ext.Path[matched], ext.Path[matched+1:]
				nodeBranchNibble, nodeLeafNibbles := nibbles[matched], nibbles[matched+1:]
				branch := NewBranchNode()
				if len(extRemainingnibbles) == 0 {
					// E 0102030
					// + 010203 good
					branch.SetBranch(branchNibble, ext.Next)
					branch.SetValue(value)
				} else {
					// E 01020304
					// + 010203 good
					newExt := NewExtensionNode(extRemainingnibbles, ext.Next)
					branch.SetBranch(branchNibble, newExt)
				}

				remainingLeaf := NewLeafNodeFromNibbles(nodeLeafNibbles, value)
				branch.SetBranch(nodeBranchNibble, remainingLeaf)

				next := NewExtensionNode(extNibbles, branch)
				*node = next
				return
			}

			nibbles = nibbles[:matched]
			node = &ext.Next
			i += matched
			continue
		}

		panic("unknown type")
	}

}
