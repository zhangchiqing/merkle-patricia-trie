package main

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
	nibbles := FromBytes(key)
	found, _, visited := walkPath(t.root, nibbles, []Node{})
	if !found {
		return nil, false
	}

	last := visited[len(visited)-1]

	if leaf, ok := last.(LeafNode); ok {
		return leaf.Value, true
	}

	if branch, ok := last.(BranchNode); ok {
		if branch.HasValue() {
			return branch.Value, true
		}
		return nil, false
	}

	if _, ok := last.(ExtensionNode); ok {
		return nil, false
	}

	panic("unknown node type")
}

// func getValue(node Node, remaining []Nibble) ([]byte, bool) {
// 	if IsEmptyNode(node) {
// 		return nil, false
// 	}
//
// 	if leaf, ok := node.(LeafNode); ok {
// 		if len(remaining) == 0 {
// 			return nil, false
// 		}
//
// 		_, unmatched := MatchedNibbles(leaf.Path, remaining)
// 		// all matched
// 		if unmatched == 0 {
// 			return leaf.Value, true
// 		}
// 		return nil, false
// 	}
//
// 	if branch, ok := node.(BranchNode); ok {
// 		if len(remaining) == 0 {
// 			return branch.Value, true
// 		}
//
// 		nextNibble, nextRemaining := remaining[0], remaining[1:]
// 		nextNode := branch.Branches[nextNibble]
// 		return getValue(nextNode, nextRemaining)
// 	}
//
// 	if ext, ok := node.(ExtensionNode); ok {
// 		if len(remaining) == 0 {
// 			return nil, false
// 		}
//
// 		_, unmatched := MatchedNibbles(ext.Path, remaining)
// 		if unmatched == 0 {
// 			return getValue(ext.Next, []Nibble{})
// 		}
//
// 		return nil, false
// 	}
//
// 	panic("unknown node type")
// }

// In general, when inserting into a MPT
// if you stopped at an empty node, you add a new leaf node with the remaining path and replace the empty node with the hash of the new leaf node
// if you stopped at a leaf node, you need to convert it to an extension node and add a new branch and a new leaf node
// if you stopped at an extension node, you convert it to another extension node with shorter path and create a new branch a leaves

// L 01020304 hello

// E 01020304
// B 0         hello
// L 506			 world

// 01020304 hello
// 010203040506 world
// 010203050403 apple
//

//

func (t *Trie) put(key []byte, value []byte) {
	// need to use pointer, so that I can update root in place without
	// keeping trace of the parent node
	nodeRef := &t.root
	node := *nodeRef
	nibbles := FromBytes(key)
	for i := 0; i < len(nibbles); i++ {
		if IsEmptyNode(node) {
			leaf := NewLeafNodeFromBytes(key[i:], value)
			*nodeRef = leaf
			return
		}

		// TODO: how to make this safer? node.(LeafNode)
		if leaf, ok := node.(*LeafNode); ok {
			matched := PrefixMatchedLen(leaf.Path, nibbles)
			if matched < len(leaf.Path) {
				// have dismatched
				// L 01020304 hello
				// + 010203   world
				newLeaf := NewLeafNodeFromNibbles(leaf.Path[matched+1:], leaf.Value)
				branch := NewBranchNode()
				branch.SetBranch(leaf.Path[matched], newLeaf)
				branch.SetValue(value)
				ext := NewExtensionNode(leaf.Path[:matched], branch)
				*nodeRef = ext
				return
			} else {
				panic("not implemented")
			}

			i += len(leaf.Path)
		}

		panic("unknown type")

		// if ext, ok := node.(ExtensionNode); ok {
		// }
		//
		// if branch, ok := node.(BranchNode); ok {
		// }

	}

	// L 01020304 hello
	// + 010203040 world

	// L 01020304 hello
	// + 010203040506 world
}

// 01020304 hello
// 010203040506 world
// 010204030506 trie
//
//
// 01020
// 3 4
// 04 hello
// 0
// 506 world
// 030506 trie
// func (t *Trie) Put(key []byte, value []byte) {
// 	if IsEmptyNode(t.root) {
// 		t.root = NewLeafNodeFromBytes(key, value)
// 		return
// 	}
//
// 	nibbles := FromBytes(key)
//
// 	found, remaining, visited := walkPath(t.root, nibbles, []Node{})
// 	// last must be found, because root is not empty node
// 	last := visited[len(visited)-1]
//
// 	if leaf, ok := last.(LeafNode); ok {
// 		// L 01020304 hello
// 		//   01020304 world
// 		if found {
// 			leaf.Value = value
// 			return
// 		}
//
// 		matched := PrefixMatchedLen(leaf.Path, remaining)
// 		branch := NewBranchNode()
// 		// L 01020304 hello
// 		//   01020506 world
// 		if matched < len(leaf.Path) {
// 			branchNibble, leafNibbles := leaf.Path[matched], leaf.Path[:matched+1]
// 			oldLeaf := NewLeafNodeFromNibbles(leafNibbles, leaf.Value)
// 			branch.SetBranch(branchNibble, oldLeaf)
// 		} else {
// 			// L 01020304 hello
// 			//   0102030405 world
// 			branchNibble, leafNibbles := remaining[matched+1], remaining[matched+1:]
// 			oldLeaf := NewLeafNodeFromNibbles(leafNibbles, leaf.Value)
// 			branch.SetBranch(branchNibble, oldLeaf)
// 		}
//
// 		ext := NewExtensionNode(leaf.Path[:matched], branch)
// 		updateNode(visited, ext)
//
// 		return
// 	}
//
// 	if branch, ok := last.(BranchNode); ok {
//
// 	}
//
// 	if ext, ok := last.(ExtensionNode); ok {
// 	}
//
// 	panic("unknown node type")
// }

func walkPath(node Node, remaining []Nibble, visited []Node) (bool, []Nibble, []Node) {
	if IsEmptyNode(node) {
		return false, remaining, visited
	}

	visited = append(visited, node)

	// L 01020304 hello
	// 01020305 world
	// =>
	// E 0102030
	// B 4 5
	// L "" hello
	// L "" world
	if leaf, ok := node.(LeafNode); ok {
		matched := PrefixMatchedLen(leaf.Path, remaining)
		found := matched == len(leaf.Path) && matched == len(remaining)
		return found, remaining, visited
	}

	// E 0102030
	// B 4 5
	// L "" hello
	// L 06 apple

	// 0102030405 world

	// E 0102030
	// B 4 5
	// B 0      hello
	// L 506    world
	// L 06 apple
	if branch, ok := node.(BranchNode); ok {
		if len(remaining) == 0 {
			return true, remaining, visited
		}

		nextNibble, nextRemaining := remaining[0], remaining[1:]
		nextNode := branch.Branches[nextNibble]
		return walkPath(nextNode, nextRemaining, visited)
	}

	if ext, ok := node.(ExtensionNode); ok {
		matched := PrefixMatchedLen(ext.Path, remaining)
		// E 0102030
		// B 4 5
		// L "" hello
		// L 06 apple

		// "0102" "good"
		if len(ext.Path) > matched {
			return false, remaining, visited
		}

		// E 0102030
		// B 4 5
		// L "" hello
		// L 06 apple

		// 0102030 "xxx"
		return walkPath(ext.Next, remaining[:matched], visited)
	}

	panic("unknown node type")
}
