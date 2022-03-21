package mpt

import "fmt"

/// Trie is an in-memory representation of a Merkle Patricia Trie using RLP-encoding.
/// Trie supports loading data from, and saving data to, persistent storage using the
/// `LoadFromDB` and `SaveToDB` methods.
///
/// Trie exposes a state-machine-type API that simplifies implementation of Veritas'
/// fraud proof functionality. This means that generally, its functions need to be
/// called in careful orders (depending on what the calling code is trying to do).
///
/// # Usage
///
/// 1. Normal mode:
///    Op 1. NewTrie(mode: MODE_NORMAL)
///    Op 2. LoadFromDB()
///    Op 3. *Get()/Put()
///    Op 4. state_root = GetStateRoot()
///    Op 5. if state_root == expected_state_root
///            then SaveToDB()
///            else go to 'Generate fraud proof mode'
///
/// 2. Generate fraud proof mode:
///    Op 1. NewTrie(mode: MODE_GENERATE_FRAUD_PROOF)
///    Op 2. LoadFromDB()
///    Op 3. *Get()/Put()
///    Op 4. pre_state, pseudo_post_state = GetPreAndPseudoPostState()
///
/// 3. Execute fraud proof mode:
///    Op 1. NewTrie(mode: VERIFY_FRAUD_PROOF)
///    Op 2. LoadPreState(pre_state)
///    Op 3. *Get/Put()
///    Op 4. if WasPreStateComplete() then continue else exit
///    Op 5. LoadPseudoPostState(pseudo_post_state)
///    Op 6. state_root = GetStateRoot()
///    Op 7. if state_root == published_state_root
///          then do nothing
///          else disable the rollup
///
type Trie struct {
	root Node
	mode TrieMode

	// TODO [Alice]: using string as a key here is non-ideal.
	// readSet is non-nil only if mode == MODE_GENERATE_FRAUD_PROOF
	readSet map[string][]byte
}

type TrieMode uint

const (
	MODE_NORMAL               TrieMode = 0
	MODE_GENERATE_FRAUD_PROOF TrieMode = 1
	MODE_VERIFY_FRAUD_PROOF   TrieMode = 2
	MODE_DEAD                 TrieMode = 3
)

/// NewTrie returns an empty Trie in the specified, immutable mode.
func NewTrie(mode TrieMode) *Trie {
	if mode != MODE_NORMAL || mode != MODE_GENERATE_FRAUD_PROOF || mode != MODE_VERIFY_FRAUD_PROOF {
		panic("attempted to create a new trie with an invalid mode.")
	}

	return &Trie{
		root: nil,
		mode: mode,
	}
}

/// Get returns the value associated with key in the Trie, if it exists, and nil if does not.
func (t *Trie) Get(key []byte) []byte {
	if t.mode == MODE_DEAD {
		panic("attempted to use dead Trie. Read Trie documentation.")
	}

	if t.mode == MODE_NORMAL {
		return t.getFromTrie(key)
	} else if t.mode == MODE_GENERATE_FRAUD_PROOF {
		value := t.getFromTrie(key)

		key_as_string := fmt.Sprintf("%x", key)
		if _, exists := t.readSet[key_as_string]; !exists {
			t.readSet[key_as_string] = value
		}

		return value
	} else { // if t.mode == MODE_VERIFY_FRAUD_PROOF
		// TODO [Alice]: differentiate between incomplete pre-state and actually-non-existent key.
		return t.getFromTrie(key)
	}
}

type PreState = [][2][]byte
type PseudoPostState = []PseudoNode

/// GetPreAndPseudoPostState returns PreState: the list of key-value pairs that have to be loaded into
/// a Trie (using `LoadPreState`) to serve reads into world state during fraud proof execution, and
/// PseudoPostState: the list of PseudoNodes that have to be loaded into a Trie (using `LoadPostState`)
/// to calculate its post state root after fraud proof execution.
///
/// After calling this method, the Trie becomes dead.
///
/// # Panics
/// This method panics if called when t.mode != MODE_GENERATE_FRAUD_PROOF.
func (t *Trie) GetPreAndPseudoPostState() (PreState, PseudoPostState) {
	if t.mode != MODE_GENERATE_FRAUD_PROOF {
		panic("attempted to GetPreAndPseudoPostState, but Trie is not in generate fraud proof mode.")
	}

	pre_state := make([][2][]byte, 0)
	for key, value := range t.readSet {
		pre_state = append(pre_state, [2][]byte{[]byte(key), value})
	}

	// TODO [Alice]
	post_state := make([]PseudoNode, 0)

	t.mode = MODE_DEAD

	return pre_state, post_state
}

/// Put adds a key value pair to the Trie.
///
/// # Panics
/// This method panics if called when t.mode != MODE_NORMAL || MODE_GENERATE_FRAUD_PROOF || MODE_VERIFY_FRAUD_PROOF.
func (t *Trie) Put(key []byte, value []byte) {
	if t.mode != MODE_NORMAL && t.mode != MODE_GENERATE_FRAUD_PROOF && t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	// need to use pointer, so that I can update root in place without
	// keeping trace of the parent node
	node := &t.root
	nibbles := NibblesFromBytes(key)
	for {
		if IsEmptyNode(*node) {
			leaf := NewLeafNodeFromNibbles(nibbles, value)
			*node = leaf
			return
		}

		if leaf, ok := (*node).(*LeafNode); ok {
			matched := PrefixMatchedLen(leaf.path, nibbles)

			// if all matched, update value even if the value are equal
			if matched == len(nibbles) && matched == len(leaf.path) {
				newLeaf := NewLeafNodeFromNibbles(leaf.path, value)
				*node = newLeaf
				return
			}

			branch := NewBranchNode()
			// if matched some nibbles, check if matches either all remaining nibbles
			// or all leaf nibbles
			if matched == len(leaf.path) {
				branch.SetValue(leaf.value)
			}

			if matched == len(nibbles) {
				branch.SetValue(value)
			}

			// if there is matched nibbles, an extension node will be created
			if matched > 0 {
				// create an extension node for the shared nibbles
				ext := NewExtensionNode(leaf.path[:matched], branch)
				*node = ext
			} else {
				// when there no matched nibble, there is no need to keep the extension node
				*node = branch
			}

			if matched < len(leaf.path) {
				// have dismatched
				// L 01020304 hello
				// + 010203   world

				// 01020304, 0, 4
				branchNibble, leafNibbles := leaf.path[matched], leaf.path[matched+1:]
				newLeaf := NewLeafNodeFromNibbles(leafNibbles, leaf.value) // not :matched+1
				branch.SetBranch(branchNibble, newLeaf)
			}

			if matched < len(nibbles) {
				// L 01020304 hello
				// + 010203040 world

				// L 01020304 hello
				// + 010203040506 world
				branchNibble, leafNibbles := nibbles[matched], nibbles[matched+1:]
				newLeaf := NewLeafNodeFromNibbles(leafNibbles, value)
				branch.SetBranch(branchNibble, newLeaf)
			}

			return
		}

		if branch, ok := (*node).(*BranchNode); ok {
			if len(nibbles) == 0 {
				branch.SetValue(value)
				return
			}

			b, remaining := nibbles[0], nibbles[1:]
			nibbles = remaining
			node = &branch.branches[b]
			continue
		}

		// E 01020304
		// B 0 hello
		// L 506 world
		// + 010203 good
		if ext, ok := (*node).(*ExtensionNode); ok {
			matched := PrefixMatchedLen(ext.path, nibbles)
			if matched < len(ext.path) {
				// E 01020304
				// + 010203 good
				extNibbles, branchNibble, extRemainingnibbles := ext.path[:matched], ext.path[matched], ext.path[matched+1:]
				nodeBranchNibble, nodeLeafNibbles := nibbles[matched], nibbles[matched+1:]
				branch := NewBranchNode()
				if len(extRemainingnibbles) == 0 {
					// E 0102030
					// + 010203 good
					branch.SetBranch(branchNibble, ext.next)
				} else {
					// E 01020304
					// + 010203 good
					newExt := NewExtensionNode(extRemainingnibbles, ext.next)
					branch.SetBranch(branchNibble, newExt)
				}

				remainingLeaf := NewLeafNodeFromNibbles(nodeLeafNibbles, value)
				branch.SetBranch(nodeBranchNibble, remainingLeaf)

				// if there is no shared extension nibbles any more, then we don't need the extension node
				// any more
				// E 01020304
				// + 1234 good
				if len(extNibbles) == 0 {
					*node = branch
				} else {
					// otherwise create a new extension node
					*node = NewExtensionNode(extNibbles, branch)
				}
				return
			}

			nibbles = nibbles[matched:]
			node = &ext.next
			continue
		}

		panic("unknown type")
	}
}

/// LoadFromDB populates the Trie with data from db. It returns an error if db
/// does not contain the key "root".
///
/// # Panics
/// This method panics if called when t.mode != MODE_NORMAL
func (t *Trie) LoadFromDB(db DB) error {
	serializedRoot, err := db.Get([]byte("root"))
	if err != nil {
		return err
	}

	rootNode := Deserialize(serializedRoot, db)
	t.root = rootNode

	return nil
}

/// LoadPreState populates the Trie with data from pre_state.
///
/// # Panics
/// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
func (t *Trie) LoadPreState(pre_state PreState) {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	for _, kv_pair := range pre_state {
		key := kv_pair[0]
		value := kv_pair[1]

		t.Put(key, value)
	}
}

/// LoadPseudoPostState 'completes' an already populated Trie with PseudoNodes from pseudo_post_state.
///
/// # Panics
/// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
func (t *Trie) LoadPseudoPostState(pseudo_post_state PseudoPostState) {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}
	// TODO [Alice]
}

/// SaveToDB saves the Trie into db. At the end of this operation, the root of
/// the Trie is stored in key "root".
func (t *Trie) SaveToDB(db DB) {
	nodes := []Node{t.root}
	currentNode := (Node)(nil)

	for len(nodes) > 0 {
		currentNode = nodes[0]
		nodes = nodes[1:]

		if IsEmptyNode(currentNode) {
			continue
		}

		if leaf, ok := currentNode.(*LeafNode); ok {
			leafHash := leaf.Hash()
			db.Put(leafHash, leaf.Serialize())
			continue
		}

		if branch, ok := currentNode.(*BranchNode); ok {
			branchHash := branch.Hash()
			db.Put(branchHash, branch.Serialize())

			for i := 0; i < 16; i++ {
				if !IsEmptyNode(branch.branches[i]) {
					nodes = append(nodes, branch.branches[i])
				}
			}
		}

		if ext, ok := currentNode.(*ExtensionNode); ok {
			extHash := ext.Hash()
			db.Put(extHash, ext.Serialize())

			nodes = append(nodes, ext.next)
			continue
		}
	}

	rootHash := t.root.Hash()

	// TOD0 [Alice]: Ask Ahsan why these two lines (it /was/ two lines when
	// WriteBatch was still a thing) were originally swapped.
	//
	// TODO [Alice]: Ask Ahsan why we delete rootHash.
	db.Delete(rootHash)
	db.Put([]byte("root"), Serialize(t.root))
}

/// Hash returns the root hash of the Trie.
func (t *Trie) Hash() []byte {
	if IsEmptyNode(t.root) {
		return EmptyNodeHash
	}
	return t.root.Hash()
}

/// WasPreStateComplete returns whether PreState was complete during fraud proof transaction execution.
///
/// # Panics
/// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
func (t *Trie) WasPreStateComplete() bool {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}
	return true
}

////////////////////
// Private methods
////////////////////

func (t *Trie) getFromTrie(key []byte) []byte {
	node := t.root
	nibbles := NibblesFromBytes(key)
	for {
		if IsEmptyNode(node) {
			return nil
		}

		if leaf, ok := node.(*LeafNode); ok {
			matched := PrefixMatchedLen(leaf.path, nibbles)
			if matched != len(leaf.path) || matched != len(nibbles) {
				return nil
			}
			return leaf.value
		}

		if branch, ok := node.(*BranchNode); ok {
			if len(nibbles) == 0 {
				return branch.value
			}

			b, remaining := nibbles[0], nibbles[1:]
			nibbles = remaining
			node = branch.branches[b]
			continue
		}

		if ext, ok := node.(*ExtensionNode); ok {
			matched := PrefixMatchedLen(ext.path, nibbles)
			// E 01020304
			//   010203
			if matched < len(ext.path) {
				return nil
			}

			nibbles = nibbles[matched:]
			node = ext.next
			continue
		}

		panic("not found")
	}
}
