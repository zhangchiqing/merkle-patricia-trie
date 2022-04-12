package mpt

import "reflect"

// Trie is an in-memory representation of a Merkle Patricia Trie using RLP-encoding.
// Trie supports loading data from, and saving data to, persistent storage using the
// `LoadFromDB` and `SaveToDB` methods.
//
// Trie exposes a state-machine-type API that simplifies implementation of Veritas'
// fraud proof functionality. This means that generally, its functions need to be
// called in careful orders (depending on what the calling code is trying to do).
//
// # Usage
//
// 1. Normal mode:
//    Op 1. NewTrie(mode: MODE_NORMAL)
//    Op 2. LoadFromDB()
//    Op 3. *Get()/Put()
//    Op 4. state_root = GetStateRoot()
//    Op 5. if state_root == expected_state_root
//            then SaveToDB()
//            else go to 'Generate fraud proof mode'
//
// 2. Generate fraud proof mode:
//    Op 1. NewTrie(mode: MODE_GENERATE_FRAUD_PROOF)
//    Op 2. LoadFromDB()
//    Op 3. *Get()/Put()
//    Op 4. pre_state, pseudo_post_state = GetPreAndPseudoPostState()
//
// 3. Execute fraud proof mode:
//    Op 1. NewTrie(mode: VERIFY_FRAUD_PROOF)
//    Op 2. LoadPreState(pre_state)
//    Op 3. *Get/Put()
//    Op 4. if WasPreStateComplete() then continue else exit
//    Op 5. LoadPseudoPostState(pseudo_post_state)
//    Op 6. state_root = GetStateRoot()
//    Op 7. if state_root == published_state_root
//          then do nothing
//          else disable the rollup
//
type Trie struct {
	root Node
	mode TrieMode

	// readSet, preStateProofNodes, and writeList are non-Nil only when mode == MODE_GENERATE_FRAUD_PROOF.
	readSet            []KVPair
	preStateProofNodes []ProofNode
	writeList          []KVPair
}

type TrieMode = uint

const (
	MODE_NORMAL               TrieMode = 0
	MODE_GENERATE_FRAUD_PROOF TrieMode = 1
	MODE_VERIFY_FRAUD_PROOF   TrieMode = 2
	MODE_FAILED_FRAUD_PROOF   TrieMode = 3
	MODE_DEAD                 TrieMode = 4
)

type KVPair struct {
	key   []byte
	value []byte
}

// PreState is an array of either: ProofNode, or KVPair.
type PreState []interface{}

// PostState is an array of ProofNodes.
type PostState []ProofNode

// NewTrie returns an empty Trie in the specified, immutable mode.
func NewTrie(mode TrieMode) *Trie {
	if mode != MODE_NORMAL && mode != MODE_GENERATE_FRAUD_PROOF && mode != MODE_VERIFY_FRAUD_PROOF {
		panic("attempted to create a new trie with an invalid mode.")
	}

	return &Trie{
		root: nil,
		mode: mode,
	}
}

// Get returns the value associated with key in the Trie, if it exists, and nil if does not.
func (t *Trie) Get(key []byte) []byte {
	if t.mode == MODE_DEAD {
		panic("attempted to use dead Trie. Read Trie documentation.")
	}

	switch true {
	case t.mode == MODE_NORMAL:
		return t.getNormally(key)
	case t.mode == MODE_GENERATE_FRAUD_PROOF:
		// 1. At this expected stage in the Trie lifecycle, writeList would not have been committed into
		// Trie, so first, try to get from writeList.
		getFrom := func(writeList []KVPair, key []byte) []byte {
			// Range through writeList from the rear to get the latest value.
			for i := len(t.writeList) - 1; i >= 0; i-- {
				kvPair := t.writeList[i]
				if reflect.DeepEqual(key, kvPair.key) {
					return kvPair.value
				}
			}

			return nil
		}
		value := getFrom(t.writeList, key)
		if value != nil {
			return value
		}

		// 2. The key has not been updated in the writeList, so, try to get it from the Trie.
		value = t.getNormally(key)
		inReadSet := func(readSet []KVPair, key []byte) bool {
			for _, kvPair := range readSet {
				if reflect.DeepEqual(key, kvPair.key) {
					return true
				}
			}
			return false
		}
		// There's no need to add KVPair to readSet if it is already in there.
		if !inReadSet(t.readSet, key) {
			t.readSet = append(t.readSet, KVPair{key, value})
		}

		return value
	case t.mode == MODE_VERIFY_FRAUD_PROOF:
		// TODO [Alice]: differentiate between incomplete PreState and actually non-existent KV pair.
		return t.getNormally(key)
	default:
		panic("unreachable code")
	}
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
	nibbles := newNibbles(key)
	for {
		if *node == nil {
			leaf := newLeafNode(nibbles, value)
			*node = leaf
			return
		}

		if leaf, ok := (*node).(*LeafNode); ok {
			matched := commonPrefixLength(leaf.path, nibbles)

			// if all matched, update value even if the value are equal
			if matched == len(nibbles) && matched == len(leaf.path) {
				newLeaf := newLeafNode(leaf.path, value)
				*node = newLeaf
				return
			}

			branch := newBranchNode()
			// if matched some nibbles, check if matches either all remaining nibbles
			// or all leaf nibbles
			if matched == len(leaf.path) {
				branch.setValue(leaf.value)
			}

			if matched == len(nibbles) {
				branch.setValue(value)
			}

			// if there is matched nibbles, an extension node will be created
			if matched > 0 {
				// create an extension node for the shared nibbles
				ext := newExtensionNode(leaf.path[:matched], branch)
				*node = ext
			} else {
				// when there no matched nibble, there is no need to keep the extension node
				*node = branch
			}

			if matched < len(leaf.path) {
				branchNibble, leafNibbles := leaf.path[matched], leaf.path[matched+1:]
				newLeaf := newLeafNode(leafNibbles, leaf.value) // not :matched+1
				branch.setBranch(branchNibble, newLeaf)
			}

			if matched < len(nibbles) {
				branchNibble, leafNibbles := nibbles[matched], nibbles[matched+1:]
				newLeaf := newLeafNode(leafNibbles, value)
				branch.setBranch(branchNibble, newLeaf)
			}

			return
		}

		if branch, ok := (*node).(*BranchNode); ok {
			if len(nibbles) == 0 {
				branch.setValue(value)
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
			matched := commonPrefixLength(ext.path, nibbles)
			if matched < len(ext.path) {
				// E 01020304
				// + 010203 good
				extNibbles, branchNibble, extRemainingnibbles := ext.path[:matched], ext.path[matched], ext.path[matched+1:]
				nodeBranchNibble, nodeLeafNibbles := nibbles[matched], nibbles[matched+1:]
				branch := newBranchNode()
				if len(extRemainingnibbles) == 0 {
					// E 0102030
					// + 010203 good
					branch.setBranch(branchNibble, ext.next)
				} else {
					// E 01020304
					// + 010203 good
					newExt := newExtensionNode(extRemainingnibbles, ext.next)
					branch.setBranch(branchNibble, newExt)
				}

				remainingLeaf := newLeafNode(nodeLeafNibbles, value)
				branch.setBranch(nodeBranchNibble, remainingLeaf)

				// if there is no shared extension nibbles any more, then we don't need the extension node
				// any more
				// E 01020304
				// + 1234 good
				if len(extNibbles) == 0 {
					*node = branch
				} else {
					// otherwise create a new extension node
					*node = newExtensionNode(extNibbles, branch)
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

/// RootHash returns the root hash of the Trie.
func (t *Trie) RootHash() []byte {
	if t.root == nil {
		return nilNodeHash
	}

	return t.root.hash()
}

// GetPreAndPseudoPostState returns PreState: the list of key-value pairs that have to be loaded into
// a Trie (using `LoadPreState`) to serve reads into world state during fraud proof execution, and
// PseudoPostState: the list of PseudoNodes that have to be loaded into a Trie (using `LoadPostState`)
// to calculate its post state root after fraud proof execution.
//
// After calling this method, the Trie becomes dead.
//
// # Panics
// This method panics if called when t.mode != MODE_GENERATE_FRAUD_PROOF.
func (t *Trie) GetPreAndPseudoPostState() (PreState, PostState) {
	if t.mode != MODE_GENERATE_FRAUD_PROOF {
		panic("attempted to GetPreAndPseudoPostState, but Trie is not in generate fraud proof mode.")
	}

	preState := make(PreState, 0)
	for _, kvPair := range t.readSet {
		preState = append(preState, interface{}(kvPair))
	}

	// TODO [Alice]
	post_state := make(PostState, 0)

	t.mode = MODE_DEAD

	return preState, post_state
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

	rootNode, err := NodeFromSerialBytes(serializedRoot, db)
	if err != nil {
		return err
	}

	t.root = rootNode

	return nil
}

/// LoadPreState populates the Trie with data from pre_state.
///
/// # Panics
/// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
func (t *Trie) LoadPreState(preState PreState) {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	for _, kvPairOrProofNode := range preState {
		switch v := kvPairOrProofNode.(type) {
		case ProofNode:
			// TODO [Alice]
			panic("")
		case KVPair:
			t.Put(v.key, v.value)
		default:
			panic("unreachable code")
		}
	}
}

/// LoadPseudoPostState 'completes' an already populated Trie with PseudoNodes from pseudo_post_state.
///
/// # Panics
/// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
func (t *Trie) LoadPseudoPostState(pseudo_post_state PostState) {
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

		if currentNode == nil {
			continue
		}

		if leaf, ok := currentNode.(*LeafNode); ok {
			leafHash := leaf.hash()
			db.Put(leafHash, leaf.serialized())
			continue
		}

		if branch, ok := currentNode.(*BranchNode); ok {
			branchHash := branch.hash()
			db.Put(branchHash, branch.serialized())

			for i := 0; i < 16; i++ {
				if branch.branches[i] != nil {
					nodes = append(nodes, branch.branches[i])
				}
			}
		}

		if ext, ok := currentNode.(*ExtensionNode); ok {
			extHash := ext.hash()
			db.Put(extHash, ext.serialized())

			nodes = append(nodes, ext.next)
			continue
		}
	}

	rootHash := t.root.hash()

	db.Delete(rootHash)
	db.Put([]byte("root"), serializeNode(t.root))
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

func (t *Trie) getNormally(key []byte) []byte {
	node := t.root
	nibbles := newNibbles(key)
	for {
		if node == nil {
			return nil
		}

		if leaf, ok := node.(*LeafNode); ok {
			matched := commonPrefixLength(leaf.path, nibbles)
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
			matched := commonPrefixLength(ext.path, nibbles)
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
