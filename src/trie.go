package mpt

import (
	"fmt"
	"reflect"
)

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
type PostState []struct {
	path []Nibble
	hash []byte
}

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

	node := &t.root
	remainingPath := newNibbles(key)
	for {
		if *node == nil {
			leaf := newLeafNode(remainingPath, value)
			*node = leaf
			return
		}

		switch n := (*node).(type) {
		case *LeafNode:
			leaf := n
			lenCommonPrefix := commonPrefixLength(remainingPath, leaf.path)

			// Case 1: leaf.path == remainingPath.
			//
			// Illust.:
			// ... -> Leaf {value}
			if lenCommonPrefix == len(remainingPath) && lenCommonPrefix == len(leaf.path) {
				newLeaf := newLeafNode(leaf.path, value)
				*node = newLeaf
				return
			}

			branch := newBranchNode()
			if lenCommonPrefix == len(remainingPath) {
				// Case 2: leaf.path is a superstring of remainingPath. In other words, leaf.path
				// contains excess nibbles beyond remainingPath.
				//
				// Illust.:
				// ... -> branch {value}
				//           ⤷ Leaf {(leaf.path - commonPrefix)[1:], leaf.value}
				branch.setValue(value)
				branchNibble, leafNibbles := leaf.path[lenCommonPrefix], leaf.path[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafNibbles, leaf.value)
				branch.setBranch(branchNibble, newLeaf)
			} else if lenCommonPrefix == len(leaf.path) {
				// Case 3: remainingPath is a superstring of leaf.path. In other words,
				// remainingPath contains excess nibbles beyond what leaf.path can 'satisfy'.
				//
				// Illust.:
				// ... -> branch {leaf.value}
				//          ⤷ Leaf {(remainingPath - commonPrefix)[1:], value}
				branch.setValue(leaf.value)
				branchNibble, leafNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafNibbles, value)
				branch.setBranch(branchNibble, newLeaf)
			}

			if lenCommonPrefix > 0 {
				// If a commonPrefix exists, we place it in an ExtensionNode which sits before branch.
				//
				// Illust.:
				// ... -> ExtensionNode {commonPrefix} -> branch
				ext := newExtensionNode(leaf.path[:lenCommonPrefix], branch)
				*node = ext
			} else {
				// If, on the other hand, commonPrefix does not exist, we attach branch directly onto the
				// Trie.
				//
				// Illust.:
				// ... -> branch
				*node = branch
			}

			if lenCommonPrefix < len(leaf.path) {
				branchNibble, leafNibbles := leaf.path[lenCommonPrefix], leaf.path[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafNibbles, leaf.value)
				branch.setBranch(branchNibble, newLeaf)
			}

			if lenCommonPrefix < len(remainingPath) {
				branchNibble, leafNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafNibbles, value)
				branch.setBranch(branchNibble, newLeaf)
			}
			return
		case *BranchNode:
			branchNode := n
			if len(remainingPath) == 0 {
				// Arriving at this BranchNode exhausts remainingPath. Set the value as the BranchNode's value.
				//
				// Illust.:
				// ... -> Branch {value}
				branchNode.setValue(value)
				return
			} else {
				// remainingPath is still not exhausted. Recurse into the branch corresponding to the first nibble
				// of the remainingPath.
				//
				// Illust.:
				// ... -> branchNode
				//           ⤷ recurse
				b, remaining := remainingPath[0], remainingPath[1:]
				remainingPath = remaining
				node = &branchNode.branches[b]
				continue
			}
		case *ExtensionNode:
			ext := n
			lenCommonPrefix := commonPrefixLength(ext.path, remainingPath)
			if len(ext.path) > lenCommonPrefix {
				// Case 1: ext.path is a superstring of remainingPath. In other words, ext.path contains excess
				// nibbles beyond remainingPath.
				commonPrefix, firstExcessNibble, extExcessPath := ext.path[:lenCommonPrefix], ext.path[lenCommonPrefix], ext.path[lenCommonPrefix+1:]
				nodeBranchNibble, nodeLeafNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				branch := newBranchNode()
				if len(extExcessPath) == 0 {
					// Case 1A: ext.path is a superstring of remainingPath with exactly one more excess nibble.
					//
					// Illust.:
					//          ... -> branch
					// firstExcessNibble ⤷ ext.next
					branch.setBranch(firstExcessNibble, ext.next)
				} else {
					// Case 1B: ext.path is a superstring of remainingPath with more than one excess nibble.
					//
					// Illust.:
					//           ... -> branch
					// firstExcessNibble ⤷ ExtensionNode{extExcessPath, ext.next}
					excessExt := newExtensionNode(extExcessPath, ext.next)
					branch.setBranch(firstExcessNibble, excessExt)
				}

				remainingLeaf := newLeafNode(nodeLeafNibbles, value)
				branch.setBranch(nodeBranchNibble, remainingLeaf)

				if lenCommonPrefix > 0 {
					// Regardless of whether Case 1A or Case 1B, if a commonPrefix exists, we place it in an
					// ExtensionNode which sits before branch.
					*node = newExtensionNode(commonPrefix, branch)
				} else {
					// If, on the other hand, commonPrefix does not exist, we attach branch directly onto the
					// the Trie.
					*node = branch
				}
				return
			} else {
				// Case 2: ext.path is a substring of remainingPath.
				remainingPath = remainingPath[lenCommonPrefix:]
				node = &ext.next
				continue
			}
		case *ProofNode:
			if t.mode != MODE_VERIFY_FRAUD_PROOF {
				panic("found a ProofNode in a Trie that is not in MODE_VERIFY_FRAUD_PROOF")
			}
			// TODO [Alice]
			// proofNode := n
		default:
			panic("trie contains a node that cannot be deserialized into either a BranchNode, ExtensionNode, LeafNode, or ProofNode")
		}
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
/// 1. panics if called when t.mode != MODE_NORMAL.
/// 2. panics if Trie does not contain hard-coded key "root".
func (t *Trie) LoadFromDB(db DB) error {
	if t.mode != MODE_NORMAL {
		panic("")
	}

	// DB does not contain the hard-coded key "root".
	serializedRoot, err := db.Get([]byte("root"))
	if err != nil {
		panic("")
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

		return nil
	}
}

// putProofNode places
func (t *Trie) putProofNode(completePath []Nibble, hash []byte) error {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	node := &t.root
	remainingPath := completePath
	for {
		if *node == nil {
			*node = newProofNode(remainingPath, hash)
			return nil
		}

		switch n := (*node).(type) {
		case *LeafNode:
			leaf := n
			lenCommonPrefix := commonPrefixLength(remainingPath, leaf.path)

			// Case 1: leaf.path == remainingPath. This case is unreachable if PreState is
			// valid (read: isPreStateValid). If this case is reached when putProofNode is used
			// as a subroutine of LoadPostState, then PostState is invalid.
			//
			// Illust.:
			// "... -> Leaf" cannot be changed to "... -> ProofNode"
			if lenCommonPrefix == len(remainingPath) && lenCommonPrefix == len(leaf.path) {
				return fmt.Errorf("proofNode overwrites existing LeafNode")
			}

			branch := newBranchNode()
			if lenCommonPrefix == len(remainingPath) {
				// Case 2: leaf.path is a superstring of remainingPath. In other words, leaf.path
				// contains excess nibbles beyond remainingPath.
				//
				// This case cannot be entered in LoadPreState and LoadPostState.
				// Informal argument: the node that was in this position in the complete PreState
				// trie was a BranchNode that is an ancestor of a KVPair included in PreState. This
				// BranchNode should not be included in PreState as a ProofNode, its direct children
				// and its value should.
				return fmt.Errorf("proofNode corresponds to a BranchNode that is an ancestor of a KVPair included in PreState")
			} else if lenCommonPrefix == len(leaf.path) {
				// Case 3: remainingPath is a superstring of leaf.path. In other words,
				// remainingPath contains excess nibbles beyond what leaf.path can 'satisfy'.
				//
				// Illust.:
				//                 ... -> branch {leaf.value}
				//      proofNodeExcessNibbles ⤷ ProofNode { proofNodeExcessNibbles, value }
				branch.setValue(leaf.value)
				firstProofNodeExcessNibble, proofNodeExcessPath := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				branch.setBranch(firstProofNodeExcessNibble, newProofNode(proofNodeExcessPath, hash))
			}

			if lenCommonPrefix > 0 {
				// If a commonPrefix exists, we place it in an ExtensionNode which sits before
				// branch.
				//
				// Illust.:
				// ... -> ExtensionNode {commonPrefix} -> the branch created in Case 3.
				*node = newExtensionNode(leaf.path[:lenCommonPrefix], branch)
			} else {
				// If, on the other hand, commonPrefix does not exist, we attach branch directly onto
				// the Trie.
				//
				// Ilust.:
				// ... -> the branch created in Case 3.
				*node = branch
			}

			if lenCommonPrefix < len(leaf.path) {
				branchNibble, leafNibbles := leaf.path[lenCommonPrefix], leaf.path[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafNibbles, leaf.value)
				branch.setBranch(branchNibble, newLeaf)
			}

			if lenCommonPrefix < len(remainingPath) {
				branchNibble, proofNodeNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodeNibbles, hash)
				branch.setBranch(branchNibble, proofNode)
			}
			return nil
		case *BranchNode:
			branchNode := n
			if len(remainingPath) == 0 {
				// Arriving at this BranchNode exhausts remainingPath. This case is unreachable if
				// PreState was created using GetPreStateAndPostState.
				return fmt.Errorf("proofNode overwrites existing BranchNode")
			} else {
				// remainingPath is still not exhausted. Recurse into the branch corresponding to
				// the first nibble of the remainingPath.
				// Illust.:
				// ... -> branchNode
				//           ⤷ recurse
				b, remaining := remainingPath[0], remainingPath[1:]
				remainingPath = remaining
				node = &branchNode.branches[b]
				continue
			}
		case *ExtensionNode:
			ext := n
			lenCommonPrefix := commonPrefixLength(ext.path, remainingPath)
			if len(ext.path) > lenCommonPrefix {
				// Case 1: ext.path is a superstring of remainingPath. In other words, ext.path
				// contains excess nibbles beyond remainingPath.
				commonPrefix, firstExcessNibble, extExcessPath := ext.path[:lenCommonPrefix], ext.path[lenCommonPrefix], ext.path[lenCommonPrefix+1:]
				firstProofNodeExcessNibble, proofNodeExcessPath := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				branch := newBranchNode()
				if len(extExcessPath) == 0 {
					// Case 1A: ext.path is a superstring of remainingPath with exactly one excess
					// nibble.
					//
					// Illust.:
					//          ... -> branch
					// firstExcessNibble ⤷ ext.next
					branch.setBranch(firstExcessNibble, ext.next)
				} else {
					// Case 1B: ext.path is a superstring of remainingPath with more than one excess
					// nibble.
					//
					// Illust.:
					//           ... -> branch
					// firstExcessNibble ⤷ ExtensionNode{extExcessPath, ext.next}
					excessExt := newExtensionNode(extExcessPath, ext.next)
					branch.setBranch(firstExcessNibble, excessExt)
				}

				proofNode := newProofNode(proofNodeExcessPath, hash)
				branch.setBranch(firstProofNodeExcessNibble, proofNode)

				if lenCommonPrefix > 0 {
					// Regardless of whether Case 1A or Case 1B, if a commonPrefix exists, we place it
					// in an ExtensionNode which sits before branch.
					*node = newExtensionNode(commonPrefix, branch)
				} else {
					// If, on the other hand, commonPrefix does not exist, we attach branch directly
					// onto the Trie.
					*node = branch
				}
				return nil
			} else {
				// Case 2: ext.path is a substring of remainingPath
				remainingPath = remainingPath[lenCommonPrefix:]
				node = &ext.next
				continue
			}
		case *ProofNode:
			proofNode := n
			lenCommonPrefix := commonPrefixLength(remainingPath, proofNode.path)

			// Case 1: proofNode.path == remainingPath. This case is unreachable if PreState
			// is valid (read: isPreStateValid). If this case is reached when putProofNode is
			// used as a subroutine of LoadPostState, then PostState is invalid (redundant
			// ProofNode).
			if lenCommonPrefix == len(remainingPath) && lenCommonPrefix == len(proofNode.path) {
				return fmt.Errorf("proofNode overwrites existing ProofNode")
			}

			branch := newBranchNode()
			if lenCommonPrefix == len(remainingPath) {
				// Case 2: proofNode.path is a superstring of remainingPath. In other words,
				// proofNode.path contains excess nibbles beyond remainingPath.
				//
				// This case cannot be entered in LoadPreState and LoadPostState.
				// Informal argument: remainingPath should not be fully consumed at this point.
				return fmt.Errorf("TODO [Alice] are you sure this should error?")
			} else if lenCommonPrefix == len(proofNode.path) {
				// Case 3: remainingPath is a superstring of leaf.path. In other words,
				// remainingPath contains excess nibbles beyond what leaf.path can 'satisfy'.
				return fmt.Errorf("TODO [Alice] are you sure this should error?")
			}

			if lenCommonPrefix > 0 {
				// TODO [Alice]
				*node = newExtensionNode(proofNode.path[:lenCommonPrefix], branch)
			} else {
				// TODO [Alice]
				*node = branch
			}

			if lenCommonPrefix < len(proofNode.path) {
				branchNibble, proofNodeNibbles := proofNode.path[lenCommonPrefix], proofNode.path[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodeNibbles, proofNode.hash())
				branch.setBranch(branchNibble, proofNode)
			}

			if lenCommonPrefix < len(remainingPath) {
				branchNibble, proofNodeNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodeNibbles, hash)
				branch.setBranch(branchNibble, proofNode)
			}
			return nil
		default:
			panic("trie contains a node that cannot be deserialized into either a BranchNode, ExtensionNode, LeafNode, or ProofNode")
		}
	}
}

func minimizePreState(preState PreState) PreState {
	// TODO [Alice]
	panic("")
}

func minimizePostState(postState PostState) PostState {
	// TODO [Alice]
	panic("")
}

// isPreStateValid returns whether preState meets two simple validity conditions:
// 1. Its elements are either KVPair, or ProofNode.
// 2. ProofNode elements appear before KVPair elements. LoadPreState ranges through preState
//    from front to rear, iteratively building up the mode == MODE_VERIFY_FRAUD_PROOF trie.
//    this second validity condition ensures that during this process, ProofNodes do not
//    overwrite already-inserted KVPairs.
//
// PreState pre-processed by minimizePreState are guaranteed to pass this isPreStateValid.
func isPreStateValid(preState PreState) bool {
	// TODO [Alice]
	panic("")
}
