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
//    Op 4. stateRoot = GetStateRoot()
//    Op 5. if stateRoot == publishedStateRoot
//            then SaveToDB()
//            else go to 'Generate fraud proof mode'
//
// 2. Generate fraud proof mode:
//    Op 1. NewTrie(mode: MODE_GENERATE_FRAUD_PROOF)
//    Op 2. LoadFromDB()
//    Op 3. *Get()/Put()
//    Op 4. preState, postState = GetPreAndPostState()
//    Op 5. serializedPreState, serializedPostState = preState.Serialize(), postState.Serialize()
//
// 3. Execute fraud proof mode:
//    Op 1. NewTrie(mode: VERIFY_FRAUD_PROOF)
//    Op 2. preState, postState = DeserializePreState(serializedPreState),
//                                                       DeserializePostState(serializedPostState)
//    Op 3. LoadPreStateAndPostState(preState, postState)
//    Op 4. *Get/Put()
//    Op 5. if WasPreStateComplete() then continue else exit
//    Op 6. stateRoot = GetStateRoot()
//    Op 7. if stateRoot == publishedStateRoot
//          then do nothing
//          else disable the rollup
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

// NewTrie returns an empty Trie in the specified mode. A Trie, once constructed, cannot have its
// mode explicitly changed.
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
			if len(remainingPath) == lenCommonPrefix {
				// Case 2: leaf.path is a superstring of remainingPath.
				//
				// Illust.:
				// ... -> branch {value}
				branch.setValue(value)
			} else if len(leaf.path) == lenCommonPrefix {
				// Case 3: remainingPath is a superstring of leaf.path.
				//
				// Illust.:
				// ... -> branch {leaf.value}
				branch.setValue(leaf.value)
			}
			// ↓ This commented out conditional branch is deliberately left here for exhaustiveness and clarity. ↓
			// else {
			// 	   Case 4: leaf.path is not a superstring of remainingPath, nor vice versa.
			//
			// 	   In this case, there is no need to set a value on branch; both values will sit on new leaves.
			// }

			if len(leaf.path) > lenCommonPrefix {
				// If leaf.path is longer than commonPrefix, then we create a new leaf to hold leaf.value.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ Leaf {leaf.value}
				firstLeafNibble, leafPath := leaf.path[lenCommonPrefix], leaf.path[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafPath, leaf.value)
				branch.setBranch(firstLeafNibble, newLeaf)
			}

			if len(remainingPath) > lenCommonPrefix {
				// If remainingPath is longer than commonPrefix, then we create a new leaf to hold value.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ Leaf {leaf.value}
				firstLeafNibble, leafPath := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafPath, value)
				branch.setBranch(firstLeafNibble, newLeaf)
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

			proofNode := n
			lenCommonPrefix := commonPrefixLength(remainingPath, proofNode.path)

			// The cases here largely correspond to the cases in the '*LeafNode' arm, so comments are omitted for
			// brevity.

			// TODO [Alice]: this case can be further constrained to shrink PreState.
			if len(remainingPath) == lenCommonPrefix && len(proofNode.path) == len(remainingPath) {
				newLeaf := newLeafNode(proofNode.path, value)
				*node = newLeaf
				return
			}

			branch := newBranchNode()
			if len(remainingPath) == lenCommonPrefix {
				branch.setValue(value)
			} else if len(proofNode.path) == lenCommonPrefix {
				// SAFETY: this case is precluded by the illegal cases in putProofNode.
				panic("unreachable code")
			}

			if len(proofNode.path) > lenCommonPrefix {
				firstProofNodeNibble, proofNodePath := proofNode.path[lenCommonPrefix], proofNode.path[lenCommonPrefix+1:]
				newProofNode := newProofNode(proofNodePath, proofNode.hash())
				branch.setBranch(firstProofNodeNibble, newProofNode)
			}

			if len(remainingPath) > lenCommonPrefix {
				firstLeafNibble, leafPath := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafPath, value)
				branch.setBranch(firstLeafNibble, newLeaf)
			}

			if lenCommonPrefix > 0 {
				ext := newExtensionNode(proofNode.path[:lenCommonPrefix], branch)
				*node = ext
			} else {
				*node = branch
			}

			return
		default:
			panic("trie contains a node that cannot be deserialized into either a BranchNode, ExtensionNode, LeafNode, or ProofNode")
		}
	}
}

// RootHash returns the root hash of the Trie.
func (t *Trie) RootHash() []byte {
	if t.root == nil {
		return nilNodeHash
	}

	return t.root.hash()
}

// GetPreAndPostState returns PreState: the list of key-value pairs that have to be loaded into
// a Trie (using `LoadPreState`) to serve reads into world state during fraud proof execution, and
// PseudoPostState: the list of PseudoNodes that have to be loaded into a Trie (using `LoadPostState`)
// to calculate its post state root after fraud proof execution.
//
// After calling this method, the Trie becomes dead.
//
// # Panics
// Panics if called when t.mode != MODE_GENERATE_FRAUD_PROOF.
func (t *Trie) GetPreAndPostState() (PreState, PostState) {
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

/// LoadPreAndPostState prepares a Trie to be used in MODE_VERIFY_FRAUD_PROOF.
///
/// # Panics
///Panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF.
func (t *Trie) LoadPreAndPostState(preState PreState, postState PostState) {
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

// LoadFromDB populates the Trie with data from db. It returns an error if db
// does not contain the key "root".
//
// # Panics
// 1. panics if called when t.mode != MODE_NORMAL.
// 2. panics if DB does not contain hard-coded key "root".
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

// SaveToDB saves the Trie into db. At the end of this operation, the root of
// the Trie is stored in key "root".
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

// WasPreStateComplete returns whether PreState was complete during fraud proof transaction execution.
//
// # Panics
// This method panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF
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

// putProofNode places hash into the Trie at completePath as a ProofNode.
//
// # Errors
// putProofNode returns an error if adding (completePath, hash) to the Trie is an 'Illegal' operation. Illegal
// operations can be defined by construction: a Verifier that calls the GetPreAndPostState method defined in this
// library should never receive a PreState or a PostState that contains an illegal operation. The comments in
// this function describes all possible illegal operations.
//
// TODO [Alice]: come up with a more insightful definition of Illegal operation.
//
// # Panics
// 1. Panics if mode != MODE_VERIFY_FRAUD_PROOF
// 2. Panics if the Trie contains a node that cannot be deserialized into either a LeafNode, BranchNode, ExtensionNode,
//    or ProofNode.
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

			if lenCommonPrefix == len(remainingPath) && lenCommonPrefix == len(leaf.path) {
				// Illegal case L1:
				// ProofNode overwrites existing LeafNode.
				return fmt.Errorf("illegal case L1: read the source of putProofNode")
			}

			branch := newBranchNode()
			if len(remainingPath) == lenCommonPrefix {
				// Illegal case L2:
				// This conditional block is entered when the value of a BranchNode needs to
				// be proven. Because this library does not define a `ProofBranchNode`, values
				// of branch nodes that need to be proven must be included whole in PreState.
				//
				// This is a limitation of this library that ought to be rectified in future
				// releases (TODO [Alice]).
				return fmt.Errorf("illegal case L2: read the source of putProofNode")
			} else if len(leaf.path) == lenCommonPrefix {
				// Legal case 1:
				// remainingPath is a superstring of leaf.path.
				//
				// Illust.:
				//                 ... -> branch {leaf.value}
				branch.setValue(leaf.value)
			}
			// ↓ This commented out conditional branch is deliberately left here for exhaustiveness and clarity. ↓
			// else {
			// 	   Legal case 2: leaf.path is not a superstring of remainingPath, nor vice versa.
			//
			// 	   In this case, there is no need to set a value on branch; leaf.value will sit on a new leaf.
			// }

			if len(leaf.path) > lenCommonPrefix {
				// If leaf.path is longer than commonPrefix, then we create a new leaf to hold leaf.value.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ Leaf {leaf.value}
				branchNibble, leafPath := leaf.path[lenCommonPrefix], leaf.path[lenCommonPrefix+1:]
				newLeaf := newLeafNode(leafPath, leaf.value)
				branch.setBranch(branchNibble, newLeaf)
			}

			if len(remainingPath) > lenCommonPrefix {
				// If remainingPath is longer than commonPrefix, then we create a new proof node. This conditional
				// block must be entered.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ ProofNode {leaf.value}
				branchNibble, proofNodePath := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodePath, hash)
				branch.setBranch(branchNibble, proofNode)
			} else {
				// Illegal case L3: len(remainingPath) < lenCommonPrefix
				// No ProofNode is created by putProofNode.
				return fmt.Errorf("illegal case L3: read the source of putProofNode")
			}

			if lenCommonPrefix > 0 {
				// If a commonPrefix exists, we place it in an ExtensionNode which sits before
				// branch.
				//
				// Illust.:
				// ... -> ExtensionNode {commonPrefix} -> branch
				*node = newExtensionNode(leaf.path[:lenCommonPrefix], branch)
			} else {
				// If, on the other hand, commonPrefix does not exist, we attach branch directly onto
				// the Trie.
				//
				// Ilust.:
				// ... -> branch
				*node = branch
			}

			return nil
		case *BranchNode:
			branchNode := n
			if len(remainingPath) == 0 {
				// Illegal case B1:
				// ProofNode overwrites existing BranchNode.
				return fmt.Errorf("illegal case B1: read the source of putProofNode")
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

			// Illegal case P1:
			// ProofNode overwrites existing ProofNode.
			if lenCommonPrefix == len(remainingPath) && lenCommonPrefix == len(proofNode.path) {
				return fmt.Errorf("illegal case P1: read the source of putProofNode")
			}

			branch := newBranchNode()
			if lenCommonPrefix == len(remainingPath) {
				// Illegal case P2:
				// Read "Illegal case L2".
				return fmt.Errorf("illegal case P2: read the source of putProofNode")
			} else if lenCommonPrefix == len(proofNode.path) {
				// Illegal case P3:
				// Read "Illegal case L2".
				return fmt.Errorf("illegal case P3: read the source of putProofNode")
			}

			if len(proofNode.path) > lenCommonPrefix {
				// If leaf.path is longer than commonPrefix, then we create a new leaf to hold leaf.value.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ Leaf {leaf.value}
				branchNibble, proofNodeNibbles := proofNode.path[lenCommonPrefix], proofNode.path[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodeNibbles, proofNode.hash())
				branch.setBranch(branchNibble, proofNode)
			}

			if len(remainingPath) > lenCommonPrefix {
				// If remainingPath is longer than commonPrefix, then we create a new proof node. This conditional
				// block must be entered.
				//
				// Illust.:
				// ... -> branch
				//           ⤷ ProofNode {leaf.value}
				branchNibble, proofNodeNibbles := remainingPath[lenCommonPrefix], remainingPath[lenCommonPrefix+1:]
				proofNode := newProofNode(proofNodeNibbles, hash)
				branch.setBranch(branchNibble, proofNode)
			}

			if lenCommonPrefix > 0 {
				// If a commonPrefix exists, we place it in an ExtensionNode which sits before
				// branch.
				//
				// Illust.:
				// ... -> ExtensionNode {commonPrefix} -> branch
				*node = newExtensionNode(proofNode.path[:lenCommonPrefix], branch)
			} else {
				// If, on the other hand, commonPrefix does not exist, we attach branch directly onto
				// the Trie.
				//
				// Ilust.:
				// ... -> branch
				*node = branch
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
