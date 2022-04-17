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
// 3. Verify fraud proof mode:
//    Op 1. NewTrie(mode: VERIFY_FRAUD_PROOF)
//    Op 2. preState, postState = DeserializePreState(serializedPreState),
//                                                       DeserializePostState(serializedPostState)
//    Op 3. LoadPreStateAndPostState(preState, postState)
//    Op 4. stateRoot = GetStateRoot()
//    Op 5. if stateRoot != published StateRoot before fraudulent transaction.
//          then break (fraud proof unsuccessful)
//          else continue
//    Op 4. *Get/Put()
//    Op 5. if WasPostStateProofsValid() && WasPreStateComplete()
//          then break (fraud proof unsuccessful)
//          else continue
//    Op 6. stateRoot = GetStateRoot()
//    Op 7. if stateRoot == published StateRoot after fraudulent transaction.
//          then break (fraud proof unsuccessful)
//          else disable the rollup
//
// *OP indicates that multiple operations of OP-sort may happen.
type Trie struct {
	root Node
	mode TrieMode

	// readSet, postStateProofs, and writeList are non-Nil only when mode == MODE_GENERATE_FRAUD_PROOF.
	readSet         []KVPair
	writeList       []KVPair
	postStateProofs PostStateProofs
}

type TrieMode = uint

const (
	MODE_NORMAL               TrieMode = 0
	MODE_GENERATE_FRAUD_PROOF TrieMode = 1
	MODE_VERIFY_FRAUD_PROOF   TrieMode = 2
	MODE_FAILED_FRAUD_PROOF   TrieMode = 3
	MODE_DEAD                 TrieMode = 4
)

// KVPair stands for "Key, Value Pair". KVPairs are inserted into Trie using Put.
type KVPair struct {
	key   []byte
	value []byte
}

// PHPair stands for "Path, Hash Pair". PHPairs are inserted into Trie using putProofNode.
type PHPair struct {
	path []Nibble
	hash []byte
}

type PreState struct {
	kvPairs []KVPair
	phPairs []PHPair
}

func newPreState() PreState {
	return PreState{
		kvPairs: make([]KVPair, 0),
		phPairs: make([]PHPair, 0),
	}
}

// PostStateProof 'proves' a single mutation (Set) during fraud proof execution.
type PostStateProof struct {
	phPairs      []PHPair
	proofKVPairs []KVPair
}

// PostStateProofs is a slice of PostStateProof. Its length must be exactly the number of mutations
// done by the fraudulent transaction.
type PostStateProofs []PostStateProof

func newPostStateProofs() PostStateProofs {
	return make([]PostStateProof, 0)
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

	// Update writeList.
	if t.mode == MODE_GENERATE_FRAUD_PROOF || t.mode == MODE_VERIFY_FRAUD_PROOF {
		t.writeList = append(t.writeList, KVPair{key, value})
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

// GetPreStateAndPostStateProofs returns PreState: the list of KVPairs and PHPairs that have to be loaded into
// a Trie (using `tryLoadPreState`) to serve reads into world state during fraud proof execution, and
// postStateProofs: the list of PostStateProofs that have to be loaded into a Trie (using `tryLoadPostStateProofs`)
// to calculate its post state root after fraud proof execution.
//
// After calling this method, the Trie becomes dead.
//
// # Panics
// Panics if called when t.mode != MODE_GENERATE_FRAUD_PROOF.
func (t *Trie) GetPreStateAndPostStateProofs() (PreState, PostStateProofs) {
	if t.mode != MODE_GENERATE_FRAUD_PROOF {
		panic("attempted to GetPreAndPseudoPostState, but Trie is not in generate fraud proof mode.")
	}

	/////////////////////////
	// 1. Generate PreState
	/////////////////////////
	preState := newPreState()
	shadowTrie := NewTrie(MODE_VERIFY_FRAUD_PROOF)
	for _, kvPair := range t.readSet {
		// 1.1. Use shadowTrie to get the path to the root of the 'Stray Trie', the subtrie of (t *Trie)
		// whose nodes have paths that are superstrings of kvPair.key && are not 'Trusted Nodes' yet.
		strayTrieRootPath := getStrayTrieRootPath(kvPair.key, shadowTrie)

		// 1.2. Update shadowTrie with the kvPair.
		shadowTrie.Put(kvPair.key, kvPair.value)

		// 1.3. Collect 'Proof Pairs', phPairs and kvPairs in the strayTrie that are either siblings of
		// the node that contains kvPair, or a direct child of its ancestors.
		phPairs, proofKVPairs := getProofPairs(kvPair.key, strayTrieRootPath, shadowTrie)

		// 1.4. Add Proof Pairs to preState.
		preState.kvPairs = append(preState.kvPairs, kvPair)
		preState.kvPairs = append(preState.kvPairs, proofKVPairs...)
		preState.phPairs = append(preState.phPairs, phPairs...)

		// 1.5. Update shadowTrie with phPairs and proofKVPairs.
		for _, phPair := range phPairs {
			shadowTrie.putProofNode(phPair.path, phPair.hash)
		}
		for _, proofKVPair := range proofKVPairs {
			shadowTrie.Put(proofKVPair.key, proofKVPair.value)
		}
	}

	///////////////////////////////
	// 2. Generate PostStateProof
	///////////////////////////////
	postStateProofs := newPostStateProofs()
	for _, kvPair := range t.writeList {
		// 2.1. Use shadowTrie to get the path to the root of the Stray Trie
		strayTrieRootPath := getStrayTrieRootPath(kvPair.key, shadowTrie)

		// 2.2. Update shadowTrie with the kvPair
		shadowTrie.Put(kvPair.key, kvPair.value)

		// 2.3. Collect Proof Pairs.
		phPairs, proofKVPairs := getProofPairs(kvPair.key, strayTrieRootPath, shadowTrie)

		// 2.4. Add Proof Pairs to postStateProofs
		postStateProofs = append(postStateProofs, PostStateProof{phPairs, proofKVPairs})

		// Update shadowTrie with phPairs and proofKVPairs
		for _, phPair := range phPairs {
			shadowTrie.putProofNode(phPair.path, phPair.hash)
		}
		for _, proofKVPair := range proofKVPairs {
			shadowTrie.Put(proofKVPair.key, proofKVPair.value)
		}
	}

	// Disable trie
	t.mode = MODE_DEAD

	return preState, postStateProofs
}

/// LoadPreAndPostState prepares a Trie to be used in MODE_VERIFY_FRAUD_PROOF.
///
/// # Panics
///Panics if called when t.mode != MODE_VERIFY_FRAUD_PROOF.
func (t *Trie) LoadPreAndPostState(preState PreState, postState PostStateProofs) {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	for _, phPair := range preState.phPairs {
		t.putProofNode(phPair.path, phPair.hash)
	}

	for _, kvPair := range preState.kvPairs {
		t.Put(kvPair.key, kvPair.value)
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
func (t *Trie) putProofNode(path []Nibble, hash []byte) error {
	if t.mode != MODE_VERIFY_FRAUD_PROOF {
		panic("")
	}

	node := &t.root
	remainingPath := path
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

func (t *Trie) tryLoadPreState(preState PreState) error {
	panic("")
}

func (t *Trie) tryLoadPostStateProof(postStateProof PostStateProof) error {
	panic("")
}

// getStrayTrieRootPath returns newNibbles(key) if there is no stray Trie.
func getStrayTrieRootPath(key []byte, shadowTrie *Trie) []Nibble {
	targetPath := newNibbles(key)
	accumulatedPath := make([]Nibble, 0)
	node := &shadowTrie.root
	for {
		// Base case 1: There isn't a stray Trie. Key can be inserted without PostStateProof.
		if commonPrefixLength(accumulatedPath, targetPath) >= len(targetPath) {
			return targetPath
		}

		switch n := (*node).(type) {
		case *LeafNode:
			// Base case 2: There isn't a stray Trie. Key can be inserted without PostStateProof.
			return targetPath
		case *ProofNode:
			// Base case 3: There is a stray Trie.
			return accumulatedPath
		case *ExtensionNode:
			extension := n
			accumulatedPath = append(accumulatedPath, extension.path...)
			node = &extension.next
			continue
		case *BranchNode:
			branch := n
			nextNibble := targetPath[commonPrefixLength(accumulatedPath, targetPath)]
			// Base case 4: There isn't a stray Trie.
			if branch.branches[nextNibble] == nil {
				return targetPath
			} else {
				accumulatedPath = append(accumulatedPath, nextNibble)
				node = &branch.branches[nextNibble]
			}
			continue
		default:
			panic("unreachable code")
		}
	}
}

// getProofPairs returns the PHPairs corresponding to all nodes in trie that is a sibling of of the node identified by
// key, or a direct child of any of its ancestors, *except* those that hash to an entry in trustedNodes. Nodes that
// serialize to less than 32 bytes are included as a KVPair in the second return value instead.
//
// An intuitive way to think about getProofPairs is that it uses key and strayTrieRootPaths as 'upper and lower bounds'
// to form a subtrie from trie.
//
// This routine makes the optimizing assumption that if a node is a trustedNode, all of its ancestors are also
// trustedNodes and can be ignored.
func getProofPairs(key []byte, strayTrieRootPath []Nibble, trie *Trie) ([]PHPair, []KVPair) {
	targetPath := newNibbles(key)
	accumulatedPath := make([]Nibble, 0)
	visitedNodes := make([]*Node, 0)

	// 1. Navigate to the node that stores key
	node := &trie.root
	for {
		if reflect.DeepEqual(accumulatedPath, targetPath) {
			break
		}
		switch n := (*node).(type) {
		case *ProofNode:
			// SAFETY: trie should not contain any ProofNodes.
			panic("unreachable code")
		case *LeafNode:
			leaf := n
			accumulatedPath = append(accumulatedPath, leaf.path...)
			if !reflect.DeepEqual(accumulatedPath, targetPath) {
				// SAFETY: unreachable if key is already put in trie beforehand.
				panic("unreachable code")
			}
		case *BranchNode:
			branch := n
			nextNibble := targetPath[commonPrefixLength(accumulatedPath, targetPath)]
			if reflect.DeepEqual(accumulatedPath, targetPath) && branch.value == nil {
				// SAFETY: unreachable if key is already put in trie beforehand.
				panic("unreachable code")
			}
			if branch.branches[nextNibble] == nil {
				// SAFETY: unreachable if key is already put in trie beforehand.
				panic("unreachable code")
			}
			accumulatedPath = append(accumulatedPath, nextNibble)
			node = &branch.branches[nextNibble]
		case *ExtensionNode:
			extension := n
			accumulatedPath = append(accumulatedPath, extension.path...)
			node = &extension.next
		default:
			panic("trie contains a node that cannot be deserialized to either a LeafNode, ProofNode, BranchNode, or ExtensionNode")
		}
		visitedNodes = append(visitedNodes, node)
		continue
	}

	phPairs := make([]PHPair, 0)
	kvPairs := make([]KVPair, 0)

	// 2. Backtrack to the node identified by strayTrieRootPath, collecting PHPairs and KVPairs along the way.
	if len(visitedNodes) == 0 {
		// SAFETY: getProofPairs is only entered after the Trie has been Put once.
		panic("unreachable code")
	}
	// Pop the Put LeafNode
	visitedNodes, previouslyVisitedNode := visitedNodes[:len(visitedNodes)-1], visitedNodes[len(visitedNodes)-1]
	decumulatedPath := accumulatedPath
	node = visitedNodes[len(visitedNodes)-1]
	for {
		if commonPrefixLength(decumulatedPath, strayTrieRootPath) == 0 {
			break
		}
		switch n := (*node).(type) {
		case *BranchNode:
			branch := n
			branchIndexOfPreviouslyVisitedNode := -1
			for i, n := range branch.branches {
				if n == *previouslyVisitedNode {
					branchIndexOfPreviouslyVisitedNode = i
					break
				}
			}
			if branchIndexOfPreviouslyVisitedNode == -1 {
				panic("unreachable code")
			}
			proofPairs := collectProofPairs(decumulatedPath, branch, branchIndexOfPreviouslyVisitedNode)
			for _, proofPair := range proofPairs {
				switch p := proofPair.(type) {
				case KVPair:
					kvPair := p
					kvPairs = append(kvPairs, kvPair)
				case PHPair:
					phPair := p
					phPairs = append(phPairs, phPair)
				default:
					panic("unreachable code")
				}
			}
			decumulatedPath = decumulatedPath[:len(decumulatedPath)-1]
		case *ExtensionNode:
			extension := n
			decumulatedPath = decumulatedPath[:len(decumulatedPath)-(1+len(extension.path))]
		default:
			// visitedNodes cannot have contained LeafNodes and ProofNodes.
			panic("unreachable code")
		}

		visitedNodes, previouslyVisitedNode = visitedNodes[:len(visitedNodes)-1], visitedNodes[len(visitedNodes)-1]
		node = visitedNodes[len(visitedNodes)-1]
		continue
	}

	return phPairs, kvPairs
}

// collectProofPair returns a slice of either KVPairs, or PHPairs. Path is the path from the root of the origin Trie
// to branchNode.
func collectProofPairs(path []Nibble, branchNode *BranchNode, ignoreBranch int) []interface{} {
	if len(path)%2 != 0 {
		// TODO [Alice]: write a SAFETY comment.
		panic("unreachable code")
	}
	proofPairs := make([]interface{}, 0)

	if branchNode.value != nil {
		proofPairs = append(proofPairs, interface{}(KVPair{key: nibblesAsBytes(path), value: branchNode.value}))
	}

	for branchIndex, node := range branchNode.branches {
		if branchIndex == ignoreBranch {
			continue
		}

		if node == nil {
			continue
		} else {
			branchNibble, err := bytesAsNibbles(byte(branchIndex))
			if err != nil {
				// TODO [Alice]: write a SAFETY comment.
				panic("unreachable code")
			}

			pathToBranch := append(path, branchNibble...)
			switch n := node.(type) {
			case *ProofNode:
				// SAFETY: trie should not contain any ProofNodes.
				panic("unreachable code")
			case *LeafNode:
				leaf := n
				pathToLeaf := append(pathToBranch, leaf.path...)

				// TODO [Alice]: write a SAFETY comment.
				if len(pathToLeaf)%2 != 0 || leaf.value == nil {
					panic("unreachable code")
				}

				if len(leaf.serialized()) < 32 {
					// If serialized leaf is smaller than size of Keccak256 hash, include it directly in proofPairs
					// as a KVPair
					leafKey := nibblesAsBytes(pathToLeaf)
					proofPairs = append(proofPairs, KVPair{
						key:   leafKey,
						value: leaf.value,
					})
				} else {
					proofPairs = append(proofPairs, PHPair{
						path: pathToLeaf,
						hash: leaf.hash(),
					})
				}
				continue
			case *ExtensionNode:
				extension := n
				pathToExtension := append(pathToBranch, extension.path...)
				proofPairs = append(proofPairs, PHPair{
					path: pathToExtension,
					hash: extension.hash(),
				})
				continue
			case *BranchNode:
				branch := n
				proofPairs = append(proofPairs, PHPair{
					path: pathToBranch,
					hash: branch.hash(),
				})
			default:
				panic("trie contains a node that cannot be deserialized to either a LeafNode, ProofNode, BranchNode, or ExtensionNode")

			}
		}
	}

	return proofPairs
}
