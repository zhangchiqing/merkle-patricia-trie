package mpt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The fraud_proof_test test suite demonstrates how verifier nodes can make fraud proof challenges without
// having to upload the entire PreState, which can be data intensive.
//
// Instead, verifier nodes upload in-whole only the key-value pairs read during a fraudulent
// transaction, plus enough hashes (`ProofNode`s) of not-read subtries to reproduce the PreState hash.
// Collision resistance of the Keccak256 hash function guarantees that a PPT verifier cannot forge a
// PreState with a *conflicting* set of key-value pairs that hashes to the same roothash.

// TestPutProofNode tests Trie's putProofNode method.
func TestPutProofNode(t *testing.T) {

	// 1_LeafNode creates a trie, `trie1`, with one key-value pair: (0, "cutealice").
	//
	// It then creates another trie, `trie2`, which replaces that key-value pair with the hash of
	// LeafNode. Both tries have the same root hash, even though `trie2`does not contain the key-
	// value pair.
	t.Run("1_LeafNode", func(t *testing.T) {
		trie1 := NewTrie(MODE_NORMAL)
		trie1.Put([]byte{0}, []byte("cutealice"))

		trie2 := NewTrie(MODE_VERIFY_FRAUD_PROOF)
		nibbles := newNibbles([]byte{0})
		leafNode := newLeafNode(nibbles, []byte("cutealice"))
		err := trie2.putProofNode([]Nibble{}, leafNode.hash())
		require.NoError(t, err)

		require.Equal(t, trie1.RootHash(), trie2.RootHash())
	})

	// 1_Branch_2_LeafNodes creates `trie1` with two key-value pairs, both with different keys
	// and values. Both pairs share the key prefix []byte{0}, and therefore sit in LeafNodes
	// sharing the same BranchNode parent, as illustrated below:
	//                                      ExtensionNode
	//                                            |
	//                                       BranchNode
	//    									     / \
	//                                       Leaf   Leaf
	//
	// It then creates `trie2`, which replaces both key-value pairs with the hashes of their
	// LeafNodes:
	//                                      ExtensionNode
	//                                            |
	//                                       BranchNode
	//                                          /  \
	//                                  ProofNode   ProofNode
	//
	// Both tries have the same RootHash.
	t.Run("1_Branch_2_LeafNodes", func(t *testing.T) {
		trie1 := NewTrie(MODE_NORMAL)

		// The reason why we put key-value pairs with values that have a large number of bytes
		// (at least 32 bytes) is because Keccak256 has a fixed-length 32 byte output. Therefore,
		// it is more space efficient to include small LeafNodes in the PreState than their hashes.
		//
		// The curving arrow symbols "⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷" used in these values are chosen because they
		// have large unicode encodings but only take up a single character-width in text editors.
		trie1.Put([]byte{0, 1}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{0, 2}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷a⤷⤷"))

		trie2 := NewTrie(MODE_VERIFY_FRAUD_PROOF)
		leafNode1 := newLeafNode([]Nibble{}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		leafNode2 := newLeafNode([]Nibble{}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷a⤷⤷"))
		err := trie2.putProofNode(newNibbles([]byte{0, 1}), leafNode1.hash())
		require.NoError(t, err)
		err = trie2.putProofNode(newNibbles([]byte{0, 2}), leafNode2.hash())
		require.NoError(t, err)

		require.Equal(t, trie1.RootHash(), trie2.RootHash())
	})

	// Big_Trie tests the the use of putProofNode in the scenario illustrated below. Imagine that
	// the Trie below is the complete Veritas rollup state trie before the fraudulent transaction.
	//
	// The nodes marked * represent key-value pairs that is read during the fraudulent transaction,
	// and thus have to be included in the challenge transaction in full.
	//
	// The nodes marked () represent key-value pairs that are not read during the fraudulent
	// transaction, but have to have their hashes included in the challenge transaction in order
	// to reproduce the trie root hash.
	//
	// Ignore the node marked +Leaf+. This will be used in the later TestGetStrayTrieRootPath.
	//
	//                                     Extension
	//                                         |
	//                                      Branch
	//                                    /    |    \
	//                           Extension   (Leaf)  Branch*
	//                                |              /     \
	//                             Branch         (Leaf)   (Extension)
	//                            /      \                      |
	//                       (Leaf)      Leaf*                Branch
	//                                                     /    |    \
	//                                                  Leaf  +Leaf+   Leaf
	t.Run("Big_Trie", func(t *testing.T) {
		// Build trie1.
		trie1 := NewTrie(MODE_NORMAL)

		// Build the leftmost subtrie.
		trie1.Put([]byte{00, 00, 00, 00, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷Alice is cute,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{00, 00, 00, 00, 01, 00, 00, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷Alice is small.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))

		// Build the middle subtrie.
		trie1.Put([]byte{01}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷These are important facts.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))

		// Build the right subtrie.
		trie1.Put([]byte{02, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷If you deny these facts,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{02}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷then you are evil,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{02, 16, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷I don't want to be friends with you,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{02, 16, 01}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷and please,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
		trie1.Put([]byte{02, 16, 02}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷go away.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))

		// Walk through trie1 structure.
		middleBranch := trie1.root.(*ExtensionNode).next.(*BranchNode)
		leftBranch := middleBranch.branches[0].(*ExtensionNode).next.(*BranchNode)
		leftLeftLeaf := leftBranch.branches[0].(*LeafNode)
		leftRightLeaf := leftBranch.branches[1].(*LeafNode)
		middleLeaf := middleBranch.branches[1].(*LeafNode)
		rightBranch := middleBranch.branches[2].(*BranchNode)
		rightLeftLeaf := rightBranch.branches[0].(*LeafNode)
		rightExtension := rightBranch.branches[1].(*ExtensionNode)
		rightRightBranch := rightExtension.next.(*BranchNode)
		_ = rightRightBranch.branches[0].(*LeafNode)
		_ = rightRightBranch.branches[1].(*LeafNode)
		_ = rightRightBranch.branches[2].(*LeafNode)

		// Build trie2.
		trie2 := NewTrie(MODE_VERIFY_FRAUD_PROOF)

		// Insert read key-value pairs: leftRightLeaf.value and rightBranch.value
		trie2.Put([]byte{00, 00, 00, 00, 01, 00, 00, 00}, leftRightLeaf.value)
		trie2.Put([]byte{02}, rightBranch.value)

		// Insert hashes: leftLeftLeaf.hash(), middleLeaf.hash(), rightLeftLeaf.hash(), and rightExtension.hash()
		trie2.putProofNode(newNibbles([]byte{00, 00, 00, 00, 00}), leftLeftLeaf.hash())
		trie2.putProofNode(newNibbles([]byte{01}), middleLeaf.hash())
		trie2.putProofNode(newNibbles([]byte{02, 00}), rightLeftLeaf.hash())
		trie2.putProofNode(newNibbles([]byte{02, 16}), rightExtension.hash())

		require.Equal(t, trie1.RootHash(), trie2.RootHash())
	})
}

// TestGetProofPairs demonstrates:
// - the correctness of the getStrayTrieRootPath function by comparing its output with a manually calculated
//   strayTrieRootPath, and
// - the correctness of the getProofPairs function, feeding strayTrieRootPath as an argument, by
//   comparing its output with a manually computed list of proofPairs.
//
// We create a shadowTrie emulating what an L1 MPT would produce after being sent the
// 2 KVPairs and 4 PHPairs used to produce trie2 in TestPutProofNode/Big_Trie.
func TestGetProofPairs(t *testing.T) {
	// Copy of Big_Trie.
	trie1 := NewTrie(MODE_NORMAL)
	trie1.Put([]byte{00, 00, 00, 00, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷Alice is cute,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{00, 00, 00, 00, 01, 00, 00, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷Alice is small.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{01}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷These are important facts.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{02, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷If you deny these facts,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{02}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷then you are evil,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{02, 16, 00}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷I don't want to be friends with you,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{02, 16, 01}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷and please,⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))
	trie1.Put([]byte{02, 16, 02}, []byte("⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷go away.⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷⤷"))

	middleBranch := trie1.root.(*ExtensionNode).next.(*BranchNode)
	leftBranch := middleBranch.branches[0].(*ExtensionNode).next.(*BranchNode)
	leftLeftLeaf := leftBranch.branches[0].(*LeafNode)
	leftRightLeaf := leftBranch.branches[1].(*LeafNode)
	middleLeaf := middleBranch.branches[1].(*LeafNode)
	rightBranch := middleBranch.branches[2].(*BranchNode)
	rightLeftLeaf := rightBranch.branches[0].(*LeafNode)
	rightExtension := rightBranch.branches[1].(*ExtensionNode)
	rightRightBranch := rightExtension.next.(*BranchNode)
	rightRightLeftLeaf := rightRightBranch.branches[0].(*LeafNode)
	_ = rightRightBranch.branches[1].(*LeafNode)
	rightRightRightLeaf := rightRightBranch.branches[2].(*LeafNode)

	// Build shadowTrie.
	shadowTrie := NewTrie(MODE_VERIFY_FRAUD_PROOF)

	// Insert read key-value pairs: leftRightLeaf.value and rightBranch.value
	shadowTrie.Put([]byte{00, 00, 00, 00, 01, 00, 00, 00}, leftRightLeaf.value)
	shadowTrie.Put([]byte{02}, rightBranch.value)

	// Insert hashes: leftLeftLeaf.hash(), middleLeaf.hash(), rightLeftLeaf.hash(), and rightExtension.hash()
	shadowTrie.putProofNode(newNibbles([]byte{00, 00, 00, 00, 00}), leftLeftLeaf.hash())
	shadowTrie.putProofNode(newNibbles([]byte{01}), middleLeaf.hash())
	shadowTrie.putProofNode(newNibbles([]byte{02, 00}), rightLeftLeaf.hash())
	shadowTrie.putProofNode(newNibbles([]byte{02, 16}), rightExtension.hash())
	// Copy of Big_Trie - END //

	// shadowTrie should at this point look like this:
	//
	//                          Extension
	//                              |
	//                            Branch
	//                          /   |    \
	//                 Extension  Proof   Branch
	//                     |			 /      \
	//                   Branch	    Proof        Proof (correct stray trie root)
	//                 /        \
	//            Proof          Leaf         +set KVPair+
	//
	// Now, suppose that the first mutation a fraud proof execution makes is to Set a KVPair corresponding
	// to the LeafNode marked +Leaf+ in the illustration for +Big Trie+. For this Set, the correct stray
	// trie root is the rightmost ProofNode in shadowTrie.

	setKey := []byte{02, 16, 01}
	expectedStrayTrieRootPath := []Nibble{0, 2, 1}
	actualStrayTrieRootPath := getStrayTrieRootPath(setKey, shadowTrie)
	require.Equal(t, expectedStrayTrieRootPath, actualStrayTrieRootPath)

	// We now test getProofPairs. getProofPairs should contain proof nodes corresponding to every node under
	// the rightmost ExtensionNode of trie1 (again, refer to the diagram in Big_Trie):
	//
	//                                 ...
	//                                  |
	//                              Extension
	//                                  |
	//                                Branch
	//                             /    |    \
	//                       (Leaf)   +Leaf+  (Leaf)
	//
	// We expect getProofPairs to return the hashes of the two leaves marked (Leaf).
	expectedKVPairs := make([]KVPair, 0)
	expectedPHPairs := []PHPair{
		{path: []Nibble{0, 2, 1, 0, 0, 0}, hash: rightRightLeftLeaf.hash()},
		{path: []Nibble{0, 2, 1, 0, 0, 2}, hash: rightRightRightLeaf.hash()},
	}

	actualPHPairs, actualKVPairs := getProofPairs(setKey, actualStrayTrieRootPath, trie1)
	require.Equal(t, expectedKVPairs, actualKVPairs)
	require.Equal(t, expectedPHPairs, actualPHPairs)
}
