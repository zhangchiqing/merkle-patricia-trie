package mpt

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestDeserializeNodes(t *testing.T) {
	t.Run("deserialize_branch_node", func(t *testing.T) {
		branchNode := newBranchNode()
		leafNode1 := newLeafNode([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(leafNode1.serialized()) < 32)

		leafNode2 := newLeafNode([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(leafNode2.serialized()) >= 32)

		branchNode.branches[0] = leafNode1
		branchNode.branches[3] = leafNode2
		branchNode.value = []byte("VEGETA")

		mockDB := NewMockDB()
		mockDB.Put(leafNode2.hash(), leafNode2.serialized())

		serializedBranchNode := branchNode.serialized()
		deserializedBranchNode, err := NodeFromSerialBytes(serializedBranchNode, mockDB)
		require.Nil(t, err)

		require.True(t, reflect.DeepEqual(deserializedBranchNode, branchNode))
	})

	t.Run("deserialize_extension_node_with_raw_next_node", func(t *testing.T) {
		extensionNode := newExtensionNode([]Nibble{10, 10}, nil)
		nextNode := newLeafNode([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(nextNode.serialized()) < 32)

		extensionNode.next = nextNode
		mockDB := NewMockDB()

		serializedExtensionNode := extensionNode.serialized()
		deserializedExtensionNode, err := NodeFromSerialBytes(serializedExtensionNode, mockDB)
		require.Nil(t, err)

		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("deserialize_extension_node_with_pointer_next_node", func(t *testing.T) {
		extensionNode := newExtensionNode([]Nibble{10, 10}, nil)
		nextNode := newLeafNode([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(nextNode.serialized()) >= 32)

		extensionNode.next = nextNode
		mockDB := NewMockDB()
		mockDB.Put(nextNode.hash(), nextNode.serialized())

		serializedExtensionNode := extensionNode.serialized()
		deserializedExtensionNode, err := NodeFromSerialBytes(serializedExtensionNode, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("deep subtrie with size < 32", func(t *testing.T) {
		ext1 := newExtensionNode([]Nibble{10, 10}, nil)
		next1 := newExtensionNode([]Nibble{2, 3}, nil)
		leaf := newLeafNode([]Nibble{3}, []byte("a"))

		next1.next = leaf
		require.Less(t, len(next1.serialized()), 32)

		ext1.next = next1

		mockDB := NewMockDB()

		serializedExt := ext1.serialized()
		deserializedExt, err := NodeFromSerialBytes(serializedExt, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedExt, ext1))
	})
}

func TestBranch(t *testing.T) {
	nibbles, err := bytesAsNibbles(5, 0, 6)
	require.NoError(t, err)
	value := []byte("coin")

	leaf := newLeafNode(nibbles, value)

	b := newBranchNode()
	b.setBranch(0, leaf)
	b.setValue([]byte("verb")) // set the value for verb

	require.Equal(t, "ddc882350684636f696e8080808080808080808080808080808476657262",
		fmt.Sprintf("%x", b.serialized()))
	require.Equal(t, "d757709f08f7a81da64a969200e59ff7e6cd6b06674c3f668ce151e84298aa79",
		fmt.Sprintf("%x", b.hash()))

}

func TestEmptyNodeHash(t *testing.T) {
	emptyRLP, err := rlp.EncodeToBytes(nilNodeRaw)
	require.NoError(t, err)
	require.Equal(t, nilNodeHash, Keccak256(emptyRLP))
}

func TestExtensionNode(t *testing.T) {
	nibbles, err := bytesAsNibbles(5, 0, 6)
	require.NoError(t, err)
	value := []byte("coin")

	leaf := newLeafNode(nibbles, value)

	b := newBranchNode()
	b.setBranch(0, leaf)
	b.setValue([]byte("verb")) // set the value for verb

	ns, err := bytesAsNibbles(0, 1, 0, 2, 0, 3, 0, 4)
	require.NoError(t, err)
	e := newExtensionNode(ns, b)
	require.Equal(t, "e4850001020304ddc882350684636f696e8080808080808080808080808080808476657262", fmt.Sprintf("%x", e.serialized()))
	require.Equal(t, "64d67c5318a714d08de6958c0e63a05522642f3f1087c6fd68a97837f203d359", fmt.Sprintf("%x", e.hash()))
}

func TestLeafHash(t *testing.T) {
	require.Equal(t, "01020304", fmt.Sprintf("%x", []byte{1, 2, 3, 4}))
	require.Equal(t, "76657262", fmt.Sprintf("%x", []byte("verb")))

	// "buffer to nibbles
	require.Equal(t, "0001000200030004", fmt.Sprintf("%x", newNibbles([]byte{1, 2, 3, 4})))

	// ToPrefixed
	require.Equal(t, "02000001000200030004", fmt.Sprintf("%x", appendPrefixToNibbles(newNibbles([]byte{1, 2, 3, 4}), true)))

	// ToBuffer
	require.Equal(t, "2001020304", fmt.Sprintf("%x", nibblesAsBytes(appendPrefixToNibbles(newNibbles([]byte{1, 2, 3, 4}), true))))

	require.Equal(t, "636f696e", fmt.Sprintf("%x", []byte("coin")))
}

func Test3Nibbles(t *testing.T) {
	key, value := []byte{5, 0, 6}, []byte("coin")
	hexs := printEachCalculationSteps(key, value, true)
	require.Equal(t, "c5442690f038fcc0b8b8949b4f5149db8c0bee917be6355dc2db1855e9675700",
		hexs["hash"])
}

func TestLeafNode(t *testing.T) {
	nibbles := newNibbles([]byte{1, 2, 3, 4})
	value := []byte("verb")

	leaf := newLeafNode(nibbles, value)

	require.Equal(t, "2bafd1eef58e8707569b7c70eb2f91683136910606ba7e31d07572b8b67bf5c6", fmt.Sprintf("%x", leaf.hash()))
}

func TestLeafNode2(t *testing.T) {
	nibbles, err := bytesAsNibbles(5, 0, 6)
	require.NoError(t, err)
	value := []byte("coin")

	leaf := newLeafNode(nibbles, value)

	require.Equal(t, "c37ec985b7a88c2c62beb268750efe657c36a585beb435eb9f43b839846682ce", fmt.Sprintf("%x", leaf.hash()))
}

func printEachCalculationSteps(key, value []byte, isLeaf bool) map[string]string {
	hexs := make(map[string]string)
	hexs["key in nibbles"] = fmt.Sprintf("%x", newNibbles(key))
	hexs["key in nibbles, and prefixed"] = fmt.Sprintf("%x", appendPrefixToNibbles(newNibbles(key), isLeaf))
	hexs["key in nibbles, and prefixed, and convert back to buffer"] =
		fmt.Sprintf("%x", nibblesAsBytes(appendPrefixToNibbles(newNibbles(key), isLeaf)))
	beforeRLP := [][]byte{nibblesAsBytes(appendPrefixToNibbles(newNibbles(key), isLeaf)), value}
	hexs["beforeRLP"] = fmt.Sprintf("%x", beforeRLP)
	afterRLP, err := rlp.EncodeToBytes(beforeRLP)
	if err != nil {
		panic(err)
	}
	hexs["afterRLP"] = fmt.Sprintf("%x", afterRLP)
	hexs["hash"] = fmt.Sprintf("%x", crypto.Keccak256(afterRLP))
	return hexs
}
