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
	t.Run("deserialize branch node with serialized branches of size both < 32 and >= 32", func(t *testing.T) {
		branchNode := NewBranchNode()
		leafNode1 := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(leafNode1)) < 32)

		leafNode2 := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(leafNode2)) >= 32)

		branchNode.branches[0] = leafNode1
		branchNode.branches[3] = leafNode2
		branchNode.value = []byte("VEGETA")

		mockDB := NewMockDB()
		mockDB.Put(leafNode2.Hash(), leafNode2.Serialize())

		serializedBranchNode := branchNode.Serialize()
		deserializedBranchNode, err := Deserialize(serializedBranchNode, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedBranchNode, branchNode))
	})

	t.Run("cannot deserialize branch if hash not found in db", func(t *testing.T) {
		branchNode := NewBranchNode()
		leafNode1 := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(leafNode1)) < 32)

		leafNode2 := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(leafNode2)) >= 32)

		branchNode.branches[0] = leafNode1
		branchNode.branches[3] = leafNode2
		branchNode.value = []byte("GOKU")

		mockDB := NewMockDB()

		serializedBranchNode := branchNode.Serialize()
		require.Panics(t, func() { Deserialize(serializedBranchNode, mockDB) })
	})

	t.Run("deserialize extension node with next node of size < 32", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(nextNode)) < 32)

		extensionNode.next = nextNode
		mockDB := NewMockDB()

		serializedExtensionNode := extensionNode.Serialize()
		deserializedExtensionNode, err := Deserialize(serializedExtensionNode, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("deserialize extension node with next node of size >= 32", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(nextNode)) >= 32)

		extensionNode.next = nextNode
		mockDB := NewMockDB()
		mockDB.Put(nextNode.Hash(), nextNode.Serialize())

		serializedExtensionNode := extensionNode.Serialize()
		deserializedExtensionNode, err := Deserialize(serializedExtensionNode, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("cannot deserialize extension node if next node hash not in db", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(nextNode)) >= 32)

		extensionNode.next = nextNode
		mockDB := NewMockDB()

		serializedExtensionNode := extensionNode.Serialize()
		require.Panics(t, func() { Deserialize(serializedExtensionNode, mockDB) })
	})

	t.Run("deep subtrie with size < 32", func(t *testing.T) {
		ext1 := NewExtensionNode([]Nibble{10, 10}, nil)
		next1 := NewExtensionNode([]Nibble{2, 3}, nil)
		leaf := NewLeafNodeFromNibbles([]Nibble{3}, []byte("a"))

		next1.next = leaf
		require.Less(t, len(next1.Serialize()), 32)

		ext1.next = next1

		mockDB := NewMockDB()

		serializedExt := ext1.Serialize()
		deserializedExt, err := Deserialize(serializedExt, mockDB)
		require.Nil(t, err)
		require.True(t, reflect.DeepEqual(deserializedExt, ext1))
	})
}

func TestBranch(t *testing.T) {
	nibbles, value := []byte{5, 0, 6}, []byte("coin")
	leaf, err := NewLeafNodeFromNibbleBytes(nibbles, value)
	require.NoError(t, err)

	b := NewBranchNode()
	b.SetBranch(0, leaf)
	b.SetValue([]byte("verb")) // set the value for verb

	require.Equal(t, "ddc882350684636f696e8080808080808080808080808080808476657262",
		fmt.Sprintf("%x", b.Serialize()))
	require.Equal(t, "d757709f08f7a81da64a969200e59ff7e6cd6b06674c3f668ce151e84298aa79",
		fmt.Sprintf("%x", b.Hash()))

}

func TestEmptyNodeHash(t *testing.T) {
	emptyRLP, err := rlp.EncodeToBytes(EmptyNodeRaw)
	require.NoError(t, err)
	require.Equal(t, EmptyNodeHash, Keccak256(emptyRLP))
}

func TestExtensionNode(t *testing.T) {
	nibbles, value := []byte{5, 0, 6}, []byte("coin")
	leaf, err := NewLeafNodeFromNibbleBytes(nibbles, value)
	require.NoError(t, err)

	b := NewBranchNode()
	b.SetBranch(0, leaf)
	b.SetValue([]byte("verb")) // set the value for verb

	ns, err := CastBytesToNibbles([]byte{0, 1, 0, 2, 0, 3, 0, 4})
	require.NoError(t, err)
	e := NewExtensionNode(ns, b)
	require.Equal(t, "e4850001020304ddc882350684636f696e8080808080808080808080808080808476657262", fmt.Sprintf("%x", e.Serialize()))
	require.Equal(t, "64d67c5318a714d08de6958c0e63a05522642f3f1087c6fd68a97837f203d359", fmt.Sprintf("%x", e.Hash()))
}

func TestLeafHash(t *testing.T) {
	require.Equal(t, "01020304", fmt.Sprintf("%x", []byte{1, 2, 3, 4}))
	require.Equal(t, "76657262", fmt.Sprintf("%x", []byte("verb")))

	// "buffer to nibbles
	require.Equal(t, "0001000200030004", fmt.Sprintf("%x", NewNibblesFromBytes([]byte{1, 2, 3, 4})))

	// ToPrefixed
	require.Equal(t, "02000001000200030004", fmt.Sprintf("%x", AppendPrefixToNibbles(NewNibblesFromBytes([]byte{1, 2, 3, 4}), true)))

	// ToBuffer
	require.Equal(t, "2001020304", fmt.Sprintf("%x", ConvertNibblesToBytes(AppendPrefixToNibbles(NewNibblesFromBytes([]byte{1, 2, 3, 4}), true))))

	require.Equal(t, "636f696e", fmt.Sprintf("%x", []byte("coin")))
}

func Test3Nibbles(t *testing.T) {
	key, value := []byte{5, 0, 6}, []byte("coin")
	hexs := printEachCalculationSteps(key, value, true)
	fmt.Printf("key_hex: %x\n", key)
	fmt.Printf("value_hex: %x\n", value)
	fmt.Printf("key in nibbles: %s\n", hexs["key in nibbles"])
	fmt.Printf("key in nibbles, and prefixed: %s\n", hexs["key in nibbles, and prefixed"])
	fmt.Printf("key in nibbles, and prefixed, and convert back to buffer: %s\n",
		hexs["key in nibbles, and prefixed, and convert back to buffer"])
	fmt.Printf("beforeRLP: %s\n", hexs["beforeRLP"])
	fmt.Printf("afterRLP: %s\n", hexs["afterRLP"])
	fmt.Printf("hash: %s\n", hexs["hash"])
	require.Equal(t, "c5442690f038fcc0b8b8949b4f5149db8c0bee917be6355dc2db1855e9675700",
		hexs["hash"])
}

func TestLeafNode(t *testing.T) {
	nibbles, value := []byte{1, 2, 3, 4}, []byte("verb")
	l := NewLeafNodeFromBytes(nibbles, value)
	require.Equal(t, "2bafd1eef58e8707569b7c70eb2f91683136910606ba7e31d07572b8b67bf5c6", fmt.Sprintf("%x", l.Hash()))
}

func TestLeafNode2(t *testing.T) {
	// t.Skip()
	nibbles, value := []byte{5, 0, 6}, []byte("coin")
	l, err := NewLeafNodeFromNibbleBytes(nibbles, value)
	require.NoError(t, err)
	require.Equal(t, "c37ec985b7a88c2c62beb268750efe657c36a585beb435eb9f43b839846682ce", fmt.Sprintf("%x", l.Hash()))
}

func printEachCalculationSteps(key, value []byte, isLeaf bool) map[string]string {
	hexs := make(map[string]string)
	hexs["key in nibbles"] = fmt.Sprintf("%x", NewNibblesFromBytes(key))
	hexs["key in nibbles, and prefixed"] = fmt.Sprintf("%x", AppendPrefixToNibbles(NewNibblesFromBytes(key), isLeaf))
	hexs["key in nibbles, and prefixed, and convert back to buffer"] =
		fmt.Sprintf("%x", ConvertNibblesToBytes(AppendPrefixToNibbles(NewNibblesFromBytes(key), isLeaf)))
	beforeRLP := [][]byte{ConvertNibblesToBytes(AppendPrefixToNibbles(NewNibblesFromBytes(key), isLeaf)), value}
	hexs["beforeRLP"] = fmt.Sprintf("%x", beforeRLP)
	afterRLP, err := rlp.EncodeToBytes(beforeRLP)
	if err != nil {
		panic(err)
	}
	hexs["afterRLP"] = fmt.Sprintf("%x", afterRLP)
	hexs["hash"] = fmt.Sprintf("%x", crypto.Keccak256(afterRLP))
	return hexs
}
