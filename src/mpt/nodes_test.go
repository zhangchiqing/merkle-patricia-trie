package mpt

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeserializeNodes(t *testing.T) {
	t.Run("deserialize branch node with serialized branches of size both < 32 and >= 32", func(t *testing.T) {
		branchNode := NewBranchNode()
		leafNode1 := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(leafNode1)) < 32)

		leafNode2 := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(leafNode2)) >= 32)

		branchNode.Branches[0] = leafNode1
		branchNode.Branches[3] = leafNode2
		branchNode.Value = []byte("VEGETA")

		mockDB := NewMockDB()
		mockDB.Put(leafNode2.Hash(), leafNode2.Serialize())

		serializedBranchNode := branchNode.Serialize()
		deserializedBranchNode := Deserialize(serializedBranchNode, mockDB)
		require.True(t, reflect.DeepEqual(deserializedBranchNode, branchNode))
	})

	t.Run("cannot deserialize branch if hash not found in db", func(t *testing.T) {
		branchNode := NewBranchNode()
		leafNode1 := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(leafNode1)) < 32)

		leafNode2 := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(leafNode2)) >= 32)

		branchNode.Branches[0] = leafNode1
		branchNode.Branches[3] = leafNode2
		branchNode.Value = []byte("GOKU")

		mockDB := NewMockDB()

		serializedBranchNode := branchNode.Serialize()
		require.Panics(t, func() { Deserialize(serializedBranchNode, mockDB) })
	})

	t.Run("deserialize extension node with next node of size < 32", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{10, 10}, []byte("h"))
		require.True(t, len(Serialize(nextNode)) < 32)

		extensionNode.Next = nextNode
		mockDB := NewMockDB()

		serializedExtensionNode := extensionNode.Serialize()
		deserializedExtensionNode := Deserialize(serializedExtensionNode, mockDB)
		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("deserialize extension node with next node of size >= 32", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(nextNode)) >= 32)

		extensionNode.Next = nextNode
		mockDB := NewMockDB()
		mockDB.Put(nextNode.Hash(), nextNode.Serialize())

		serializedExtensionNode := extensionNode.Serialize()
		deserializedExtensionNode := Deserialize(serializedExtensionNode, mockDB)
		require.True(t, reflect.DeepEqual(deserializedExtensionNode, extensionNode))
	})

	t.Run("cannot deserialize extension node if next node hash not in db", func(t *testing.T) {
		extensionNode := NewExtensionNode([]Nibble{10, 10}, nil)
		nextNode := NewLeafNodeFromNibbles([]Nibble{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("helloworldgoodmorning"))
		require.True(t, len(Serialize(nextNode)) >= 32)

		extensionNode.Next = nextNode
		mockDB := NewMockDB()

		serializedExtensionNode := extensionNode.Serialize()
		require.Panics(t, func() { Deserialize(serializedExtensionNode, mockDB) })
	})

	t.Run("deep subtrie with size < 32", func(t *testing.T) {
		ext1 := NewExtensionNode([]Nibble{10, 10}, nil)
		next1 := NewExtensionNode([]Nibble{2, 3}, nil)
		leaf := NewLeafNodeFromNibbles([]Nibble{3}, []byte("a"))

		next1.Next = leaf
		require.Less(t, len(next1.Serialize()), 32)

		ext1.Next = next1

		mockDB := NewMockDB()

		serializedExt := ext1.Serialize()
		deserializedExt := Deserialize(serializedExt, mockDB)
		require.True(t, reflect.DeepEqual(deserializedExt, ext1))
	})
}
