package mpt

import (
	"github.com/ethereum/go-ethereum/rlp"
)

type Node interface {
	Hash() []byte // common.Hash
	Raw() []interface{}
}

func Hash(node Node) []byte {
	if IsEmptyNode(node) {
		return EmptyNodeHash
	}
	return node.Hash()
}

func Serialize(node Node) []byte {
	var raw interface{}

	if IsEmptyNode(node) {
		raw = EmptyNodeRaw
	} else {
		raw = node.Raw()
	}

	rlp, err := rlp.EncodeToBytes(raw)
	if err != nil {
		panic(err)
	}

	return rlp
}

// TODO [Alice]: make this return an error instead of panicking.
func FromRaw(rawNode []interface{}, db DB) Node {
	if len(rawNode) == 0 {
		return nil
	}

	if len(rawNode) == 17 {
		//it's a branch node
		branchNode := NewBranchNode()

		for i := 0; i < 16; i++ {
			rawBranch := rawNode[i]
			if rawBranchBytes, ok := rawBranch.([]byte); ok {
				if len(rawBranchBytes) != 0 {
					// Keccak256 hash
					serializedNodeFromDB, err := db.Get(rawBranchBytes)
					if err != nil {
						panic(err)
					} else {
						deserializedNode := Deserialize(serializedNodeFromDB, db)
						branchNode.Branches[i] = deserializedNode
					}
				}
			} else if rawBranchBytes, ok := rawBranch.([]interface{}); ok {
				// raw node itself
				if len(rawBranchBytes) != 0 {
					deserializedNode := FromRaw(rawBranchBytes, db)
					branchNode.Branches[i] = deserializedNode
				}
			} else {
				panic("can not deserialize/decode this node")
			}
		}

		if value, ok := rawNode[16].([]byte); ok {
			if len(value) == 0 {
				branchNode.Value = nil
			} else {
				branchNode.Value = value
			}
		} else {
			panic("value of branch node not understood")
		}
		return branchNode
	} else {
		// either extension node or leaf node
		nibbleBytes := rawNode[0]
		prefixedNibbles := NibblesFromBytes(nibbleBytes.([]byte))
		nibbles, isLeafNode := RemovePrefixFromNibbles(prefixedNibbles)

		if isLeafNode {
			leafNode := NewLeafNodeFromNibbles(nibbles, rawNode[1].([]byte))
			return leafNode
		} else {
			extensionNode := NewExtensionNode(nibbles, nil)
			rawNextNode := rawNode[1]

			if rawNextNodeBytes, ok := rawNextNode.([]byte); ok {
				if len(rawNextNodeBytes) != 0 {
					// Keccak256 hash
					serializedNodeFromDB, err := db.Get(rawNextNodeBytes)
					if err != nil {
						panic(err)
					} else {
						deserializedNode := Deserialize(serializedNodeFromDB, db)
						extensionNode.Next = deserializedNode
					}
				}
			} else if rawNextNodeBytes, ok := rawNextNode.([]interface{}); ok {
				// raw node itself
				if len(rawNextNodeBytes) != 0 {
					deserializedNode := FromRaw(rawNextNodeBytes, db)
					extensionNode.Next = deserializedNode
				}
			} else {
				panic("can not deserialize/decode this node")
			}

			return extensionNode
		}
	}
}

func Deserialize(serializedNode []byte, db DB) Node {
	var rawNode []interface{}
	err := rlp.DecodeBytes(serializedNode, &rawNode)

	if err != nil {
		panic(err)
	}

	return FromRaw(rawNode, db)
}
