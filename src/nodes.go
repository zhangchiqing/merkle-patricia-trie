package mpt

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	nilNodeRaw     = []byte{}
	nilNodeHash, _ = hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type Slots = []interface{}

/////////////
// Node API
/////////////

type Node interface {
	ComputeHash() []byte // common.Hash
	asSerialBytes() []byte
	asSlots() Slots
}

func NodeFromSerialBytes(serializedNode []byte, db DB) (Node, error) {
	if serializedNode == nil {
		return nil, nil
	}

	var Slots Slots
	err := rlp.DecodeBytes(serializedNode, &Slots)
	if err != nil {
		return nil, err
	}

	return nodeFromRaw(Slots, db)
}

// TODO [Alice]: explain the difference between a node and a serializedNode.
func nodeFromRaw(node Slots, db DB) (Node, error) {
	if len(node) == 0 {
		return nil, fmt.Errorf("serializedNode is empty")
	}

	if len(node) == 17 {
		////////////////////
		// Is a BranchNode.
		////////////////////
		branchNode := NewBranchNode()

		for i := 0; i < 16; i++ {
			branch := node[i]
			if rawBranchBytes, ok := branch.([]byte); ok {
				////////////////////////
				// Branch is a pointer.
				////////////////////////
				if len(rawBranchBytes) != 0 {
					serializedNodeFromDB, err := db.Get(rawBranchBytes)
					if err != nil {
						// SAFETY: failing to get from database is a fatal error.
						panic(err)
					}

					deserializedNode, err := NodeFromSerialBytes(serializedNodeFromDB, db)
					if err != nil {
						return nil, err
					}

					branchNode.branches[i] = deserializedNode
				}
			} else if rawBranchBytes, ok := branch.(Slots); ok {
				/////////////////////
				// Branch is a node.
				/////////////////////
				if len(rawBranchBytes) != 0 {
					deserializedNode, err := nodeFromRaw(rawBranchBytes, db)
					if err != nil {
						return nil, err
					}

					branchNode.branches[i] = deserializedNode
				}
			} else {
				return nil, fmt.Errorf("node seems to be a branch node, but its branches cannot be casted into either a hash or a Slots")
			}
		}

		if value, ok := node[16].([]byte); ok {
			if len(value) == 0 {
				branchNode.value = nil
			} else {
				branchNode.value = value
			}
		} else {
			return nil, fmt.Errorf("node seems to be a branch node, but its value cannot be casted into a slice of bytes")
		}

		return branchNode, nil
	} else {
		// Either extension node or leaf node
		nibbleBytes := node[0]
		prefixedNibbles := NewNibblesFromBytes(nibbleBytes.([]byte))
		nibbles, isLeafNode := RemovePrefixFromNibbles(prefixedNibbles)

		if isLeafNode {
			///////////////////
			// Is a LeafNode.
			///////////////////
			leafNode := NewLeafNodeFromNibbles(nibbles, node[1].([]byte))
			return leafNode, nil

		} else {
			////////////////////////
			// Is an ExtensionNode.
			////////////////////////
			extensionNode := NewExtensionNode(nibbles, nil)
			rawNextNode := node[1]

			if rawNextNodeBytes, ok := rawNextNode.([]byte); ok {
				///////////////////////////
				// Next node is a pointer.
				///////////////////////////
				if len(rawNextNodeBytes) != 0 {
					serializedNodeFromDB, err := db.Get(rawNextNodeBytes)
					// SAFETY: failing to get from database is a fatal error.
					if err != nil {
						panic(err)
					}

					deserializedNode, err := NodeFromSerialBytes(serializedNodeFromDB, db)
					if err != nil {
						return nil, err
					}
					extensionNode.next = deserializedNode
				}
			} else if rawNextNodeBytes, ok := rawNextNode.(Slots); ok {
				////////////////////////
				// Next node is a node.
				////////////////////////
				if len(rawNextNodeBytes) != 0 {
					deserializedNode, err := nodeFromRaw(rawNextNodeBytes, db)
					if err != nil {
						return nil, err
					}

					extensionNode.next = deserializedNode
				}
			} else {
				return nil, fmt.Errorf("node seems to be an ExtensionNode, but its nextNode cannot be casted into a slice")
			}

			return extensionNode, nil
		}
	}
}

func serializeNode(node Node) []byte {
	var raw interface{}

	if node == nil {
		raw = nilNodeRaw
	} else {
		raw = node.asSlots()
	}

	rlp, err := rlp.EncodeToBytes(raw)
	if err != nil {
		// SAFETY: failing to RLP encode a node is a fatal error.
		panic(err)
	}

	return rlp
}

///////////////////////////
// Branch node definitions
///////////////////////////

type BranchNode struct {
	branches [16]Node
	value    []byte
}

func NewBranchNode() *BranchNode {
	return &BranchNode{
		branches: [16]Node{},
	}
}

func (b BranchNode) asSerialBytes() []byte {
	return serializeNode(b)
}

func (b BranchNode) asSlots() Slots {
	slots := make(Slots, 17)
	for i := 0; i < 16; i++ {
		if b.branches[i] == nil {
			slots[i] = nilNodeRaw
		} else {
			node := b.branches[i]
			if len(serializeNode(node)) >= 32 {
				slots[i] = node.ComputeHash()
			} else {
				// if node can be serialized to less than 32 bits, then
				// use Serialized directly.
				// it has to be ">=", rather than ">",
				// so that when deserialized, the content can be distinguished
				// by length
				slots[i] = node.asSlots()
			}
		}
	}

	slots[16] = b.value
	return slots
}

func (b BranchNode) ComputeHash() []byte {
	return crypto.Keccak256(b.asSerialBytes())
}

func (b BranchNode) hasValue() bool {
	return b.value != nil
}

func (b *BranchNode) setBranch(nibble Nibble, node Node) {
	b.branches[int(nibble)] = node
}

func (b *BranchNode) setValue(value []byte) {
	b.value = value
}

///////////////////////////////
// Extension node definitions
///////////////////////////////

type ExtensionNode struct {
	path []Nibble
	next Node
}

func NewExtensionNode(nibbles []Nibble, next Node) *ExtensionNode {
	return &ExtensionNode{
		path: nibbles,
		next: next,
	}
}

func (e ExtensionNode) ComputeHash() []byte {
	return crypto.Keccak256(e.asSerialBytes())
}

func (e ExtensionNode) asSlots() Slots {
	slots := make(Slots, 2)
	slots[0] = NibblesAsBytes(AppendPrefixToNibbles(e.path, false))
	if len(serializeNode(e.next)) >= 32 {
		slots[1] = e.next.ComputeHash()
	} else {
		slots[1] = e.next.asSlots()
	}
	return slots
}

func (e ExtensionNode) asSerialBytes() []byte {
	return serializeNode(e)
}

//////////////////////////
// Leaf node definitions
//////////////////////////

type LeafNode struct {
	path  []Nibble
	value []byte
}

func NewLeafNodeFromNibbles(nibbles []Nibble, value []byte) *LeafNode {
	return &LeafNode{
		path:  nibbles,
		value: value,
	}
}

// TODO [Alice]: Marked for deletion.
func NewLeafNodeFromNibbleBytes(nibbles []byte, value []byte) (*LeafNode, error) {
	ns, err := BytesAsNibbles(nibbles)
	if err != nil {
		return nil, fmt.Errorf("could not leaf node from nibbles: %w", err)
	}

	return NewLeafNodeFromNibbles(ns, value), nil
}

// TODO [Alice]: Marked for deletion.
func NewLeafNodeFromBytes(key, value []byte) *LeafNode {
	return NewLeafNodeFromNibbles(NewNibblesFromBytes(key), value)
}

func (l LeafNode) ComputeHash() []byte {
	return crypto.Keccak256(l.asSerialBytes())
}

func (l LeafNode) asSlots() Slots {
	path := NibblesAsBytes(AppendPrefixToNibbles(l.path, true))
	raw := Slots{path, l.value}
	return raw
}

func (l LeafNode) asSerialBytes() []byte {
	return serializeNode(l)
}

//////////////////////////
// ProofNode definitions
//////////////////////////

type ProofNode struct {
	path []Nibble
	hash []byte
}
