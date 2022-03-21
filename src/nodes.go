package mpt

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

////////////
// Globals
////////////

var (
	EmptyNodeRaw     = []byte{}
	EmptyNodeHash, _ = hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

////////////////////////////
// Node-general definitions
////////////////////////////

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

//////////////////////////
// Empty node definitions
//////////////////////////

func IsEmptyNode(node Node) bool {
	return node == nil
}

///////////////////////////
// Branch node definitions
///////////////////////////

type BranchNode struct {
	Branches [16]Node
	Value    []byte
}

func NewBranchNode() *BranchNode {
	return &BranchNode{
		Branches: [16]Node{},
	}
}

func (b BranchNode) Hash() []byte {
	return crypto.Keccak256(b.Serialize())
}

func (b *BranchNode) SetBranch(nibble Nibble, node Node) {
	b.Branches[int(nibble)] = node
}

func (b *BranchNode) RemoveBranch(nibble Nibble) {
	b.Branches[int(nibble)] = nil
}

func (b *BranchNode) SetValue(value []byte) {
	b.Value = value
}

func (b *BranchNode) RemoveValue() {
	b.Value = nil
}

func (b BranchNode) Raw() []interface{} {
	hashes := make([]interface{}, 17)
	for i := 0; i < 16; i++ {
		if b.Branches[i] == nil {
			hashes[i] = EmptyNodeRaw
		} else {
			node := b.Branches[i]
			if len(Serialize(node)) >= 32 {
				hashes[i] = node.Hash()
			} else {
				// if node can be serialized to less than 32 bits, then
				// use Serialized directly.
				// it has to be ">=", rather than ">",
				// so that when deserialized, the content can be distinguished
				// by length
				hashes[i] = node.Raw()
			}
		}
	}

	hashes[16] = b.Value
	return hashes
}

func (b BranchNode) Serialize() []byte {
	return Serialize(b)
}

func (b BranchNode) HasValue() bool {
	return b.Value != nil
}

///////////////////////////////
// Extension node definitions
///////////////////////////////

type ExtensionNode struct {
	Path []Nibble
	Next Node
}

func NewExtensionNode(nibbles []Nibble, next Node) *ExtensionNode {
	return &ExtensionNode{
		Path: nibbles,
		Next: next,
	}
}

func (e ExtensionNode) Hash() []byte {
	return crypto.Keccak256(e.Serialize())
}

func (e ExtensionNode) Raw() []interface{} {
	hashes := make([]interface{}, 2)
	hashes[0] = NibblesToBytes(AppendPrefixToNibbles(e.Path, false))
	if len(Serialize(e.Next)) >= 32 {
		hashes[1] = e.Next.Hash()
	} else {
		hashes[1] = e.Next.Raw()
	}
	return hashes
}

func (e ExtensionNode) Serialize() []byte {
	return Serialize(e)
}

//////////////////////////
// Leaf node definitions
//////////////////////////

type LeafNode struct {
	Path  []Nibble
	Value []byte
}

// TODO [Alice]: Marked for deletion.
func NewLeafNodeFromNibbleBytes(nibbles []byte, value []byte) (*LeafNode, error) {
	ns, err := FromNibbleBytes(nibbles)
	if err != nil {
		return nil, fmt.Errorf("could not leaf node from nibbles: %w", err)
	}

	return NewLeafNodeFromNibbles(ns, value), nil
}

func NewLeafNodeFromNibbles(nibbles []Nibble, value []byte) *LeafNode {
	return &LeafNode{
		Path:  nibbles,
		Value: value,
	}
}

// TODO [Alice]: Marked for deletion.
func NewLeafNodeFromBytes(key, value []byte) *LeafNode {
	return NewLeafNodeFromNibbles(NibblesFromBytes(key), value)
}

func (l LeafNode) Hash() []byte {
	return crypto.Keccak256(l.Serialize())
}

func (l LeafNode) Raw() []interface{} {
	path := NibblesToBytes(AppendPrefixToNibbles(l.Path, true))
	raw := []interface{}{path, l.Value}
	return raw
}

func (l LeafNode) Serialize() []byte {
	return Serialize(l)
}
