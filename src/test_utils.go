package mpt

import (
	"fmt"
	"reflect"
)

// AreEqualTries returns whether the trie rooted in root1 equals the trie rooted in root2.
func AreEqualTries(root1 Node, root2 Node) bool {
	if root1 == nil && root2 == nil {
		return true
	}

	root1Ext, root1IsExt := root1.(*ExtensionNode)
	root2Ext, root2IsExt := root2.(*ExtensionNode)

	if root1IsExt && root2IsExt {
		res := reflect.DeepEqual(root1Ext.Path, root2Ext.Path) && AreEqualTries(root1Ext.Next, root2Ext.Next)
		if res == false {
			fmt.Println(root1Ext, root2Ext)
		}
		return res
	}

	root1Branch, root1IsBranch := root1.(*BranchNode)
	root2Branch, root2IsBranch := root2.(*BranchNode)

	if root1IsBranch && root2IsBranch {
		areBranchesEqual := true
		for i := 0; i < 16; i++ {
			areBranchesEqual = areBranchesEqual && AreEqualTries(root1Branch.Branches[i], root2Branch.Branches[i])
		}

		res := areBranchesEqual && reflect.DeepEqual(root1Branch.Value, root2Branch.Value)
		if res == false {
			fmt.Println(root1Branch, root2Branch, root1Branch.Value == nil, root2Branch.Value == nil)
		}
		return res
	}

	root1Leaf, root1IsLeaf := root1.(*LeafNode)
	root2Leaf, root2IsLeaf := root2.(*LeafNode)

	if root1IsLeaf && root2IsLeaf {
		res := reflect.DeepEqual(root1Leaf.Path, root2Leaf.Path) && reflect.DeepEqual(root1Leaf.Value, root2Leaf.Value)
		if res == false {
			fmt.Println(root1Leaf, root2Leaf)
		}
		return res
	}

	fmt.Println(root1, root2)
	return false
}
