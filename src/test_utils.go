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
		res := reflect.DeepEqual(root1Ext.path, root2Ext.path) && AreEqualTries(root1Ext.next, root2Ext.next)
		if res == false {
			fmt.Println(root1Ext, root2Ext)
		}
		return res
	}

	root1Branch, root1IsBranch := root1.(*BranchNode)
	root2Branch, root2IsBranch := root2.(*BranchNode)

	if root1IsBranch && root2IsBranch {
		branchesAreEqual := true
		for i := 0; i < 16; i++ {
			branchesAreEqual = branchesAreEqual && AreEqualTries(root1Branch.branches[i], root2Branch.branches[i])
		}

		res := branchesAreEqual && reflect.DeepEqual(root1Branch.value, root2Branch.value)
		if branchesAreEqual && reflect.DeepEqual(root1Branch.value, root2Branch.value) == false {
			fmt.Println(root1Branch, root2Branch, root1Branch.value == nil, root2Branch.value == nil)
		}
		return res
	}

	root1Leaf, root1IsLeaf := root1.(*LeafNode)
	root2Leaf, root2IsLeaf := root2.(*LeafNode)

	if root1IsLeaf && root2IsLeaf {
		res := reflect.DeepEqual(root1Leaf.path, root2Leaf.path) && reflect.DeepEqual(root1Leaf.value, root2Leaf.value)
		if res == false {
			fmt.Println(root1Leaf, root2Leaf)
		}
		return res
	}

	fmt.Println(root1, root2)
	return false
}
