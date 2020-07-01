package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtensionNode(t *testing.T) {
	nibbles, value := []byte{5, 0, 6}, []byte("coin")
	leaf, err := NewLeafNodeFromNibbleBytes(nibbles, value)
	require.NoError(t, err)

	b := NewBranchNode()
	b.SetBranch(0, leaf)
	b.SetValue([]byte("verb")) // set the value for verb

	ns, err := FromNibbleBytes([]byte{0, 1, 0, 2, 0, 3, 0, 4})
	require.NoError(t, err)
	e := NewExtensionNode(ns, b)
	require.Equal(t, "e4850001020304ddc882350684636f696e8080808080808080808080808080808476657262", fmt.Sprintf("%x", e.Serialize()))
	require.Equal(t, "64d67c5318a714d08de6958c0e63a05522642f3f1087c6fd68a97837f203d359", fmt.Sprintf("%x", e.Hash()))
}
