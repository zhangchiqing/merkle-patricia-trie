package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

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
