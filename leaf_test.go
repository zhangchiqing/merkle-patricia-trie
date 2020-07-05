package main

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func printEachCalculationSteps(key, value []byte, isLeaf bool) map[string]string {
	hexs := make(map[string]string)
	hexs["key in nibbles"] = fmt.Sprintf("%x", FromBytes(key))
	hexs["key in nibbles, and prefixed"] = fmt.Sprintf("%x", ToPrefixed(FromBytes(key), isLeaf))
	hexs["key in nibbles, and prefixed, and convert back to buffer"] =
		fmt.Sprintf("%x", ToBytes(ToPrefixed(FromBytes(key), isLeaf)))
	beforeRLP := [][]byte{ToBytes(ToPrefixed(FromBytes(key), isLeaf)), value}
	hexs["beforeRLP"] = fmt.Sprintf("%x", beforeRLP)
	afterRLP, err := rlp.EncodeToBytes(beforeRLP)
	if err != nil {
		panic(err)
	}
	hexs["afterRLP"] = fmt.Sprintf("%x", afterRLP)
	hexs["hash"] = fmt.Sprintf("%x", crypto.Keccak256(afterRLP))
	return hexs
}

func TestLeafHash(t *testing.T) {
	require.Equal(t, "01020304", fmt.Sprintf("%x", []byte{1, 2, 3, 4}))
	require.Equal(t, "76657262", fmt.Sprintf("%x", []byte("verb")))

	// "buffer to nibbles
	require.Equal(t, "0001000200030004", fmt.Sprintf("%x", FromBytes([]byte{1, 2, 3, 4})))

	// ToPrefixed
	require.Equal(t, "02000001000200030004", fmt.Sprintf("%x", ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true)))

	// ToBuffer
	require.Equal(t, "2001020304", fmt.Sprintf("%x", ToBytes(ToPrefixed(FromBytes([]byte{1, 2, 3, 4}), true))))

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
