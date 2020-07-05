package main

import "encoding/hex"

var (
	EmptyNodeRaw     = []byte{}
	EmptyNodeHash, _ = hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

func IsEmptyNode(node Node) bool {
	return node == nil
}
