package main

import "github.com/ethereum/go-ethereum/crypto"

func (b BranchNode) Hash() []byte {
	return crypto.Keccak256(b.Serialize())
}

func (b BranchNode) Raw() []byte {
	return nil
}

func (b BranchNode) Serialize() []byte {
	return nil
	// rlp.EncodeToBytes(buf, b.Raw())
	// return buf
}
