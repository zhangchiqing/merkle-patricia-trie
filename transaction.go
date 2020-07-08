package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type Transaction struct {
	AccountNonce uint64          `json:"nonce"    `
	Price        *big.Int        `json:"gasPrice" `
	GasLimit     uint64          `json:"gas"      `
	Recipient    *common.Address `json:"to"       `
	Amount       *big.Int        `json:"value"    `
	Payload      []byte          `json:"input"    `

	// Signature values
	V *big.Int `json:"v" `
	R *big.Int `json:"r" `
	S *big.Int `json:"s" `
}

func (t Transaction) GetRLP() ([]byte, error) {
	return rlp.EncodeToBytes(t)
}
