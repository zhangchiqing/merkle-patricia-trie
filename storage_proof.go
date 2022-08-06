package main

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type StorageStateResult struct {
	Nonce        hexutil.Uint64  `json:"nonce"`
	Balance      *hexutil.Big    `json:"balance"`
	StorageHash  common.Hash     `json:"storageHash"`
	CodeHash     common.Hash     `json:"codeHash"`
	StorageProof []StorageProof  `json:"storageProof"`
	AccountProof []hexutil.Bytes `json:"accountProof"`
}

type StorageProof struct {
	Key   HexNibbles      `json:"key"`
	Value HexNibbles      `json:"value"`
	Proof []hexutil.Bytes `json:"proof"`
}

type HexNibbles []byte

func (n HexNibbles) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("0x%v",
		new(big.Int).SetBytes(n).Text(16))), nil
}

func (n *HexNibbles) UnmarshalText(input []byte) error {
	input = bytes.TrimPrefix(input, []byte("0x"))
	v, ok := new(big.Int).SetString(string(input), 16)
	if !ok {
		return fmt.Errorf("invalid hex input")
	}
	*n = v.Bytes()
	return nil
}

type EthGetProofResponse struct {
	Result StorageStateResult `json:"result"`
}
