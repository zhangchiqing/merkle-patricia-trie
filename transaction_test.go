package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestTransactionFromJSON(t *testing.T) {
	tx := TransactionJSON(t)
	require.Equal(t, uint64(0x144), tx.Nonce())

	transaction := FromEthTransaction(tx)
	receipt := common.HexToAddress("0x897c3dec007e1bcd7b8dcc1f304c2246eea68537")
	payload, err := hex.DecodeString("6b038dca0000000000000000000000004f2604aac91114ae3b3d0be485d407d02b24480b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000147d35700000000000000000000000000000000000000000000000000000000003b9ac9ff0000000000000000000000000000000000000000000000000000000000b5bc4d")
	require.NoError(t, err)
	r, ok := (new(big.Int)).SetString("d6537ab8b4f5161b07a53265b1fb7f73d84745911e6eb9ca11613a26ccf0c2f4", 16)
	require.True(t, ok)
	s, ok := (new(big.Int)).SetString("55b26eb0b1530a0da9ea1a29a322e2b6db0e374b313a0be397a598bda48e73b3", 16)
	require.True(t, ok)
	require.Equal(t, &Transaction{
		AccountNonce: uint64(0x144),
		Price:        (new(big.Int)).SetInt64(0x3fcf6e43c5),
		GasLimit:     0x493e0,
		Recipient:    &receipt,
		Amount:       (new(big.Int)).SetInt64(0x0),
		Payload:      payload,
		V:            (new(big.Int)).SetInt64(0x26),
		R:            r,
		S:            s,
	}, transaction)
}

func TestTransactionRLP(t *testing.T) {
	tx := TransactionJSON(t)

	transaction := FromEthTransaction(tx)
	rlp, err := transaction.GetRLP()
	require.NoError(t, err)

	var b bytes.Buffer
	buf := bufio.NewWriter(&b)
	err = tx.EncodeRLP(buf)
	require.NoError(t, err)
	require.NoError(t, buf.Flush())

	require.Equal(t, b.Bytes(), rlp)
}

func TestTransactions(t *testing.T) {
	txs := TransactionsJSON(t)
	tx := TransactionJSON(t)
	require.Equal(t, tx, txs[0])
}

func TransactionJSON(t *testing.T) *types.Transaction {
	jsonFile, err := os.Open("transaction.json")
	defer jsonFile.Close()
	require.NoError(t, err)
	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)
	var tx types.Transaction
	json.Unmarshal(byteValue, &tx)
	return &tx
}

func TransactionsJSON(t *testing.T) []*types.Transaction {
	jsonFile, err := os.Open("transactions.json")
	defer jsonFile.Close()
	require.NoError(t, err)
	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)
	var txs []*types.Transaction
	json.Unmarshal(byteValue, &txs)
	return txs
}

func FromEthTransaction(t *types.Transaction) *Transaction {
	v, r, s := t.RawSignatureValues()
	return &Transaction{
		AccountNonce: t.Nonce(),
		Price:        t.GasPrice(),
		GasLimit:     t.Gas(),
		Recipient:    t.To(),
		Amount:       t.Value(),
		Payload:      t.Data(),
		V:            v,
		R:            r,
		S:            s,
	}
}
