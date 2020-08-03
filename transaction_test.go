package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestTransactionRootAndProof(t *testing.T) {

	trie := NewTrie()

	txs := TransactionsJSON(t)

	for i, tx := range txs {
		// key is the encoding of the index as the unsigned integer type
		key, err := rlp.EncodeToBytes(uint(i))
		require.NoError(t, err)

		transaction := FromEthTransaction(tx)

		// value is the RLP encoding of a transaction
		rlp, err := transaction.GetRLP()
		require.NoError(t, err)

		trie.Put(key, rlp)
	}

	// the transaction root for block 10467135
	// https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag=0x9fb73f&boolean=true&apikey=YourApiKeyToken
	transactionRoot, err := hex.DecodeString("bb345e208bda953c908027a45aa443d6cab6b8d2fd64e83ec52f1008ddeafa58")
	require.NoError(t, err)

	t.Run("merkle root hash should match with 10467135's transactionRoot", func(t *testing.T) {
		// transaction root should match with block 10467135's transactionRoot
		require.Equal(t, transactionRoot, trie.Hash())
	})

	t.Run("a merkle proof for a certain transaction can be verified by the offical trie implementation", func(t *testing.T) {
		key, err := rlp.EncodeToBytes(uint(30))
		require.NoError(t, err)

		proof, found := trie.Prove(key)
		require.Equal(t, true, found)

		txRLP, err := VerifyProof(transactionRoot, key, proof)
		require.NoError(t, err)

		// verify that if the verification passes, it returns the RLP encoded transaction
		rlp, err := FromEthTransaction(txs[30]).GetRLP()
		require.NoError(t, err)
		require.Equal(t, rlp, txRLP)
	})
}

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

func TestTrieWithOneTx(t *testing.T) {
	key, err := rlp.EncodeToBytes(uint(0))
	require.NoError(t, err)

	tx := TransactionJSON(t)

	transaction := FromEthTransaction(tx)
	rlp, err := transaction.GetRLP()
	require.NoError(t, err)

	trie := NewTrie()
	trie.Put(key, rlp)

	txRootHash := fmt.Sprintf("%x", types.DeriveSha(types.Transactions{tx}))
	require.Equal(t, txRootHash, fmt.Sprintf("%x", trie.Hash()))
}

func TestTrieWithTwoTxs(t *testing.T) {

	txs := TransactionsJSON(t)
	txs = txs[:2]

	fmt.Printf("tx0: %x\n", types.Transactions(txs).GetRlp(0))
	fmt.Printf("tx1: %x\n", types.Transactions(txs).GetRlp(1))
	trie := NewTrie()
	for i, tx := range txs {
		key, err := rlp.EncodeToBytes(uint(i))
		require.NoError(t, err)

		fmt.Printf("key %v: %x\n", i, key)
		transaction := FromEthTransaction(tx)

		rlp, err := transaction.GetRLP()
		require.NoError(t, err)

		trie.Put(key, rlp)
	}

	key, err := rlp.EncodeToBytes(uint(0))
	require.NoError(t, err)
	value, found := trie.Get(key)
	fmt.Printf("==0 value: %x, found: %v\n", value, found)

	key, err = rlp.EncodeToBytes(uint(1))
	require.NoError(t, err)
	value, found = trie.Get(key)
	fmt.Printf("==1 value: %x, found: %v\n", value, found)

	txRootHash := fmt.Sprintf("%x", types.DeriveSha(types.Transactions(txs)))
	require.Equal(t, txRootHash, fmt.Sprintf("%x", trie.Hash()))
}

func TestTrieWithHash(t *testing.T) {
	trie := NewTrie()
	key0, err := rlp.EncodeToBytes(uint(0))
	require.NoError(t, err)
	key1, err := rlp.EncodeToBytes(uint(1))
	require.NoError(t, err)
	tx0, err := hex.DecodeString("f9010c820144853fcf6e43c5830493e094897c3dec007e1bcd7b8dcc1f304c2246eea6853780b8a46b038dca0000000000000000000000004f2604aac91114ae3b3d0be485d407d02b24480b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000147d35700000000000000000000000000000000000000000000000000000000003b9ac9ff0000000000000000000000000000000000000000000000000000000000b5bc4d26a0d6537ab8b4f5161b07a53265b1fb7f73d84745911e6eb9ca11613a26ccf0c2f4a055b26eb0b1530a0da9ea1a29a322e2b6db0e374b313a0be397a598bda48e73b3")
	require.NoError(t, err)
	tx1, err := hex.DecodeString("f8a91c85126a21a08082a10594dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb000000000000000000000000cb9e24937d393373790a1e31af300e05a501d40c00000000000000000000000000000000000000000000000000000006a79eb58025a017ba02f156b099df4a73b1f2183943dc23d5deb24e0a50fb5ea33b90bff5f6cba06cff7c6c51c50b50c2e727aa31729e261ea9b92672a69863a89fe72f1968262a")
	require.NoError(t, err)
	trie.Put(key0, tx0)
	trie.Put(key1, tx1)
	require.Equal(t, "88796e4f9cfeca7b53f666e3103a1ba981b9445b78bf687788e1ad8976843d83", fmt.Sprintf("%x", trie.Hash()))
}

func TestTrieWithBlockTxs(t *testing.T) {
	txs := TransactionsJSON(t)

	trie := NewTrie()
	for i, tx := range txs {
		key, err := rlp.EncodeToBytes(uint(i))
		require.NoError(t, err)

		transaction := FromEthTransaction(tx)

		rlp, err := transaction.GetRLP()
		require.NoError(t, err)

		trie.Put(key, rlp)
	}

	txRootHash := fmt.Sprintf("%x", types.DeriveSha(types.Transactions(txs)))
	fmt.Printf("txRootHash: %v\n", txRootHash)
	require.Equal(t, txRootHash, fmt.Sprintf("%x", trie.Hash()))
}

func Test130Items(t *testing.T) {
	trie := NewTrie()
	value, _ := hex.DecodeString("80")
	for i := 0; i < 250; i++ {
		key, err := rlp.EncodeToBytes(uint(i))
		require.NoError(t, err)
		trie.Put(key, value)
		fmt.Printf("\"%x\", // %v\n", key, i)
	}

	fmt.Printf("root: %x\n", trie.Hash())
}
