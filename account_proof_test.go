package main

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

type AccountState struct {
	Nonce       hexutil.Uint64 `json:"nonce"`
	Balance     *hexutil.Big   `json:"balance"`
	StorageHash common.Hash    `json:"storageHash"`
	CodeHash    common.Hash    `json:"codeHash"`
}

func TestStorageProof(t *testing.T) {
	// 1ee3017a85544556ea847c203623a9c84efdb77fa4951a5b01296d9aacefc5f7
	account1Hash := crypto.Keccak256(common.HexToAddress("0x24264ae01b1abbc9a91e18926818ad5cbf39017b").Bytes())
	accountState1, err := rlp.EncodeToBytes([]interface{}{
		uint64(1),                     // Nonce
		(new(big.Int)).SetInt64(1e18), // 1 ETH
		EmptyNodeHash,                 // Empty StorageHash
		crypto.Keccak256([]byte("")),  // Empty CodeHash
	})
	require.NoError(t, err)

	// 1eeced8d7a011c27d9aed60517c8e596509852f1d208a8a6d6f16d17ea5da204
	account2Hash := crypto.Keccak256(common.HexToAddress("0x3a844bb6252b584f76febb40c941ec898df9bc23").Bytes())
	accountState2, err := rlp.EncodeToBytes([]interface{}{
		uint64(3),                     // Nonce
		(new(big.Int)).SetInt64(2e18), // 2 ETH
		EmptyNodeHash,                 // Empty StorageHash
		crypto.Keccak256([]byte("")),  // Empty CodeHash
	})
	require.NoError(t, err)

	// the above two account hashes have some common part at the beginning: "1ee",
	// which will become extension node when storing into merkle trie

	// create a world state with the two accounts
	worldStateTrie := NewTrie()
	worldStateTrie.Put(account1Hash, accountState1)
	worldStateTrie.Put(account2Hash, accountState2)

	// compute the state root hash
	stateRoot := worldStateTrie.Hash()

	// create proof for account1's state
	accountState1Proof, ok := worldStateTrie.Prove(account1Hash)
	require.True(t, ok)

	serialized := accountState1Proof.Serialize()

	// print the proof
	for _, node := range serialized {
		fmt.Println(fmt.Sprintf("proof node: %x", node))
	}

	// create a proof trie, and add each node from the serialized proof
	proofTrie := NewProofDB()
	for _, node := range serialized {
		// store each node under its hash
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	// verify the proof against the stateRoot
	validAccountState, err := VerifyProof(stateRoot, account1Hash, proofTrie)
	require.NoError(t, err)

	// double check the account state is identical with the original account state.
	require.True(t, bytes.Equal(validAccountState, accountState1))
}
