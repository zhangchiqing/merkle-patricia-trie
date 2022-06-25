package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

type AccountStateResult struct {
	Nonce        hexutil.Uint64  `json:"nonce"`
	Balance      *hexutil.Big    `json:"balance"`
	StorageHash  common.Hash     `json:"storageHash"`
	CodeHash     common.Hash     `json:"codeHash"`
	AccountProof []hexutil.Bytes `json:"accountProof"`
}

type EthRPCGetProofResponse struct {
	Result AccountStateResult `json:"result"`
}

func TestEIP1186Proof(t *testing.T) {

	// open the downloaded proof data that is requested from eth_getProof RPC call
	// using the following query to get the json data:
	// curl https://eth-mainnet.alchemyapi.io/v2/<alchemy_api_key> \
	// -X POST \
	// -H "Content-Type: application/json" \
	// -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xB856af30B938B6f52e5BfF365675F358CD52F91B",[],"0xE35B21"],"id":1}' | jq .

	jsonFile, err := os.Open("eip1186_proof.json")
	require.NoError(t, err)

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)

	fmt.Println("loaded eip1186_proof")

	// load into the struct
	var response EthRPCGetProofResponse
	err = json.Unmarshal(byteValue, &response)
	require.NoError(t, err)

	result := response.Result

	account := common.HexToAddress("0xB856af30B938B6f52e5BfF365675F358CD52F91B")
	fmt.Println(fmt.Sprintf("decoded account state data from untrusted source for address %x: balance is %x, nonce is %x, codeHash: %x, storageHash: %x",
		account, result.Balance, result.Nonce, result.CodeHash, result.StorageHash))

	// get the state root hash from etherscan: https://etherscan.io/block/14900001
	stateRootHash := common.HexToHash("0x024c056bc5db60d71c7908c5fad6050646bd70fd772ff222702d577e2af2e56b")

	// create a proof trie, and add each node from the account proof
	proofTrie := NewProofDB()
	for _, node := range result.AccountProof {
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	// verify the proof against the stateRootHash
	validAccountState, err := VerifyProof(
		stateRootHash.Bytes(), crypto.Keccak256(account.Bytes()), proofTrie)
	require.NoError(t, err)

	// double check the account state is identical with the account state in the result.
	accountState, err := rlp.EncodeToBytes([]interface{}{
		result.Nonce,
		result.Balance.ToInt(),
		result.StorageHash,
		result.CodeHash,
	})
	require.NoError(t, err)
	require.True(t, bytes.Equal(validAccountState, accountState), fmt.Sprintf("%x!=%x", validAccountState, accountState))

	// now we can trust the data in AccountStateResult
}
