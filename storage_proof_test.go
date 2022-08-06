package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestStorageTrie(t *testing.T) {
	// slot index
	slot0 := common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000000") // 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
	slot1 := common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000001") // 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6

	// encode values to be stored
	ownerAddress, err := rlp.EncodeToBytes(common.FromHex("0xde74da73d5102a796559933296c73e7d1c6f37fb"))
	require.NoError(t, err)

	lastCompletedMigration, err := rlp.EncodeToBytes(common.FromHex("0x02"))
	require.NoError(t, err)

	// create a trie and store the key-value pairs, the key needs to be hashed
	trie := NewTrie()
	trie.Put(crypto.Keccak256(slot0), ownerAddress)
	trie.Put(crypto.Keccak256(slot1), lastCompletedMigration)

	// compute the root hash and check if consistent with the storage hash of contract 0xcca577ee56d30a444c73f8fc8d5ce34ed1c7da8b
	rootHash := trie.Hash()
	storageHash := common.FromHex("0x7317ebbe7d6c43dd6944ed0e2c5f79762113cb75fa0bed7124377c0814737fb4")
	require.Equal(t, storageHash, rootHash)
}

func TestContractStateProof(t *testing.T) {
	// curl https://eth-mainnet.g.alchemy.com/v2/<API_KEY> \
	//       -X POST \
	//       -H "Content-Type: application/json" \
	//       -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xcca577ee56d30a444c73f8fc8d5ce34ed1c7da8b",["0x0"], "0xA8894B"],"id":1}'

	jsonFile, err := os.Open("storage_proof_slot_0.json")
	require.NoError(t, err)

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)

	// load into the struct
	var response EthGetProofResponse
	err = json.Unmarshal(byteValue, &response)
	require.NoError(t, err)

	result := response.Result

	account := common.HexToAddress("0xcca577ee56d30a444c73f8fc8d5ce34ed1c7da8b")
	fmt.Println(fmt.Sprintf("decoded account state data from untrusted source for address %x: balance is %x, nonce is %x, codeHash: %x, storageHash: %x",
		account, result.Balance, result.Nonce, result.CodeHash, result.StorageHash))

	// get the state root hash from etherscan: https://etherscan.io/block/11045195
	stateRootHash := common.HexToHash("0x8c571da4c95e212e508c98a50c2640214d23f66e9a591523df6140fd8d113f29")

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

	// now we can trust the data in StorageStateResult
}

func TestContractStorageProofSlot0(t *testing.T) {
	// curl https://eth-mainnet.g.alchemy.com/v2/<API_KEY> \
	//       -X POST \
	//       -H "Content-Type: application/json" \
	//       -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xcca577ee56d30a444c73f8fc8d5ce34ed1c7da8b",["0x0"], "0xA8894B"],"id":1}'

	// Read storage proof
	jsonFile, err := os.Open("storage_proof_slot_0.json")
	require.NoError(t, err)

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)

	// parse the proof
	var response EthGetProofResponse
	err = json.Unmarshal(byteValue, &response)
	require.NoError(t, err)

	result := response.Result

	// the storage hash and the proof is the data to be verified
	storageHash := result.StorageHash
	storageProof := result.StorageProof[0]

	// encode the key-value pair
	key := common.LeftPadBytes(storageProof.Key, 32)
	value, err := rlp.EncodeToBytes(storageProof.Value)
	require.NoError(t, err)

	// build a trie with the nodes in the proof
	proofTrie := NewProofDB()
	for _, node := range storageProof.Proof {
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	// verify the proof
	verified, err := VerifyProof(
		storageHash.Bytes(), crypto.Keccak256(key), proofTrie)
	require.NoError(t, err)

	// confirm the value from the proof is consistent with the reported value
	require.True(t, bytes.Equal(verified, value), fmt.Sprintf("%x != %x", verified, value))
}

func TestContractStorageProofSlot1(t *testing.T) {
	// curl https://eth-mainnet.g.alchemy.com/v2/<API_KEY> \
	//       -X POST \
	//       -H "Content-Type: application/json" \
	//       -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xcca577ee56d30a444c73f8fc8d5ce34ed1c7da8b",["0x1"], "0xA8894B"],"id":1}'

	jsonFile, err := os.Open("storage_proof_slot_1.json")
	require.NoError(t, err)

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)

	fmt.Println("loaded eip1186_proof")

	// load into the struct
	var response EthGetProofResponse
	err = json.Unmarshal(byteValue, &response)
	require.NoError(t, err)

	result := response.Result

	storageHash := result.StorageHash
	storageProof := result.StorageProof[0]
	value, err := rlp.EncodeToBytes(storageProof.Value)
	require.NoError(t, err)
	// 0x0000000000000000000000000000000000000000000000000000000000000000
	key := common.LeftPadBytes(storageProof.Key, 32)

	proofTrie := NewProofDB()
	for _, node := range storageProof.Proof {
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	verified, err := VerifyProof(
		storageHash.Bytes(), crypto.Keccak256(key), proofTrie)

	require.NoError(t, err)
	require.True(t, bytes.Equal(verified, value), fmt.Sprintf("%x != %x", verified, value))
}
