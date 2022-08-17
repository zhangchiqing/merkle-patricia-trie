package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestERC20(t *testing.T) {

	erc20Address := common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenHolder := common.HexToAddress("0x467d543e5e4e41aeddf3b6d1997350dd9820a173")
	slotIndex, result, err := FindBalanceForERC20TokenHolder(erc20Address, tokenHolder, 15245000)
	require.NoError(t, err)
	fmt.Println(fmt.Sprintf("slot index %v", slotIndex))

	err = VerifyStorageProof(result)
	require.NoError(t, err)

	// convert hex to bigInt
	balance := new(big.Int).SetBytes(result.StorageProof[0].Value)

	fmt.Println(fmt.Sprintf("the balance of token holder %x for contract %x's %v", tokenHolder, erc20Address, balance))
}

func VerifyStorageProof(result *StorageStateResult) error {
	storageHash := result.StorageHash
	storageProof := result.StorageProof[0]
	value, err := rlp.EncodeToBytes(storageProof.Value)
	if err != nil {
		return fmt.Errorf("fail to encode value: %w", err)
	}
	key := common.LeftPadBytes(storageProof.Key, 32)
	proofTrie := NewProofDB()
	for _, node := range storageProof.Proof {
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	verified, err := VerifyProof(
		storageHash.Bytes(), crypto.Keccak256(key), proofTrie)

	if err != nil {
		return fmt.Errorf("invalid storage proof: %w", err)
	}

	if !bytes.Equal(verified, value) {
		return fmt.Errorf("invalid proof %x != %x", verified, value)
	}
	return nil
}

func FindBalanceForERC20TokenHolder(contractAddress common.Address, tokenHolder common.Address, blockNumber uint64) (int, *StorageStateResult, error) {
	// iterate through each slot index until found some data stored in the computed location
	for i := 0; i < 20; i++ {
		result, err := FindBalanceForERC20TokenHolderAtSlot(contractAddress, tokenHolder, blockNumber, i)
		if err != nil {
			return 0, nil, err
		}

		if len(result.StorageProof) == 0 {
			continue
		}

		proof := result.StorageProof[0]

		if len(proof.Value) == 0 {
			continue
		}

		return i, result, nil
	}
	return 0, nil, fmt.Errorf("not found")
}

func FindBalanceForERC20TokenHolderAtSlot(contractAddress common.Address, tokenHolder common.Address, blockNumber uint64, slotIndex int) (*StorageStateResult, error) {
	slot := GetSlotForERC20TokenHolder(slotIndex, tokenHolder)
	fmt.Println(
		fmt.Sprintf("if slot index for map is %v, 0x467d543e5e4e41aeddf3b6d1997350dd9820a173 's token is stored at %x",
			slotIndex, slot),
	)

	result, err := RequestEthGetProof(
		contractAddress,
		[]hexutil.Bytes{hexutil.Bytes(slot[:])},
		15245000,
	)
	if err != nil {
		return nil, fmt.Errorf("could not get proof for token holder %v in contract %v: %w", tokenHolder, contractAddress, err)
	}

	return result, nil
}

func RequestEthGetProof(contractAddress common.Address, keys []hexutil.Bytes, blockNumber uint64) (*StorageStateResult, error) {

	// ▸ curl https://eth-mainnet.g.alchemy.com/v2/ \
	//            -X POST \
	//            -H "Content-Type: application/json" \
	//            -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",["0x4065d4ec50c2a4fc400b75cca2760227b773c3e315ed2f2a7784cd505065cb07"], "0xE89D2E"],"id":1}' | jq .

	keysData := make([]string, 0, len(keys))
	for _, k := range keys {
		keysData = append(keysData, k.String())
	}
	data := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getProof",
		"params": []interface{}{
			contractAddress.String(),         // erc20 token contract address
			keysData,                         // slot for token holder balance
			fmt.Sprintf("0x%x", blockNumber), // hex encoded block number
		},
	}

	payload := new(bytes.Buffer)
	json.NewEncoder(payload).Encode(data)

	resp, err := http.Post(
		"https://eth-mainnet.g.alchemy.com/v2/sljmVCoQ7nCZGHYf_3SAvSLpq0zUEhdd",
		"application/json",
		payload,
	)
	if err != nil {
		return nil, fmt.Errorf("fail to get response: %w", err)
	}
	defer resp.Body.Close()

	var response EthGetProofResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("fail to parse response: %w", err)
	}

	return &response.Result, nil
}
