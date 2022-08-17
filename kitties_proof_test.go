package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func GetKittySlot(slotIndexForKitties int, kittyID int) [32]byte {
	return GetSlotForArrayItem(slotIndexForKitties, kittyID, 2)
}

func TestKittiesProof(t *testing.T) {
	slotIndexForKitties := 6
	ckContractAddress := common.HexToAddress("0x06012c8cf97bead5deae237070f9587f8e7a266d")
	blockNumber := uint64(15289000)
	fmt.Println(slotIndexForKitties)

	kittiesLengthProof, err := RequestEthGetProof(
		ckContractAddress,
		[]hexutil.Bytes{hexutil.Bytes{byte(slotIndexForKitties)}},
		blockNumber,
	)
	require.NoError(t, err)

	// verify the proof and get the decoded value
	kittiesLength, err := GetValueFromProof(kittiesLengthProof)
	require.NoError(t, err)

	require.Equal(t, "1eb85c", fmt.Sprintf("%x", kittiesLength)) // 2013276 kitties in total

	// https://etherscan.io/address/0x06012c8cf97bead5deae237070f9587f8e7a266d#readContract
	// getKitty(1) =>
	// [ getKitty(uint256) method Response ]
	// isGestating   bool :  false
	// isReady   bool :  true
	// cooldownIndex   uint256 :  0
	// nextActionAt   uint256 :  0
	// siringWithId   uint256 :  0
	// birthTime   uint256 :  1511417999
	// matronId   uint256 :  0
	// sireId   uint256 :  0
	// generation   uint256 :  0
	// genes   uint256 :  626837621154801616088980922659877168609154386318304496692374110716999053
	kitty1Slot := GetSlotForArrayItem(slotIndexForKitties, 1, 2)

	fmt.Println(fmt.Sprintf("kitty1 's data is stored at slot: %x", kitty1Slot))

	kitty1GenesProof, err := RequestEthGetProof(
		ckContractAddress,
		[]hexutil.Bytes{kitty1Slot[:]},
		blockNumber,
	)
	require.NoError(t, err)

	// verify the proof and get the decoded value
	kitty1Genes, err := GetValueFromProof(kitty1GenesProof)
	require.NoError(t, err)

	// 5ad2b318e6724ce4b9290146531884721ad18c63298a5308a55ad6b6b58d (hex) is the hex format of
	// uint256 genes value 626837621154801616088980922659877168609154386318304496692374110716999053 (uint256)
	require.Equal(t, "5ad2b318e6724ce4b9290146531884721ad18c63298a5308a55ad6b6b58d", fmt.Sprintf("%x", kitty1Genes))
}

// verify the proof and return value if the proof is valid
func GetValueFromProof(result *StorageStateResult) ([]byte, error) {
	// the storage hash and the proof is the data to be verified
	storageHash := result.StorageHash
	storageProof := result.StorageProof[0]

	// encode the key-value pair
	key := common.LeftPadBytes(storageProof.Key, 32)
	value, err := rlp.EncodeToBytes(storageProof.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid value: %w", err)
	}

	// build a trie with the nodes in the proof
	proofTrie := NewProofDB()
	for _, node := range storageProof.Proof {
		proofTrie.Put(crypto.Keccak256(node), node)
	}

	// verify the proof
	verified, err := VerifyProof(
		storageHash.Bytes(), crypto.Keccak256(key), proofTrie)
	if err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}

	// confirm the value from the proof is consistent with the reported value
	if !bytes.Equal(verified, value) {
		return nil, fmt.Errorf("invalid proof, %x != %x", verified, value)
	}

	return storageProof.Value, nil
}
