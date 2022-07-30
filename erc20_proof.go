package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func GetSlotForMapKey(slotIndexForMap int, keyInMap []byte) [32]byte {
	return crypto.Keccak256Hash(
		keyInMap,
		common.LeftPadBytes(big.NewInt(int64(slotIndexForMap)).Bytes(), 32),
	)
}

func GetSlotForERC20TokenHolder(slotIndexForHoldersMap int, tokenHolder common.Address) [32]byte {
	return GetSlotForMapKey(slotIndexForHoldersMap, common.LeftPadBytes(tokenHolder[:], 32))
}
