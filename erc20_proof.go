package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func GetSlotForMapKey(keyInMap []byte, slotIndexForMap int) [32]byte {
	return crypto.Keccak256Hash(
		keyInMap,
		common.LeftPadBytes(big.NewInt(int64(slotIndexForMap)).Bytes(), 32),
	)
}

func GetSlotForERC20TokenHolder(slotIndexForHoldersMap int, tokenHolder common.Address) [32]byte {
	return GetSlotForMapKey(common.LeftPadBytes(tokenHolder[:], 32), slotIndexForHoldersMap)
}

func GetSlotForArrayItem(slotIndexForArray int, indexInArray int, itemSize int) [32]byte {
	bytes := crypto.Keccak256Hash(common.LeftPadBytes(big.NewInt(int64(slotIndexForArray)).Bytes(), 32))
	arrayPos := new(big.Int).SetBytes(bytes[:])
	itemPos := arrayPos.Add(arrayPos, big.NewInt(int64(indexInArray*itemSize)))
	var pos [32]byte
	copy(pos[:], itemPos.Bytes()[:32])

	return pos
}
