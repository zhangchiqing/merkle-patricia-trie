package mpt

import (
	"fmt"
)

type MockDB struct {
	keyValueStore map[string][]byte
}

func NewMockDB() *MockDB {
	return &MockDB{
		keyValueStore: make(map[string][]byte),
	}
}

func (db *MockDB) Put(key []byte, value []byte) error {
	db.keyValueStore[fmt.Sprintf("%x", key)] = value
	return nil
}

func (db *MockDB) Get(key []byte) (value []byte, err error) {
	value, isPresent := db.keyValueStore[fmt.Sprintf("%x", key)]
	if !isPresent {
		return nil, fmt.Errorf("key not found")
	} else {
		return value, nil
	}
}

func (db *MockDB) Delete(key []byte) error {
	delete(db.keyValueStore, fmt.Sprintf("%x", key))
	return nil
}
