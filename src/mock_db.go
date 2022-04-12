package mpt

import (
	"fmt"
)

// MockDB is a simple implementation of the `DB` interfaces that is used for tests.
// It does not write values in persistent storage.
type MockDB struct {
	keyValueStore map[string][]byte
}

// NewMockDB returns a pointer to an empty MockDB.
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
		return nil, nil
	} else {
		return value, nil
	}
}

func (db *MockDB) Delete(key []byte) error {
	delete(db.keyValueStore, fmt.Sprintf("%x", key))
	return nil
}
