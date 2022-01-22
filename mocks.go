package main

import "fmt"

type MockDB struct {
	keyValueStore map[string][]byte
}

func NewMockDB() *MockDB {
	return &MockDB{
		keyValueStore: make(map[string][]byte),
	}
}

func (db *MockDB) Put(key []byte, value []byte) (ok bool) {
	db.keyValueStore[fmt.Sprintf("%x", key)] = value
	return true
}

func (db *MockDB) Get(key []byte) (value []byte, ok bool) {
	value, isPresent := db.keyValueStore[fmt.Sprintf("%x", key)]
	return value, isPresent
}

func (db *MockDB) Delete(key []byte) (value []byte, ok bool) {
	if value, isPresent := db.keyValueStore[fmt.Sprintf("%x", key)]; isPresent {
		delete(db.keyValueStore, fmt.Sprintf("%x", key))
		return value, true
	} else {
		return nil, false
	}
}
