package main

import (
	"fmt"
)

type MockDB struct {
	keyValueStore map[string][]byte
}

type MockOperation struct {
	op    string
	key   []byte
	value []byte
}

type MockDBBatch struct {
	operations []MockOperation
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

func (db *MockDB) NewBatch() DBBatch {
	return &MockDBBatch{}
}

func (db *MockDB) BatchWrite(batch DBBatch) error {
	for _, operation := range batch.(*MockDBBatch).operations {
		if operation.op == "DELETE" {
			delete(db.keyValueStore, fmt.Sprintf("%x", operation.key))
		} else if operation.op == "PUT" {
			db.keyValueStore[fmt.Sprintf("%x", operation.key)] = operation.value
		}
	}

	return nil
}

func (b *MockDBBatch) Put(key []byte, value []byte) {
	b.operations = append(b.operations, MockOperation{
		op:    "PUT",
		key:   key,
		value: value,
	})
}

func (b *MockDBBatch) Delete(key []byte) {
	b.operations = append(b.operations, MockOperation{
		op:    "DELETE",
		key:   key,
		value: nil,
	})
}
