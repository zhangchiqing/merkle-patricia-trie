package mpt

import (
	"github.com/syndtr/goleveldb/leveldb"
)

type DB interface {
	Put(key []byte, value []byte) error
	Get(key []byte) (value []byte, err error)
	Delete(key []byte) error
}

type Database struct {
	keyValueDB *leveldb.DB
}

func NewDatabase(levelDB *leveldb.DB) *Database {
	return &Database{keyValueDB: levelDB}
}

func (db *Database) Put(key []byte, value []byte) error {
	err := db.keyValueDB.Put(key, value, nil)
	return err
}

func (db *Database) Get(key []byte) (value []byte, err error) {
	data, err := db.keyValueDB.Get(key, nil)
	return data, err
}

func (db *Database) Delete(key []byte) error {
	err := db.keyValueDB.Delete(key, nil)
	return err
}
