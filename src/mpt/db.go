package mpt

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type DB interface {
	Put(key []byte, value []byte) error
	Get(key []byte) (value []byte, err error)
	Delete(key []byte) error
	NewBatch() DBBatch
	BatchWrite(batch DBBatch) error
}

type DBBatch interface {
	Put(key []byte, value []byte)
	Delete(key []byte)
}

type Database struct {
	keyValueDB *leveldb.DB
}

type Batch struct {
	keyValueBatch *leveldb.Batch
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

func (db *Database) NewBatch() DBBatch {
	return &Batch{keyValueBatch: new(leveldb.Batch)}
}

func (db *Database) BatchWrite(batch DBBatch) error {
	err := db.keyValueDB.Write(batch.(*Batch).keyValueBatch, &opt.WriteOptions{Sync: true})
	return err
}

func (b *Batch) Put(key []byte, value []byte) {
	b.keyValueBatch.Put(key, value)
}

func (b *Batch) Delete(key []byte) {
	b.keyValueBatch.Delete(key)
}
