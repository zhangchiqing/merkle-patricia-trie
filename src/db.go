package mpt

type DB interface {
	Put(key []byte, value []byte) error
	Get(key []byte) (value []byte, err error)
	Delete(key []byte) error
}
