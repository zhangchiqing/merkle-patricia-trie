package mpt

type DB interface {
	Put(key []byte, value []byte) error

	// Get must not return an error if there is no value associated with a key.
	Get(key []byte) (value []byte, err error)

	Delete(key []byte) error
}
