package mpt

// DB defines the methods that a dictionary type must define. It is not guaranteed that implementors of this
// interface are backed by persistent storage.
type DB interface {
	// Put puts the (key, value) pair in DB, overriding the previous pair with the same key, if it exists. It
	// returns an error if the change failed to be persisted (i.e., it will not be observable in the next `Get`
	// on this DB).
	Put(key []byte, value []byte) error

	// Get returns the value associated with key in DB, and nil otherwise. Get returns an error if the backing
	// store failed to accept the get. Note that Get does not return an error if there is no value associated with
	// key.
	Get(key []byte) (value []byte, err error)

	// Delete removes the key-value pair identified by key from DB. It returns an error if the change failed to
	// be persisted (i.e., it will not be observable in the next `Get` on this DB).
	Delete(key []byte) error
}
