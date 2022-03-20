package mpt

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestIntegrationWithLevelDB(t *testing.T) {
	os.RemoveAll("./test_db")

	t.Run("persist trie in LevelDB", func(t *testing.T) {
		levelDB, err := leveldb.OpenFile("./test_db", nil)
		if err != nil {
			panic(err)
		}

		defer levelDB.Close()

		database := NewDatabase(levelDB)

		trie := NewTrie()

		trie.Put([]byte{1, 2, 3, 4}, []byte("verb"))
		trie.Put([]byte{1, 2, 3, 4, 5, 6}, []byte("coin"))

		trie.PersistInDB(database)

		storedRoot, err := database.Get([]byte("root"))
		if err != nil {
			panic(err)
		}

		hexEqual(t, "64d67c5318a714d08de6958c0e63a05522642f3f1087c6fd68a97837f203d359", crypto.Keccak256(storedRoot))

		ext, ok := trie.root.(*ExtensionNode)
		require.True(t, ok)
		branch, ok := ext.Next.(*BranchNode)
		require.True(t, ok)
		leaf, ok := branch.Branches[0].(*LeafNode)
		require.True(t, ok)

		expectedKeyValueStore := map[string][]byte{
			fmt.Sprintf("%x", "root"):        ext.Serialize(),
			fmt.Sprintf("%x", branch.Hash()): branch.Serialize(),
			fmt.Sprintf("%x", leaf.Hash()):   leaf.Serialize(),
		}

		actualKeyValueStore := make(map[string][]byte)

		iter := database.keyValueDB.NewIterator(nil, nil)
		for iter.Next() {
			key := iter.Key()
			value, _ := database.Get(key)
			actualKeyValueStore[fmt.Sprintf("%x", key)] = value
		}
		iter.Release()
		err = iter.Error()
		if err != nil {
			panic(err)
		}

		require.True(t, reflect.DeepEqual(expectedKeyValueStore, actualKeyValueStore))

		os.RemoveAll("./test_db")
	})

	t.Run("generate trie from LevelDB content", func(t *testing.T) {
		trie := NewTrie()

		trie.Put([]byte{1, 2, 3, 4}, []byte("verb"))
		trie.Put([]byte{1, 2, 3, 4, 5, 6}, []byte("coin"))
		trie.Put([]byte{1, 2, 3, 10}, []byte("crash"))

		levelDB, err := leveldb.OpenFile("./test_db", nil)
		if err != nil {
			panic(err)
		}

		defer levelDB.Close()

		database := NewDatabase(levelDB)

		trie.PersistInDB(database)

		newTrie := NewTrie()
		newTrie.NewTrieFromDB(database)
		require.Equal(t, trie.root.Hash(), newTrie.root.Hash())

		require.True(t, reflect.DeepEqual(trie, newTrie))
	})

	t.Cleanup(func() {
		os.RemoveAll("./test_db")
	})
}
