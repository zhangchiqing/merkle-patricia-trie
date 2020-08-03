![Go](https://github.com/zhangchiqing/merkle-patricia-trie/workflows/Go/badge.svg)

## Intro
This is a simplified implementation of Ethereum's modified Merkle Patricia Trie in golang based on the [Ethereum's yellow paper](https://ethereum.github.io/yellowpaper/paper.pdf).

- This implementation is simple because it doesn't involve tree encoding/decoding, data persistence.
- Its purely focused on the algorithm and data structure.
- It's not made for production use, but for learning purpose.

This repo also includes a tutorial of how Merkle Patrica Trie works.

## A basic key-value mapping
Ethereum's Merkle Patricia Trie is essentially a key-value mapping that provides the following standard methods:

```golang
type Trie interface {
  // methods as a basic key-value mapping
  Get(key []byte) ([]byte, bool) {
  Put(key []byte, value []byte)
  Del(key []byte, value []byte) bool
}
```

An implementation of the above Trie interface should pass the following test cases:

```golang
func TestGetPut(t *testing.T) {
	t.Run("should get nothing if key does not exist", func(t *testing.T) {
		trie := NewTrie()
		_, found := trie.Get([]byte("notexist"))
		require.Equal(t, false, found)
	})

	t.Run("should get value if key exist", func(t *testing.T) {
		trie := NewTrie()
		trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
		val, found := trie.Get([]byte{1, 2, 3, 4})
		require.Equal(t, true, found)
		require.Equal(t, val, []byte("hello"))
	})

	t.Run("should get updated value", func(t *testing.T) {
		trie := NewTrie()
		trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
		trie.Put([]byte{1, 2, 3, 4}, []byte("world"))
		val, found := trie.Get([]byte{1, 2, 3, 4})
		require.Equal(t, true, found)
		require.Equal(t, val, []byte("world"))
	})
}
```

(Test cases in this tutorial are included in the repo and passed.)

## Verify Data Integrity
What's different from a standard mapping is that it allows us to verify data integrity.

One can compute the Merkle Root Hash of the Merkle Patricia Trie with the `Hash` function, such that if any key-value pair was updated, the merkle root hash of the Trie would be different; if two Tries have the idential key-value pairs, they should have the same merkle root hash.

```
type Trie interface {
  // compute the merkle root hash for verifying data integrity
  Hash() []byte
}
```

Let's explain this behavior with some test cases:
```golang
// verify data integrity
func TestDataIntegrity(t *testing.T) {
	t.Run("should get a different hash if a new key-value pair was added or updated", func(t *testing.T) {
		trie := NewTrie()
		hash0 := trie.Hash()

		trie.Put([]byte{1, 2, 3, 4}, []byte("hello"))
		hash1 := trie.Hash()

		trie.Put([]byte{1, 2}, []byte("world"))
		hash2 := trie.Hash()

		trie.Put([]byte{1, 2}, []byte("trie"))
		hash3 := trie.Hash()

		require.NotEqual(t, hash0, hash1)
		require.NotEqual(t, hash1, hash2)
		require.NotEqual(t, hash2, hash3)
	})

	t.Run("should get the same hash if two tries have the identicial key-value pairs", func(t *testing.T) {
		trie1 := NewTrie()
		trie1.Put([]byte{1, 2, 3, 4}, []byte("hello"))
		trie1.Put([]byte{1, 2}, []byte("world"))

		trie2 := NewTrie()
		trie2.Put([]byte{1, 2, 3, 4}, []byte("hello"))
		trie2.Put([]byte{1, 2}, []byte("world"))

		require.Equal(t, trie1.Hash(), trie2.Hash())
	})
}
```

## Verify the inclusion of a key-value pair
Yes, we can verify the data integrity with the merkle root hash, but we could simply hash the list of key-value pairs, why bother creating merkle patricia trie data structure?

That's because merkle patricia trie also allows us to verify the inclusion of a key-value pair without the access to the entire key-value pairs.

That means merkle patricia trie can provide a proof to prove that a certain key-value pair is included in a key-value mapping with a certain merkle root hash.

```golang
type Proof interface {}

type Trie interface {
  // generate a merkle proof for a key-value pair for verifying the inclusion of the key-value pair
  Prove(key []byte) (Proof, bool)
}

// verify the proof for the given key with the given merkle root hash
func VerifyProof(rootHash []byte, key []byte, proof Proof) (value []byte, err error)
```

This is useful in Ethereum. For instance, imagine the world state is a key-value mapping, and the keys are each account address, and the values are the balance for each account.

As a light Client, which don't have the access to the full blockchain state like full nodes do, but only the merkle root hash, how can it trust the result of its account balance returned from a full node?

The answer is, a full node can provide a merkle proof which contains the merkle root hash, the account key and its balance value, as well as other data. This merkle proof allows a light client to verify the correctness by its own without having access to the full blockchain state.

Let's explain the behavior with the following test cases:

```golang
func TestProveAndVerifyProof(t *testing.T) {
	t.Run("should not generate proof for non-exist key", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))
		notExistKey := []byte{1, 2, 3, 4}
		_, ok := tr.Prove(notExistKey)
		require.False(t, ok)
	})

	t.Run("should generate a proof for an existing key, the proof can be verified with the merkle root hash", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))

		key := []byte{1, 2, 3}
		proof, ok := tr.Prove(key)
		require.True(t, ok)

		rootHash := tr.Hash()

		// verify the proof with the root hash, the key in question and its proof
		val, err := VerifyProof(rootHash, key, proof)
		require.NoError(t, err)

		// when the verification has passed, it should return the correct value for the key
		require.Equal(t, []byte("hello"), val)
	})

	t.Run("should fail the verification if the trie was updated", func(t *testing.T) {
		tr := NewTrie()
		tr.Put([]byte{1, 2, 3}, []byte("hello"))
		tr.Put([]byte{1, 2, 3, 4, 5}, []byte("world"))

		// the hash was taken before the trie was updated
		rootHash := tr.Hash()

		// the proof was generated after the trie was updated
		tr.Put([]byte{5, 6, 7}, []byte("trie"))
		key := []byte{1, 2, 3}
		proof, ok := tr.Prove(key)
		require.True(t, ok)

		// should fail the verification since the merkle root hash doesn't match
		_, err := VerifyProof(rootHash, key, proof)
		require.Error(t, err)
	})
}
```

A light client can ask for a merkle root hash of the trie state, and use it to verify the balance of its account. If the trie was updated, even if the updates was to other keys, then the verification would fail.

And now, the light client only needs to trust the merkle root hash, which is a small piece of data, to convince themselves whether the full node returned the correct balance for its account.

OK, but why should the light client trust the merkle root hash?

Since Ethereum's consensus mechanism is Proof of Work, and the merkle root hash for the world state is included in each block head, the computation work is the proof for verifying/trusting the merkle root hash.

It's pretty cool that small as the merkle root hash can be used to verify the state of a giant key-value mapping.

## Verify the implementation

I've explained how merkle patrica trie works. This repo provides a simple implementation of the Merkle Patricia Trie. I recommend you to implement it yourself too.

But, how can we verify our implementation?

An easy way is to verify with the Ethereum mainnet data and the official Trie implementation in golang.

Ethereum has 3 Merkle Patricia Tries: Transaction Trie, Receipt Trie and State Trie. In each block header, it includes the 3 merkle root hashes: `transactionRoot`, `receiptRoot` and the `stateRoot`.

Since the `transactionRoot` is the merkle root hash of all the transactions included in the block, we could verify our implemenation by taking all the transactions, then store them in our trie, compute its merkle root hash, and in the end compare it with the `transactionRoot` in the block header.

For instance, I picked the [block 10467135 on mainnet](https://etherscan.io/block/10467135), and saved all the 193 transactions into a [transactions.json](./transactions.json) file.

Since the transaction root for block `10467135` is [`0xbb345e208bda953c908027a45aa443d6cab6b8d2fd64e83ec52f1008ddeafa58`](https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag=0x9fb73f&boolean=true&apikey=YourApiKeyToken). I can create a test case that adds the 193 transactions of block 10467135 to our Trie and check:

1) If the merkle root hash is ``.
2) Whether a merkle proof for a certain transaction generated from our implementation could be verified by the official implementation.

But what would be the keys and values for the list of transactions? The keys are the RLP encoding of a unsigned integer starting from index 0; the values are the RLP encoding of the cooresponding transactions.

OK, let's see the test cases:

```golang
import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// use the official golang implementation to check if a valid proof from our implementation can be accepted
func VerifyProof(rootHash []byte, key []byte, proof Proof) (value []byte, err error) {
	return trie.VerifyProof(common.BytesToHash(rootHash), key, proof)
}

// load transaction from json
func TransactionJSON(t *testing.T) *types.Transaction {
	jsonFile, err := os.Open("transaction.json")
	defer jsonFile.Close()
	require.NoError(t, err)
	byteValue, err := ioutil.ReadAll(jsonFile)
	require.NoError(t, err)
	var tx types.Transaction
	json.Unmarshal(byteValue, &tx)
	return &tx
}

func TestTransactionRootAndProof(t *testing.T) {

	trie := NewTrie()

	txs := TransactionsJSON(t)

	for i, tx := range txs {
		// key is the encoding of the index as the unsigned integer type
		key, err := rlp.EncodeToBytes(uint(i))
		require.NoError(t, err)

		transaction := FromEthTransaction(tx)

		// value is the RLP encoding of a transaction
		rlp, err := transaction.GetRLP()
		require.NoError(t, err)

		trie.Put(key, rlp)
	}

	// the transaction root for block 10467135
	// https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag=0x9fb73f&boolean=true&apikey=YourApiKeyToken
	transactionRoot, err := hex.DecodeString("bb345e208bda953c908027a45aa443d6cab6b8d2fd64e83ec52f1008ddeafa58")
	require.NoError(t, err)

	t.Run("merkle root hash should match with 10467135's transactionRoot", func(t *testing.T) {
		// transaction root should match with block 10467135's transactionRoot
		require.Equal(t, transactionRoot, trie.Hash())
	})

	t.Run("a merkle proof for a certain transaction can be verified by the offical trie implementation", func(t *testing.T) {
		key, err := rlp.EncodeToBytes(uint(30))
		require.NoError(t, err)

		proof, found := trie.Prove(key)
		require.Equal(t, true, found)

		txRLP, err := VerifyProof(transactionRoot, key, proof)
		require.NoError(t, err)

		// verify that if the verification passes, it returns the RLP encoded transaction
		rlp, err := FromEthTransaction(txs[30]).GetRLP()
		require.NoError(t, err)
		require.Equal(t, rlp, txRLP)
	})
}
```
