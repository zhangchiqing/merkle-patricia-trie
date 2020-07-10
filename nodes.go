package main

type Node interface {
	Hash() []byte // common.Hash
	Raw() []interface{}
	Serialize() []byte
}
