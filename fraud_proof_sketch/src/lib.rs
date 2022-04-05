mod db;

mod node;

mod trie;

type Hash = [u8; 32];
const NULL_HASH: Hash = [0x00; 32]; 

pub fn hash(pre_image: &Vec<u8>) -> Hash { todo!() }