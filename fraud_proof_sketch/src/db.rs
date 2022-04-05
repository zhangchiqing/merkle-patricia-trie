use crate::Hash;
use crate::node::Node;

pub struct TrieDB {
    pub root_hash: Hash,
}

impl TrieDB {
    pub fn get(key: Hash) -> Node { todo!() }  
    pub fn set(key: Hash, node: Node) { todo!() }
}