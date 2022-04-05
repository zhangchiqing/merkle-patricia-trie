use crate::{Hash, NULL_HASH};

pub enum Node {
    BranchNode { 
        // 16 slots, because hexadecimal is base-16.
        slots: [Hash; 16],
        value: Option<Vec<u8>>,

        // * None if self is a root node.
        // * Must point to a branch node.
        parent: Option<Hash>,
    },
    LeafNode { 
        value: Vec<u8>,
        parent: Hash,
    },
    ProofNode {
        hash: Hash,
    }
}

impl Node {
    pub fn hash(&self) -> Hash { todo!() }
}