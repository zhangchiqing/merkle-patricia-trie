use std::collections::{HashMap, HashSet};
use crate::node::Node;
use crate::db::TrieDB;
use crate::{Hash, NULL_HASH, hash};

pub trait Trie {
    fn get(&mut self, key: Vec<u8>) -> Vec<u8>;
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>);
}

pub struct TrieCaptureFraudProof {
    root: Node,
    db: TrieDB,

    // read_set stores the key-value pairs got during fraud proof capture,
    // with two caveats:
    // 1. It only stores the value associated with a key during its first 
    //    read.
    // 2. It doesn't store key-value pairs got from the write_set.
    read_set: HashMap<Vec<u8>, Vec<u8>>,
    
    // write_list stores the list of puts made during fraud proof capture.
    write_list: Vec<(Vec<u8>, Vec<u8>)>,
}

impl TrieCaptureFraudProof {
    pub fn compute_pre_state_and_post_state(self) { 
        
        let mut pps = PreStateAndPostState::new();

        // Compute PreState.
        for (key, value) in &self.read_set {
            pps.pre_state.0.push((key.clone(), value.clone()));
            let mut proof_nodes = self.collect_proof_nodes_for_get(&key);
            pps.pre_state.1.append(&mut proof_nodes);
        }
        self.minimize_pre_state(&mut pps);


        // Compute PostState.
        for (key, value) in &self.write_list {
            let stray_trie_root = self.get_stray_trie_root_of_put(key);
            let put_hash = hash(value);

            self.put_as_normal(key, value); 
            let proof_nodes = self.collect_proof_nodes_for_put(&stray_trie_root, put_hash);
            pps.post_state.push(proof_nodes);
        }
        self.minimize_post_state(&mut pps);
    }

    fn get_as_normal(&self, key: &Vec<u8>) -> Vec<u8> { todo!() }

    fn put_as_normal(&self, key: &Vec<u8>, value: &Vec<u8>) { todo!() }

    // Methods used in PreState computation.
    fn collect_proof_nodes_for_get(&self, get_key: &Vec<u8>) -> Vec<(Vec<u8>, Hash)> { todo!() }

    fn minimize_pre_state(&self, pps: &mut PreStateAndPostState) { 
        let trusted_nodes: HashSet<Hash> = HashSet::new();

        todo!() 
    }

    // Methods used in PostState computation.
    fn get_stray_trie_root_of_put(&self, put_key: &Vec<u8>) -> Node { todo!() }

    fn collect_proof_nodes_for_put(&self, stray_trie_root: &Node, put_hash: Hash) -> Vec<Node> { todo!() }

    fn minimize_post_state(&self, pps: &mut PreStateAndPostState) {
        let trusted_nodes: HashSet<Hash> = HashSet::new();

        todo!()
    }
}

impl Trie for TrieCaptureFraudProof {
    fn get(&mut self, key: Vec<u8>) -> Vec<u8> {
        // First attempt to get from write_list (traversing from the rear
        // to get the latest value.
        for i in self.write_list.len()..0 {
            let (written_key, value) = &self.write_list[i];
            if *written_key == key {
                return value.clone();
            }
        }

        let value = self.get_as_normal(&key);
        
        // Update read_set only if the value has not been gotten before.
        if let None = self.read_set.get(&key) {
            self.read_set.insert(key, value.clone());
        }

        return value
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.write_list.push((key, value));
    }
    
    // TrieCaptureFraudProof does not have a commit_to_database method because
    // having to do a fraud proof is an exit state of the Veritas sequencer.
}

pub(crate) struct PreStateAndPostState {
    pub pre_state: (
        // Vector of (Key, Value) read pairs.
        Vec<(Vec<u8>, Vec<u8>)>,
        // Vector of (Key, Hash) pairs used to produce ProofNodes.
        Vec<(Vec<u8>, Hash)>,
    ),

    // Vector of vector of ProofNodes. Each vector of ProofNodes
    // 'proves' a single put that happens in a fraud proof execution.
    //
    // A put is 'proven' if its ProofNodes lie within the put's 
    // 'stray Trie', and the stray Trie is either the empty Trie, or
    // the root hash of the stray Trie equals the hash of the ProofNode
    // is replaces.
    pub post_state: Vec<Vec<Node>>,
}
 
impl PreStateAndPostState {
    pub fn new() -> PreStateAndPostState {
        PreStateAndPostState { 
            pre_state: (Vec::new(), Vec::new()), 
            post_state: Vec::new(), 
        }
    }

    pub fn minimize_pre_state() { todo!() }
}

pub struct TrieVerifyFraudProof {
    root: Node,
    db: TrieDB,

    post_state: Vec<Vec<(Vec<u8>, Hash)>>,
    put_count: usize,
}

impl TrieVerifyFraudProof {
    fn get_as_normal(&self, key: &Vec<u8>) -> Vec<u8> { todo!() }

    fn put_as_normal(&self, key: &Vec<u8>, value: &Vec<u8>) { todo!() }

    fn get_root_hash(&self) { todo!() }

    fn put_proof_node(&self, key: &Vec<u8>, hash: Hash) { todo!() }

    fn get_stray_trie_root_of_put(&self, put_key: &Vec<u8>) -> (Nibbles, Node) { todo!() }
}

impl Trie for TrieVerifyFraudProof {
    fn get(&mut self, key: Vec<u8>) -> Vec<u8> { 
        todo!();
        // TODO [Alice]: WasPreStateComplete enforcement.

        self.get_as_normal(&key)
    }
    
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let proof_node_precursors = self.post_state[self.put_count].clone();
        let (nibble_to_stray_trie, stray_trie_root) = self.get_stray_trie_root_of_put(&key);
        let stray_trie_hash_before_loading_proof_nodes = stray_trie_root.hash();

        // Load proof nodes.
        for (key, proof_node) in proof_node_precursors {
            if !b_extends_a(&key_as_nibbles(key.clone()), &nibble_to_stray_trie) {
                panic!("a put's post state proof nodes need to be children of its stray trie.")
            }

            self.put_proof_node(&key, proof_node);
        }

        let stray_trie_hash_after_loading_proof_nodes = stray_trie_root.hash();
        if stray_trie_hash_before_loading_proof_nodes != stray_trie_hash_after_loading_proof_nodes {
            panic!("a put's post state proof nodes should not change its stray trie's hash")
        }

        self.put_as_normal(&key, &value);
    }
}

// Helpful definitions

type Nibbles = Vec<u8>;

fn key_as_nibbles(key: Vec<u8>) -> Nibbles { todo!() }

fn b_extends_a(a: &Nibbles, b: &Nibbles) -> bool { todo!() }
