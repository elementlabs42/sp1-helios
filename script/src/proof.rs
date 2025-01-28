// Adapted from alloy-trie: https://github.com/alloy-rs/trie/blob/v0.5.3/src/proof/verify.rs
// Adapted from alloy-trie: https://github.com/alloy-rs/trie/blob/v0.5.3/src/nodes/mod.rs

//! Proof verification logic.

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::{word_rlp, BranchNode, TrieNode, CHILD_INDEX_RANGE}, proof::ProofVerificationError, EMPTY_ROOT_HASH};
use nybbles::Nibbles;

/// Verify the proof for given key value pair against the provided state root.
///
/// The expected node value can be either [Some] if it's expected to be present
/// in the tree or [None] if this is an exclusion proof.
pub fn verify_proof<'a, I>(
  root: B256,
  key: Nibbles,
  value: Option<Vec<u8>>,
  proof: I,
) -> Result<(), ProofVerificationError>
where
  I: IntoIterator<Item = &'a Bytes>,
{
  let mut proof = proof.into_iter().peekable();

  if proof.peek().is_none() {
      return if root == EMPTY_ROOT_HASH {
          if value.is_none() {
              Ok(())
          } else {
              Err(ProofVerificationError::ValueMismatch {
                  path: key,
                  got: None,
                  expected: value.map(Bytes::from),
              })
          }
      } else {
          Err(ProofVerificationError::RootMismatch { got: EMPTY_ROOT_HASH, expected: root })
      };
  }

  let mut walked_path = Nibbles::default();
  let mut next_value = Some(word_rlp(&root));
  for node in proof {
      if Some(rlp_node(node)) != next_value {
        println!(">>> RLP PROOF A");
          let got = Some(Bytes::copy_from_slice(node));
          let expected = next_value.map(|b| Bytes::copy_from_slice(&b));
          return Err(ProofVerificationError::ValueMismatch { path: walked_path, got, expected });
      }

      next_value = match TrieNode::decode(&mut &node[..])? {
          TrieNode::Branch(branch) => process_branch(branch, &mut walked_path, &key)?,
          TrieNode::Extension(extension) => {
              walked_path.extend_from_slice(&extension.key);
              Some(extension.child)
          }
          TrieNode::Leaf(leaf) => {
              walked_path.extend_from_slice(&leaf.key);
              Some(leaf.value)
          }
      };
  }

  next_value = next_value.filter(|_| walked_path == key);
  if next_value == value {
      Ok(())
  } else {
    println!(">>> RLP PROOF B");
      Err(ProofVerificationError::ValueMismatch {
          path: key,
          got: next_value.map(Bytes::from),
          expected: value.map(Bytes::from),
      })
  }
}

#[inline]
fn process_branch(
  mut branch: BranchNode,
  walked_path: &mut Nibbles,
  key: &Nibbles,
) -> Result<Option<Vec<u8>>, ProofVerificationError> {
  if let Some(next) = key.get(walked_path.len()) {
      let mut stack_ptr = branch.as_ref().first_child_index();
      for index in CHILD_INDEX_RANGE {
          if branch.state_mask.is_bit_set(index) {
              if index == *next {
                  walked_path.push(*next);

                  let child = branch.stack.remove(stack_ptr);
                  if child.len() == B256::len_bytes() + 1 {
                      return Ok(Some(child));
                  } else {
                      // This node is encoded in-place.
                      match TrieNode::decode(&mut &child[..])? {
                          TrieNode::Branch(child_branch) => {
                              // An in-place branch node can only have direct, also in-place
                              // encoded, leaf children, as anything else overflows this branch
                              // node, making it impossible to be encoded in-place in the first
                              // place.
                              return process_branch(child_branch, walked_path, key);
                          }
                          TrieNode::Extension(child_extension) => {
                              walked_path.extend_from_slice(&child_extension.key);

                              // If the extension node's child is a hash, the encoded extension
                              // node itself wouldn't fit for encoding in- place. So this
                              // extension node must have a child that is also encoded in-place.
                              //
                              // Since the child cannot be a leaf node (otherwise this node itself
                              // is a leaf node to begin with, the child must also be a branch
                              // encoded in-place.
                              match TrieNode::decode(&mut &child_extension.child[..])? {
                                  TrieNode::Branch(extension_child_branch) => {
                                      return process_branch(
                                          extension_child_branch,
                                          walked_path,
                                          key,
                                      );
                                  }
                                  TrieNode::Extension(_) | TrieNode::Leaf(_) => {
                                      unreachable!("impossible in-place extension node")
                                  }
                              }
                          }
                          TrieNode::Leaf(child_leaf) => {
                              walked_path.extend_from_slice(&child_leaf.key);
                              return Ok(Some(child_leaf.value));
                          }
                      }
                  };
              }
              stack_ptr += 1;
          }
      }
  }

  Ok(None)
}

/// Given an RLP encoded node, returns either self as RLP(node) or RLP(keccak(RLP(node)))
#[inline]
pub(crate) fn rlp_node(rlp: &[u8]) -> Vec<u8> {
    if rlp.len() < B256::len_bytes() {
        rlp.to_vec()
    } else {
        word_rlp(&keccak256(rlp))
    }
}
