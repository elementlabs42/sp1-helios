// Adapted from alloy-trie: https://github.com/alloy-rs/trie/blob/v0.7.2/src/proof/verify.rs
// Adapted from alloy-trie: https://github.com/alloy-rs/trie/blob/v0.5.3/src/nodes/mod.rs

//! Proof verification logic.
use core::ops::Deref;

use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use alloy_trie::{nodes::CHILD_INDEX_RANGE, proof::ProofVerificationError, EMPTY_ROOT_HASH};
use nybbles::Nibbles;

use crate::{branch_node::BranchNode, rlp_node::RlpNode, trie_node::TrieNode};

/// Error during proof verification.
#[derive(PartialEq, Eq, Debug)]
pub enum ProofVerificationErrorExtended {
    Base(ProofVerificationError),
    UnexpectedEmptyRoot,
}

impl From<ProofVerificationError> for ProofVerificationErrorExtended {
    fn from(err: ProofVerificationError) -> Self {
        ProofVerificationErrorExtended::Base(err)
    }
}

impl From<alloy_rlp::Error> for ProofVerificationErrorExtended {
    fn from(err: alloy_rlp::Error) -> Self {
        ProofVerificationErrorExtended::Base(ProofVerificationError::Rlp(err))
    }
}

/// Verify the proof for given key value pair against the provided state root.
///
/// The expected node value can be either [Some] if it's expected to be present
/// in the tree or [None] if this is an exclusion proof.
pub fn verify_proof<'a, I>(
  root: B256,
  key: Nibbles,
  expected_value: Option<Vec<u8>>,
  proof: I,
) -> Result<(), ProofVerificationErrorExtended>
where
  I: IntoIterator<Item = &'a Bytes>,
{
  let mut proof = proof.into_iter().peekable();

      // If the proof is empty or contains only an empty node, the expected value must be None.
      if proof.peek().map_or(true, |node| node.as_ref() == [EMPTY_STRING_CODE]) {
        return if root == EMPTY_ROOT_HASH {
            if expected_value.is_none() {
                Ok(())
            } else {
                Err(ProofVerificationError::ValueMismatch {
                    path: key,
                    got: None,
                    expected: expected_value.map(Bytes::from),
                }.into())
            }
        } else {
            Err(ProofVerificationError::RootMismatch { got: EMPTY_ROOT_HASH, expected: root }.into())
        };
    }


    let _word = RlpNode::word_rlp(&root);
    let _word_hex: String = _word.iter().map(|b| format!("{:02x}", b)).collect();
    let _decoded_word = NodeDecodingResult::Node(RlpNode::word_rlp(&root));
    let _decoded_word_hex: String = _decoded_word.iter().map(|b| format!("{:02x}", b)).collect();
    let _rlp_node = RlpNode::from_rlp(root.as_slice());
    let _rlp_hex: String = _rlp_node.iter().map(|b| format!("{:02x}", b)).collect();
    println!(">>> 43: Root {:?}", &root);
    println!(">>> 43: Word RPL Root {:?}", &_word_hex);
    println!(">>> 43: Decoded Word RPL Root {:?}", &_decoded_word_hex);

    let mut walked_path = Nibbles::with_capacity(key.len());
    let mut last_decoded_node = Some(NodeDecodingResult::Node(RlpNode::word_rlp(&root)));
    for node in proof {

        let _node_rlp_hex: String = RlpNode::from_rlp(node).as_slice().iter().map(|b| format!("{:02x}", b)).collect();
        println!(">>> 51: Node rlp_node {:?}", _node_rlp_hex);

        println!(">>> ===: Node {:?} === Root {:?}", _node_rlp_hex, _decoded_word_hex);

        // Check if the node that we just decoded (or root node, if we just started) matches
        // the expected node from the proof.
        if Some(RlpNode::from_rlp(node).as_slice()) != last_decoded_node.as_deref() {
            println!(">>> RLP PROOF A");
            let got = Some(Bytes::copy_from_slice(node));
            let expected = last_decoded_node.as_deref().map(Bytes::copy_from_slice);
            return Err(ProofVerificationError::ValueMismatch { path: walked_path, got, expected }.into());
        }
        println!(">>> RLP PROOF B");

        // Decode the next node from the proof.
        last_decoded_node = match TrieNode::decode(&mut &node[..])? {
            TrieNode::Branch(branch) => process_branch(branch, &mut walked_path, &key)?,
            TrieNode::Extension(extension) => {
                walked_path.extend_from_slice(&extension.key);
                Some(NodeDecodingResult::Node(extension.child))
            }
            TrieNode::Leaf(leaf) => {
                walked_path.extend_from_slice(&leaf.key);
                Some(NodeDecodingResult::Value(leaf.value))
            }
            TrieNode::EmptyRoot => return Err(ProofVerificationErrorExtended::UnexpectedEmptyRoot),
        };
    }

    // Last decoded node should have the key that we are looking for.
    last_decoded_node = last_decoded_node.filter(|_| walked_path == key);
    if last_decoded_node.as_deref() == expected_value.as_deref() {
        Ok(())
    } else {
        Err(ProofVerificationError::ValueMismatch {
            path: key,
            got: last_decoded_node.as_deref().map(Bytes::copy_from_slice),
            expected: expected_value.map(Bytes::from),
        }.into())
    }
}

/// The result of decoding a node from the proof.
///
/// - [`TrieNode::Branch`] is decoded into a [`NodeDecodingResult::Value`] if the node at the
///   specified nibble was decoded into an in-place encoded [`TrieNode::Leaf`], or into a
///   [`NodeDecodingResult::Node`] otherwise.
/// - [`TrieNode::Extension`] is always decoded into a [`NodeDecodingResult::Node`].
/// - [`TrieNode::Leaf`] is always decoded into a [`NodeDecodingResult::Value`].
#[derive(Debug, PartialEq, Eq)]
enum NodeDecodingResult {
    Node(RlpNode),
    Value(Vec<u8>),
}

impl Deref for NodeDecodingResult {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            NodeDecodingResult::Node(node) => node.as_slice(),
            NodeDecodingResult::Value(value) => value,
        }
    }
}

#[inline]
fn process_branch(
    mut branch: BranchNode,
    walked_path: &mut Nibbles,
    key: &Nibbles,
) -> Result<Option<NodeDecodingResult>, ProofVerificationErrorExtended> {
    if let Some(next) = key.get(walked_path.len()) {
        let mut stack_ptr = branch.as_ref().first_child_index();
        for index in CHILD_INDEX_RANGE {
            if branch.state_mask.is_bit_set(index) {
                if index == *next {
                    walked_path.push(*next);

                    let child = branch.stack.remove(stack_ptr);
                    if child.len() == B256::len_bytes() + 1 {
                        return Ok(Some(NodeDecodingResult::Node(child)));
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
                                // node itself wouldn't fit for encoding in-place. So this extension
                                // node must have a child that is also encoded in-place.
                                //
                                // Since the child cannot be a leaf node (otherwise this node itself
                                // would be a leaf node, not an extension node), the child must be a
                                // branch node encoded in-place.
                                match TrieNode::decode(&mut &child_extension.child[..])? {
                                    TrieNode::Branch(extension_child_branch) => {
                                        return process_branch(
                                            extension_child_branch,
                                            walked_path,
                                            key,
                                        );
                                    }
                                    node @ (TrieNode::EmptyRoot
                                    | TrieNode::Extension(_)
                                    | TrieNode::Leaf(_)) => {
                                        unreachable!("unexpected extension node child: {node:?}")
                                    }
                                }
                            }
                            TrieNode::Leaf(child_leaf) => {
                                walked_path.extend_from_slice(&child_leaf.key);
                                return Ok(Some(NodeDecodingResult::Value(child_leaf.value)));
                            }
                            TrieNode::EmptyRoot => {
                                return Err(ProofVerificationErrorExtended::UnexpectedEmptyRoot)
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
