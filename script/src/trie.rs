/// Adapted from reth: https://github.com/paradigmxyz/reth/blob/v1.0.1/crates/trie/common/src/root.rs

use std::collections::BTreeMap;
use alloy::{
  consensus::ReceiptEnvelope, core::rlp::{encode_fixed_size, Encodable}, primitives::{Bytes, B256}
};
use alloy_trie::{proof::ProofRetainer, HashBuilder};
use nybbles::Nibbles;

/// Adjust the index of an item for rlp encoding.
pub const fn adjust_index_for_rlp(i: usize, len: usize) -> usize {
  if i > 0x7f {
      i
  } else if i == 0x7f || i + 1 == len {
      0
  } else {
      i + 1
  }
}

/// Compute a trie root of the collection of rlp encodable items.
pub fn ordered_trie_root<T: Encodable>(items: &[T]) -> B256 {
  ordered_trie_root_with_encoder(items, |item, buf| item.encode(buf), None).0
}

/// Compute a trie root of the collection of items with a custom encoder.
pub fn ordered_trie_root_with_encoder<T, F>(items: &[T], mut encode: F, proof_nibbles: Option<Vec<Nibbles>>) -> (B256, Option<BTreeMap<Nibbles, Bytes>>)
where
  F: FnMut(&T, &mut Vec<u8>),
{
  let mut value_buffer = Vec::new();

  let mut hb = HashBuilder::default();

  if proof_nibbles.is_some() {
    let proof_retainer = ProofRetainer::new(proof_nibbles.unwrap());
    hb = HashBuilder::with_proof_retainer(hb, proof_retainer);
  }
  
  let items_len = items.len();
  for i in 0..items_len {
      let index = adjust_index_for_rlp(i, items_len);

      let index_buffer = encode_fixed_size(&index);

      value_buffer.clear();
      encode(&items[index], &mut value_buffer);

      // println!("RECEIPT LEAF: {:?} | {:?}, encoded val: {:?}\r\n", i, index, &value_buffer);

      hb.add_leaf(Nibbles::unpack(&index_buffer), &value_buffer);
  }

  let mut proofs: Option<BTreeMap<Nibbles, Bytes>> = None;
  if hb.proof_retainer.is_some() {
    proofs = Some(hb.take_proofs());
  }

  (hb.root(), proofs)
}
