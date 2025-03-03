use alloy::{
    core::rlp::{encode_fixed_size, Encodable},
    primitives::{Bytes, B256},
};
use alloy_trie::{proof::ProofRetainer, HashBuilder};
use nybbles::Nibbles;
/// Adapted from reth: https://github.com/paradigmxyz/reth/blob/v1.0.1/crates/trie/common/src/root.rs
use std::collections::BTreeMap;

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
pub fn ordered_trie_root_with_encoder<T, F>(
    items: &[T],
    mut encode: F,
    proof_nibbles: Option<Vec<Nibbles>>,
) -> (B256, Option<BTreeMap<Nibbles, Bytes>>)
where
    F: FnMut(&T, &mut Vec<u8>),
{
    let mut value_buffer = Vec::new();
    let mut hb = HashBuilder::default();
    let mut proof_retainer = None;

    if let Some(nibbles) = proof_nibbles {
        proof_retainer = Some(ProofRetainer::new(nibbles));
        hb = HashBuilder::with_proof_retainer(hb, proof_retainer.as_ref().unwrap().clone());
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

    let proofs = proof_retainer.map(|retainer| {
        let nodes = retainer.into_proof_nodes();
        let mut map = BTreeMap::new();
        for (key, value) in nodes.iter() {
            map.insert(key.clone(), value.clone());
        }
        map
    });

    (hb.root(), proofs)
}
