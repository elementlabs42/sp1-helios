/// Adapted from reth: https://github.com/paradigmxyz/reth/blob/v1.0.1/crates/primitives-traits/src/header/mod.rs
/// Merged with alloy: https://github.com/alloy-rs/alloy/blob/main/crates/consensus/src/block/header.rs
use alloy::{
  core::rlp::{bytes::BufMut, length_of_length, Encodable, Header},
  primitives::{keccak256, Address, BlockNumber, Bloom, Bytes, B256, B64, U256},
  rpc::types::Header as RpcHeader
};

pub struct BlockHeader {
  /// The Keccak 256-bit hash of the parent
  /// block’s header, in its entirety; formally Hp.
  pub parent_hash: B256,
  /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
  pub ommers_hash: B256,
  /// The 160-bit address to which all fees collected from the successful mining of this block
  /// be transferred; formally Hc.
  pub beneficiary: Address,
  /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
  /// executed and finalisations applied; formally Hr.
  pub state_root: B256,
  /// The Keccak 256-bit hash of the root node of the trie structure populated with each
  /// transaction in the transactions list portion of the block; formally Ht.
  pub transactions_root: B256,
  /// The Keccak 256-bit hash of the root node of the trie structure populated with the receipts
  /// of each transaction in the transactions list portion of the block; formally He.
  pub receipts_root: B256,
  /// The Keccak 256-bit hash of the withdrawals list portion of this block.
  ///
  /// See [EIP-4895](https://eips.ethereum.org/EIPS/eip-4895).
  pub withdrawals_root: Option<B256>,
  /// The Bloom filter composed from indexable information (logger address and log topics)
  /// contained in each log entry from the receipt of each transaction in the transactions list;
  /// formally Hb.
  pub logs_bloom: Bloom,
  /// A scalar value corresponding to the difficulty level of this block. This can be calculated
  /// from the previous block’s difficulty level and the timestamp; formally Hd.
  pub difficulty: U256,
  /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
  /// zero; formally Hi.
  pub number: BlockNumber,
  /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
  pub gas_limit: u64,
  /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
  pub gas_used: u64,
  /// A scalar value equal to the reasonable output of Unix’s time() at this block’s inception;
  /// formally Hs.
  pub timestamp: u64,
  /// A 256-bit hash which, combined with the
  /// nonce, proves that a sufficient amount of computation has been carried out on this block;
  /// formally Hm.
  pub mix_hash: B256,
  /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
  /// computation has been carried out on this block; formally Hn.
  pub nonce: B64,
  /// A scalar representing EIP1559 base fee which can move up or down each block according
  /// to a formula which is a function of gas used in parent block and gas target
  /// (block gas limit divided by elasticity multiplier) of parent block.
  /// The algorithm results in the base fee per gas increasing when blocks are
  /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
  /// gas is burned.
  pub base_fee_per_gas: Option<u64>,
  /// The total amount of blob gas consumed by the transactions within the block, added in
  /// EIP-4844.
  pub blob_gas_used: Option<u64>,
  /// A running total of blob gas consumed in excess of the target, prior to the block. Blocks
  /// with above-target blob gas consumption increase this value, blocks with below-target blob
  /// gas consumption decrease it (bounded at 0). This was added in EIP-4844.
  pub excess_blob_gas: Option<u64>,
  /// The hash of the parent beacon block's root is included in execution blocks, as proposed by
  /// EIP-4788.
  ///
  /// This enables trust-minimized access to consensus state, supporting staking pools, bridges,
  /// and more.
  ///
  /// The beacon roots contract handles root storage, enhancing Ethereum's functionalities.
  pub parent_beacon_block_root: Option<B256>,
  /// The Keccak 256-bit hash of the root node of the trie structure populated with each
  /// [EIP-7685] request in the block body.
  ///
  /// [EIP-7685]: https://eips.ethereum.org/EIPS/eip-7685
  pub requests_root: Option<B256>,
  /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
  /// fewer; formally Hx.
  pub extra_data: Bytes,
}

impl BlockHeader {

    pub fn from(header: &RpcHeader) -> Self {
        Self {
            parent_hash: header.parent_hash,
            ommers_hash: header.uncles_hash,
            beneficiary: header.miner,
            state_root: header.state_root,
            transactions_root: header.transactions_root,
            receipts_root: header.receipts_root,
            withdrawals_root: header.withdrawals_root,
            logs_bloom: header.logs_bloom,
            difficulty: header.difficulty,
            number: header.number.unwrap(),
            gas_limit: header.gas_limit as u64, // Convert to U64
            gas_used: header.gas_used as u64, // Convert to U64
            timestamp: header.timestamp,
            mix_hash: header.mix_hash.unwrap(),
            nonce: header.nonce.unwrap(),
            base_fee_per_gas: header.base_fee_per_gas.map(|value| value as u64), // Convert from U128 to U64
            blob_gas_used: header.blob_gas_used.map(|value| value as u64), // Convert from U128 to U64
            excess_blob_gas: header.excess_blob_gas.map(|value| value as u64), // Convert from U128 to U64
            parent_beacon_block_root: header.parent_beacon_block_root,
            requests_root: header.requests_root,
            extra_data: header.extra_data.clone(),
        }
    }

    /// Heavy function that will calculate hash of data and will *not* save the change to metadata.
    /// Use [`Header::seal`], [`SealedHeader`] and unlock if you need hash to be persistent.
    pub fn hash_slow(&self) -> B256 {
        let mut out = Vec::<u8>::new();
        self.encode(&mut out);
        keccak256(&out)
    }

    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length(); // Hash of the previous block.
        length += self.ommers_hash.length(); // Hash of uncle blocks.
        length += self.beneficiary.length(); // Address that receives rewards.
        length += self.state_root.length(); // Root hash of the state object.
        length += self.transactions_root.length(); // Root hash of transactions in the block.
        length += self.receipts_root.length(); // Hash of transaction receipts.
        length += self.logs_bloom.length(); // Data structure containing event logs.
        length += self.difficulty.length(); // Difficulty value of the block.
        length += U256::from(self.number).length(); // Block number.
        length += U256::from(self.gas_limit).length(); // Maximum gas allowed.
        length += U256::from(self.gas_used).length(); // Actual gas used.
        length += self.timestamp.length(); // Block timestamp.
        length += self.extra_data.length(); // Additional arbitrary data.
        length += self.mix_hash.length(); // Hash used for mining.
        length += self.nonce.length();

        if let Some(base_fee) = self.base_fee_per_gas {
            // Adding base fee length if it exists.
            length += U256::from(base_fee).length();
        }

        if let Some(root) = self.withdrawals_root {
            // Adding withdrawals_root length if it exists.
            length += root.length();
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            // Adding blob_gas_used length if it exists.
            length += U256::from(blob_gas_used).length();
        }

        if let Some(excess_blob_gas) = self.excess_blob_gas {
            // Adding excess_blob_gas length if it exists.
            length += U256::from(excess_blob_gas).length();
        }

        if let Some(parent_beacon_block_root) = self.parent_beacon_block_root {
            length += parent_beacon_block_root.length();
        }

        if let Some(requests_root) = self.requests_root {
            length += requests_root.length();
        }

        length
    }
}

impl Encodable for BlockHeader {
  fn encode(&self, out: &mut dyn BufMut) {
      // Create a header indicating the encoded content is a list with the payload length computed
      // from the header's payload calculation function.
      let list_header =
          Header { list: true, payload_length: self.header_payload_length() };
      list_header.encode(out);

      // Encode each header field sequentially
      self.parent_hash.encode(out); // Encode parent hash.
      self.ommers_hash.encode(out); // Encode ommer's hash.
      self.beneficiary.encode(out); // Encode beneficiary.
      self.state_root.encode(out); // Encode state root.
      self.transactions_root.encode(out); // Encode transactions root.
      self.receipts_root.encode(out); // Encode receipts root.
      self.logs_bloom.encode(out); // Encode logs bloom.
      self.difficulty.encode(out); // Encode difficulty.
      U256::from(self.number).encode(out); // Encode block number.
      U256::from(self.gas_limit).encode(out); // Encode gas limit.
      U256::from(self.gas_used).encode(out); // Encode gas used.
      self.timestamp.encode(out); // Encode timestamp.
      self.extra_data.encode(out); // Encode extra data.
      self.mix_hash.encode(out); // Encode mix hash.
      self.nonce.encode(out); // Encode nonce.

      // Encode base fee.
      if let Some(ref base_fee) = self.base_fee_per_gas {
          U256::from(*base_fee).encode(out);
      }

      // Encode withdrawals root.
      if let Some(ref root) = self.withdrawals_root {
          root.encode(out);
      }

      // Encode blob gas used.
      if let Some(ref blob_gas_used) = self.blob_gas_used {
          U256::from(*blob_gas_used).encode(out);
      }

      // Encode excess blob gas.
      if let Some(ref excess_blob_gas) = self.excess_blob_gas {
          U256::from(*excess_blob_gas).encode(out);
      }

      // Encode parent beacon block root.
      if let Some(ref parent_beacon_block_root) = self.parent_beacon_block_root {
          parent_beacon_block_root.encode(out);
      }

      // Encode EIP-7685 requests root
      if let Some(ref requests_root) = self.requests_root {
          requests_root.encode(out);
      }
  }

  fn length(&self) -> usize {
      let mut length = 0;
      length += self.header_payload_length();
      length += length_of_length(length);
      length
  }
}