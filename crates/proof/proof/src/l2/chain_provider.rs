//! Contains the concrete implementation of the [L2ChainProvider] trait for the client program.

use crate::{eip2935::eip_2935_history_lookup, errors::OracleProviderError, HintType};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_consensus::{BlockBody, Header};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, B256};
use alloy_rlp::Decodable;
use async_trait::async_trait;
use kona_derive::L2ChainProvider;
use kona_driver::PipelineCursor;
use kona_executor::TrieDBProvider;
use kona_genesis::{RollupConfig, SystemConfig};
use kona_mpt::{OrderedListWalker, TrieHinter, TrieNode, TrieProvider};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_protocol::{to_system_config, BatchValidationProvider, L2BlockInfo};
use op_alloy_consensus::{OpBlock, OpTxEnvelope};
use spin::RwLock;

/// The oracle-backed L2 chain provider for the client program.
#[derive(Debug, Clone)]
pub struct OracleL2ChainProvider<T: CommsClient> {
    /// The L2 safe head block hash.
    l2_head: B256,
    /// The rollup configuration.
    rollup_config: Arc<RollupConfig>,
    /// The preimage oracle client.
    oracle: Arc<T>,
    /// The derivation pipeline cursor
    cursor: Option<Arc<RwLock<PipelineCursor>>>,
    /// The L2 chain ID to use for the provider's hints.
    chain_id: Option<u64>,
}

impl<T: CommsClient> OracleL2ChainProvider<T> {
    /// Creates a new [OracleL2ChainProvider] with the given boot information and oracle client.
    pub const fn new(l2_head: B256, rollup_config: Arc<RollupConfig>, oracle: Arc<T>) -> Self {
        Self { l2_head, rollup_config, oracle, cursor: None, chain_id: None }
    }

    /// Sets the L2 chain ID to use for the provider's hints.
    pub const fn set_chain_id(&mut self, chain_id: Option<u64>) {
        self.chain_id = chain_id;
    }

    /// Updates the derivation pipeline cursor
    pub fn set_cursor(&mut self, cursor: Arc<RwLock<PipelineCursor>>) {
        self.cursor = Some(cursor);
    }

    /// Fetches the latest known safe head block hash according to the derivation pipeline cursor
    /// or uses the initial l2_head value if no cursor is set.
    pub async fn l2_safe_head(&self) -> Result<B256, OracleProviderError> {
        self.cursor
            .as_ref()
            .map_or(Ok(self.l2_head), |cursor| Ok(cursor.read().l2_safe_head().block_info.hash))
    }
}

impl<T: CommsClient> OracleL2ChainProvider<T> {
    /// Returns a [Header] corresponding to the given L2 block number, by walking back from the
    /// L2 safe head.
    async fn header_by_number(&mut self, block_number: u64) -> Result<Header, OracleProviderError> {
        tracing::debug!(target: "oracle_l2_chain_provider", block_number = block_number, "Starting header_by_number");

        // Fetch the starting block header.
        let l2_safe_head_hash = self.l2_safe_head().await?;
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = block_number,
            l2_safe_head_hash = ?l2_safe_head_hash,
            "Retrieved L2 safe head hash"
        );

        let mut header = self.header_by_hash(l2_safe_head_hash)?;
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = block_number,
            safe_head_number = header.number,
            safe_head_hash = ?l2_safe_head_hash,
            "Fetched safe head header"
        );

        // Check if the block number is in range. If not, we can fail early.
        if block_number > header.number {
            tracing::error!(
                target: "oracle_l2_chain_provider",
                block_number = block_number,
                safe_head_number = header.number,
                "Block number is past the safe head"
            );
            return Err(OracleProviderError::BlockNumberPastHead(block_number, header.number));
        }

        let mut linear_fallback = false;
        let mut steps = 0;
        while header.number > block_number {
            steps += 1;
            let is_isthmus_active = self.rollup_config.is_isthmus_active(header.timestamp);

            tracing::debug!(
                target: "oracle_l2_chain_provider",
                block_number = block_number,
                current_header_number = header.number,
                current_header_hash = ?header.hash_slow(),
                parent_hash = ?header.parent_hash,
                is_isthmus_active = is_isthmus_active,
                linear_fallback = linear_fallback,
                steps = steps,
                "Walking back to find block"
            );

            if is_isthmus_active && !linear_fallback {
                // If Isthmus is active, the EIP-2935 contract is used to perform leaping lookbacks
                // through consulting the ring buffer within the contract. If this
                // lookup fails for any reason, we fall back to linear walk back.
                tracing::debug!(
                    target: "oracle_l2_chain_provider",
                    block_number = block_number,
                    current_header_number = header.number,
                    "Attempting EIP-2935 history lookup"
                );

                let block_hash =
                    match eip_2935_history_lookup(&header, block_number, self, self).await {
                        Ok(hash) => {
                            tracing::debug!(
                                target: "oracle_l2_chain_provider",
                                block_number = block_number,
                                found_hash = ?hash,
                                "EIP-2935 lookup succeeded"
                            );
                            hash
                        }
                        Err(e) => {
                            // If the EIP-2935 lookup fails for any reason, attempt fallback to
                            // linear walk back.
                            tracing::warn!(
                                target: "oracle_l2_chain_provider",
                                block_number = block_number,
                                error = ?e,
                                "EIP-2935 lookup failed, falling back to linear walk"
                            );
                            linear_fallback = true;
                            continue;
                        }
                    };

                header = self.header_by_hash(block_hash)?;
            } else {
                // Walk back the block headers one-by-one until the desired block number is reached.
                tracing::debug!(
                    target: "oracle_l2_chain_provider",
                    block_number = block_number,
                    current_header_number = header.number,
                    parent_hash = ?header.parent_hash,
                    "Walking back via parent hash"
                );
                header = self.header_by_hash(header.parent_hash)?;
            }
        }

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = block_number,
            header_hash = ?header.hash_slow(),
            total_steps = steps,
            "Successfully found header by number"
        );

        Ok(header)
    }
}

#[async_trait]
impl<T: CommsClient + Send + Sync> BatchValidationProvider for OracleL2ChainProvider<T> {
    type Error = OracleProviderError;

    async fn l2_block_info_by_number(&mut self, number: u64) -> Result<L2BlockInfo, Self::Error> {
        // Get the block at the given number.
        let block = self.block_by_number(number).await?;

        // Construct the system config from the payload.
        L2BlockInfo::from_block_and_genesis(&block, &self.rollup_config.genesis)
            .map_err(OracleProviderError::BlockInfo)
    }

    async fn block_by_number(&mut self, number: u64) -> Result<OpBlock, Self::Error> {
        // here
        tracing::debug!(target: "oracle_l2_chain_provider", block_number = number, "Fetching block by number");

        // Fetch the header for the given block number.
        let header @ Header { transactions_root, timestamp, .. } =
            self.header_by_number(number).await?;

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            header = ?header,
            "Retrieved header for block"
        );

        // Compute the header hash - this is critical for fetching transactions
        let header_hash = header.hash_slow();

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            header_hash = ?header_hash,
            "Computed header hash using hash_slow()"
        );

        // Fetch the transactions in the block.
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            header_hash = ?header_hash,
            chain_id = ?self.chain_id,
            "Sending L2Transactions hint to oracle"
        );

        HintType::L2Transactions
            .with_data(&[header_hash.as_ref()])
            .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
            .send(self.oracle.as_ref())
            .await?;

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            transactions_root = ?transactions_root,
            "Creating trie walker for transactions"
        );

        let trie_walker = OrderedListWalker::try_new_hydrated(transactions_root, self)
            .map_err(OracleProviderError::TrieWalker)?;

        // Decode the transactions within the transactions trie.
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            "Decoding transactions from trie"
        );

        let transactions = trie_walker
            .into_iter()
            .map(|(_, rlp)| {
                let res = OpTxEnvelope::decode_2718(&mut rlp.as_ref())?;
                Ok(res)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(OracleProviderError::Rlp)?;

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            tx_count = transactions.len(),
            "Successfully decoded transactions"
        );

        let is_canyon_active = self.rollup_config.is_canyon_active(timestamp);
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            timestamp = timestamp,
            is_canyon_active = is_canyon_active,
            "Checking Canyon activation for withdrawals"
        );

        let optimism_block = OpBlock {
            header,
            body: BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: is_canyon_active
                    .then(|| alloy_eips::eip4895::Withdrawals::new(Vec::new())),
            },
        };

        tracing::debug!(
            target: "oracle_l2_chain_provider",
            block_number = number,
            header_hash = ?header_hash,
            "Successfully constructed OpBlock"
        );

        Ok(optimism_block)
    }
}

#[async_trait]
impl<T: CommsClient + Send + Sync> L2ChainProvider for OracleL2ChainProvider<T> {
    type Error = OracleProviderError;

    async fn system_config_by_number(
        &mut self,
        number: u64,
        rollup_config: Arc<RollupConfig>,
    ) -> Result<SystemConfig, <Self as L2ChainProvider>::Error> {
        // Get the block at the given number.
        let block = self.block_by_number(number).await?;

        // Construct the system config from the payload.
        to_system_config(&block, rollup_config.as_ref())
            .map_err(OracleProviderError::OpBlockConversion)
    }
}

impl<T: CommsClient> TrieProvider for OracleL2ChainProvider<T> {
    type Error = OracleProviderError;

    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, OracleProviderError> {
        // On L2, trie node preimages are stored as keccak preimage types in the oracle. We assume
        // that a hint for these preimages has already been sent, prior to this call.
        crate::block_on(async move {
            TrieNode::decode(
                &mut self
                    .oracle
                    .get(PreimageKey::new(*key, PreimageKeyType::Keccak256))
                    .await
                    .map_err(OracleProviderError::Preimage)?
                    .as_ref(),
            )
            .map_err(OracleProviderError::Rlp)
        })
    }
}

impl<T: CommsClient> TrieDBProvider for OracleL2ChainProvider<T> {
    fn bytecode_by_hash(&self, hash: B256) -> Result<Bytes, OracleProviderError> {
        // Fetch the bytecode preimage from the caching oracle.
        crate::block_on(async move {
            HintType::L2Code
                .with_data(&[hash.as_slice()])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await?;
            self.oracle
                .get(PreimageKey::new_keccak256(*hash))
                .await
                .map(Into::into)
                .map_err(OracleProviderError::Preimage)
        })
    }

    fn header_by_hash(&self, hash: B256) -> Result<Header, OracleProviderError> {
        // here
        tracing::debug!(
            target: "oracle_l2_chain_provider",
            hash = ?hash,
            "Starting header_by_hash"
        );

        // Fetch the header from the caching oracle.
        crate::block_on(async move {
            tracing::debug!(
                target: "oracle_l2_chain_provider",
                hash = ?hash,
                chain_id = ?self.chain_id,
                "Sending L2BlockHeader hint to oracle"
            );

            HintType::L2BlockHeader
                .with_data(&[hash.as_slice()])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await?;

            tracing::debug!(
                target: "oracle_l2_chain_provider",
                hash = ?hash,
                "Fetching header bytes from oracle via preimage key"
            );

            let header_bytes = self.oracle.get(PreimageKey::new_keccak256(*hash)).await?;

            tracing::debug!(
                target: "oracle_l2_chain_provider",
                hash = ?hash,
                bytes_len = header_bytes.len(),
                "Retrieved header bytes, decoding"
            );

            let header =
                Header::decode(&mut header_bytes.as_slice()).map_err(OracleProviderError::Rlp)?;

            tracing::debug!(
                target: "oracle_l2_chain_provider",
                hash = ?hash,
                header_number = header.number,
                parent_hash = ?header.parent_hash,
                timestamp = header.timestamp,
                "Successfully decoded header"
            );

            Ok(header)
        })
    }
}

impl<T: CommsClient> TrieHinter for OracleL2ChainProvider<T> {
    type Error = OracleProviderError;

    fn hint_trie_node(&self, hash: B256) -> Result<(), Self::Error> {
        crate::block_on(async move {
            HintType::L2StateNode
                .with_data(&[hash.as_slice()])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await
        })
    }

    fn hint_account_proof(&self, address: Address, block_number: u64) -> Result<(), Self::Error> {
        crate::block_on(async move {
            HintType::L2AccountProof
                .with_data(&[block_number.to_be_bytes().as_ref(), address.as_slice()])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await
        })
    }

    fn hint_storage_proof(
        &self,
        address: alloy_primitives::Address,
        slot: alloy_primitives::U256,
        block_number: u64,
    ) -> Result<(), Self::Error> {
        crate::block_on(async move {
            HintType::L2AccountStorageProof
                .with_data(&[
                    block_number.to_be_bytes().as_ref(),
                    address.as_slice(),
                    slot.to_be_bytes::<32>().as_ref(),
                ])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await
        })
    }

    fn hint_execution_witness(
        &self,
        parent_hash: B256,
        op_payload_attributes: &op_alloy_rpc_types_engine::OpPayloadAttributes,
    ) -> Result<(), Self::Error> {
        crate::block_on(async move {
            let encoded_attributes =
                serde_json::to_vec(op_payload_attributes).map_err(OracleProviderError::Serde)?;

            HintType::L2PayloadWitness
                .with_data(&[parent_hash.as_slice(), &encoded_attributes])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await
        })
    }
}
