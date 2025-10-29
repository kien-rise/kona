//! Contains the concrete implementation of the [L2ChainProvider] trait for the client program.

use crate::{HintType, eip2935::eip_2935_history_lookup, errors::OracleProviderError};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_consensus::{BlockBody, Header};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rlp::Decodable;
use async_trait::async_trait;
use kona_derive::L2ChainProvider;
use kona_driver::PipelineCursor;
use kona_executor::TrieDBProvider;
use kona_genesis::{RollupConfig, SystemConfig};
use kona_mpt::{OrderedListWalker, TrieHinter, TrieNode, TrieProvider};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_protocol::{BatchValidationProvider, L2BlockInfo, to_system_config};
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
        tracing::debug!("KONA: Starting l2_safe_head lookup");
        
        // Step 1: Check if we have a cursor available
        tracing::debug!("KONA: Checking if derivation pipeline cursor is available");
        let cursor_option = self.cursor.as_ref();
        
        if cursor_option.is_none() {
            tracing::debug!("KONA: No derivation pipeline cursor found, using initial l2_head: {:?}", self.l2_head);
            return Ok(self.l2_head);
        }
        
        // Step 2: We have a cursor, so we need to read from it
        tracing::debug!("KONA: Derivation pipeline cursor found, reading from cursor");
        let cursor = cursor_option.unwrap();
        
        // Step 3: Acquire read lock on the cursor
        tracing::debug!("KONA: Acquiring read lock on derivation pipeline cursor");
        let cursor_guard = cursor.read();
        
        // Step 4: Get the safe head from the cursor
        tracing::debug!("KONA: Getting L2 safe head from cursor");
        let safe_head_info = cursor_guard.l2_safe_head();
        
        // Step 5: Extract the block hash from the safe head info
        tracing::debug!("KONA: Extracting block hash from safe head info");
        let safe_head_hash = safe_head_info.block_info.hash;
        
        tracing::debug!("KONA: Successfully retrieved L2 safe head hash from cursor: {:?}", safe_head_hash);
        Ok(safe_head_hash)
    }
}

impl<T: CommsClient> OracleL2ChainProvider<T> {
    /// Returns a [Header] corresponding to the given L2 block number, by walking back from the
    /// L2 safe head.
    async fn header_by_number(&mut self, block_number: u64) -> Result<Header, OracleProviderError> {
        // Fetch the starting block header.
        let safe_head_hash = self.l2_safe_head().await?;
        tracing::debug!("KONA: Fetching header by hash for L2 safe head: {:?}", safe_head_hash);
        let mut header = self.header_by_hash(safe_head_hash)?;
        tracing::debug!("KONA: Successfully fetched header for L2 safe head: {:?}", safe_head_hash);

        // Check if the block number is in range. If not, we can fail early.
        if block_number > header.number {
            return Err(OracleProviderError::BlockNumberPastHead(block_number, header.number));
        }

        let mut linear_fallback = false;
        while header.number > block_number {
            if self.rollup_config.is_isthmus_active(header.timestamp) && !linear_fallback {
                // If Isthmus is active, the EIP-2935 contract is used to perform leaping lookbacks
                // through consulting the ring buffer within the contract. If this
                // lookup fails for any reason, we fall back to linear walk back.
                let block_hash =
                    match eip_2935_history_lookup(&header, block_number, self, self).await {
                        Ok(hash) => hash,
                        Err(_) => {
                            // If the EIP-2935 lookup fails for any reason, attempt fallback to
                            // linear walk back.
                            linear_fallback = true;
                            continue;
                        }
                    };

                tracing::debug!("KONA: Fetching header by hash (EIP-2935): {:?}", block_hash);
                header = self.header_by_hash(block_hash)?;
                tracing::debug!("KONA: Successfully fetched header (EIP-2935): {:?}", block_hash);
            } else {
                // Walk back the block headers one-by-one until the desired block number is reached.
                tracing::debug!("KONA: Fetching parent header by hash: {:?}", header.parent_hash);
                header = self.header_by_hash(header.parent_hash)?;
                tracing::debug!("KONA: Successfully fetched parent header: {:?}", header.parent_hash);
            }
        }

        Ok(header)
    }
}

#[async_trait]
impl<T: CommsClient + Send + Sync> BatchValidationProvider for OracleL2ChainProvider<T> {
    type Error = OracleProviderError;

    async fn l2_block_info_by_number(&mut self, number: u64) -> Result<L2BlockInfo, Self::Error> {
        tracing::debug!("KONA: Starting l2_block_info_by_number for block number: {}", number);
        tracing::debug!("KONA: Using chain ID: {:?}", self.chain_id);

        // Step 1: Get the block at the given number
        tracing::debug!("KONA: Fetching L2 block by number: {}", number);
        let block = self.block_by_number(number).await
            .map_err(|e| {
                tracing::error!("KONA: Failed to fetch L2 block by number {}: {:?}", number, e);
                e
            })?;
        
        tracing::debug!("KONA: Successfully fetched L2 block {} - hash: {:?}, parent: {:?}, tx count: {}", 
            number, block.header.hash_slow(), block.header.parent_hash, block.body.transactions.len());
        tracing::debug!("KONA: Block timestamp: {}, gas_used: {}, gas_limit: {}", 
            block.header.timestamp, block.header.gas_used, block.header.gas_limit);

        // Step 2: Get genesis configuration info for logging
        tracing::debug!("KONA: Using genesis config - L1: {:?}, L2: {:?}", 
            self.rollup_config.genesis.l1, self.rollup_config.genesis.l2);

        // Step 3: Construct the L2BlockInfo from the payload and genesis
        tracing::debug!("KONA: Converting block to L2BlockInfo using genesis configuration");
        let l2_block_info = L2BlockInfo::from_block_and_genesis(&block, &self.rollup_config.genesis)
            .map_err(|e| {
                tracing::error!("KONA: Failed to construct L2BlockInfo from block {} and genesis: {:?}", number, e);
                OracleProviderError::BlockInfo(e)
            })?;

        tracing::debug!("KONA: Successfully created L2BlockInfo for block {} - L1 origin: {:?}, sequence: {}", 
            number, l2_block_info.l1_origin, l2_block_info.seq_num);
        tracing::debug!("KONA: L2BlockInfo timestamp: {}, block hash: {:?}", 
            l2_block_info.block_info.timestamp, l2_block_info.block_info.hash);

        tracing::debug!("KONA: Completed l2_block_info_by_number for block number: {}", number);
        Ok(l2_block_info)
    }

    async fn block_by_number(&mut self, number: u64) -> Result<OpBlock, Self::Error> {
        // Fetch the header for the given block number.
        let header @ Header { transactions_root, timestamp, .. } =
            self.header_by_number(number).await?;
        let header_hash = header.hash_slow();

        // Fetch the transactions in the block.
        HintType::L2Transactions
            .with_data(&[header_hash.as_ref()])
            .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
            .send(self.oracle.as_ref())
            .await?;
        let trie_walker = OrderedListWalker::try_new_hydrated(transactions_root, self)
            .map_err(OracleProviderError::TrieWalker)?;

        // Decode the transactions within the transactions trie.
        let transactions = trie_walker
            .into_iter()
            .map(|(_, rlp)| {
                let res = OpTxEnvelope::decode_2718(&mut rlp.as_ref())?;
                Ok(res)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(OracleProviderError::Rlp)?;

        let optimism_block = OpBlock {
            header,
            body: BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: self
                    .rollup_config
                    .is_canyon_active(timestamp)
                    .then(|| alloy_eips::eip4895::Withdrawals::new(Vec::new())),
            },
        };
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
        tracing::debug!("KONA: header_by_hash called for hash: {:?}", hash);
        // Fetch the header from the caching oracle.
        crate::block_on(async move {
            tracing::debug!("KONA: Sending L2BlockHeader hint for hash: {:?}", hash);
            HintType::L2BlockHeader
                .with_data(&[hash.as_slice()])
                .with_data(self.chain_id.map_or_else(Vec::new, |id| id.to_be_bytes().to_vec()))
                .send(self.oracle.as_ref())
                .await?;
            tracing::debug!("KONA: Getting preimage for hash: {:?}", hash);
            let header_bytes = self.oracle.get(PreimageKey::new_keccak256(*hash)).await?;

            tracing::debug!("KONA: Decoding header bytes for hash: {:?}", hash);
            Header::decode(&mut header_bytes.as_slice()).map_err(OracleProviderError::Rlp)
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
