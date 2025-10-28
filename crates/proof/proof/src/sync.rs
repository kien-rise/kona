//! Sync Start

use crate::errors::OracleProviderError;
use alloc::sync::Arc;
use alloy_consensus::{Header, Sealed};
use alloy_primitives::B256;
use core::fmt::Debug;
use kona_derive::ChainProvider;
use kona_driver::{PipelineCursor, TipCursor};
use kona_protocol::BatchValidationProvider;
use kona_registry::RollupConfig;
use spin::RwLock;

/// Constructs a [`PipelineCursor`] from the caching oracle, boot info, and providers.
pub async fn new_oracle_pipeline_cursor<L1, L2>(
    rollup_config: &RollupConfig,
    safe_header: Sealed<Header>,
    chain_provider: &mut L1,
    l2_chain_provider: &mut L2,
) -> Result<Arc<RwLock<PipelineCursor>>, OracleProviderError>
where
    L1: ChainProvider + Send + Sync + Debug + Clone,
    L2: BatchValidationProvider + Send + Sync + Debug + Clone,
    OracleProviderError:
        From<<L1 as ChainProvider>::Error> + From<<L2 as BatchValidationProvider>::Error>,
{
    tracing::debug!("KONA: Starting new_oracle_pipeline_cursor construction");
    tracing::debug!("KONA: Safe header number: {}, hash: {:?}", safe_header.number, safe_header.hash());

    // Step 1: Get L2 block info for the safe header
    tracing::debug!("KONA: Fetching L2 block info for safe header number: {}", safe_header.number);
    let safe_head_info = l2_chain_provider.l2_block_info_by_number(safe_header.number).await?;
    tracing::debug!("KONA: Successfully fetched L2 block info - L1 origin number: {}, L1 origin hash: {:?}", 
        safe_head_info.l1_origin.number, safe_head_info.l1_origin.hash);

    // Step 2: Get L1 origin block info
    tracing::debug!("KONA: Fetching L1 origin block info for number: {}", safe_head_info.l1_origin.number);
    let l1_origin = chain_provider.block_info_by_number(safe_head_info.l1_origin.number).await?;
    tracing::debug!("KONA: Successfully fetched L1 origin block info - number: {}, hash: {:?}", 
        l1_origin.number, l1_origin.hash);

    // Walk back the starting L1 block by `channel_timeout` to ensure that the full channel is
    // captured.
    // Step 3: Calculate channel timeout and determine L1 origin number
    tracing::debug!("KONA: Calculating channel timeout for timestamp: {}", safe_head_info.block_info.timestamp);
    let channel_timeout = rollup_config.channel_timeout(safe_head_info.block_info.timestamp);
    tracing::debug!("KONA: Channel timeout calculated: {}", channel_timeout);
    
    let original_l1_origin_number = l1_origin.number;
    let mut l1_origin_number = l1_origin.number.saturating_sub(channel_timeout);
    tracing::debug!("KONA: L1 origin number after channel timeout subtraction: {} (was {})", 
        l1_origin_number, original_l1_origin_number);
    
    if l1_origin_number < rollup_config.genesis.l1.number {
        tracing::debug!("KONA: L1 origin number {} is less than genesis L1 number {}, using genesis", 
            l1_origin_number, rollup_config.genesis.l1.number);
        l1_origin_number = rollup_config.genesis.l1.number;
    }
    tracing::debug!("KONA: Final L1 origin number: {}", l1_origin_number);

    // Step 4: Get the actual origin block info
    tracing::debug!("KONA: Fetching final origin block info for number: {}", l1_origin_number);
    let origin = chain_provider.block_info_by_number(l1_origin_number).await?;
    tracing::debug!("KONA: Successfully fetched final origin block info - number: {}, hash: {:?}", 
        origin.number, origin.hash);

    // Construct the cursor.
    // Step 5: Create pipeline cursor
    tracing::debug!("KONA: Creating PipelineCursor with channel timeout: {}", channel_timeout);
    let mut cursor = PipelineCursor::new(channel_timeout, origin);
    tracing::debug!("KONA: PipelineCursor created successfully");

    // Step 6: Create tip cursor
    tracing::debug!("KONA: Creating TipCursor with safe head info");
    let tip = TipCursor::new(safe_head_info, safe_header, B256::ZERO);
    tracing::debug!("KONA: TipCursor created successfully");

    // Step 7: Advance the cursor
    tracing::debug!("KONA: Advancing cursor with origin and tip");
    cursor.advance(origin, tip);
    tracing::debug!("KONA: Cursor advanced successfully");

    // Wrap the cursor in a shared read-write lock
    // Step 8: Wrap in shared lock
    tracing::debug!("KONA: Wrapping cursor in shared RwLock");
    let cursor_arc = Arc::new(RwLock::new(cursor));
    
    tracing::debug!("KONA: Successfully completed new_oracle_pipeline_cursor construction");
    Ok(cursor_arc)
}
