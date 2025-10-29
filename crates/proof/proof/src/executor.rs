//! An executor constructor.

use alloc::boxed::Box;
use alloy_consensus::{Header, Sealed};
use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use alloy_primitives::B256;
use async_trait::async_trait;
use core::fmt::Debug;
use kona_driver::Executor;
use kona_executor::{BlockBuildingOutcome, StatelessL2Builder, TrieDBProvider};
use kona_genesis::RollupConfig;
use kona_mpt::TrieHinter;
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use op_revm::OpSpecId;

/// An executor wrapper type.
#[derive(Debug)]
pub struct KonaExecutor<'a, P, H, Evm>
where
    P: TrieDBProvider + Send + Sync + Clone,
    H: TrieHinter + Send + Sync + Clone,
    Evm: EvmFactory + Send + Sync + Clone,
{
    /// The rollup config for the executor.
    rollup_config: &'a RollupConfig,
    /// The trie provider for the executor.
    trie_provider: P,
    /// The trie hinter for the executor.
    trie_hinter: H,
    /// The evm factory for the executor.
    evm_factory: Evm,
    /// The executor.
    inner: Option<StatelessL2Builder<'a, P, H, Evm>>,
}

impl<'a, P, H, Evm> KonaExecutor<'a, P, H, Evm>
where
    P: TrieDBProvider + Send + Sync + Clone,
    H: TrieHinter + Send + Sync + Clone,
    Evm: EvmFactory + Send + Sync + Clone,
{
    /// Creates a new executor.
    pub const fn new(
        rollup_config: &'a RollupConfig,
        trie_provider: P,
        trie_hinter: H,
        evm_factory: Evm,
        inner: Option<StatelessL2Builder<'a, P, H, Evm>>,
    ) -> Self {
        Self { rollup_config, trie_provider, trie_hinter, evm_factory, inner }
    }
}

#[async_trait]
impl<P, H, Evm> Executor for KonaExecutor<'_, P, H, Evm>
where
    P: TrieDBProvider + Debug + Send + Sync + Clone,
    H: TrieHinter + Debug + Send + Sync + Clone,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    type Error = kona_executor::ExecutorError;

    /// Waits for the executor to be ready.
    async fn wait_until_ready(&mut self) {
        /* no-op for the kona executor */
        /* This is used when an engine api is used instead of a stateless block executor */
    }

    /// Updates the safe header.
    ///
    /// Since the L2 block executor is stateless, on an update to the safe head,
    /// a new executor is created with the updated header.
    fn update_safe_head(&mut self, header: Sealed<Header>) {
        self.inner = Some(StatelessL2Builder::new(
            self.rollup_config,
            self.evm_factory.clone(),
            self.trie_provider.clone(),
            self.trie_hinter.clone(),
            header,
        ));
    }

    /// Execute the given payload attributes.
    async fn execute_payload(
        &mut self,
        attributes: OpPayloadAttributes,
    ) -> Result<BlockBuildingOutcome, Self::Error> {
        tracing::debug!("KONA: Starting execute_payload operation");
        tracing::debug!("KONA: Payload attributes - timestamp: {}, gas_limit: {:?}", 
            attributes.payload_attributes.timestamp, attributes.gas_limit);
        tracing::debug!("KONA: Payload attributes - eip_1559_params: {:?}", attributes.eip_1559_params);
        tracing::debug!("KONA: Payload attributes - suggested_fee_recipient: {:?}", 
            attributes.payload_attributes.suggested_fee_recipient);
        
        if let Some(ref txs) = attributes.transactions {
            tracing::debug!("KONA: Payload contains {} transactions", txs.len());
        } else {
            tracing::debug!("KONA: Payload contains no transactions");
        }

        // Step 1: Check if executor is available
        tracing::debug!("KONA: Checking if inner executor is available");
        let executor = match self.inner.as_mut() {
            Some(executor) => {
                tracing::debug!("KONA: Inner executor found, proceeding with block building");
                executor
            }
            None => {
                tracing::error!("KONA: Inner executor is missing, cannot execute payload");
                return Err(kona_executor::ExecutorError::MissingExecutor);
            }
        };

        // Step 2: Execute block building
        tracing::debug!("KONA: Calling build_block on inner executor");
        let result = executor.build_block(attributes);
        
        match &result {
            Ok(outcome) => {
                tracing::debug!("KONA: Block building succeeded - block number: {}, gas used: {}", 
                    outcome.header.number, outcome.execution_result.gas_used);
                tracing::debug!("KONA: Block hash: {:?}", outcome.header.hash());
                tracing::debug!("KONA: State root: {:?}", outcome.header.state_root);
                tracing::debug!("KONA: Successfully completed execute_payload operation");
            }
            Err(e) => {
                tracing::error!("KONA: Block building failed: {:?}", e);
            }
        }

        result
    }

    /// Computes the output root.
    fn compute_output_root(&mut self) -> Result<B256, Self::Error> {
        self.inner.as_mut().map_or_else(
            || Err(kona_executor::ExecutorError::MissingExecutor),
            |e| e.compute_output_root(),
        )
    }
}
