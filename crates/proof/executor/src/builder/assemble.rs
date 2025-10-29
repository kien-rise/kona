//! [Header] assembly logic for the [StatelessL2Builder].

use super::StatelessL2Builder;
use crate::{
    ExecutorError, ExecutorResult, TrieDBError, TrieDBProvider,
    util::{encode_holocene_eip_1559_params, encode_jovian_eip_1559_params},
};
use alloc::vec::Vec;
use alloy_consensus::{EMPTY_OMMER_ROOT_HASH, Header, Sealed};
use alloy_eips::{Encodable2718, eip7685::EMPTY_REQUESTS_HASH};
use alloy_evm::{EvmFactory, block::BlockExecutionResult};
use alloy_primitives::{B256, Sealable, U256, logs_bloom};
use alloy_trie::EMPTY_ROOT_HASH;
use kona_genesis::RollupConfig;
use kona_mpt::{TrieHinter, ordered_trie_with_encoder};
use kona_protocol::{OutputRoot, Predeploys};
use op_alloy_consensus::OpReceiptEnvelope;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use revm::{context::BlockEnv, database::BundleState};

impl<P, H, Evm> StatelessL2Builder<'_, P, H, Evm>
where
    P: TrieDBProvider,
    H: TrieHinter,
    Evm: EvmFactory,
{
    /// Seals the block executed from the given [OpPayloadAttributes] and [BlockEnv], returning the
    /// computed [Header].
    pub(crate) fn seal_block(
        &mut self,
        attrs: &OpPayloadAttributes,
        parent_hash: B256,
        block_env: &BlockEnv,
        ex_result: &BlockExecutionResult<OpReceiptEnvelope>,
        bundle: BundleState,
    ) -> ExecutorResult<Sealed<Header>> {
        tracing::debug!("KONA: Starting seal_block operation");

        let timestamp = block_env.timestamp.saturating_to::<u64>();
        tracing::debug!("KONA: eip_1559_params: {:?}", attrs.eip_1559_params);
        tracing::debug!("KONA: Block timestamp: {}", timestamp);
        tracing::debug!("KONA: Block number: {}", block_env.number.saturating_to::<u64>());
        tracing::debug!("KONA: Parent hash: {:?}", parent_hash);
        tracing::debug!("KONA: Gas used in execution: {}", ex_result.gas_used);
        tracing::debug!("KONA: Number of receipts: {}", ex_result.receipts.len());

        // Compute the roots for the block header.
        tracing::debug!("KONA: Computing state root from bundle");
        let state_root = self.trie_db.state_root(&bundle)?;
        tracing::debug!("KONA: Computed state root: {:?}", state_root);
        tracing::debug!("KONA: Computing transactions root");
        let tx_count = attrs.transactions.as_ref().map(|txs| txs.len()).unwrap_or(0);
        tracing::debug!("KONA: Number of transactions: {}", tx_count);
        let transactions_root = ordered_trie_with_encoder(
            // SAFETY: The OP Stack protocol will never generate a payload attributes with an empty
            // transactions field. Panicking here is the desired behavior, as it indicates a severe
            // protocol violation.
            attrs.transactions.as_ref().expect("Transactions must be non-empty"),
            |tx, buf| buf.put_slice(tx.as_ref()),
        )
        .root();
        tracing::debug!("KONA: Computed transactions root: {:?}", transactions_root);

        tracing::debug!("KONA: Computing receipts root");
        let receipts_root = compute_receipts_root(&ex_result.receipts, self.config, timestamp);
        tracing::debug!("KONA: Computed receipts root: {:?}", receipts_root);

        tracing::debug!("KONA: Determining withdrawals root based on hardfork activation");
        let withdrawals_root = if self.config.is_isthmus_active(timestamp) {
            tracing::debug!("KONA: Isthmus active, computing message passer account root");
            Some(self.message_passer_account(block_env.number.saturating_to::<u64>())?)
        } else if self.config.is_canyon_active(timestamp) {
            tracing::debug!("KONA: Canyon active, using empty root hash");
            Some(EMPTY_ROOT_HASH)
        } else {
            tracing::debug!("KONA: Pre-Canyon, no withdrawals root");
            None
        };
        tracing::debug!("KONA: Withdrawals root: {:?}", withdrawals_root);

        // Compute the logs bloom from the receipts generated during block execution.
        tracing::debug!("KONA: Computing logs bloom from receipts");
        let total_logs = ex_result.receipts.iter().map(|r| r.logs().len()).sum::<usize>();
        tracing::debug!("KONA: Total logs across all receipts: {}", total_logs);
        let logs_bloom = logs_bloom(ex_result.receipts.iter().flat_map(|r| r.logs()));
        tracing::debug!("KONA: Computed logs bloom");

        // Compute Cancun fields, if active.
        tracing::debug!("KONA: Determining blob gas fields based on Ecotone activation");
        let (blob_gas_used, excess_blob_gas) = if self.config.is_ecotone_active(timestamp) {
            tracing::debug!("KONA: Ecotone active, setting blob gas fields to 0");
            (Some(0), Some(0))
        } else {
            tracing::debug!("KONA: Pre-Ecotone, no blob gas fields");
            Default::default()
        };
        tracing::debug!("KONA: Blob gas used: {:?}, Excess blob gas: {:?}", blob_gas_used, excess_blob_gas);

        // At holocene activation, the base fee parameters from the payload are placed
        // into the Header's `extra_data` field.
        //
        // If the payload's `eip_1559_params` are equal to `0`, then the header's `extraData`
        // field is set to the encoded canyon base fee parameters.
        tracing::debug!("KONA: Encoding base fee parameters based on hardfork activation");
        let encoded_base_fee_params = match self.config {
            config if config.is_jovian_active(timestamp) => {
                tracing::debug!("KONA: Jovian active, encoding Jovian EIP-1559 params");
                let extra_data = encode_jovian_eip_1559_params(self.config, attrs)?;
                tracing::debug!("KONA: Encoded Jovian params length: {}", extra_data.len());
                Ok(extra_data)
            }
            config if config.is_holocene_active(timestamp) => {
                tracing::debug!("KONA: Holocene active, encoding Holocene EIP-1559 params");
                let result = encode_holocene_eip_1559_params(self.config, attrs);
                if let Ok(ref data) = result {
                    tracing::debug!("KONA: Encoded Holocene params length: {}", data.len());
                }
                result
            }
            _ => {
                tracing::debug!("KONA: Pre-Holocene, using default empty extra data");
                Ok(Default::default())
            },
        }?;
        tracing::debug!("KONA: Final base fee params length: {}", encoded_base_fee_params.len());

        // The requests hash on the OP Stack, if Isthmus is active, is always the empty SHA256 hash.
        tracing::debug!("KONA: Determining requests hash based on Isthmus activation");
        let requests_hash = self.config.is_isthmus_active(timestamp).then_some(EMPTY_REQUESTS_HASH);
        tracing::debug!("KONA: Requests hash: {:?}", requests_hash);

        // Construct the new header.
        tracing::debug!("KONA: Constructing block header with computed values");
        tracing::debug!("KONA: Header beneficiary: {:?}", attrs.payload_attributes.suggested_fee_recipient);
        tracing::debug!("KONA: Header gas limit: {:?}", attrs.gas_limit);
        tracing::debug!("KONA: Header base fee: {}", block_env.basefee);
        tracing::debug!("KONA: Header prev_randao: {:?}", attrs.payload_attributes.prev_randao);
        tracing::debug!("KONA: Header parent_beacon_block_root: {:?}", attrs.payload_attributes.parent_beacon_block_root);

        let header = Header {
            parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: attrs.payload_attributes.suggested_fee_recipient,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            requests_hash,
            logs_bloom,
            difficulty: U256::ZERO,
            number: block_env.number.saturating_to::<u64>(),
            gas_limit: attrs.gas_limit.ok_or(ExecutorError::MissingGasLimit)?,
            gas_used: ex_result.gas_used,
            timestamp,
            mix_hash: attrs.payload_attributes.prev_randao,
            nonce: Default::default(),
            base_fee_per_gas: Some(block_env.basefee),
            blob_gas_used,
            excess_blob_gas: excess_blob_gas.and_then(|x| x.try_into().ok()),
            parent_beacon_block_root: attrs.payload_attributes.parent_beacon_block_root,
            extra_data: encoded_base_fee_params,
        };

        tracing::debug!("KONA: Sealing header (computing hash)");
        let sealed_header = header.seal_slow();
        tracing::debug!("KONA: Header sealed with hash: {:?}", sealed_header.hash());
        tracing::debug!("KONA: Successfully completed seal_block operation");

        Ok(sealed_header)
    }

    /// Computes the current output root of the latest executed block, based on the parent header
    /// and the underlying state trie.
    ///
    /// **CONSTRUCTION:**
    /// ```text
    /// output_root = keccak256(version_byte .. payload)
    /// payload = state_root .. withdrawal_storage_root .. latest_block_hash
    /// ```
    pub fn compute_output_root(&mut self) -> ExecutorResult<B256> {
        let parent_number = self.trie_db.parent_block_header().number;

        info!(
            target: "block_builder",
            parent_state_root = ?self.trie_db.parent_block_header().state_root,
            parent_block_number = parent_number,
            "Computing output root",
        );

        let storage_root = self.message_passer_account(parent_number)?;
        let parent_header = self.trie_db.parent_block_header();

        // Construct the raw output and hash it.
        let output_root_hash =
            OutputRoot::from_parts(parent_header.state_root, storage_root, parent_header.seal())
                .hash();

        info!(
            target: "block_builder",
            parent_block_number = parent_number,
            output_root = ?output_root_hash,
            "Computed output root",
        );

        // Hash the output and return
        Ok(output_root_hash)
    }

    /// Fetches the L2 to L1 message passer account from the cache or underlying trie.
    fn message_passer_account(&mut self, block_number: u64) -> Result<B256, TrieDBError> {
        match self.trie_db.storage_roots().get(&Predeploys::L2_TO_L1_MESSAGE_PASSER) {
            Some(storage_root) => Ok(storage_root.blind()),
            None => Ok(self
                .trie_db
                .get_trie_account(&Predeploys::L2_TO_L1_MESSAGE_PASSER, block_number)?
                .ok_or(TrieDBError::MissingAccountInfo)?
                .storage_root),
        }
    }
}

/// Computes the receipts root from the given set of receipts.
pub fn compute_receipts_root(
    receipts: &[OpReceiptEnvelope],
    config: &RollupConfig,
    timestamp: u64,
) -> B256 {
    // There is a minor bug in op-geth and op-erigon where in the Regolith hardfork,
    // the receipt root calculation does not include the deposit nonce in the
    // receipt encoding. In the Regolith hardfork, we must strip the deposit nonce
    // from the receipt encoding to match the receipt root calculation.
    if config.is_regolith_active(timestamp) && !config.is_canyon_active(timestamp) {
        let receipts = receipts
            .iter()
            .cloned()
            .map(|receipt| match receipt {
                OpReceiptEnvelope::Deposit(mut deposit_receipt) => {
                    deposit_receipt.receipt.deposit_nonce = None;
                    OpReceiptEnvelope::Deposit(deposit_receipt)
                }
                _ => receipt,
            })
            .collect::<Vec<_>>();

        ordered_trie_with_encoder(receipts.as_ref(), |receipt, mut buf| {
            receipt.encode_2718(&mut buf)
        })
        .root()
    } else {
        ordered_trie_with_encoder(receipts, |receipt, mut buf| receipt.encode_2718(&mut buf)).root()
    }
}
