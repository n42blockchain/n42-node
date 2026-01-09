//! N42 node component builders.
//!
//! This module demonstrates how to implement custom builders for each node component.
//! These builders are used by the [`ComponentsBuilder`] to construct the node.
//!
//! # Component Builders
//!
//! - **PoolBuilder**: Transaction pool configuration
//! - **ExecutorBuilder**: EVM and block executor configuration
//! - **PayloadBuilder**: Block payload construction
//! - **NetworkBuilder**: P2P networking setup (eth66)
//! - **ConsensusBuilder**: Consensus mechanism

use crate::evm::N42EvmConfig;
use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use alloy_consensus::Header;
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::eth::spec::EthExecutorSpec;
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, PeersInfo};
use reth_node_api::{NodePrimitives, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder, PoolBuilder, TxPoolBuilder,
    },
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_payload_primitives::PayloadTypes;
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, EthTransactionPool, PoolPooledTx, PoolTransaction,
    TransactionPool, TransactionValidationTaskExecutor,
};
use reth_tracing::tracing::{debug, info};
use std::{sync::Arc, time::SystemTime};

use super::{N42Node, N42PayloadBuilder};

// ============================================================================
// Pool Builder
// ============================================================================

/// N42 transaction pool builder.
///
/// This builder configures the transaction pool for the custom node.
/// It can be extended to add custom validation rules, prioritization, or filtering.
///
/// # N42ization Points
///
/// - N42 transaction validation rules
/// - N42 transaction ordering/prioritization
/// - N42 blob store configuration
/// - N42 local transaction handling
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42PoolBuilder;

impl<Types, Node> PoolBuilder<Node> for N42PoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();

        // N42: Configure blob cache size based on chain spec
        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            Some(blob_cache_size)
        } else {
            let current_timestamp =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            // 2 epochs worth of blobs
            Some((blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32)
        };

        let blob_store =
            reth_node_builder::components::create_blob_store_with_cache(ctx, blob_cache_size)?;

        // Build the transaction validator
        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(ctx.head().timestamp)
            .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
            .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        // Initialize KZG settings in background for blob transactions
        if validator.validator().eip4844() {
            let kzg_settings = validator.validator().kzg_settings().clone();
            ctx.task_executor().spawn_blocking(async move {
                let _ = kzg_settings.get();
                debug!(target: "custom_node", "Initialized KZG settings");
            });
        }

        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "custom_node", "N42 transaction pool initialized");

        Ok(transaction_pool)
    }
}

// ============================================================================
// Executor Builder
// ============================================================================

/// N42 EVM and executor builder.
///
/// This builder configures the EVM execution environment and block executor.
/// It returns our [`N42EvmConfig`] which wraps the standard Ethereum config.
///
/// # N42ization Points
///
/// - N42 precompiles
/// - N42 gas pricing
/// - N42 EVM environment modifications
/// - N42 block execution hooks
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42ExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for N42ExecutorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec<Header = Header>
                       + Hardforks
                       + EthExecutorSpec
                       + EthereumHardforks
                       + Clone
                       + 'static,
        Primitives = EthPrimitives,
    >,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = N42EvmConfig<Types::ChainSpec>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        // Create our custom EVM config with extra data from payload builder config
        let evm_config = N42EvmConfig::new(ctx.chain_spec());

        info!(target: "custom_node", "N42 EVM config initialized");

        Ok(evm_config)
    }
}

// ============================================================================
// Network Builder
// ============================================================================

/// N42 network builder.
///
/// This builder configures the P2P networking stack using eth66 protocol.
/// The eth66 protocol is configured via `N42NetworkPrimitives` to use our
/// custom `N42BroadcastBlock` type in `NewBlock` messages.
///
/// # eth66 Protocol
///
/// The standard eth66 protocol is used for:
/// - Block propagation (`NewBlock`, `NewBlockHashes`)
/// - Block sync (`GetBlockHeaders`, `BlockHeaders`, `GetBlockBodies`, `BlockBodies`)
/// - Transaction propagation
///
/// # N42ization Points
///
/// - N42NetworkPrimitives: Configures eth66 with N42BroadcastBlock
/// - N42 peer scoring/filtering
/// - N42 block propagation behavior
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42NetworkBuilder;

impl<Node, Pool> NetworkBuilder<Node, Pool> for N42NetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network = ctx.network_builder().await?;
        let handle = ctx.start_network(network, pool);

        info!(
            target: "custom_node",
            enode = %handle.local_node_record(),
            protocols = "eth66, eth67, eth68",
            "N42 P2P network initialized with eth66"
        );

        Ok(handle)
    }
}

// ============================================================================
// Consensus Builder
// ============================================================================

/// N42 consensus builder.
///
/// This builder configures the consensus mechanism.
/// For Ethereum mainnet, this uses the beacon chain consensus.
///
/// # N42ization Points
///
/// - N42 block validation rules
/// - N42 fork choice rules
/// - N42 finality mechanisms
/// - N42 proof-of-stake parameters
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42ConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<ChainSpec: EthChainSpec + EthereumHardforks, Primitives = EthPrimitives>,
    >,
{
    type Consensus = Arc<EthBeaconConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        info!(target: "custom_node", "N42 consensus initialized");
        Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
    }
}

// ============================================================================
// Components Method
// ============================================================================

impl N42Node {
    /// Returns a [`ComponentsBuilder`] configured for the custom node.
    ///
    /// This method creates a builder with all custom components:
    /// - [`N42PoolBuilder`]: Transaction pool with custom configuration
    /// - [`N42ExecutorBuilder`]: EVM with custom configuration
    /// - [`BasicPayloadServiceBuilder`]: Standard payload service with custom builder
    /// - [`N42NetworkBuilder`]: P2P network with eth66 protocol
    /// - [`N42ConsensusBuilder`]: Consensus mechanism
    ///
    /// # Type Parameters
    ///
    /// - `Node`: The full node type implementing [`FullNodeTypes`]
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = NodeBuilder::new(config)
    ///     .with_types::<N42Node>()
    ///     .with_components(N42Node::components());
    /// ```
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        N42PoolBuilder,
        BasicPayloadServiceBuilder<N42PayloadBuilder>,
        N42NetworkBuilder,
        N42ExecutorBuilder,
        N42ConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                ChainSpec: EthChainSpec<Header = Header>
                               + Hardforks
                               + EthereumHardforks
                               + EthExecutorSpec
                               + Clone
                               + 'static,
                Primitives = EthPrimitives,
            >,
        >,
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(N42PoolBuilder::default())
            .executor(N42ExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(N42PayloadBuilder::default()))
            .network(N42NetworkBuilder::default())
            .consensus(N42ConsensusBuilder::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_pool_builder() {
        let _builder = N42PoolBuilder::default();
    }

    #[test]
    fn test_custom_executor_builder() {
        let _builder = N42ExecutorBuilder::default();
    }

    #[test]
    fn test_custom_network_builder() {
        let _builder = N42NetworkBuilder::default();
    }

    #[test]
    fn test_custom_consensus_builder() {
        let _builder = N42ConsensusBuilder::default();
    }
}
