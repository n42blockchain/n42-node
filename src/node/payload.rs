//! Payload builder configuration for the custom node.
//!
//! This module implements [`PayloadBuilderBuilder`] for our custom node.
//! The payload builder is responsible for constructing new blocks for the
//! consensus layer.

use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::PayloadBuilderBuilder, BuilderContext, PayloadBuilderConfig, PayloadTypes,
};
use reth_transaction_pool::{PoolTransaction, TransactionPool};

/// N42 payload builder.
///
/// This builder creates [`EthereumPayloadBuilder`](reth_ethereum_payload_builder::EthereumPayloadBuilder)
/// instances for constructing new blocks.
///
/// # N42ization Points
///
/// - N42 block building strategies
/// - N42 transaction ordering
/// - N42 fee recipient handling
/// - N42 gas limit policies
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct N42PayloadBuilder;

impl<Types, Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for N42PayloadBuilder
where
    Types: NodeTypes<ChainSpec: EthereumHardforks, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<
            Primitives = PrimitivesTy<Types>,
            NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes,
        > + 'static,
    Types::Payload: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = EthPayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    type PayloadBuilder =
        reth_ethereum_payload_builder::EthereumPayloadBuilder<Pool, Node::Provider, Evm>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        // N42 payload builder configuration
        let builder_config = EthereumBuilderConfig::new().with_gas_limit(gas_limit);

        Ok(reth_ethereum_payload_builder::EthereumPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            builder_config,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_payload_builder() {
        let _builder = N42PayloadBuilder::default();
    }
}
