//! N42 EVM configuration.
//!
//! [`ConfigureEvm`] is the trait that controls EVM behavior and block execution.
//! It's one of the most powerful customization points in reth.
//!
//! # What ConfigureEvm Controls
//!
//! - **EVM Environment**: Gas limits, block context, transaction context
//! - **Block Execution**: How transactions are executed in blocks
//! - **Block Building**: How new blocks are constructed for payload building
//! - **Precompiles**: N42 precompiled contracts
//! - **Hardfork Behavior**: Chain-specific rule changes
//!
//! # Implementation Approaches
//!
//! 1. **Wrap EthEvmConfig**: Add custom logic around standard execution
//! 2. **N42 EvmFactory**: Replace the EVM implementation entirely
//! 3. **N42 BlockExecutorFactory**: Change block execution strategy

use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{eth::spec::EthExecutorSpec, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::NextBlockEnvAttributes;
use std::sync::Arc;

/// N42 EVM configuration wrapping the standard Ethereum configuration.
///
/// This demonstrates how to extend EVM behavior for a custom chain.
/// The type is generic over the chain spec type `C` to support different
/// chain configurations.
///
/// # N42ization Examples
///
/// - Add custom precompiles for L2 features
/// - Modify gas pricing for L2 execution
/// - Inject custom transaction processing
///
/// # Type Parameters
///
/// - `C`: The chain specification type, must implement [`EthereumHardforks`]
#[derive(Debug, Clone)]
pub struct N42EvmConfig<C = ChainSpec> {
    /// Inner Ethereum EVM config.
    inner: EthEvmConfig<C>,
    /// N42 configuration field example.
    #[allow(dead_code)]
    custom_gas_multiplier: u64,
}

impl<C> N42EvmConfig<C>
where
    C: EthChainSpec<Header = alloy_consensus::Header>
        + EthereumHardforks
        + Hardforks
        + EthExecutorSpec
        + Clone
        + 'static,
{
    /// Create a new custom EVM config with the given chain spec.
    pub fn new(chain_spec: Arc<C>) -> Self {
        Self {
            inner: EthEvmConfig::new(chain_spec),
            custom_gas_multiplier: 100, // 100% = no change
        }
    }

    /// Create with custom gas multiplier (for L2 gas pricing).
    pub fn with_gas_multiplier(chain_spec: Arc<C>, multiplier: u64) -> Self {
        Self { inner: EthEvmConfig::new(chain_spec), custom_gas_multiplier: multiplier }
    }

    /// Get the inner config.
    pub const fn inner(&self) -> &EthEvmConfig<C> {
        &self.inner
    }

    /// Get the custom gas multiplier.
    pub const fn gas_multiplier(&self) -> u64 {
        self.custom_gas_multiplier
    }
}

// Delegate ConfigureEvm to inner EthEvmConfig.
impl<C> ConfigureEvm for N42EvmConfig<C>
where
    C: EthChainSpec<Header = alloy_consensus::Header>
        + EthereumHardforks
        + Hardforks
        + EthExecutorSpec
        + Clone
        + 'static,
{
    type Primitives = <EthEvmConfig<C> as ConfigureEvm>::Primitives;
    type Error = <EthEvmConfig<C> as ConfigureEvm>::Error;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = <EthEvmConfig<C> as ConfigureEvm>::BlockExecutorFactory;
    type BlockAssembler = <EthEvmConfig<C> as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self.inner.block_executor_factory()
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(
        &self,
        header: &alloy_consensus::Header,
    ) -> Result<reth_evm::EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &alloy_consensus::Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<reth_evm::EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a reth_primitives_traits::SealedBlock<
            <Self::Primitives as reth_primitives_traits::NodePrimitives>::Block,
        >,
    ) -> Result<reth_evm::ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &reth_primitives_traits::SealedHeader<alloy_consensus::Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<reth_evm::ExecutionCtxFor<'_, Self>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::MAINNET;

    #[test]
    fn test_custom_evm_config() {
        let config = N42EvmConfig::new(MAINNET.clone());
        assert_eq!(config.custom_gas_multiplier, 100);
    }

    #[test]
    fn test_with_gas_multiplier() {
        let config = N42EvmConfig::with_gas_multiplier(MAINNET.clone(), 150);
        assert_eq!(config.custom_gas_multiplier, 150);
    }

    #[test]
    fn test_implements_configure_evm() {
        fn assert_configure_evm<T: ConfigureEvm>() {}
        assert_configure_evm::<N42EvmConfig<ChainSpec>>();
    }
}
