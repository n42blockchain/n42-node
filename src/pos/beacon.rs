//! Beacon state and block types for POS consensus.
//!
//! This module provides a complete BeaconState implementation with VecTree storage
//! for efficient validator management.

use std::time::Instant;
use tree_hash_derive::TreeHash;
use tree_hash::TreeHash;
use blst::min_pk::PublicKey;
use blst::min_pk::SecretKey;
use std::collections::BTreeSet;
use blst::min_pk::{AggregateSignature, Signature};
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use ssz_derive::{Encode, Decode};
use ssz::Encode;
use integer_sqrt::IntegerSquareRoot;
use alloy_eips::{
    eip4895::Withdrawal, eip7002::WithdrawalRequest,
};
use serde::{Deserialize, Serialize};
use alloy_primitives::{FixedBytes, Sealable};
use alloy_primitives::{Address, Bytes, keccak256, BlockHash, B256, Log};
use alloy_sol_types::{SolEvent, sol};
use tracing::{debug, error};

use crate::pos::{activation_queue::ActivationQueue, Hash256, Slot, Validator, CommitteeIndex};
use crate::pos::safe_arith::SafeArith;
use crate::pos::safe_arith::SafeArithIter;
use crate::pos::committee_cache::CommitteeCache;
use ethereum_hashing::hash;
use crate::merkle_db::tree::VecTree;
use typenum::U100000;
use derivative::Derivative;

pub const SLOTS_PER_EPOCH: u64 = 32;

pub const DOMAIN_CONSTANT_BEACON_ATTESTER: u32 = 1;

// EthSpec
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 16;
pub const MAX_DEPOSITS: u64 = 16;
pub const GENESIS_EPOCH: u64 = 0;

#[derive(Debug, Default, Clone)]
pub struct ChainSpec {
    pub max_pending_partials_per_withdrawals_sweep: u64,
    pub min_activation_balance: u64,
    pub ejection_balance: u64,
    pub far_future_epoch: u64,
    pub max_validators_per_withdrawals_sweep: u64,
    pub max_effective_balance: u64,
    pub full_exit_request_amount: u64,
    pub shard_committee_period: u64,
    pub compounding_withdrawal_prefix_byte: u8,
    pub eth1_address_withdrawal_prefix_byte: u8,
    pub max_seed_lookahead: u64,
    pub max_per_epoch_activation_exit_churn_limit: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub churn_limit_quotient: u64,
    pub effective_balance_increment: u64,
    pub base_rewards_per_epoch: u64,
    pub base_reward_factor: u64,
    pub min_epochs_to_inactivity_penalty: u64,
    pub inactivity_penalty_quotient: u64,
    pub proposer_reward_quotient: u64,
    pub min_per_epoch_churn_limit: u64,
    pub max_committees_per_slot: usize,
    pub target_committee_size: usize,
    pub min_seed_lookahead: u64,
    pub shuffle_round_count: u8,

    pub inactivity_score_bias: u64,
    pub inactivity_score_recovery_rate: u64,
    pub max_inactivity_score: u64,
    pub trigger_punish_inactivity_score: u64,
    pub multiple_reward_for_inactivity_penalty: u64,

    pub min_validator_withdrawability_delay: u64,
}

pub fn beacon_chain_spec() -> ChainSpec {
    ChainSpec {
        max_pending_partials_per_withdrawals_sweep: 16,
        min_activation_balance: 32000000000,
        ejection_balance: 16000000000,
        far_future_epoch: u64::max_value(),
        max_validators_per_withdrawals_sweep: 16384,
        max_effective_balance: 32000000000,
        full_exit_request_amount: 0,
        shard_committee_period: 1,
        compounding_withdrawal_prefix_byte: 0x02,
        eth1_address_withdrawal_prefix_byte: 0x01,
        max_seed_lookahead: 4,
        max_per_epoch_activation_exit_churn_limit: 256000000000,
        min_per_epoch_churn_limit_electra: 128000000000,
        churn_limit_quotient: 32,
        effective_balance_increment: 1000000000,
        base_rewards_per_epoch: 1,
        base_reward_factor: 1,
        min_epochs_to_inactivity_penalty: 4,
        inactivity_penalty_quotient: 67108864,
        proposer_reward_quotient: 4,
        min_per_epoch_churn_limit: 4,
        max_committees_per_slot: 4,
        target_committee_size: 4,
        min_seed_lookahead: 1,
        shuffle_round_count: 10,

        inactivity_score_bias: 1,
        inactivity_score_recovery_rate: 48,
        max_inactivity_score: 8100,
        trigger_punish_inactivity_score: 2700,
        multiple_reward_for_inactivity_penalty: 3,

        min_validator_withdrawability_delay: 1,
    }
}

pub const CACHED_EPOCHS: usize = 3;

// lighthouse: consensus/types/src/chain_spec.rs, get_deposit_domain()
const DOMAIN_DEPOSIT: [u8; 32] = hex_literal::hex!("03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9");

macro_rules! verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err(eyre::eyre!($result));
        }
    };
}

/// Solidity-style struct for the DepositEvent
sol! {
    #[derive(Debug)]
    event DepositEvent (
        bytes pubkey,
        bytes withdrawal_credentials,
        bytes amount,
        bytes signature,
        bytes index,
    );
}

pub type Epoch = u64;

pub fn epoch_to_block_number(epoch: Epoch) -> u64 {
    epoch.saturating_mul(SLOTS_PER_EPOCH)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExitWithSig {
    pub voluntary_exit: VoluntaryExit,
    pub signature: Bytes,
}

pub struct BeaconStateChangeset {
    pub beaconstates: Vec<(BlockHash, BeaconState)>,
}

pub struct BeaconBlockChangeset {
    pub beaconblocks: Vec<(BlockHash, PosBeaconBlock)>,
}

#[derive(Derivative, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[derivative(Debug)]
pub struct BeaconState {
    pub slot: u64,
    pub eth1_deposit_index: u64,

    pub validators: Hash256,
    pub validators_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug="ignore")]
    pub validators_store: VecTree<Validator, U100000>,

    pub balances: Hash256,
    pub balances_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug="ignore")]
    pub balances_store: VecTree<Gwei, U100000>,

    pub inactivity_scores: Hash256,
    pub inactivity_scores_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug="ignore")]
    pub inactivity_scores_store: VecTree<u64, U100000>,

    pub randao_mix: B256,

    pub next_withdrawal_index: u64,
    pub next_withdrawal_validator_index: u64,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub earliest_exit_epoch: Epoch,
    pub exit_balance_to_consume: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    pub total_active_balance: Option<TotalActiveBalance>,

    pub epoch_attester_indexes: Hash256,
    pub epoch_attester_indexes_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug="ignore")]
    pub epoch_attester_indexes_store: VecTree<u64, U100000>,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug="ignore")]
    pub epoch_attester_indexes_set: BTreeSet<u64>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize)]
pub struct TotalActiveBalance(pub Epoch, pub u64);

impl Sealable for BeaconState {
    fn hash_slow(&self) -> B256 {
        let out = self.as_ssz_bytes();
        keccak256(&out)
    }
}

pub type Gwei = u64;

// BLS types
pub type BLSPubkey = FixedBytes<48>;
pub type BLSSignature = FixedBytes<96>;

/// POS BeaconBlock - compatible with N42-rs but with additional difficulty field for POA
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct PosBeaconBlock {
    pub slot: Slot,
    pub eth1_block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub state_root: B256,
    pub body: PosBeaconBlockBody,
    /// POA difficulty (2 = in_turn, 1 = out_of_turn).
    /// This field is used for Clique POA consensus compatibility.
    pub difficulty: u64,
}

impl Sealable for PosBeaconBlock {
    fn hash_slow(&self) -> B256 {
        let out = self.as_ssz_bytes();
        keccak256(&out)
    }
}

impl PosBeaconBlock {
    /// Create a new POS beacon block with difficulty (for POA).
    pub fn new(
        slot: Slot,
        eth1_block_hash: BlockHash,
        parent_hash: BlockHash,
        state_root: B256,
        body: PosBeaconBlockBody,
        difficulty: u64,
    ) -> Self {
        Self { slot, eth1_block_hash, parent_hash, state_root, body, difficulty }
    }

    /// Create without difficulty (defaults to 0).
    pub fn new_without_difficulty(
        slot: Slot,
        eth1_block_hash: BlockHash,
        parent_hash: BlockHash,
        state_root: B256,
        body: PosBeaconBlockBody,
    ) -> Self {
        Self { slot, eth1_block_hash, parent_hash, state_root, body, difficulty: 0 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct BlockVerifyResultAggregate {
    pub validator_indexes: BTreeSet<u64>,
    pub block_aggregate_signature: Option<FixedBytes<96>>,
}

pub fn agg_sig_to_fixed(sig: &AggregateSignature) -> FixedBytes<96> {
    FixedBytes::from(sig.to_signature().to_bytes())
}

pub fn fixed_to_agg_sig(bytes: &FixedBytes<96>) -> eyre::Result<AggregateSignature> {
    Ok(
        AggregateSignature::from_signature(
        &Signature::from_bytes(bytes.as_ref())
            .map_err(|e| eyre::eyre!("Signature::from_bytes error: {e:?}"))?
        )
    )
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct PosBeaconBlockBody {
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub voluntary_exits: Vec<VoluntaryExitWithSig>,
    pub execution_requests: ExecutionRequestsV4,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct DepositRequest {
    pub pubkey: Bytes,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: Bytes,
    pub index: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: Bytes,
    pub target_pubkey: Bytes,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Attestation {
    pub validator_indexes: BTreeSet<u64>,
    pub data: AttestationData,
    pub block_aggregate_signature: Option<FixedBytes<96>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationData {
    pub slot: Slot,
    pub committee_index: CommitteeIndex,
    pub receipts_root: B256,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Deposit {
    pub proof: Vec<B256>,
    pub data: DepositData,
}

/// Used by deposit data signing and verifying, do not modify field data types
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositData {
    pub pubkey: FixedBytes<48>,
    #[serde(rename = "withdrawal_credentials")]
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: FixedBytes<96>,
}

impl DepositData {
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Generate the signature for a given DepositData details.
    pub fn create_signature(&self, secret_key: &SecretKey) -> FixedBytes<96> {
        debug!("domain: 0x{}", hex::encode(DOMAIN_DEPOSIT));

        let msg = self.as_deposit_message().signing_root(FixedBytes::from_slice(&DOMAIN_DEPOSIT));
        debug!("signing_root: 0x{}", hex::encode(msg));
        FixedBytes(secret_key.sign(msg.as_ref(),
                alloy_rpc_types_beacon::constants::BLS_DST_SIG,
                &[]).to_bytes())
    }

    pub fn verify_signature(&self) -> bool {
        let signature = match Signature::from_bytes(self.signature.as_ref()) {
            Ok(v) => v,
            _ => return false,
        };

        let pubkey = match PublicKey::from_bytes(self.pubkey.as_ref()) {
            Ok(v) => v,
            _ => return false,
        };

        let msg = self.as_deposit_message().signing_root(FixedBytes::from_slice(&DOMAIN_DEPOSIT));
        let err = signature.verify(true, msg.as_ref(), alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[], &pubkey, true);
        err == blst::BLST_ERROR::BLST_SUCCESS
    }
}

#[derive(TreeHash, Serialize, Deserialize)]
pub struct DepositMessage {
    pub pubkey: FixedBytes<48>,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

impl SignedRoot for DepositMessage {}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SigningData {
    pub object_root: B256,
    pub domain: B256,
}

pub trait SignedRoot: tree_hash::TreeHash {
    fn signing_root(&self, domain: Hash256) -> Hash256 {
        SigningData {
            object_root: self.tree_hash_root(),
            domain,
        }.tree_hash_root()
    }
}

pub fn parse_deposit_log(log: &Log) -> Option<DepositEvent> {
    let deposit_event_sig = b"DepositEvent(bytes,bytes,bytes,bytes,bytes)";
    let deposit_topic: B256 = keccak256(deposit_event_sig).into();
    debug!(target: "consensus-client", ?deposit_topic, "parse_deposit_log");
    if let Some(&topic) = log.topics().first() {
        if topic == deposit_topic {
            match DepositEvent::decode_log(log) {
                Ok(v) => Some(v.data),
                Err(err) => {
                    error!(target: "consensus-client", ?err, "parse_deposit_log failed");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    }
}

impl BeaconState {
    pub fn new() -> Self {
        let validators_len = 0;
        let validators_store = VecTree::try_new(validators_len).unwrap();
        let inactivity_scores_len = 0;
        let inactivity_scores_store = VecTree::try_new(inactivity_scores_len).unwrap();
        let balances_len = 0;
        let balances_store = VecTree::try_new(balances_len).unwrap();
        let epoch_attester_indexes_len = 0;
        let epoch_attester_indexes_store = VecTree::try_new(epoch_attester_indexes_len).unwrap();
        Self {
            validators: validators_store.root(),
            validators_store,
            validators_len,
            inactivity_scores: inactivity_scores_store.root(),
            inactivity_scores_store,
            inactivity_scores_len,
            balances: balances_store.root(),
            balances_store,
            balances_len,
            epoch_attester_indexes: epoch_attester_indexes_store.root(),
            epoch_attester_indexes_store,
            epoch_attester_indexes_len,
            ..Default::default()
        }
    }

    pub fn state_transition(old_beacon_state: &BeaconState, beacon_block: &PosBeaconBlock) -> eyre::Result<Self> {
        debug!(target: "consensus-client", ?old_beacon_state, ?beacon_block, "state_transition");
        let spec = beacon_chain_spec();
        let mut new_beacon_state = old_beacon_state.clone();
        new_beacon_state.slot += 1;
        new_beacon_state.build_total_active_balance_cache(&spec)?;
        if (new_beacon_state.slot) % SLOTS_PER_EPOCH == 0 {
            let start = Instant::now();
            new_beacon_state.process_epoch(&spec)?;
            let duration_process_epoch = start.elapsed();
            debug!(?duration_process_epoch);
        }
        new_beacon_state.process_block(beacon_block, &spec)?;

        Ok(new_beacon_state)
    }

    fn process_epoch(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        let mut new_total_active_balance: u64 = 0;

        self.validators_store.update_indices(&(0..self.validators_store.len()).collect(), |index, validator| {
            let balance = self.balances_store.get(index).unwrap().min(&spec.max_effective_balance);
            let new_effective_balance = round_to_nearest(*balance, spec.effective_balance_increment);
            if new_effective_balance != validator.effective_balance {
                validator.effective_balance = new_effective_balance;
            }
            new_total_active_balance = new_total_active_balance.saturating_add(new_effective_balance);
        })?;
        self.total_active_balance.replace(TotalActiveBalance(self.current_epoch(),
        std::cmp::max(
            new_total_active_balance,
            spec.effective_balance_increment,
        )));

        let epoch = self.previous_epoch();
        let active_validator_indices = self.get_active_validator_indices(epoch);

        self.inactivity_scores_store.update_indices(&active_validator_indices.into_iter().collect(), |index, inactivity_score| {
            let is_active = self.epoch_attester_indexes_set.contains(&(index as u64));
            if is_active {
                *inactivity_score = inactivity_score.saturating_sub(spec.inactivity_score_recovery_rate);
            } else {
                if *inactivity_score < spec.max_inactivity_score {
                    *inactivity_score = inactivity_score.saturating_add(spec.inactivity_score_bias);
                }
            }
        })?;
        let validator_statuses = ValidatorStatuses::new(self, spec)?;
        self.epoch_attester_indexes_store.clear();
        self.epoch_attester_indexes_set.clear();

        self.process_rewards_and_penalties(&validator_statuses, spec)?;
        self.process_registry_updates(spec)?;

        self.prune();

        Ok(())
    }

    fn process_registry_updates(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        let current_epoch = self.current_epoch();
        let is_ejectable = |validator: &Validator| {
            validator.is_active_at(current_epoch)
                && validator.effective_balance <= spec.ejection_balance
        };
        let indices_to_update: Vec<_> = self
            .validators_store
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.is_eligible_for_activation_queue(spec) || is_ejectable(validator)
            })
            .map(|(idx, _)| idx)
            .collect();

        for index in indices_to_update {
            let mut validator = self.validators_store.get(index).ok_or(eyre::eyre!("ValidatorNotfound"))?.clone();
            if validator.is_eligible_for_activation_queue(spec) {
                validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
                self.validators_store.set(index, validator.clone())?;
            }
            if is_ejectable(&validator) {
                self.initiate_validator_exit(index, spec)?;
            }
        }

        let churn_limit = self.get_activation_churn_limit(spec)? as usize;
        let next_epoch = self.next_epoch()?;
        let mut full_activation_queue = ActivationQueue::default();

        for (index, validator) in self.validators_store.iter().enumerate() {
            full_activation_queue
                .add_if_could_be_eligible_for_activation(index, validator, next_epoch, spec);
        }

        let activation_queue =
            full_activation_queue
            .get_validators_eligible_for_activation(current_epoch, churn_limit);

        let delayed_activation_epoch = self.compute_activation_exit_epoch(current_epoch, spec)?;
        for index in activation_queue {
            let mut validator = self.validators_store.get(index).ok_or(eyre::eyre!("ValidatorNotfound"))?.clone();
            validator.activation_epoch = delayed_activation_epoch;
            self.validators_store.set(index, validator)?;
        }

        Ok(())
    }

    fn process_block(&mut self, beacon_block: &PosBeaconBlock, spec: &ChainSpec) -> eyre::Result<()> {
        self.process_randao(&beacon_block.body, spec)?;
        self.process_operations(&beacon_block.body, spec)?;
        Ok(())
    }

    fn process_randao(&mut self, beacon_block_body: &PosBeaconBlockBody, _spec: &ChainSpec) -> eyre::Result<()> {
        for attestation in &beacon_block_body.attestations {
            self.verify_aggregate_signature(attestation)?;
        }

        let mut mix = self.randao_mix;
        for attestation in &beacon_block_body.attestations {
            mix = mix ^ keccak256(attestation.block_aggregate_signature.unwrap());
        }

        self.randao_mix = mix;

        Ok(())
    }

    fn process_operations(&mut self, beacon_block_body: &PosBeaconBlockBody, spec: &ChainSpec) -> eyre::Result<()> {
        self.process_attestation(&beacon_block_body.attestations)?;

        let deposits: Vec<Deposit> = beacon_block_body.execution_requests.deposits.clone().iter().map(|deposit_request| {
            Deposit {
                proof: Default::default(),
                data: DepositData {
                    pubkey: deposit_request.pubkey,
                    withdrawal_credentials: deposit_request.withdrawal_credentials,
                    amount: deposit_request.amount,
                    signature: deposit_request.signature,
                }
            }
        }).collect();
        self.process_deposits(&deposits, spec)?;
        self.process_exits(&beacon_block_body.voluntary_exits, spec)?;
        self.process_withdrawal_requests(&beacon_block_body.execution_requests.withdrawals, spec)?;

        Ok(())
    }

    fn process_withdrawal_requests(&mut self, requests: &[WithdrawalRequest], spec: &ChainSpec) -> eyre::Result<()> {
        for request in requests {
            let amount = request.amount;
            let is_full_exit_request = amount == spec.full_exit_request_amount;

            if self.pending_partial_withdrawals.len() == PENDING_PARTIAL_WITHDRAWALS_LIMIT
                && !is_full_exit_request
            {
                continue;
            }

            let Some(validator_index) = self.get_validator_index_from_pubkey(&request.validator_pubkey) else {
                continue;
            };

            let validator = self.get_validator(validator_index)?;
            let has_correct_credential = validator.has_execution_withdrawal_credential(spec);
            let is_correct_source_address = validator
                .get_execution_withdrawal_address()
                .map(|addr| addr == request.source_address)
                .unwrap_or(false);

            if !(has_correct_credential && is_correct_source_address) {
                continue;
            }

            if !validator.is_active_at(self.current_epoch()) {
                continue;
            }

            if validator.exit_epoch != spec.far_future_epoch {
                continue;
            }

            if self.current_epoch()
                < validator
                .activation_epoch
                .safe_add(spec.shard_committee_period)?
            {
                continue;
            }

            let pending_balance_to_withdraw = self.get_pending_balance_to_withdraw(validator_index)?;
            if is_full_exit_request {
                if pending_balance_to_withdraw == 0 {
                    self.initiate_validator_exit(validator_index, spec)?
                }
                continue;
            }

            let balance = self.get_balance(validator_index)?;
            let has_sufficient_effective_balance =
                validator.effective_balance >= spec.min_activation_balance;
            let has_excess_balance = balance
                >
                spec.min_activation_balance
                .safe_add(pending_balance_to_withdraw)?;

            if validator.has_compounding_withdrawal_credential(spec)
                && has_sufficient_effective_balance
                && has_excess_balance
            {
                let to_withdraw = std::cmp::min(
                    balance
                        .safe_sub(spec.min_activation_balance)?
                        .safe_sub(pending_balance_to_withdraw)?,
                    amount,
                );
                let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(to_withdraw, spec)?;
                let withdrawable_epoch =
                    exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
                self
                    .pending_partial_withdrawals
                    .push(PendingPartialWithdrawal {
                        validator_index: validator_index as u64,
                        amount: to_withdraw,
                        withdrawable_epoch,
                    });
            }
        }
        Ok(())
    }

    fn process_attestation(&mut self, attestations: &Vec<Attestation>) -> eyre::Result<()> {
        for attestation in attestations {
            self.process_one_attestation(attestation)?;
        }
        Ok(())
    }

    fn process_one_attestation(&mut self, attestation: &Attestation) -> eyre::Result<()> {
        let start = Instant::now();
        self.verify_aggregate_signature(attestation)?;
        let duration_verify_aggregate_signature = start.elapsed();
        let indexes: Vec<u64> = attestation.validator_indexes.iter().copied().collect();
        self.epoch_attester_indexes_store.push_batch(&indexes)?;
        self.epoch_attester_indexes_set.extend(&attestation.validator_indexes);
        let duration_process_one_attestation = start.elapsed();
        debug!(?duration_verify_aggregate_signature, ?duration_process_one_attestation, "process_one_attestation");
        Ok(())
    }

    fn verify_aggregate_signature(&self, attestation: &Attestation) -> eyre::Result<()> {
        let sig = match attestation.block_aggregate_signature {
            Some(ref v) => v,
            None => {
                return Err(eyre::eyre!("aggregate signature is empty"));
            }
        };
        let sig = fixed_to_agg_sig(sig)?;
        let mut pubkeys = Vec::new();
        for validator_index in &attestation.validator_indexes {
            let validator = self.get_validator(*validator_index as usize)?;
            pubkeys.push(PublicKey::from_bytes(&validator.pubkey.as_slice())
                .map_err(|e| eyre::eyre!("PublicKey::from_bytes error {e:?}"))?
                );
        }
        let pubkeys: Vec<&PublicKey> = pubkeys.iter().collect();
        let bytes: Vec<u8> = serde_json::to_vec(&attestation.data)?;
        let bytes_slice: &[u8] = &bytes;
        let aggregate_sig_verify_result = sig.to_signature().fast_aggregate_verify(true, bytes_slice, alloy_rpc_types_beacon::constants::BLS_DST_SIG, pubkeys.as_slice());
        debug!(target: "consensus-client", slot=?attestation.data.slot, pubkeys_len=?pubkeys.len(), ?aggregate_sig_verify_result);

        if aggregate_sig_verify_result == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(eyre::eyre!("failed: {aggregate_sig_verify_result:?}"))
        }
    }

    fn get_expected_withdrawals(&self, spec: &ChainSpec) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        debug!(target: "consensus-client", "get_expected_withdrawals");
        let epoch = self.current_epoch();
        let mut withdrawal_index = self.next_withdrawal_index;
        let mut validator_index = self.next_withdrawal_validator_index;
        let mut withdrawals = Vec::<Withdrawal>::with_capacity(MAX_WITHDRAWALS_PER_PAYLOAD);

        let mut processed_partial_withdrawals_count = 0;

        for withdrawal in self.pending_partial_withdrawals.iter() {
            if withdrawal.withdrawable_epoch > epoch
                || withdrawals.len() == spec.max_pending_partials_per_withdrawals_sweep as usize
            {
                break;
            }

            let validator = self.get_validator(withdrawal.validator_index as usize)?;

            let has_sufficient_effective_balance =
                validator.effective_balance >= spec.min_activation_balance;
            let total_withdrawn = withdrawals
                .iter()
                .filter_map(|w| {
                    (w.validator_index == withdrawal.validator_index).then_some(w.amount)
                })
                .safe_sum()?;
            let balance = self
                .get_balance(withdrawal.validator_index as usize)?
                .safe_sub(total_withdrawn)?;
            let has_excess_balance = balance > spec.min_activation_balance;

            if validator.exit_epoch == spec.far_future_epoch
                && has_sufficient_effective_balance
                && has_excess_balance
            {
                let withdrawable_balance = std::cmp::min(
                    balance.safe_sub(spec.min_activation_balance)?,
                    withdrawal.amount,
                );
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index: withdrawal.validator_index,
                    address: validator
                        .get_execution_withdrawal_address()
                        .ok_or(eyre::eyre!("NonExecutionAddressWithdrawalCredential"))?,
                    amount: withdrawable_balance,
                });
                withdrawal_index.safe_add_assign(1)?;
            }
            processed_partial_withdrawals_count.safe_add_assign(1)?;
        }

        let bound = std::cmp::min(
            self.validators_store.len() as u64,
            spec.max_validators_per_withdrawals_sweep,
        );
        debug!(target: "consensus-client", ?bound, "get_expected_withdrawals");
        for _ in 0..bound {
            let validator = self.get_validator(validator_index as usize)?;
            let partially_withdrawn_balance = withdrawals
                .iter()
                .filter_map(|withdrawal| {
                    (withdrawal.validator_index == validator_index).then_some(withdrawal.amount)
                })
                .safe_sum()?;
            let balance = self.get_balance(validator_index as usize)?
                .safe_sub(partially_withdrawn_balance)?;
            if validator.is_fully_withdrawable_validator(balance, epoch) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: validator
                        .get_execution_withdrawal_address()
                        .ok_or(eyre::eyre!("WithdrawalCredentialsInvalid"))?,
                    amount: balance,
                });
                withdrawal_index.safe_add_assign(1)?;
            } else if validator.is_partially_withdrawable_validator(balance, spec) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: validator
                        .get_execution_withdrawal_address()
                        .ok_or(eyre::eyre!("WithdrawalCredentialsInvalid"))?,
                    amount: balance.safe_sub(spec.max_effective_balance)?,
                });
                withdrawal_index.safe_add_assign(1)?;
            }
            if withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            validator_index = validator_index
                .safe_add(1)?
                .safe_rem(self.validators_store.len() as u64)?;
        }

        Ok((withdrawals, Some(processed_partial_withdrawals_count)))
    }

    pub fn process_withdrawals(&mut self) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        let spec = beacon_chain_spec();
        let (expected_withdrawals, processed_partial_withdrawals_count) =
            self.get_expected_withdrawals(&spec)?;

        for withdrawal in expected_withdrawals.iter() {
            decrease_balance(
                self,
                withdrawal.validator_index as usize,
                withdrawal.amount,
            )?;
        }

        if let Some(processed_partial_withdrawals_count) = processed_partial_withdrawals_count.clone() {
            self.pending_partial_withdrawals
                .drain(0..processed_partial_withdrawals_count);
        }

        if let Some(latest_withdrawal) = expected_withdrawals.last() {
            self.next_withdrawal_index = latest_withdrawal.index.safe_add(1)?;

            if expected_withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD {
                let next_validator_index = latest_withdrawal
                    .validator_index
                    .safe_add(1)?
                    .safe_rem(self.validators_store.len() as u64)?;
                self.next_withdrawal_validator_index = next_validator_index;
            }
        }

        if expected_withdrawals.len() != MAX_WITHDRAWALS_PER_PAYLOAD && !self.validators_store.is_empty() {
            let next_validator_index = self
                .next_withdrawal_validator_index
                .safe_add(spec.max_validators_per_withdrawals_sweep)?
                .safe_rem(self.validators_store.len() as u64)?;
            self.next_withdrawal_validator_index = next_validator_index;
        }

        Ok((expected_withdrawals, processed_partial_withdrawals_count))
    }

    pub fn current_epoch(&self) -> Epoch {
        self.slot / SLOTS_PER_EPOCH
    }

    fn next_epoch(&self) -> eyre::Result<Epoch> {
        Ok(self.current_epoch().safe_add(1)?)
    }

    fn previous_epoch(&self) -> Epoch {
        let current_epoch = self.current_epoch();
        if let Ok(prev_epoch) = current_epoch.safe_sub(1) {
            prev_epoch
        } else {
            current_epoch
        }
    }

    pub fn get_validator(&self, validator_index: usize) -> eyre::Result<&Validator> {
        self.validators_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
    }

    pub fn get_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.balances_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
            .copied()
    }

    pub fn get_inactivity_score(&self, validator_index: usize) -> eyre::Result<u64> {
        self.inactivity_scores_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
            .copied()
    }

    fn get_pending_balance_to_withdraw(&self, validator_index: usize) -> eyre::Result<u64> {
        let mut pending_balance = 0;
        for withdrawal in self
            .pending_partial_withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index as usize == validator_index)
        {
            pending_balance.safe_add_assign(withdrawal.amount)?;
        }
        Ok(pending_balance)
    }

    fn compute_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> eyre::Result<Epoch> {
        Ok(epoch.safe_add(1)?.safe_add(spec.max_seed_lookahead)?)
    }

    fn compute_exit_epoch_and_update_churn(&mut self, exit_balance: u64, spec: &ChainSpec) -> eyre::Result<Epoch> {
        let mut earliest_exit_epoch = std::cmp::max(
            self.earliest_exit_epoch,
            self.compute_activation_exit_epoch(self.current_epoch(), spec)?,
        );

        let per_epoch_churn = self.get_activation_exit_churn_limit(spec)?;
        let mut exit_balance_to_consume = if self.earliest_exit_epoch < earliest_exit_epoch {
            per_epoch_churn
        } else {
            self.exit_balance_to_consume
        };

        if exit_balance > exit_balance_to_consume {
            let balance_to_process = exit_balance.safe_sub(exit_balance_to_consume)?;
            let additional_epochs = balance_to_process
                .safe_sub(1)?
                .safe_div(per_epoch_churn)?
                .safe_add(1)?;
            earliest_exit_epoch.safe_add_assign(additional_epochs)?;
            exit_balance_to_consume
                .safe_add_assign(additional_epochs.safe_mul(per_epoch_churn)?)?;
        }
        self.exit_balance_to_consume =
            exit_balance_to_consume.safe_sub(exit_balance)?;
        self.earliest_exit_epoch = earliest_exit_epoch;
        Ok(self.earliest_exit_epoch)
    }

    pub fn get_validator_index_from_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.validators_store.iter().position(|validator| validator.pubkey == *pubkey)
    }

    pub fn get_effective_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.get_validator(validator_index)
            .map(|v| v.effective_balance)
    }

    fn initiate_validator_exit(&mut self, index: usize, spec: &ChainSpec) -> eyre::Result<()> {
        let validator = self.get_validator(index)?;

        if validator.exit_epoch != spec.far_future_epoch {
            return Ok(());
        }

        let effective_balance = self.get_effective_balance(index)?;
        let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(effective_balance, spec)?;

        let mut validator = self.validators_store.get(index).ok_or(eyre::eyre!("ValidatorNotfound"))?.clone();
        validator.exit_epoch = exit_queue_epoch;
        validator.withdrawable_epoch =
            exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
        self.validators_store.set(index, validator)?;

        Ok(())
    }

    fn get_activation_exit_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        Ok(std::cmp::min(
            spec.max_per_epoch_activation_exit_churn_limit,
            self.get_balance_churn_limit(spec)?,
        ))
    }

    fn get_balance_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        let total_active_balance = self.get_total_active_balance(spec)?;
        let churn = std::cmp::max(
            spec.min_per_epoch_churn_limit_electra,
            total_active_balance.safe_div(spec.churn_limit_quotient)?,
        );

        Ok(churn.safe_sub(churn.safe_rem(spec.effective_balance_increment)?)?)
    }

    pub fn get_total_active_balance(&self, _spec: &ChainSpec) -> eyre::Result<u64> {
        self.get_total_active_balance_at_epoch(self.current_epoch())
    }

    fn get_total_active_balance_at_epoch(&self, epoch: Epoch) -> eyre::Result<u64> {
        let TotalActiveBalance(initialized_epoch, balance) = self
            .total_active_balance.clone()
            .ok_or(eyre::eyre!("TotalActiveBalanceCacheUninitialized"))?;

        if initialized_epoch == epoch {
            Ok(balance)
        } else {
            Err(eyre::eyre!("TotalActiveBalanceCacheInconsistent , initialized_epoch={initialized_epoch}, current_epoch={epoch}"))
        }
    }

    fn build_total_active_balance_cache(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        if self
            .get_total_active_balance_at_epoch(self.current_epoch())
            .is_err()
        {
            self.force_build_total_active_balance_cache(spec)?;
        }
        Ok(())
    }

    fn force_build_total_active_balance_cache(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        let total_active_balance = self.compute_total_active_balance_slow(spec)?;
        self.total_active_balance = Some(TotalActiveBalance(self.current_epoch(), total_active_balance));
        Ok(())
    }

    fn process_exits(&mut self, voluntary_exits: &[VoluntaryExitWithSig], spec: &ChainSpec) -> eyre::Result<()> {
        for (i, exit) in voluntary_exits.iter().enumerate() {
            self.verify_exit(None, exit, spec)
                .map_err(|e| eyre::eyre!("verify_exit error {e}, index {i}"))?;

            self.initiate_validator_exit(exit.voluntary_exit.validator_index as usize, spec)?;
        }
        Ok(())
    }

    fn verify_exit(&mut self, current_epoch: Option<Epoch>, signed_exit: &VoluntaryExitWithSig, spec: &ChainSpec) -> eyre::Result<()> {
        let current_epoch = current_epoch.unwrap_or(self.current_epoch());
        let exit = &signed_exit.voluntary_exit;

        let validator = self
            .validators_store
            .get(exit.validator_index as usize)
            .ok_or_else(|| eyre::eyre!("ExitInvalid::ValidatorUnknown({}", exit.validator_index))?;

        verify!(
            validator.is_active_at(current_epoch),
            format!("ExitInvalid::NotActive({})", exit.validator_index)
        );

        verify!(
            validator.exit_epoch == spec.far_future_epoch,
            format!("ExitInvalid::AlreadyExited({})", exit.validator_index)
        );

        verify!(
            current_epoch >= exit.epoch,
            format!("ExitInvalid::FutureEpoch(state: {}, exit {})", current_epoch, exit.epoch)
        );

        let earliest_exit_epoch = validator
            .activation_epoch
            .safe_add(spec.shard_committee_period)?;
        verify!(
            current_epoch >= earliest_exit_epoch,
            format!("ExitInvalid::TooYoungToExit (current_epoch: {}, earliest_exit_epoch {})", current_epoch, earliest_exit_epoch)
        );

        if let Ok(pending_balance_to_withdraw) =
            self.get_pending_balance_to_withdraw(exit.validator_index as usize)
        {
            verify!(
                pending_balance_to_withdraw == 0,
                format!("ExitInvalid::PendingWithdrawalInQueue({})", exit.validator_index)
            );
        }

        Ok(())
    }

    fn process_deposits(&mut self, deposits: &[Deposit], spec: &ChainSpec) -> eyre::Result<()> {
        debug!(target: "consensus-client", deposists_length=?deposits.len(), "process_deposits");

        for deposit in deposits {
            self.apply_deposit(deposit.data.clone(), None, true, spec)?;
        }

        Ok(())
    }

    fn apply_deposit(&mut self, deposit_data: DepositData, _proof: Option<u8>, increment_eth1_deposit_index: bool, spec: &ChainSpec) -> eyre::Result<()> {
        if increment_eth1_deposit_index {
            self.eth1_deposit_index.safe_add_assign(1)?;
        }

        let validator_index = self.get_validator_index_from_pubkey(&deposit_data.pubkey);
        let amount = deposit_data.amount;

        if let Some(index) = validator_index {
            increase_balance(self, index, amount)?;
        } else {
            self.add_validator_to_registry(
                deposit_data.pubkey,
                deposit_data.withdrawal_credentials,
                amount,
                spec,
            )?;
        }

        Ok(())
    }

    fn add_validator_to_registry(&mut self, pubkey: BLSPubkey, withdrawal_credentials: B256, amount: u64, spec: &ChainSpec) -> eyre::Result<usize> {
        let index = self.validators_store.len();
        self.validators_store.push(Validator::from_deposit(
            pubkey,
            withdrawal_credentials,
            amount,
            spec,
        ))?;
        self.balances_store.push(amount)?;
        self.inactivity_scores_store.push(0)?;

        Ok(index)
    }

    fn process_rewards_and_penalties(&mut self, validator_statuses: &ValidatorStatuses, spec: &ChainSpec) -> eyre::Result<()> {
        if self.current_epoch() == GENESIS_EPOCH {
            return Ok(());
        }

        if validator_statuses.statuses.len() != self.balances_store.len()
            || validator_statuses.statuses.len() != self.validators_store.len()
        {
            return Err(eyre::eyre!("ValidatorStatusesInconsistent"));
        }

        let deltas = self.get_attestation_deltas_all(
            validator_statuses,
            ProposerRewardCalculation::Include,
            spec,
        )?;

        let mut balances_vec: Vec<_> = self.balances_store.iter().cloned().collect();
        for (i, delta) in deltas.into_iter().enumerate() {
            let combined_delta = delta.flatten()?;
            let balance = balances_vec.get_mut(i)
            .ok_or(eyre::eyre!("BalancesOutOfBounds, {i}"))?;
            increase_balance_directly(balance, combined_delta.rewards)?;
            decrease_balance_directly(balance, combined_delta.penalties)?;
        }
        self.balances_store = VecTree::from_vec(balances_vec)?;

        Ok(())
    }

    fn get_attestation_deltas_all(&self, validator_statuses: &ValidatorStatuses, proposer_reward: ProposerRewardCalculation, spec: &ChainSpec) -> eyre::Result<Vec<AttestationDelta>> {
        self.get_attestation_deltas(validator_statuses, proposer_reward, spec)
    }

    fn get_attestation_deltas(&self, validator_statuses: &ValidatorStatuses, _proposer_reward: ProposerRewardCalculation, spec: &ChainSpec) -> eyre::Result<Vec<AttestationDelta>> {
        let finality_delay = 0;

        let mut deltas = vec![AttestationDelta::default(); self.validators_store.len()];

        let total_balances = &validator_statuses.total_balances;
        let sqrt_total_active_balance = SqrtTotalActiveBalance::new(total_balances.current_epoch());

        for (index, validator) in validator_statuses.statuses.iter().enumerate() {
            if !validator.is_eligible {
                continue;
            }

            let base_reward = get_base_reward(
                validator.current_epoch_effective_balance,
                sqrt_total_active_balance,
                spec,
            )?;

            let all_delta =
                get_all_delta(validator, base_reward, total_balances, finality_delay, spec)?;

            let delta = deltas
                .get_mut(index)
                .ok_or(eyre::eyre!("DeltaOutOfBounds, {index}"))?;
            delta.all_delta.combine(all_delta)?;
        }

        Ok(deltas)
    }

    fn get_validator_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        Ok(spec.min_per_epoch_churn_limit)
    }

    fn get_activation_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        self.get_validator_churn_limit(spec)
    }

    fn is_eligible_validator(&self, previous_epoch: Epoch, val: &Validator) -> eyre::Result<bool> {
        Ok(val.is_active_at(previous_epoch)
            || (val.slashed && previous_epoch.safe_add(1)? < val.withdrawable_epoch))
    }

    fn compute_total_active_balance_slow(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        let current_epoch = self.current_epoch();

        let mut total_active_balance = 0;

        for validator in self.validators_store.iter() {
            if validator.is_active_at(current_epoch) {
                total_active_balance.safe_add_assign(validator.effective_balance)?;
            }
        }
        Ok(std::cmp::max(
            total_active_balance,
            spec.effective_balance_increment,
        ))
    }

    pub fn get_seed(&self, epoch: Epoch, domain_constant: u32) -> eyre::Result<Hash256> {
        let mix = self.randao_mix;

        let domain_bytes = domain_constant.to_le_bytes();
        let epoch_bytes = epoch.to_le_bytes();

        const NUM_DOMAIN_BYTES: usize = 4;
        const NUM_EPOCH_BYTES: usize = 8;
        const MIX_OFFSET: usize = NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES;
        const NUM_MIX_BYTES: usize = 32;

        let mut preimage = [0; NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES + NUM_MIX_BYTES];
        preimage[0..NUM_DOMAIN_BYTES].copy_from_slice(&domain_bytes);
        preimage[NUM_DOMAIN_BYTES..MIX_OFFSET].copy_from_slice(&epoch_bytes);
        preimage[MIX_OFFSET..].copy_from_slice(mix.as_slice());

        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    fn has_active_validators(&self, relative_epoch: RelativeEpoch) -> bool {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let active_validator_indices = self.get_active_validator_indices(epoch);

        !active_validator_indices.is_empty()
    }

    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
        let mut active = Vec::with_capacity(self.validators_store.len());
        for (index, validator) in self.validators_store.iter().enumerate() {
            if validator.is_active_at(epoch) {
                active.push(index)
            }
        }

        active
    }

    pub fn gen_committee_cache(&self, relative_epoch: RelativeEpoch) -> eyre::Result<CommitteeCache> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let spec = beacon_chain_spec();
        CommitteeCache::initialized(self, epoch, &spec)
    }

    fn prune(&mut self) {
        let validators_store_num_pruned = self.validators_store.prune();
        let balances_store_num_pruned = self.balances_store.prune();
        let inactivity_scores_store_num_pruned = self.inactivity_scores_store.prune();
        debug!(?validators_store_num_pruned, ?balances_store_num_pruned, ?inactivity_scores_store_num_pruned, "prune BeaconState");
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct PendingPartialWithdrawal {
    pub validator_index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance(state: &mut BeaconState, index: usize, delta: u64) -> eyre::Result<()> {
    let balance = state.balances_store.get(index).ok_or(eyre::eyre!("BalanceNotfound"))?;
    Ok(state.balances_store.set(index, balance.saturating_add(delta))?)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    balance.safe_add_assign(delta)?;
    Ok(())
}

pub fn decrease_balance(state: &mut BeaconState, index: usize, delta: u64) -> eyre::Result<()> {
    let balance = state.balances_store.get(index).ok_or(eyre::eyre!("BalanceNotfound"))?;
    Ok(state.balances_store.set(index, balance.saturating_sub(delta))?)
}

pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}

pub fn is_compounding_withdrawal_credential(withdrawal_credentials: B256, spec: &ChainSpec) -> bool {
    withdrawal_credentials
        .as_slice()
        .first()
        .map(|prefix_byte| *prefix_byte == spec.compounding_withdrawal_prefix_byte)
        .unwrap_or(false)
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExitInvalid {
    NotActive(u64),
    ValidatorUnknown(u64),
    AlreadyExited(u64),
    AlreadyInitiatedExit(u64),
    FutureEpoch {
        state: Epoch,
        exit: Epoch,
    },
    TooYoungToExit {
        current_epoch: Epoch,
        earliest_exit_epoch: Epoch,
    },
    BadSignature,
    PendingWithdrawalInQueue(u64),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ValidatorStatuses {
    pub statuses: Vec<ValidatorStatus>,
    pub total_balances: TotalBalances,
}

impl ValidatorStatuses {
    pub fn new(state: &BeaconState, spec: &ChainSpec) -> eyre::Result<Self> {
        let mut statuses = Vec::with_capacity(state.validators_store.len());
        let mut total_balances = TotalBalances::new(spec);

        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        for (validator_index, validator) in state.validators_store.iter().enumerate() {
            let effective_balance = validator.effective_balance;
            let inactivity_score = state.get_inactivity_score(validator_index)?;
            let is_punishable = inactivity_score >= spec.trigger_punish_inactivity_score;
            let mut status = ValidatorStatus {
                is_slashed: validator.slashed,
                is_eligible: state.is_eligible_validator(previous_epoch, validator)?,
                is_withdrawable_in_current_epoch: validator.is_withdrawable_at(current_epoch),
                current_epoch_effective_balance: effective_balance,

                is_previous_epoch_attester: state.epoch_attester_indexes_set.contains(&(validator_index as u64)),
                is_punishable,

                ..ValidatorStatus::default()
            };

            if validator.is_active_at(current_epoch) {
                status.is_active_in_current_epoch = true;
                total_balances
                    .current_epoch
                    .safe_add_assign(effective_balance)?;
            }

            if validator.is_active_at(previous_epoch) {
                status.is_active_in_previous_epoch = true;
                total_balances
                    .previous_epoch
                    .safe_add_assign(effective_balance)?;
            }

            statuses.push(status);
        }

        Ok(Self {
            statuses,
            total_balances,
        })
    }
}

#[derive(Debug)]
pub enum ProposerRewardCalculation {
    Include,
    Exclude,
}

#[derive(Default, Clone, Debug)]
pub struct AttestationDelta {
    pub all_delta: Delta,
    pub inactivity_penalty_delta: Delta,
}

impl AttestationDelta {
    pub fn flatten(self) -> eyre::Result<Delta> {
        let AttestationDelta {
            all_delta,
            inactivity_penalty_delta,
        } = self;
        let mut result = Delta::default();
        for delta in [
            all_delta,
            inactivity_penalty_delta,
        ] {
            result.combine(delta)?;
        }
        Ok(result)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Delta {
    pub rewards: u64,
    pub penalties: u64,
}

impl Delta {
    pub fn reward(&mut self, reward: u64) -> eyre::Result<()> {
        self.rewards = self.rewards.safe_add(reward)?;
        Ok(())
    }

    pub fn penalize(&mut self, penalty: u64) -> eyre::Result<()> {
        self.penalties = self.penalties.safe_add(penalty)?;
        Ok(())
    }

    pub fn combine(&mut self, other: Delta) -> eyre::Result<()> {
        self.reward(other.rewards)?;
        self.penalize(other.penalties)
    }
}

#[derive(Copy, Clone)]
pub struct SqrtTotalActiveBalance(u64);

impl SqrtTotalActiveBalance {
    pub fn new(total_active_balance: u64) -> Self {
        Self(total_active_balance.integer_sqrt())
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Returns the base reward for some validator.
pub fn get_base_reward(validator_effective_balance: u64, sqrt_total_active_balance: SqrtTotalActiveBalance, spec: &ChainSpec) -> eyre::Result<u64> {
    Ok(validator_effective_balance
        .safe_mul(spec.base_reward_factor)?
        .safe_div(sqrt_total_active_balance.as_u64())?
        .safe_div(spec.base_rewards_per_epoch)?)
}

fn get_all_delta(validator: &ValidatorStatus, base_reward: u64, _total_balances: &TotalBalances, _finality_delay: u64, spec: &ChainSpec) -> eyre::Result<Delta> {
    get_attestation_component_delta_n42(
        base_reward,
        validator.is_punishable,
        spec,
    )
}

pub fn get_attestation_component_delta_n42(base_reward: u64, is_punishable: bool, spec: &ChainSpec) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    delta.reward(base_reward)?;
    if is_punishable {
        delta.penalize(base_reward * spec.multiple_reward_for_inactivity_penalty)?;
    }

    Ok(delta)
}

pub fn get_inactivity_penalty_delta(validator: &ValidatorStatus, base_reward: u64, finality_delay: u64, spec: &ChainSpec) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    debug!(?finality_delay, "get_inactivity_penalty_delta");
    if finality_delay > spec.min_epochs_to_inactivity_penalty {
        delta.penalize(
            spec.base_rewards_per_epoch
                .safe_mul(base_reward)?
                .safe_sub(get_proposer_reward(base_reward, spec)?)?,
        )?;

        if validator.is_slashed || !validator.is_previous_epoch_attester {
            delta.penalize(
                validator
                    .current_epoch_effective_balance
                    .safe_mul(finality_delay)?
                    .safe_div(spec.inactivity_penalty_quotient)?,
            )?;
        }
    }

    Ok(delta)
}

macro_rules! set_self_if_other_is_true {
    ($self_: ident, $other: ident, $var: ident) => {
        if $other.$var {
            $self_.$var = true;
        }
    };
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ValidatorStatus {
    pub is_slashed: bool,
    pub is_eligible: bool,
    pub is_active_in_current_epoch: bool,
    pub is_active_in_previous_epoch: bool,
    pub current_epoch_effective_balance: u64,

    pub is_current_epoch_attester: bool,
    pub is_previous_epoch_attester: bool,
    pub is_withdrawable_in_current_epoch: bool,

    pub is_punishable: bool,
}

impl ValidatorStatus {
    pub fn update(&mut self, other: &Self) {
        set_self_if_other_is_true!(self, other, is_slashed);
        set_self_if_other_is_true!(self, other, is_eligible);
        set_self_if_other_is_true!(self, other, is_active_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_previous_epoch);
        set_self_if_other_is_true!(self, other, is_current_epoch_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_attester);
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TotalBalances {
    effective_balance_increment: u64,
    current_epoch: u64,
    previous_epoch: u64,
    current_epoch_attesters: u64,
    previous_epoch_attesters: u64,
}

macro_rules! balance_accessor {
    ($field_name:ident) => {
        pub fn $field_name(&self) -> u64 {
            std::cmp::max(self.effective_balance_increment, self.$field_name)
        }
    };
}

impl TotalBalances {
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            effective_balance_increment: spec.effective_balance_increment,
            current_epoch: 0,
            previous_epoch: 0,
            current_epoch_attesters: 0,
            previous_epoch_attesters: 0,
        }
    }

    balance_accessor!(current_epoch);
    balance_accessor!(previous_epoch);
    balance_accessor!(previous_epoch_attesters);
}

fn get_proposer_reward(base_reward: u64, spec: &ChainSpec) -> eyre::Result<u64> {
    Ok(base_reward.safe_div(spec.proposer_reward_quotient)?)
}

#[derive(Debug, PartialEq, Clone, Copy, arbitrary::Arbitrary)]
pub enum RelativeEpoch {
    Previous,
    Current,
    Next,
}

impl RelativeEpoch {
    pub fn into_epoch(self, base: Epoch) -> Epoch {
        match self {
            RelativeEpoch::Current => base,
            RelativeEpoch::Previous => base.saturating_sub(1u64),
            RelativeEpoch::Next => base.saturating_add(1u64),
        }
    }
}

pub fn round_down(n: u64, step: u64) -> u64 {
    n - (n % step)
}

fn round_to_nearest(n: u64, step: u64) -> u64 {
    ((n + step / 2) / step) * step
}
