extern crate core;

use dashmap::DashMap;
use qbft::Completed;
use qbft_manager::{CommitteeInstanceId, QbftError, QbftManager, ValidatorInstanceId};
use safe_arith::{ArithError, SafeArith};
use signature_collector::{CollectionError, SignatureCollectorManager, SignatureRequest};
use slot_clock::SlotClock;
use ssv_types::message::{
    BeaconVote, DataSsz, ValidatorConsensusData, ValidatorDuty, BEACON_ROLE_AGGREGATOR,
    BEACON_ROLE_PROPOSER, DATA_VERSION_ALTAIR, DATA_VERSION_BELLATRIX, DATA_VERSION_CAPELLA,
    DATA_VERSION_DENEB, DATA_VERSION_PHASE0, DATA_VERSION_UNKNOWN,
};
use ssv_types::{Cluster, OperatorId};
use std::sync::Arc;
use tracing::{error, warn};
use types::attestation::Attestation;
use types::beacon_block::BeaconBlock;
use types::graffiti::Graffiti;
use types::selection_proof::SelectionProof;
use types::signed_aggregate_and_proof::SignedAggregateAndProof;
use types::signed_beacon_block::SignedBeaconBlock;
use types::signed_contribution_and_proof::SignedContributionAndProof;
use types::signed_voluntary_exit::SignedVoluntaryExit;
use types::slot_epoch::{Epoch, Slot};
use types::sync_committee_contribution::SyncCommitteeContribution;
use types::sync_committee_message::SyncCommitteeMessage;
use types::sync_selection_proof::SyncSelectionProof;
use types::sync_subnet_id::SyncSubnetId;
use types::validator_registration_data::{
    SignedValidatorRegistrationData, ValidatorRegistrationData,
};
use types::voluntary_exit::VoluntaryExit;
use types::{
    AbstractExecPayload, Address, AggregateAndProof, BlindedPayload, ChainSpec, Domain, EthSpec,
    FullPayload, Hash256, PublicKeyBytes, SecretKey, Signature, SignedRoot,
    SyncAggregatorSelectionData,
};
use validator_store::{
    DoppelgangerStatus, Error as ValidatorStoreError, ProposalData, SignBlock, ValidatorStore,
};

pub struct InitializedCluster {
    pub cluster: Cluster,
    pub decrypted_key_share: SecretKey,
}

pub struct AnchorValidatorStore<T: SlotClock + 'static, E: EthSpec> {
    clusters: DashMap<PublicKeyBytes, InitializedCluster>,
    signature_collector: Arc<SignatureCollectorManager>,
    qbft_manager: Arc<QbftManager<T, E>>,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    operator_id: OperatorId,
}

impl<T: SlotClock, E: EthSpec> AnchorValidatorStore<T, E> {
    pub fn new(
        _processor: processor::Senders,
        signature_collector: Arc<SignatureCollectorManager>,
        qbft_manager: Arc<QbftManager<T, E>>,
        spec: Arc<ChainSpec>,
        genesis_validators_root: Hash256,
        operator_id: OperatorId,
    ) -> AnchorValidatorStore<T, E> {
        Self {
            clusters: DashMap::new(),
            signature_collector,
            qbft_manager,
            spec,
            genesis_validators_root,
            operator_id,
        }
    }

    fn cluster(&self, validator_pubkey: PublicKeyBytes) -> Result<Cluster, Error> {
        self.clusters
            .get(&validator_pubkey)
            .map(|c| c.cluster.clone())
            .ok_or(Error::UnknownPubkey(validator_pubkey))
    }

    fn get_domain(&self, epoch: Epoch, domain: Domain) -> Hash256 {
        self.spec.get_domain(
            epoch,
            domain,
            &self.spec.fork_at_epoch(epoch),
            self.genesis_validators_root,
        )
    }

    async fn collect_signature(
        &self,
        validator_pubkey: PublicKeyBytes,
        signing_root: Hash256,
    ) -> Result<Signature, Error> {
        let Some(cluster) = self.clusters.get(&validator_pubkey) else {
            return Err(Error::UnknownPubkey(validator_pubkey));
        };

        let collector = self.signature_collector.sign_and_collect(
            SignatureRequest {
                cluster_id: cluster.cluster.cluster_id,
                signing_root,
                threshold: cluster
                    .cluster
                    .faulty
                    .safe_mul(2)
                    .and_then(|x| x.safe_add(1))
                    .map_err(SpecificError::from)?,
            },
            self.operator_id,
            cluster.decrypted_key_share.clone(),
        );

        // free lock before invoking future
        drop(cluster);
        Ok((*collector.await.map_err(SpecificError::from)?).clone())
    }

    async fn sign_abstract_block<
        P: AbstractExecPayload<E>,
        F: FnOnce(BeaconBlock<E, P>) -> DataSsz<E>,
    >(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: BeaconBlock<E, P>,
        current_slot: Slot,
        wrapper: F,
    ) -> Result<DataSsz<E>, Error> {
        // Make sure the block slot is not higher than the current slot to avoid potential attacks.
        if block.slot() > current_slot {
            warn!(
                block_slot = block.slot().as_u64(),
                current_slot = current_slot.as_u64(),
                "Not signing block with slot greater than current slot",
            );
            return Err(Error::GreaterThanCurrentSlot {
                slot: block.slot(),
                current_slot,
            });
        }

        // todo slashing protection

        let cluster = self.cluster(validator_pubkey)?;

        // first, we have to get to consensus
        let completed = self
            .qbft_manager
            .decide_instance(
                ValidatorInstanceId {
                    validator: validator_pubkey,
                    instance_height: block.slot().as_usize().into(),
                },
                ValidatorConsensusData {
                    duty: ValidatorDuty {
                        r#type: BEACON_ROLE_PROPOSER,
                        pub_key: validator_pubkey,
                        slot: block.slot().as_usize().into(),
                        validator_index: cluster.validator_metadata.validator_index,
                        committee_index: 0,
                        committee_length: 0,
                        committees_at_slot: 0,
                        validator_committee_index: 0,
                        validator_sync_committee_indices: Default::default(),
                    },
                    version: match &block {
                        BeaconBlock::Base(_) => DATA_VERSION_PHASE0,
                        BeaconBlock::Altair(_) => DATA_VERSION_ALTAIR,
                        BeaconBlock::Bellatrix(_) => DATA_VERSION_BELLATRIX,
                        BeaconBlock::Capella(_) => DATA_VERSION_CAPELLA,
                        BeaconBlock::Deneb(_) => DATA_VERSION_DENEB,
                        BeaconBlock::Electra(_) => DATA_VERSION_UNKNOWN,
                    },
                    data_ssz: Box::new(wrapper(block)),
                },
                &cluster,
            )
            .await
            .map_err(SpecificError::from)?;
        let data = match completed {
            Completed::TimedOut => return Err(Error::SpecificError(SpecificError::Timeout)),
            Completed::Success(data) => data,
        };
        Ok(*data.data_ssz)
    }

    pub fn add_cluster(&self, public_key_bytes: PublicKeyBytes, cluster: InitializedCluster) {
        self.clusters.insert(public_key_bytes, cluster);
    }
}

#[derive(Debug)]
pub enum SpecificError {
    ExitsUnsupported,
    SignatureCollectionFailed(CollectionError),
    ArithError(ArithError),
    QbftError(QbftError),
    Timeout,
    InvalidQbftData,
}

impl From<CollectionError> for SpecificError {
    fn from(err: CollectionError) -> SpecificError {
        SpecificError::SignatureCollectionFailed(err)
    }
}

impl From<ArithError> for SpecificError {
    fn from(err: ArithError) -> SpecificError {
        SpecificError::ArithError(err)
    }
}

impl From<QbftError> for SpecificError {
    fn from(err: QbftError) -> SpecificError {
        SpecificError::QbftError(err)
    }
}

pub type Error = ValidatorStoreError<SpecificError>;

impl<T: SlotClock, E: EthSpec> ValidatorStore for AnchorValidatorStore<T, E> {
    type Error = SpecificError;
    type E = E;

    fn validator_index(&self, pubkey: &PublicKeyBytes) -> Option<u64> {
        self.clusters
            .get(pubkey)
            .map(|v| v.cluster.validator_metadata.validator_index.0 as u64)
    }

    fn voting_pubkeys<I, F>(&self, _filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>,
    {
        // we don't care about doppelgangers
        self.clusters.iter().map(|v| *v.key()).collect()
    }

    fn doppelganger_protection_allows_signing(&self, _validator_pubkey: PublicKeyBytes) -> bool {
        // we don't care about doppelgangers
        true
    }

    fn num_voting_validators(&self) -> usize {
        self.clusters.len()
    }

    fn graffiti(&self, validator_pubkey: &PublicKeyBytes) -> Option<Graffiti> {
        self.clusters
            .get(validator_pubkey)
            .map(|v| v.cluster.validator_metadata.graffiti)
    }

    fn get_fee_recipient(&self, validator_pubkey: &PublicKeyBytes) -> Option<Address> {
        self.clusters
            .get(validator_pubkey)
            .map(|v| v.cluster.validator_metadata.fee_recipient)
    }

    fn determine_builder_boost_factor(&self, _validator_pubkey: &PublicKeyBytes) -> Option<u64> {
        Some(1)
    }

    async fn randao_reveal(
        &self,
        validator_pubkey: PublicKeyBytes,
        signing_epoch: Epoch,
    ) -> Result<Signature, Error> {
        let domain_hash = self.get_domain(signing_epoch, Domain::Randao);
        let signing_root = signing_epoch.signing_root(domain_hash);
        self.collect_signature(validator_pubkey, signing_root).await
    }

    fn set_validator_index(&self, validator_pubkey: &PublicKeyBytes, index: u64) {
        // we actually have the index already. we use the opportunity to do a sanity check
        match self.clusters.get(validator_pubkey) {
            None => warn!(
                validator = validator_pubkey.as_hex_string(),
                "Trying to set index for unknown validator"
            ),
            Some(v) => {
                if v.cluster.validator_metadata.validator_index.0 as u64 != index {
                    error!(
                        validator = validator_pubkey.as_hex_string(),
                        expected = v.cluster.validator_metadata.validator_index.0,
                        actual = index,
                        "Mismatched validator index",
                    )
                }
            }
        }
    }

    async fn sign_attestation(
        &self,
        validator_pubkey: PublicKeyBytes,
        validator_committee_position: usize,
        attestation: &mut Attestation<E>,
        current_epoch: Epoch,
    ) -> Result<(), Error> {
        // Make sure the target epoch is not higher than the current epoch to avoid potential attacks.
        if attestation.data().target.epoch > current_epoch {
            return Err(Error::GreaterThanCurrentEpoch {
                epoch: attestation.data().target.epoch,
                current_epoch,
            });
        }

        // todo slashing protection

        let cluster = self.cluster(validator_pubkey)?;

        let completed = self
            .qbft_manager
            .decide_instance(
                CommitteeInstanceId {
                    committee: cluster.cluster_id,
                    instance_height: current_epoch.as_usize().into(),
                },
                BeaconVote {
                    block_root: attestation.data().beacon_block_root,
                    source: attestation.data().source,
                    target: attestation.data().target,
                },
                &cluster,
            )
            .await
            .map_err(SpecificError::from)?;
        let data = match completed {
            Completed::TimedOut => return Err(Error::SpecificError(SpecificError::Timeout)),
            Completed::Success(data) => data,
        };
        attestation.data_mut().beacon_block_root = data.block_root;
        attestation.data_mut().source = data.source;
        attestation.data_mut().target = data.target;

        // yay - we agree! let's sign the att we agreed on
        let domain_hash = self.get_domain(current_epoch, Domain::BeaconAttester);
        let signing_root = attestation.data().signing_root(domain_hash);
        let signature = self
            .collect_signature(validator_pubkey, signing_root)
            .await?;
        attestation
            .add_signature(&signature, validator_committee_position)
            .map_err(Error::UnableToSignAttestation)?;

        Ok(())
    }

    async fn sign_voluntary_exit(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _voluntary_exit: VoluntaryExit,
    ) -> Result<SignedVoluntaryExit, Error> {
        // there should be no situation ever where we want to sign an exit
        Err(Error::SpecificError(SpecificError::ExitsUnsupported))
    }

    async fn sign_validator_registration_data(
        &self,
        validator_registration_data: ValidatorRegistrationData,
    ) -> Result<SignedValidatorRegistrationData, Error> {
        let domain_hash = self.spec.get_builder_domain();
        let signing_root = validator_registration_data.signing_root(domain_hash);

        let signature = self
            .collect_signature(validator_registration_data.pubkey, signing_root)
            .await?;

        Ok(SignedValidatorRegistrationData {
            message: validator_registration_data,
            signature,
        })
    }

    async fn produce_signed_aggregate_and_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        aggregator_index: u64,
        aggregate: Attestation<E>,
        selection_proof: SelectionProof,
    ) -> Result<SignedAggregateAndProof<E>, Error> {
        let signing_epoch = aggregate.data().target.epoch;
        let cluster = self.cluster(validator_pubkey)?;

        let message =
            AggregateAndProof::from_attestation(aggregator_index, aggregate, selection_proof);

        // first, we have to get to consensus
        let completed = self
            .qbft_manager
            .decide_instance(
                ValidatorInstanceId {
                    validator: validator_pubkey,
                    // todo not sure if correct height
                    instance_height: message.aggregate().data().slot.as_usize().into(),
                },
                ValidatorConsensusData {
                    duty: ValidatorDuty {
                        r#type: BEACON_ROLE_AGGREGATOR,
                        pub_key: validator_pubkey,
                        slot: message.aggregate().data().slot,
                        validator_index: cluster.validator_metadata.validator_index,
                        committee_index: message.aggregate().data().index,
                        // todo fill rest correctly
                        committee_length: 0,
                        committees_at_slot: 0,
                        validator_committee_index: 0,
                        validator_sync_committee_indices: Default::default(),
                    },
                    version: DATA_VERSION_PHASE0,
                    data_ssz: Box::new(DataSsz::AggregateAndProof(message)),
                },
                &cluster,
            )
            .await
            .map_err(SpecificError::from)?;
        let data = match completed {
            Completed::TimedOut => return Err(Error::SpecificError(SpecificError::Timeout)),
            Completed::Success(data) => data,
        };
        let message = match *data.data_ssz {
            DataSsz::AggregateAndProof(message) => message,
            _ => return Err(Error::SpecificError(SpecificError::InvalidQbftData)),
        };

        let signing_context = self.get_domain(signing_epoch, Domain::AggregateAndProof);
        let signing_root = message.signing_root(signing_context);
        let signature = self
            .collect_signature(validator_pubkey, signing_root)
            .await?;

        Ok(SignedAggregateAndProof::from_aggregate_and_proof(
            message, signature,
        ))
    }

    async fn produce_selection_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> Result<SelectionProof, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain_hash = self.get_domain(epoch, Domain::SelectionProof);
        let signing_root = slot.signing_root(domain_hash);

        self.collect_signature(validator_pubkey, signing_root)
            .await
            .map(SelectionProof::from)
    }

    async fn produce_sync_selection_proof(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        subnet_id: SyncSubnetId,
    ) -> Result<SyncSelectionProof, Error> {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain_hash = self.get_domain(epoch, Domain::SyncCommitteeSelectionProof);
        let signing_root = SyncAggregatorSelectionData {
            slot,
            subcommittee_index: subnet_id.into(),
        }
        .signing_root(domain_hash);

        self.collect_signature(*validator_pubkey, signing_root)
            .await
            .map(SyncSelectionProof::from)
    }

    async fn produce_sync_committee_signature(
        &self,
        _slot: Slot,
        _beacon_block_root: Hash256,
        _validator_index: u64,
        _validator_pubkey: &PublicKeyBytes,
    ) -> Result<SyncCommitteeMessage, Error> {
        todo!()
    }

    async fn produce_signed_contribution_and_proof(
        &self,
        _aggregator_index: u64,
        _aggregator_pubkey: PublicKeyBytes,
        _contribution: SyncCommitteeContribution<E>,
        _selection_proof: SyncSelectionProof,
    ) -> Result<SignedContributionAndProof<E>, Error> {
        todo!()
    }

    fn prune_slashing_protection_db(&self, _current_epoch: Epoch, _first_run: bool) {
        // TODO slashing protection
    }

    fn proposal_data(&self, pubkey: &PublicKeyBytes) -> Option<ProposalData> {
        self.clusters.get(pubkey).map(|v| ProposalData {
            validator_index: Some(v.cluster.validator_metadata.validator_index.0 as u64),
            fee_recipient: Some(v.cluster.validator_metadata.fee_recipient),
            gas_limit: 29_999_998,    // TODO support scalooors
            builder_proposals: false, // TODO support MEVooors
        })
    }
}

impl<T: SlotClock, E: EthSpec> SignBlock<E, FullPayload<E>, SpecificError>
    for AnchorValidatorStore<T, E>
{
    async fn sign_block(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: BeaconBlock<E, FullPayload<E>>,
        current_slot: Slot,
    ) -> Result<SignedBeaconBlock<E, FullPayload<E>>, ValidatorStoreError<SpecificError>> {
        let data = self
            .sign_abstract_block(validator_pubkey, block, current_slot, DataSsz::BeaconBlock)
            .await?;
        let block = match data {
            DataSsz::BeaconBlock(block) => block,
            // todo what do if we agree on a blind block
            _ => return Err(Error::SpecificError(SpecificError::InvalidQbftData)),
        };

        // yay - we agree! let's sign the block we agreed on
        let domain_hash = self.get_domain(block.epoch(), Domain::BeaconProposer);
        let signing_root = block.signing_root(domain_hash);
        let signature = self
            .collect_signature(validator_pubkey, signing_root)
            .await?;

        Ok(SignedBeaconBlock::from_block(block, signature))
    }
}

impl<T: SlotClock, E: EthSpec> SignBlock<E, BlindedPayload<E>, SpecificError>
    for AnchorValidatorStore<T, E>
{
    async fn sign_block(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: BeaconBlock<E, BlindedPayload<E>>,
        current_slot: Slot,
    ) -> Result<SignedBeaconBlock<E, BlindedPayload<E>>, Error> {
        let data = self
            .sign_abstract_block(
                validator_pubkey,
                block,
                current_slot,
                DataSsz::BlindedBeaconBlock,
            )
            .await?;
        let block = match data {
            DataSsz::BlindedBeaconBlock(block) => block,
            // todo what do if we agree on a non-blind block
            _ => return Err(Error::SpecificError(SpecificError::InvalidQbftData)),
        };

        // yay - we agree! let's sign the block we agreed on
        let domain_hash = self.get_domain(block.epoch(), Domain::BeaconProposer);
        let signing_root = block.signing_root(domain_hash);
        let signature = self
            .collect_signature(validator_pubkey, signing_root)
            .await?;

        Ok(SignedBeaconBlock::from_block(block, signature))
    }
}
