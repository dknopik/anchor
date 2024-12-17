use dashmap::DashMap;
use signature_collector::{CollectionError, SignatureCollectorManager, SignatureRequest};
use ssv_types::{Cluster, OperatorId};
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::{error, warn};
use types::attestation::Attestation;
use types::beacon_block::BeaconBlock;
use types::graffiti::Graffiti;
use types::payload::AbstractExecPayload;
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
    Address, ChainSpec, Domain, EthSpec, Hash256, PublicKeyBytes, SecretKey, Signature, SignedRoot,
};
use validator_store::{
    DoppelgangerStatus, Error as ValidatorStoreError, ProposalData, ValidatorStore,
};

struct InitializedCluster {
    cluster: Cluster,
    decrypted_key_share: SecretKey,
}

pub struct AnchorValidatorStore<E> {
    clusters: DashMap<PublicKeyBytes, InitializedCluster>,
    signature_collector: Arc<SignatureCollectorManager>,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    operator_id: OperatorId,
    _phantom: PhantomData<E>,
}

impl<E> AnchorValidatorStore<E> {
    pub fn new(
        _processor: processor::Senders,
        signature_collector: Arc<SignatureCollectorManager>,
        spec: Arc<ChainSpec>,
        genesis_validators_root: Hash256,
        operator_id: OperatorId,
    ) -> AnchorValidatorStore<E> {
        Self {
            clusters: DashMap::new(),
            signature_collector,
            spec,
            genesis_validators_root,
            operator_id,
            _phantom: PhantomData,
        }
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
                threshold: cluster.cluster.cluster_members.len() as u64 - cluster.cluster.faulty,
            },
            self.operator_id,
            cluster.decrypted_key_share.clone(),
        );

        // free lock before invoking future
        drop(cluster);
        Ok((*collector.await.map_err(SpecificError::from)?).clone())
    }
}

#[derive(Debug)]
pub enum SpecificError {
    ExitsUnsupported,
    SignatureCollectionFailed(CollectionError),
}

impl From<CollectionError> for SpecificError {
    fn from(err: CollectionError) -> SpecificError {
        SpecificError::SignatureCollectionFailed(err)
    }
}

pub type Error = ValidatorStoreError<SpecificError>;

impl<E: EthSpec> ValidatorStore<E> for AnchorValidatorStore<E> {
    type Error = SpecificError;

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
        let domain = self.spec.get_domain(
            signing_epoch,
            Domain::Randao,
            &self.spec.fork_at_epoch(signing_epoch),
            self.genesis_validators_root,
        );
        let signing_root = signing_epoch.signing_root(domain);
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

    async fn sign_block<Payload: AbstractExecPayload<E>>(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _block: BeaconBlock<E, Payload>,
        _current_slot: Slot,
    ) -> Result<SignedBeaconBlock<E, Payload>, Error> {
        todo!()
    }

    async fn sign_attestation(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _validator_committee_position: usize,
        _attestation: &mut Attestation<E>,
        _current_epoch: Epoch,
    ) -> Result<(), Error> {
        todo!()
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
        _validator_registration_data: ValidatorRegistrationData,
    ) -> Result<SignedValidatorRegistrationData, Error> {
        todo!()
    }

    async fn produce_signed_aggregate_and_proof(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _aggregator_index: u64,
        _aggregate: Attestation<E>,
        _selection_proof: SelectionProof,
    ) -> Result<SignedAggregateAndProof<E>, Error> {
        todo!()
    }

    async fn produce_selection_proof(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _slot: Slot,
    ) -> Result<SelectionProof, Error> {
        todo!()
    }

    async fn produce_sync_selection_proof(
        &self,
        _validator_pubkey: &PublicKeyBytes,
        _slot: Slot,
        _subnet_id: SyncSubnetId,
    ) -> Result<SyncSelectionProof, Error> {
        todo!()
    }

    async fn produce_sync_committee_signature(
        &self,
        _slot: Slot,
        _beacon_block_root: types::Hash256,
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
            gas_limit: 30_000_000,    // TODO support scalooors
            builder_proposals: false, // TODO support MEVooors
        })
    }
}
