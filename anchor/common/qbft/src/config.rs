use super::error::ConfigBuilderError;
use crate::types::{DefaultLeaderFunction, InstanceHeight, LeaderFunction, OperatorId, Round};
use indexmap::IndexSet;
use std::fmt::Debug;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config<F>
where
    F: LeaderFunction + Clone,
{
    pub operator_id: OperatorId,
    pub instance_height: InstanceHeight,
    pub round: Round,
    pub committee_members: IndexSet<OperatorId>,
    pub quorum_size: usize,
    pub round_time: Duration,
    pub max_rounds: usize,
    pub leader_fn: F,
}

impl<F: Clone + LeaderFunction> Config<F> {
    /// A unique identification number assigned to the QBFT consensus and given to all members of
    /// the committee
    pub fn operator_id(&self) -> OperatorId {
        self.operator_id
    }

    pub fn commmittee_members(&self) -> &IndexSet<OperatorId> {
        &self.committee_members
    }

    /// The round number -- likely always 1 at initialisation unless we want to implement re-joining an existing
    /// instance that has been dropped locally
    pub fn round(&self) -> Round {
        self.round
    }

    /// How long the round will last
    pub fn round_time(&self) -> Duration {
        self.round_time
    }

    pub fn max_rounds(&self) -> usize {
        self.max_rounds
    }

    /// Whether the operator is the lead of the committee for the round -- need to properly
    /// implement this in a way that is deterministic based on node IDs
    pub fn leader_fn(&self) -> &F {
        &self.leader_fn
    }

    /// Obtains the maximum number of faulty nodes that this consensus can tolerate
    pub(crate) fn get_f(&self) -> usize {
        get_f(self.committee_members.len())
    }
}

fn get_f(members: usize) -> usize {
    (members - 1) / 3
}

/// Builder struct for constructing the QBFT instance configuration
#[derive(Clone, Debug)]
pub struct ConfigBuilder<F: LeaderFunction + Clone> {
    operator_id: Option<OperatorId>,
    instance_height: Option<InstanceHeight>,
    round: Round,
    committee_members: IndexSet<OperatorId>,
    quorum_size: Option<usize>,
    round_time: Duration,
    max_rounds: usize,
    leader_fn: F,
}

impl Default for ConfigBuilder<DefaultLeaderFunction> {
    fn default() -> Self {
        ConfigBuilder {
            operator_id: None,
            instance_height: None,
            committee_members: IndexSet::new(),
            quorum_size: None,
            round: Round::default(),
            round_time: Duration::new(2, 0),
            max_rounds: 4,
            leader_fn: DefaultLeaderFunction {},
        }
    }
}

impl<F: LeaderFunction + Clone> ConfigBuilder<F> {
    pub fn operator_id(&mut self, operator_id: OperatorId) -> &mut Self {
        self.operator_id = Some(operator_id);
        self
    }

    pub fn instance_height(&mut self, instance_height: InstanceHeight) -> &mut Self {
        self.instance_height = Some(instance_height);
        self
    }

    pub fn committee_members(&mut self, committee_members: IndexSet<OperatorId>) -> &mut Self {
        self.committee_members = committee_members;
        self
    }

    pub fn quorum_size(&mut self, quorum_size: usize) -> &mut Self {
        self.quorum_size = Some(quorum_size);
        self
    }

    pub fn round(&mut self, round: Round) -> &mut Self {
        self.round = round;
        self
    }

    pub fn max_round(&mut self, max_rounds: usize) -> &mut Self {
        self.max_rounds = max_rounds;
        self
    }

    pub fn round_time(&mut self, round_time: Duration) -> &mut Self {
        self.round_time = round_time;
        self
    }

    pub fn leader_fn(&mut self, leader_fn: F) -> &mut Self {
        self.leader_fn = leader_fn;
        self
    }

    pub fn build(&self) -> Result<Config<F>, ConfigBuilderError> {
        let committee_size = self.committee_members.len();
        if committee_size < 1 {
            return Err(ConfigBuilderError::NoParticipants);
        }

        let f = get_f(committee_size);

        let quorum_size = match self.quorum_size {
            None => committee_size - f,
            Some(quorum_size) => {
                if quorum_size < f * 2 + 1 || quorum_size > committee_size - f {
                    return Err(ConfigBuilderError::InvalidQuorumSize);
                }
                quorum_size
            }
        };

        if self.max_rounds == 0 {
            return Err(ConfigBuilderError::ZeroMaxRounds);
        }

        if self.round.get() > self.max_rounds {
            return Err(ConfigBuilderError::ExceedingStartingRound);
        }

        let operator_id = self
            .operator_id
            .ok_or(ConfigBuilderError::MissingOperatorId)?;
        if !self.committee_members.contains(&operator_id) {
            return Err(ConfigBuilderError::OperatorNotParticipant);
        }

        Ok(Config {
            operator_id,
            instance_height: self
                .instance_height
                .ok_or(ConfigBuilderError::MissingInstanceHeight)?,
            committee_members: self.committee_members.clone(),
            quorum_size,
            round: self.round,
            round_time: self.round_time,
            max_rounds: self.max_rounds,
            leader_fn: self.leader_fn.clone(),
        })
    }
}
