//! A collection of unit tests for the QBFT Protocol.
//!
//! These test individual components and also provide full end-to-end tests of the entire protocol.

use std::cell::RefCell;
use super::*;
use crate::validation::{validate_data, ValidatedData};
use std::collections::VecDeque;
use std::rc::Rc;
use tracing_subscriber::filter::EnvFilter;
use types::DefaultLeaderFunction;

// HELPER FUNCTIONS FOR TESTS

/// Enable debug logging for tests
const ENABLE_TEST_LOGGING: bool = true;

/// A struct to help build and initialise a test of running instances
struct TestQBFTCommitteeBuilder {
    /// The configuration to use for all the instances.
    config: Config<DefaultLeaderFunction>,
}

impl Default for TestQBFTCommitteeBuilder {
    fn default() -> Self {
        let config = Config::<DefaultLeaderFunction> {
            // Set a default committee size of 5.
            committee_size: 5,
            // Populate the committee members
            committee_members: (0..5).map(OperatorId::from).collect::<HashSet<_>>(),
            ..Default::default()
        };

        TestQBFTCommitteeBuilder {
            config,
        }
    }
}

#[allow(dead_code)]
impl TestQBFTCommitteeBuilder {
    /// Sets the size of the testing committee.
    pub fn committee_size(mut self, committee_size: usize) -> Self {
        self.config.committee_size = committee_size;
        self
    }

    /// Sets the config for all instances to run
    pub fn set_config(mut self, config: Config<DefaultLeaderFunction>) -> Self {
        self.config = config;
        self
    }

    /// Consumes self and runs a test scenario. This returns a [`TestQBFTCommittee`] which
    /// represents a running quorum.
    pub fn run<D>(self, data: D) -> TestQBFTCommittee<D, impl FnMut(Message<D>)>
    where
        D: Default + Data,
    {
        if ENABLE_TEST_LOGGING {
            let env_filter = EnvFilter::new("debug");
            tracing_subscriber::fmt()
                .compact()
                .with_env_filter(env_filter)
                .init();
        }

        // Validate the data
        let validated_data = validate_data(data).unwrap();

        construct_and_run_committee(self.config, validated_data)
    }
}

/// A testing structure representing a committee of running instances
#[allow(clippy::type_complexity)]
struct TestQBFTCommittee<D: Default + Data + 'static, S: FnMut(Message<D>)> {
    msg_queue: Rc<RefCell<VecDeque<(OperatorId, Message<D>)>>>,
    instances: HashMap<OperatorId, Qbft<DefaultLeaderFunction, D, S>>,
}

/// Constructs and runs committee of QBFT Instances
///
/// This will create instances and spawn them in a task and return the sender/receiver channels for
/// all created instances.
fn construct_and_run_committee<D: Data + Default + 'static>(
    mut config: Config<DefaultLeaderFunction>,
    validated_data: ValidatedData<D>,
) -> TestQBFTCommittee<D, impl FnMut(Message<D>)> {
    // The ID of a committee is just an integer in [0,committee_size)

    let msg_queue = Rc::new(RefCell::new(VecDeque::new()));
    let mut instances = HashMap::with_capacity(config.committee_size);

    for id in 0..config.committee_size {
        let msg_queue = Rc::clone(&msg_queue);
        let id = OperatorId::from(id);
        // Creates a new instance
        config.operator_id = id;
        let mut instance = Qbft::new(config.clone(), validated_data.clone(), move |message| msg_queue.borrow_mut().push_back((id, message)));
        instance.start_round();
        instances.insert(id, instance);
    }

    TestQBFTCommittee {
        msg_queue, instances
    }
}

impl<D: Default + Data, S: FnMut(Message<D>)> TestQBFTCommittee<D, S> {
    fn wait_until_end(mut self) {
        loop {
            let msg = self.msg_queue.borrow_mut().pop_front();
            let Some((sender, msg)) = msg else {
                // we are done!
                return;
            };
            for instance in self.instances.iter_mut().filter_map(|(id, instance)| (id.0 != sender.0).then_some(instance)) {
                instance.receive(msg.clone());
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct TestData(usize);

impl Data for TestData {
    type Hash = usize;

    fn hash(&self) -> Self::Hash {
        self.0
    }
}

#[test]
fn test_basic_committee() {
    // Construct and run a test committee

    let test_instance = TestQBFTCommitteeBuilder::default().run(TestData(21));

    // Wait until consensus is reached or all the instances have ended
    test_instance.wait_until_end();
}
