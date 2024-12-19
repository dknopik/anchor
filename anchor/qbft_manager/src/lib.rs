use dashmap::DashMap;
use processor::{DropOnFinish, Senders, WorkItem};
use qbft::{
    Completed, Config, ConfigBuilder, ConfigBuilderError, DefaultLeaderFunction, InstanceHeight,
    Message as NetworkMessage, OperatorId as QbftOperatorId,
};
use slot_clock::SlotClock;
use ssv_types::message::{BeaconVote, ValidatorConsensusData};
use ssv_types::{Cluster, ClusterId, OperatorId};
use std::fmt::Debug;
use std::hash::Hash;
use tokio::select;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::{error, warn};
use types::{EthSpec, Hash256, PublicKeyBytes};

const QBFT_INSTANCE_NAME: &str = "qbft_instance";
const QBFT_MESSAGE_NAME: &str = "qbft_message";

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CommitteeInstanceId {
    committee: ClusterId,
    instance_height: InstanceHeight,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ValidatorInstanceId {
    validator: PublicKeyBytes,
    instance_height: InstanceHeight,
}

#[derive(Debug)]
pub struct QbftMessage<D: qbft::Data> {
    pub kind: QbftMessageKind<D>,
    pub drop_on_finish: DropOnFinish,
}

#[derive(Debug)]
pub enum QbftMessageKind<D: qbft::Data> {
    Initialize {
        initial: D, // deja vu - i've just been in this place before
        config: qbft::Config<DefaultLeaderFunction>,
        on_completed: oneshot::Sender<Completed<D>>,
    },
    NetworkMessage(NetworkMessage<D>),
}

type Qbft<D, S> = qbft::Qbft<DefaultLeaderFunction, D, S>;

type Map<I, D> = DashMap<I, UnboundedSender<QbftMessage<D>>>;

pub struct QbftManager<T: SlotClock + 'static, E: EthSpec> {
    processor: Senders,
    operator_id: QbftOperatorId,
    slot_clock: T, // TODO: I added this for some reason - why?
    validator_consensus_data_instances: Map<ValidatorInstanceId, ValidatorConsensusData<E>>,
    beacon_vote_instances: Map<CommitteeInstanceId, BeaconVote>,
}

impl<T: SlotClock, E: EthSpec> QbftManager<T, E> {
    pub fn new(processor: Senders, operator_id: OperatorId, slot_clock: T) -> Self {
        QbftManager {
            processor,
            operator_id: QbftOperatorId(operator_id.0 as usize),
            slot_clock,
            validator_consensus_data_instances: DashMap::new(),
            beacon_vote_instances: DashMap::new(),
        }
    }

    pub async fn decide_instance<D: QbftDecidable<T, E>>(
        &self,
        id: D::Id,
        initial: D,
        committee: &Cluster,
    ) -> Result<Completed<D>, QbftError> {
        let (result_sender, result_receiver) = oneshot::channel();
        let mut config = ConfigBuilder::default();
        config
            .operator_id(self.operator_id)
            .committee_size(committee.cluster_members.len())
            .quorum_size(committee.cluster_members.len() - committee.faulty as usize);
        let config = initial.config(&mut config, &id)?;
        let sender = D::get_or_spawn_instance(self, id);
        self.processor.urgent_consensus.send_immediate(
            move |drop_on_finish: DropOnFinish| {
                let _ = sender.send(QbftMessage {
                    kind: QbftMessageKind::Initialize {
                        initial,
                        config,
                        on_completed: result_sender,
                    },
                    drop_on_finish,
                });
            },
            QBFT_MESSAGE_NAME,
        )?;
        Ok(result_receiver.await?)
    }

    pub fn receive_data<D: QbftDecidable<T, E>>(
        &self,
        id: D::Id,
        data: NetworkMessage<D>,
    ) -> Result<(), QbftError> {
        let sender = D::get_or_spawn_instance(self, id);
        self.processor.urgent_consensus.send_immediate(
            move |drop_on_finish: DropOnFinish| {
                let _ = sender.send(QbftMessage {
                    kind: QbftMessageKind::NetworkMessage(data),
                    drop_on_finish,
                });
            },
            QBFT_MESSAGE_NAME,
        )?;
        Ok(())
    }
}

pub trait QbftDecidable<T: SlotClock + 'static, E: EthSpec>:
    qbft::Data<Hash = Hash256> + Send + 'static
{
    type Id: Hash + Eq + Send;

    fn get_map(manager: &QbftManager<T, E>) -> &Map<Self::Id, Self>;

    fn get_or_spawn_instance(
        manager: &QbftManager<T, E>,
        id: Self::Id,
    ) -> UnboundedSender<QbftMessage<Self>> {
        let map = Self::get_map(manager);
        let ret = match map.entry(id) {
            dashmap::Entry::Occupied(entry) => entry.get().clone(),
            dashmap::Entry::Vacant(entry) => {
                let (tx, rx) = mpsc::unbounded_channel();
                let tx = entry.insert(tx);
                let _ = manager
                    .processor
                    .permitless
                    .send_async(Box::pin(qbft_instance(rx)), QBFT_INSTANCE_NAME);
                tx.clone()
            }
        };
        ret
    }
    fn config(
        &self,
        builder: &mut ConfigBuilder<DefaultLeaderFunction>,
        id: &Self::Id,
    ) -> Result<qbft::Config<DefaultLeaderFunction>, ConfigBuilderError>;
}

impl<T: SlotClock + 'static, E: EthSpec> QbftDecidable<T, E> for ValidatorConsensusData<E> {
    type Id = ValidatorInstanceId;
    fn get_map(manager: &QbftManager<T, E>) -> &Map<Self::Id, Self> {
        &manager.validator_consensus_data_instances
    }

    fn config(
        &self,
        builder: &mut ConfigBuilder<DefaultLeaderFunction>,
        id: &Self::Id,
    ) -> Result<qbft::Config<DefaultLeaderFunction>, ConfigBuilderError> {
        builder.instance_height(id.instance_height).build()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> QbftDecidable<T, E> for BeaconVote {
    type Id = CommitteeInstanceId;
    fn get_map(manager: &QbftManager<T, E>) -> &Map<Self::Id, Self> {
        &manager.beacon_vote_instances
    }

    fn config(
        &self,
        builder: &mut ConfigBuilder<DefaultLeaderFunction>,
        id: &Self::Id,
    ) -> Result<Config<DefaultLeaderFunction>, ConfigBuilderError> {
        builder.instance_height(id.instance_height).build()
    }
}

enum QbftInstance<D: qbft::Data, S: FnMut(NetworkMessage<D>)> {
    Uninitialized {
        // todo: proooobably limit this
        message_buffer: Vec<NetworkMessage<D>>,
    },
    Initialized {
        qbft: Box<Qbft<D, S>>,
        round_end: Interval,
        on_completed: oneshot::Sender<Completed<D>>,
    },
}

async fn qbft_instance<D: qbft::Data>(mut rx: UnboundedReceiver<QbftMessage<D>>) {
    let mut instance = QbftInstance::Uninitialized {
        message_buffer: Vec::new(),
    };

    loop {
        let message = match &mut instance {
            QbftInstance::Uninitialized { .. } => rx.recv().await,
            QbftInstance::Initialized {
                qbft: instance,
                round_end,
                ..
            } => {
                select! {
                    message = rx.recv() => message,
                    _ = round_end.tick() => {
                        instance.end_round();
                        continue;
                    }
                }
            }
        };

        let Some(message) = message else {
            break;
        };

        match message.kind {
            QbftMessageKind::Initialize {
                initial,
                config,
                on_completed,
            } => {
                instance = match instance {
                    QbftInstance::Uninitialized { message_buffer } => {
                        // todo: actually send messages somewhere
                        let mut instance = Box::new(Qbft::new(
                            config,
                            qbft::ValidatedData { data: initial },
                            |_| {},
                        ));
                        for message in message_buffer {
                            instance.receive(message);
                        }
                        QbftInstance::Initialized {
                            round_end: tokio::time::interval(instance.config().round_time),
                            qbft: instance,
                            on_completed,
                        }
                    }
                    instance @ QbftInstance::Initialized { .. } => {
                        warn!("got double initialization of qbft instance, ignoring");
                        instance
                    }
                }
            }
            QbftMessageKind::NetworkMessage(message) => match &mut instance {
                QbftInstance::Initialized { qbft: instance, .. } => {
                    instance.receive(message);
                }
                QbftInstance::Uninitialized { message_buffer } => {
                    message_buffer.push(message);
                }
            },
        }

        if let QbftInstance::Initialized {
            qbft,
            round_end,
            on_completed,
        } = instance
        {
            if let Some(completed) = qbft.completed() {
                if on_completed.send(completed).is_err() {
                    error!("could not send qbft result");
                }
                break;
            } else {
                instance = QbftInstance::Initialized {
                    qbft,
                    round_end,
                    on_completed,
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum QbftError {
    QueueClosedError,
    QueueFullError,
    ConfigBuilderError(ConfigBuilderError),
}

impl From<TrySendError<WorkItem>> for QbftError {
    fn from(value: TrySendError<WorkItem>) -> Self {
        match value {
            TrySendError::Full(_) => QbftError::QueueFullError,
            TrySendError::Closed(_) => QbftError::QueueClosedError,
        }
    }
}

impl From<RecvError> for QbftError {
    fn from(_: RecvError) -> Self {
        QbftError::QueueClosedError
    }
}

impl From<ConfigBuilderError> for QbftError {
    fn from(value: ConfigBuilderError) -> Self {
        QbftError::ConfigBuilderError(value)
    }
}
