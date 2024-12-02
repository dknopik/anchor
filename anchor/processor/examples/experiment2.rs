use processor::experiment2::earliest_deadline::{DeadlineScheduler, DeadlinedWork};
use processor::experiment2::{spawn, DropOnFinish, Scheduler, TaskRunner, Work};
use processor::Config;
use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;

trait AnchorQueueable {
    fn queue_kind(&self) -> AnchorQueueKinds;
}

enum AnchorQueueKinds {
    StartQbftQueue,
    SomethingQbftQueue,
}

#[derive(Default)]
struct AnchorWorkQueues {
    start_queue: VecDeque<Box<dyn AnchorWork>>,
    something_queue: VecDeque<Box<dyn AnchorWork>>,
}

impl Scheduler<dyn AnchorWork> for AnchorWorkQueues {
    fn received(&mut self, work_item: Box<dyn AnchorWork>) -> Option<Box<dyn AnchorWork>> {
        match work_item.queue_kind() {
            AnchorQueueKinds::StartQbftQueue => self.start_queue.push_back(work_item),
            AnchorQueueKinds::SomethingQbftQueue => self.something_queue.push_back(work_item),
        }
        None
    }

    async fn next_task(&mut self) -> Option<Box<dyn AnchorWork>> {
        self.start_queue
            .pop_front()
            .or_else(|| self.something_queue.pop_front())
    }
}

trait AnchorWork: DeadlinedWork + AnchorQueueable + Work<State = QBFTStore> {}
impl<T: DeadlinedWork + AnchorQueueable + Work<State = QBFTStore>> AnchorWork for T {}

#[derive(Default)]
struct QBFTStore {
    instances: HashMap<i64, mpsc::Sender<(SomethingQBFTInstance, DropOnFinish)>>,
}

struct StartQBFTInstance {
    round: i64,
}

impl Work for StartQBFTInstance {
    type State = QBFTStore;

    fn run(self: Box<Self>, state: &mut QBFTStore, runner: TaskRunner) {
        let (tx, mut rx) = mpsc::channel(10);
        runner.run_future(async move {
            println!("StartQBFTInstance");
            rx.recv().await.unwrap();
        });
        state.instances.insert(self.round, tx);
    }

    fn kind_name(&self) -> &'static str {
        "start_qbft_instance"
    }
}
impl DeadlinedWork for StartQBFTInstance {
    fn get_deadline(&self) -> i64 {
        self.round
    }
}
impl AnchorQueueable for StartQBFTInstance {
    fn queue_kind(&self) -> AnchorQueueKinds {
        AnchorQueueKinds::StartQbftQueue
    }
}

struct SomethingQBFTInstance {
    round: i64,
}

impl Work for SomethingQBFTInstance {
    type State = QBFTStore;

    fn run(self: Box<Self>, state: &mut QBFTStore, runner: TaskRunner) {
        runner.run_immediate(|drop_on_finish| {
            state
                .instances
                .get(&self.round)
                .unwrap()
                .try_send((*self, drop_on_finish))
                .unwrap()
        })
    }

    fn kind_name(&self) -> &'static str {
        "start_qbft_instance"
    }
}
impl DeadlinedWork for SomethingQBFTInstance {
    fn get_deadline(&self) -> i64 {
        self.round
    }
}
impl AnchorQueueable for SomethingQBFTInstance {
    fn queue_kind(&self) -> AnchorQueueKinds {
        AnchorQueueKinds::SomethingQbftQueue
    }
}

#[tokio::main]
async fn main() {
    let sched = blackbox();
    let executor = blackbox();

    let tx = if sched {
        spawn::<dyn AnchorWork, DeadlineScheduler>(
            Config::default(),
            DeadlineScheduler,
            executor,
        )
        .await
    } else {
        spawn::<dyn AnchorWork, AnchorWorkQueues>(
            Config::default(),
            AnchorWorkQueues::default(),
            executor,
        )
        .await
    };

    let _ = tx.send(Box::new(StartQBFTInstance { round: 0 })).await;
    let _ = tx.send(Box::new(SomethingQBFTInstance { round: 0 })).await;
}

fn blackbox<T>() -> T {
    unimplemented!()
}
