use processor::experiment::earliest_deadline::{DeadlineScheduler, DeadlinedWork};
use processor::experiment::{spawn, DropOnFinish, Scheduler, TaskRunner, Work};
use processor::Config;
use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;

#[derive(Default)]
struct AnchorWorkQueues {
    start_queue: VecDeque<AnchorWork>,
    something_queue: VecDeque<AnchorWork>,
}

impl Scheduler<AnchorWork> for AnchorWorkQueues {
    fn received(&mut self, work_item: AnchorWork) -> Option<AnchorWork> {
        match &work_item {
            AnchorWork::StartQBFTInstance { .. } => self.start_queue.push_back(work_item),
            AnchorWork::SomethingQBFTInstance { .. } => self.something_queue.push_back(work_item),
        }
        None
    }

    async fn next_task(&mut self) -> Option<AnchorWork> {
        self.start_queue
            .pop_front()
            .or_else(|| self.something_queue.pop_front())
    }
}

#[derive(Default)]
struct QBFTStore {
    instances: HashMap<i64, mpsc::Sender<(usize, DropOnFinish)>>,
}

enum AnchorWork {
    StartQBFTInstance { round: i64 },
    SomethingQBFTInstance { round: i64 },
}

impl Work<QBFTStore> for AnchorWork {
    fn run(self, state: &mut QBFTStore, runner: TaskRunner) {
        match self {
            AnchorWork::StartQBFTInstance { round } => {
                let (tx, mut rx) = mpsc::channel(10);
                runner.run_future(async move {
                    println!("StartQBFTInstance");
                    rx.recv().await.unwrap();
                });
                state.instances.insert(round, tx);
            }
            AnchorWork::SomethingQBFTInstance { round } => runner.run_immediate(|drop_on_finish| {
                state
                    .instances
                    .get(&round)
                    .unwrap()
                    .try_send((42, drop_on_finish))
                    .unwrap()
            }),
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            AnchorWork::StartQBFTInstance { .. } => "StartQBFTInstance",
            AnchorWork::SomethingQBFTInstance { .. } => "SomethingQBFTInstance",
        }
    }
}

impl DeadlinedWork for AnchorWork {
    fn get_deadline(&self) -> i64 {
        match self {
            AnchorWork::StartQBFTInstance { round } => *round,
            AnchorWork::SomethingQBFTInstance { round } => *round,
        }
    }
}

#[tokio::main]
async fn main() {
    let sched = blackbox();
    let executor = blackbox();

    let tx = if sched {
        spawn::<AnchorWork, DeadlineScheduler, QBFTStore>(
            Config::default(),
            DeadlineScheduler,
            executor,
        )
        .await
    } else {
        spawn::<AnchorWork, AnchorWorkQueues, QBFTStore>(
            Config::default(),
            AnchorWorkQueues::default(),
            executor,
        )
        .await
    };

    let _ = tx.send(AnchorWork::StartQBFTInstance { round: 0 }).await;
    let _ = tx
        .send(AnchorWork::SomethingQBFTInstance { round: 0 })
        .await;
}

fn blackbox<T>() -> T {
    unimplemented!()
}
