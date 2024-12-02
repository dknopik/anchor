pub mod earliest_deadline;

use crate::Config;
use std::future::Future;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::select;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::error;

pub struct DropOnFinish {
    _permit: OwnedSemaphorePermit,
    //_worker_timer: Option<metrics::HistogramTimer>,
}

pub trait Work<T>: Send {

    fn run(self, state: &mut T, runner: TaskRunner);
    fn kind_name(&self) -> &'static str;
}

pub struct TaskRunner<'a> {
    executor: &'a TaskExecutor,
    drop_on_finish: DropOnFinish,
    name: &'static str,
}

impl TaskRunner<'_> {
    pub fn run_future(self, future: impl Future<Output = ()> + Send + 'static) {
        self.executor.spawn(
            async move {
                future.await;
                drop(self.drop_on_finish)
            },
            self.name,
        );
    }

    pub fn run_blocking(self, function: impl FnOnce() + Send + 'static) {
        self.executor.spawn_blocking(
            || {
                function();
                drop(self.drop_on_finish)
            },
            self.name,
        );
    }

    pub fn run_immediate(self, function: impl FnOnce(DropOnFinish)) {
        function(self.drop_on_finish);
    }
}

pub trait Scheduler<W>: Send {
    fn received(&mut self, work_item: W) -> Option<W>;
    fn next_task(&mut self) -> impl std::future::Future<Output = Option<W>> + Send;
}

pub async fn spawn<W, S, T>(
    config: Config,
    scheduler: S,
    executor: TaskExecutor,
) -> mpsc::Sender<W>
where
    W: Work<T> + 'static,
    S: Scheduler<W> + Default + 'static,
    T: Default + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1000);
    executor.spawn(
        processor(config, rx, scheduler, executor.clone()),
        "processor",
    );
    tx
}

async fn processor<W, S, T>(
    config: Config,
    mut rx: mpsc::Receiver<W>,
    mut scheduler: S,
    executor: TaskExecutor,
) where
    W: Work<T>,
    S: Scheduler<W>,
    T: Default,
{
    // TODO: consider having separate limits for blocking and async?
    let semaphore = Arc::new(Semaphore::new(config.max_workers));
    let mut state = T::default();

    loop {
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            error!("Processor semaphore closed unexpectedly");
            break;
        };

        let work_item = loop {
            if let Some(work_item) = select! {
                biased;
                Some(work_item) = rx.recv() => scheduler.received(work_item),
                Some(work_item) = scheduler.next_task() => Some(work_item),
                else => return,
            } {
                break work_item;
            }
        };

        let runner = TaskRunner {
            executor: &executor,
            drop_on_finish: DropOnFinish { _permit: permit },
            name: work_item.kind_name(),
        };
        work_item.run(&mut state, runner);
    }
}
