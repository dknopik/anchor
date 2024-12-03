mod metrics;

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::select;
use tokio::time::Instant;
use tracing::{error, warn};

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub max_workers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_workers: num_cpus::get(),
        }
    }
}

pub struct Sender {
    tx: mpsc::Sender<WorkItem>,
}

impl Sender {
    pub fn send_async(
        &mut self,
        future: AsyncFn,
        name: &'static str,
    ) -> Result<(), TrySendError<WorkItem>> {
        self.send_work_item(WorkItem {
            func: WorkKind::Async(future),
            expiry: None,
            name,
        })
    }

    pub fn send_blocking(
        &mut self,
        func: BlockingFn,
        name: &'static str,
    ) -> Result<(), TrySendError<WorkItem>> {
        self.send_work_item(WorkItem {
            func: WorkKind::Blocking(func),
            expiry: None,
            name,
        })
    }

    pub fn send_immediate(
        &mut self,
        func: ImmediateFn,
        name: &'static str,
    ) -> Result<(), TrySendError<WorkItem>> {
        self.send_work_item(WorkItem {
            func: WorkKind::Immediate(func),
            expiry: None,
            name,
        })
    }

    pub fn send_work_item(&mut self, item: WorkItem) -> Result<(), TrySendError<WorkItem>> {
        let name = item.name;
        let result = self.tx.try_send(item);
        if let Err(err) = &result {
            metrics::inc_counter_vec(&metrics::ANCHOR_PROCESSOR_SEND_ERROR_PER_WORK_TYPE, &[name]);
            match err {
                TrySendError::Full(_) => {
                    warn!(task = name, "Processor queue full")
                }
                TrySendError::Closed(_) => {
                    error!("Processor queue closed unexpectedly")
                }
            }
        } else {
            metrics::inc_counter_vec(
                &metrics::ANCHOR_PROCESSOR_WORK_EVENTS_SUBMITTED_COUNT,
                &[name],
            );
            metrics::inc_gauge_vec(&metrics::ANCHOR_PROCESSOR_QUEUE_LENGTH, &[name]);
        }
        result
    }
}

pub struct Senders {
    pub permitless_tx: Sender,
    pub example2_tx: Sender,
    // todo add all the needed queues here
}

struct Receivers {
    permitless_rx: mpsc::Receiver<WorkItem>,
    example2_rx: mpsc::Receiver<WorkItem>,
    // todo add all the needed queues here
}

pub type AsyncFn = Pin<Box<dyn Future<Output = ()> + Send>>;
pub type BlockingFn = Box<dyn FnOnce() + Send>;
pub type ImmediateFn = Box<dyn FnOnce(DropOnFinish) + Send>;

enum WorkKind {
    Async(AsyncFn),
    Blocking(BlockingFn),
    Immediate(ImmediateFn),
}

pub struct WorkItem {
    func: WorkKind,
    expiry: Option<Instant>,
    name: &'static str,
}

impl WorkItem {
    pub fn new_async(name: &'static str, func: AsyncFn) -> Self {
        Self {
            name,
            expiry: None,
            func: WorkKind::Async(func),
        }
    }

    pub fn new_blocking(name: &'static str, func: BlockingFn) -> Self {
        Self {
            name,
            expiry: None,
            func: WorkKind::Blocking(func),
        }
    }

    pub fn set_expiry(&mut self, expiry: Instant) {
        self.expiry = Some(expiry);
    }

    pub fn with_expiry(mut self, expiry: Instant) -> Self {
        self.set_expiry(expiry);
        self
    }
}

pub struct DropOnFinish {
    permit: Option<OwnedSemaphorePermit>,
    _work_timer: Option<metrics::HistogramTimer>,
}
impl Drop for DropOnFinish {
    fn drop(&mut self) {
        metrics::dec_gauge(&metrics::ANCHOR_PROCESSOR_WORKERS_ACTIVE_TOTAL);
        if self.permit.is_some() {
            metrics::dec_gauge(&metrics::ANCHOR_PROCESSOR_PERMIT_WORKERS_ACTIVE_TOTAL);
        }
    }
}

pub async fn spawn(config: Config, executor: TaskExecutor) -> Senders {
    // todo macro? just specifying name and capacity?
    let (permitless_tx, permitless_rx) = mpsc::channel(1000);
    let (example2_tx, example2_rx) = mpsc::channel(1000);

    let senders = Senders {
        permitless_tx: Sender { tx: permitless_tx },
        example2_tx: Sender { tx: example2_tx },
    };
    let receivers = Receivers {
        permitless_rx,
        example2_rx,
    };

    executor.spawn(processor(config, receivers, executor.clone()), "processor");
    senders
}

async fn processor(config: Config, mut receivers: Receivers, executor: TaskExecutor) {
    let semaphore = Arc::new(Semaphore::new(config.max_workers));

    loop {
        let _timer = metrics::start_timer(&metrics::ANCHOR_PROCESSOR_EVENT_HANDLING_SECONDS);

        let (permit, work_item) = select! {
            biased;
            Some(w) = receivers.permitless_rx.recv() => (None, Some(w)),
            Ok(permit) = semaphore.clone().acquire_owned() => {
                select! {
                    biased;
                    Some(w) = receivers.example2_rx.recv() => (Some(permit), Some(w)),

                    // we have a permit, so we prefer other queues at this point,
                    // but it should still be possible to receive a permitless event
                    Some(w) = receivers.permitless_rx.recv() => (None, Some(w)),
                    else => (None, None),
                }
            }
            else => (None, None),
        };

        let Some(work_item) = work_item else {
            error!("Processor queues closed unexpectedly");
            break;
        };

        if let Some(expiry) = work_item.expiry {
            if expiry < Instant::now() {
                metrics::inc_counter_vec(
                    &metrics::ANCHOR_PROCESSOR_WORK_EVENTS_EXPIRED_COUNT,
                    &[work_item.name],
                );
                continue;
            }
        }

        metrics::inc_gauge(&metrics::ANCHOR_PROCESSOR_WORKERS_ACTIVE_TOTAL);
        if permit.is_some() {
            metrics::inc_gauge(&metrics::ANCHOR_PROCESSOR_PERMIT_WORKERS_ACTIVE_TOTAL);
        }
        metrics::inc_counter_vec(
            &metrics::ANCHOR_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
            &[work_item.name],
        );
        let drop_on_finish = DropOnFinish {
            permit,
            _work_timer: metrics::start_timer_vec(
                &metrics::ANCHOR_PROCESSOR_WORKER_TIME,
                &[work_item.name],
            ),
        };
        match work_item.func {
            WorkKind::Async(async_fn) => executor.spawn(
                async move {
                    async_fn.await;
                    drop(drop_on_finish);
                },
                work_item.name,
            ),
            WorkKind::Blocking(blocking_fn) => {
                executor.spawn_blocking(
                    move || {
                        blocking_fn();
                        drop(drop_on_finish);
                    },
                    work_item.name,
                );
            }
            WorkKind::Immediate(immediate_fn) => immediate_fn(drop_on_finish),
        }
    }
}
