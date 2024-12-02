use crate::experiment::Scheduler;

pub trait DeadlinedWork {
    fn get_deadline(&self) -> i64;
}

#[derive(Default)]
pub struct DeadlineScheduler;

impl<W: DeadlinedWork> Scheduler<W> for DeadlineScheduler {
    fn received(&mut self, _work_item: W) -> Option<W> {
        todo!()
    }

    async fn next_task(&mut self) -> Option<W> {
        todo!()
    }
}
