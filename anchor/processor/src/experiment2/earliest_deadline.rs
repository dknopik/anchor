use crate::experiment2::{Scheduler, Work};

pub trait DeadlinedWork: Work {
    fn get_deadline(&self) -> i64;
}

#[derive(Default)]
pub struct DeadlineScheduler;

impl<W: DeadlinedWork + ?Sized> Scheduler<W> for DeadlineScheduler {
    fn received(&mut self, _work_item: Box<W>) -> Option<Box<W>> {
        todo!()
    }

    async fn next_task(&mut self) -> Option<Box<W>> {
        todo!()
    }
}
