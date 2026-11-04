use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
#[derive(Default)]
struct State {
    closing: bool,
    active: usize,
}
#[derive(Default)]
pub struct Tasks {
    state: Mutex<State>,
    done: Notify,
}
impl Tasks {
    pub fn acquire(self: &Arc<Self>) -> Option<Lease> {
        let mut state = self.state.lock().unwrap();
        if state.closing {
            return None;
        }
        state.active += 1;
        Some(Lease(self.clone()))
    }
    pub fn close(&self) {
        self.state.lock().unwrap().closing = true;
    }
    pub async fn join(&self) {
        loop {
            let notified = self.done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.lock().unwrap().active == 0 {
                return;
            }
            notified.await;
        }
    }
}
pub struct Lease(Arc<Tasks>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.done.notify_waiters();
    }
}
