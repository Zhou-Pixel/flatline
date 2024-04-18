use super::error::{Error, Result};
use bytes::BytesMut;
use derive_new::new;
use std::{mem::take, sync::Arc};
use tokio::sync::{
    mpsc::{self, error::TryRecvError},
    RwLock,
};

#[derive(Default)]
struct IOState {
    eof: bool,
    closed: bool,
}

#[derive(new)]
pub(crate) struct IOSender {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    state: Arc<RwLock<IOState>>,
}

impl IOReceiver {
    pub(crate) fn try_read(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.buf.is_empty() {
            return Ok(Some(take(&mut self.buf).to_vec()));
        }
        match self.recver.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(TryRecvError::Disconnected) => Err(Error::Disconnected),
            Err(TryRecvError::Empty) => Ok(None),
        }
    }

    pub(crate) async fn read(&mut self) -> Result<Vec<u8>> {
        if !self.buf.is_empty() {
            return Ok(take(&mut self.buf).to_vec());
        }
        match self.recver.recv().await {
            Some(data) => Ok(data),
            None => {
                let state = self.state.read().await;
                if state.closed {
                    Ok(vec![])
                } else if state.eof {
                    Ok(vec![])
                } else {
                    Err(Error::Disconnected)
                }
            }
        }
    }

    pub(crate) async fn read_exact(&mut self, size: usize) -> Result<Vec<u8>> {
        while self.buf.len() < size {
            let data = self.read().await?;
            self.buf.extend(data);
        }
        Ok(self.buf.split_to(size).to_vec())
    }

    pub(crate) async fn is_closed(&self) -> bool {
        self.state.read().await.closed
    }

    pub(crate) async fn is_eof(&self) -> bool {
        self.state.read().await.eof
    }
}

impl IOSender {
    pub(crate) async fn eof(&mut self) {
        self.sender.take();
        self.state.write().await.eof = true;
    }

    pub(crate) async fn closed(&mut self) {
        self.sender.take();
        self.state.write().await.closed = true;
    }

    pub(crate) async fn write(&mut self, data: Vec<u8>) -> Result<()> {
        self.sender
            .as_ref()
            .ok_or(Error::ub("Close by user"))?
            .send(data)
            .await
            .map_err(|_| Error::ub("Channel was dropped"))
    }
}

#[derive(new)]
pub(crate) struct IOReceiver {
    recver: mpsc::Receiver<Vec<u8>>,
    state: Arc<RwLock<IOState>>,

    #[new(default)]
    buf: BytesMut,
}

pub(crate) fn io_channel() -> (IOSender, IOReceiver) {
    let (sender, recver) = mpsc::channel(4096);

    let state = Arc::new(RwLock::new(IOState::default()));

    let sender = IOSender::new(Some(sender), Arc::clone(&state));
    let recver = IOReceiver::new(recver, state);

    (sender, recver)
}
