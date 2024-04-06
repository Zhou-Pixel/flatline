use std::{mem::take, sync::Arc};
use super::error::{Error, Result};
use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use derive_new::new;
use tokio::sync::RwLock;



#[derive(Default)]
struct IOState {
    eof: bool,
    closed: bool,
}

#[derive(new)]
pub(crate) struct IOSender {
    sender: Sender<Vec<u8>>,
    state: Arc<RwLock<IOState>>,
}

impl IOReceiver {

    pub(crate) fn try_read(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.buf.is_empty() {
            return Ok(Some(take(&mut self.buf).to_vec()));
        }
        Ok(self.recver.try_recv().ok())
    }

    pub(crate) async fn read(&mut self) -> Result<Vec<u8>> {
        if !self.buf.is_empty() {
            return Ok(take(&mut self.buf).to_vec());
        }
        match self.recver.recv().await {
            Ok(data) => Ok(data),
            Err(_) => {
                let state = self.state.read().await;
                if state.closed {
                    Err(Error::ChannelClosed)
                } else if state.eof {
                    Ok(vec![])
                } else {
                    Err(Error::Disconnect)
                }
            },
        }
    }

    pub(crate) async fn read_exact(&mut self, size: usize) -> Result<Vec<u8>> {
        while self.buf.len() < size {
            let data = self.read().await?;
            self.buf.extend(data);
        }
        Ok(self.buf.split_to(size).to_vec())
    }
}

impl IOSender {
    pub(crate) async fn eof(&mut self) {
        self.sender.close();
        self.state.write().await.eof = true;
    }

    pub(crate) async fn close(&mut self) {
        self.sender.close();
        self.state.write().await.closed = true;
    }

    pub(crate) async fn write(&mut self, data: Vec<u8>) -> Result<()> {
        self.sender.send(data).await.map_err(|_| Error::ub("Channel was dropped"))
    }
}


#[derive(new)]
pub(crate) struct IOReceiver {
    recver: Receiver<Vec<u8>>,
    
    state: Arc<RwLock<IOState>>,

    #[new(default)]
    buf: BytesMut
}


pub(crate) fn io_channel() -> (IOSender, IOReceiver) {
    let (sender, recver) = async_channel::unbounded();

    let state = Arc::new(RwLock::new(IOState::default()));

    let sender = IOSender::new(sender, Arc::clone(&state));
    let recver = IOReceiver::new(recver, state);


    (sender, recver)

}