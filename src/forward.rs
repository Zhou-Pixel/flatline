use std::{
    io,
    mem::{self, ManuallyDrop},
    pin::{pin, Pin},
    task::Poll,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::{channel::Channel, msg::Request};
use crate::{
    channel::Stream,
    error::{Error, Result},
};

pub struct Socket {
    channel: Stream,
    address: String,
    port: u32,
}

use std::result::Result as StdResult;

pub const ALL: &str = "";
pub const IPV4_ALL: &str = "0.0.0.0";
pub const IPV6_ALL: &str = "::";
pub const LOCALHOST: &str = "localhost";
pub const IPV4_LOCALHOST: &str = "127.0.0.1";
pub const IPV6_LOCALHOST: &str = "::1";

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.channel).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, io::Error>> {
        pin!(&mut self.channel).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<StdResult<(), io::Error>> {
        pin!(&mut self.channel).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<StdResult<(), io::Error>> {
        pin!(&mut self.channel).poll_shutdown(cx)
    }
}

impl Socket {
    pub(crate) fn new(channel: Channel, address: impl Into<String>, port: u32) -> Self {
        Self {
            channel: Stream::new(channel),
            address: address.into(),
            port,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn port(&self) -> u32 {
        self.port
    }
}

pub struct Listener {
    session: ManuallyDrop<mpsc::Sender<Request>>,
    recver: ManuallyDrop<mpsc::Receiver<Socket>>,
    address: ManuallyDrop<String>,
    port: u32,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.session.try_send(Request::CancelTcpipForward {
            address: (*self.address).clone(),
            port: self.port,
            sender: None,
        });

        self.manually_drop();
    }
}

impl Listener {
    pub(crate) fn new(
        session: mpsc::Sender<Request>,
        recver: mpsc::Receiver<Socket>,
        address: String,
        port: u32,
    ) -> Self {
        Self {
            session: ManuallyDrop::new(session),
            recver: ManuallyDrop::new(recver),
            address: ManuallyDrop::new(address),
            port,
        }
    }

    pub async fn accpet(&mut self) -> Result<Socket> {
        self.recver.recv().await.ok_or(Error::Disconnected)
    }

    fn manually_drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.session);
            ManuallyDrop::drop(&mut self.recver);
            ManuallyDrop::drop(&mut self.address);
        }
    }

    pub async fn cancel(mut self) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::CancelTcpipForward {
            address: (*self.address).clone(),
            port: self.port,
            sender: Some(sender),
        };

        self.session
            .send(request)
            .await
            .map_err(|_| Error::Disconnected)?;

        self.manually_drop();

        mem::forget(self);

        recver.await.map_err(|_| Error::Disconnected)?
    }

    pub fn listen_port(&self) -> u32 {
        self.port
    }

    pub fn listen_address(&self) -> &str {
        &self.address
    }
}
