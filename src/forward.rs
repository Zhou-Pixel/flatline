use std::{
    io,
    mem::{self, ManuallyDrop},
    pin::{pin, Pin},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{channel::Channel, msg::Request};
use crate::{
    channel::Stream as ChannelStream,
    error::{Error, Result},
};

use super::{KMReceiver, KMSender};

pub struct Stream {
    channel: ChannelStream,
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

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.channel).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, io::Error>> {
        pin!(&mut self.channel).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), io::Error>> {
        pin!(&mut self.channel).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), io::Error>> {
        pin!(&mut self.channel).poll_shutdown(cx)
    }
}

impl Stream {
    pub(crate) fn new(channel: Channel, address: impl Into<String>, port: u32) -> Self {
        Self {
            channel: ChannelStream::new(channel),
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
    session: ManuallyDrop<KMSender<Request>>,
    recver: ManuallyDrop<KMReceiver<Stream>>,
    address: ManuallyDrop<String>,
    port: u32,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.session.as_sync().send(Request::CancelTcpipForward {
            address: (*self.address).clone(),
            port: self.port,
            sender: None,
        });

        self.manually_drop();
    }
}

impl Listener {
    pub(crate) fn new(
        session: KMSender<Request>,
        recver: KMReceiver<Stream>,
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

    pub async fn accpet(&self) -> Result<Stream> {
        self.recver.recv().await.map_err(|_| Error::Disconnected)
    }

    fn manually_drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.session);
            ManuallyDrop::drop(&mut self.recver);
            ManuallyDrop::drop(&mut self.address);
        }
    }

    pub async fn cancel(mut self) -> Result<()> {
        let (sender, recver) = kanal::oneshot_async();
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

        recver.recv().await?
    }

    pub fn listen_port(&self) -> u32 {
        self.port
    }

    pub fn listen_address(&self) -> &str {
        &self.address
    }
}
