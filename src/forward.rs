use std::{
    io,
    mem::{self, ManuallyDrop},
    pin::{pin, Pin},
    task::{Context, Poll},
};

use derive_new::new;
use snafu::OptionExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{channel::Channel, error::builder, msg::Request};
use crate::{channel::Stream as ChannelStream, error::Result};

use super::{o_channel, MReceiver, MSender};

#[derive(Debug, Clone, PartialEq, Eq, Hash, new)]
pub struct SocketAddr {
    pub host: String,
    pub port: u32,
}

impl SocketAddr {
    pub const ALL: &'static str = "";
    pub const IPV4_ALL: &'static str = "0.0.0.0";
    pub const IPV6_ALL: &'static str = "::";
    pub const LOCALHOST: &'static str = "localhost";
    pub const IPV4_LOCALHOST: &'static str = "127.0.0.1";
    pub const IPV6_LOCALHOST: &'static str = "::1";
}

pub struct Stream {
    channel: ChannelStream,
    address: SocketAddr,
}

use std::result::Result as StdResult;

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
    pub(crate) fn new(channel: Channel, address: SocketAddr) -> Self {
        Self {
            channel: ChannelStream::new(channel),
            address,
        }
    }

    pub async fn close(self) -> Result<()> {
        self.channel.close().await
    }

    pub fn address(&self) -> &SocketAddr {
        &self.address
    }
}

pub struct Listener {
    session: ManuallyDrop<MSender<Request>>,
    recver: ManuallyDrop<MReceiver<Stream>>,
    address: ManuallyDrop<SocketAddr>,
    // port: u32,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.session.send(Request::CancelTcpipForward {
            address: (*self.address).clone(),
            // port: self.port,
            sender: None,
        });

        self.manually_drop();
    }
}

impl Listener {
    pub(crate) fn new(
        session: MSender<Request>,
        recver: MReceiver<Stream>,
        address: SocketAddr,
        // port: u32,
    ) -> Self {
        Self {
            session: ManuallyDrop::new(session),
            recver: ManuallyDrop::new(recver),
            address: ManuallyDrop::new(address),
            // port,
        }
    }

    pub async fn accpet(&mut self) -> Result<Stream> {
        self.recver.recv().await.context(builder::Disconnected) //.ok_or(Error::Disconnected)
    }

    fn manually_drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.session);
            ManuallyDrop::drop(&mut self.recver);
            ManuallyDrop::drop(&mut self.address);
        }
    }

    pub async fn cancel(mut self) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::CancelTcpipForward {
            address: (*self.address).clone(),
            // port: self.port,
            sender: Some(sender),
        };

        self.session
            .send(request)
            .map_err(|_| builder::Disconnected.build())?;

        self.manually_drop();

        mem::forget(self);

        recver.await.map_err(|_| builder::Disconnected.build())?
    }

    // pub fn listen_port(&self) -> u32 {
    //     self.port
    // }

    pub fn listen_address(&self) -> &SocketAddr {
        &self.address
    }
}
