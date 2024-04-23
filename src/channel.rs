use bytes::BytesMut;
use derive_new::new;
use std::cmp::min;
use std::future::Future;
use std::io;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::sync::PollSender;

use super::ssh::common::code::*;
use crate::sftp::SFtp;

use super::error::{Error, Result};
use super::msg::Request;

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ChannelOpenFailureReson(pub u32);

impl ChannelOpenFailureReson {
    pub const ADMINISTRATIVELY_PROHIBITED: Self = Self(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
    pub const CONNECT_FAILED: Self = Self(SSH_OPEN_CONNECT_FAILED);
    pub const UNKNOWN_CHANNELTYPE: Self = Self(SSH_OPEN_UNKNOWN_CHANNELTYPE);
    pub const RESOURCE_SHORTAGE: Self = Self(SSH_OPEN_RESOURCE_SHORTAGE);
}

#[derive(Debug, Clone)]
pub struct Signal(pub String);

impl PartialEq<&str> for Signal {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl<T: Into<String>> From<T> for Signal {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Signal {
    pub const ABRT: &'static str = "ABRT";
    pub const FPE: &'static str = "FPE";
    pub const HUP: &'static str = "HUP";
    pub const ILL: &'static str = "ILL";
    pub const INT: &'static str = "INT";
    pub const KILL: &'static str = "KILL";
    pub const PIPE: &'static str = "PIPE";
    pub const QUIT: &'static str = "QUIT";
    pub const SEGV: &'static str = "SEGV";
    pub const TERM: &'static str = "TERM";
    pub const USR1: &'static str = "USR1";
    pub const USR2: &'static str = "USR2";
}

#[derive(Debug, Clone, new)]
pub enum ExitStatus {
    Normal(u32),
    Interrupt {
        signal: Signal,
        core_dumped: bool,
        error_msg: String,
        tag: String,
    },
}

#[derive(Debug)]
pub enum Message {
    Close,
    Eof,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(ExitStatus),
}

enum State<T> {
    Idle,
    Started,
    Wait(oneshot::Receiver<Result<T>>),
}

pub struct Stream {
    channel: Channel,

    poll_sender: PollSender<Request>,

    // write_recver: Option<oneshot::Receiver<Result<bool>>>,
    write_state: State<bool>,

    // flush_recver: Option<oneshot::Receiver<Result<()>>>,
    flush_state: State<()>,

    stdout: BytesMut,

    stderr: BytesMut,

    rw_stdout: bool,

    closed: bool,

    eof: bool,
}

impl Stream {
    pub(crate) fn inner(&self) -> &Channel {
        &self.channel
    }

    pub fn new(channel: Channel) -> Self {
        let poll_sender = PollSender::new((*channel.session).clone());
        Self {
            channel,
            poll_sender,
            // write_recver: None,
            write_state: State::Idle,
            // flush_recver: None,
            flush_state: State::Idle,
            stdout: BytesMut::default(),
            stderr: BytesMut::default(),
            rw_stdout: true,
            closed: false,
            eof: false,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                State::Idle => match ready!(self.poll_sender.poll_reserve(cx)) {
                    Ok(_) => {
                        self.write_state = State::Started;
                    }
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Connection lost",
                        )))
                    }
                },
                State::Started => {
                    let (sender, recver) = oneshot::channel();
                    let request = Request::ChannelWriteStdout {
                        id: self.channel.id,
                        data: buf.to_vec(),
                        sender,
                    };

                    match self.poll_sender.send_item(request) {
                        Ok(_) => {
                            self.write_state = State::Wait(recver);
                            // self.write_recver = Some(recver);
                        }
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Connection lost",
                            )));
                        }
                    }
                }
                State::Wait(ref mut recver) => {
                    // let recver = self.write_recver.as_mut().unwrap();

                    let res = ready!(Pin::new(recver).poll(cx));
                    self.write_state = State::Idle;
                    // self.write_recver = None;
                    return match res {
                        Ok(_) => Poll::Ready(Ok(buf.len())),
                        Err(_) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Connection lost",
                        ))),
                    };
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.flush_state {
                State::Idle => match ready!(self.poll_sender.poll_reserve(cx)) {
                    Ok(_) => {
                        self.flush_state = State::Started;
                    }
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Connection lost",
                        )))
                    }
                },
                State::Started => {
                    let (sender, recver) = oneshot::channel();
                    let request = Request::ChannelFlushStdout {
                        id: self.channel.id,
                        sender,
                    };

                    match self.poll_sender.send_item(request) {
                        Ok(_) => {
                            self.flush_state = State::Wait(recver);
                            // self.flush_recver = Some(recver);
                        }
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Connection lost",
                            )));
                        }
                    }
                }
                State::Wait(ref mut recver) => {
                    // let recver = self.flush_recver.as_mut().unwrap();

                    let res = ready!(Pin::new(recver).poll(cx));
                    self.flush_state = State::Idle;
                    // self.flush_recver = None;
                    return match res {
                        Ok(_) => Poll::Ready(Ok(())),
                        Err(_) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Connection lost",
                        ))),
                    };
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stdout: Vec<u8> = vec![];
        let mut stderr: Vec<u8> = vec![];
        let mut closed = self.closed;
        let mut eof = self.eof;

        let mut ret = Poll::Ready(Ok(()));

        if self.rw_stdout {
            if self.stdout.is_empty() {
                if self.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Disconnected",
                    )));
                }
                if self.eof {
                    return Poll::Ready(Ok(()));
                }
                loop {
                    let data = ready!(self.channel.recver.poll_recv(cx));
                    let data = match data {
                        Some(data) => data,
                        None => {
                            ret = Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Disconnected",
                            )));
                            break;
                        }
                    };
                    match data {
                        Message::Close => {
                            closed = true;
                            ret = Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Disconnected",
                            )));
                            break;
                        }
                        Message::Eof => {
                            eof = true;
                            ret = Poll::Ready(Ok(()));
                            break;
                        }
                        Message::Stdout(data) => {
                            let remain = buf.remaining();
                            if remain > data.len() {
                                buf.put_slice(&data);
                            } else {
                                buf.put_slice(&data[..remain]);
                                stdout.extend(&data[remain..])
                            }
                            break;
                        }
                        Message::Stderr(data) => stderr.extend(data),
                        Message::Exit(_) => break,
                    };
                }
            } else {
                let min = min(buf.remaining(), self.stdout.len());

                buf.put_slice(&self.stdout.split_to(min));
            }
        } else if self.stderr.is_empty() {
            if self.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Disconnected",
                )));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            loop {
                let data = ready!(self.channel.recver.poll_recv(cx));
                let data = match data {
                    Some(data) => data,
                    None => {
                        ret = Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Disconnected",
                        )));
                        break;
                    }
                };
                match data {
                    Message::Close => {
                        closed = true;
                        ret = Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Disconnected",
                        )));
                        break;
                    }
                    Message::Eof => {
                        eof = true;
                        ret = Poll::Ready(Ok(()));
                        break;
                    }
                    Message::Stderr(data) => {
                        let remain = buf.remaining();
                        if remain > data.len() {
                            buf.put_slice(&data);
                        } else {
                            buf.put_slice(&data[..remain]);
                            stderr.extend(&data[remain..])
                        }
                        break;
                    }
                    Message::Stdout(data) => stdout.extend(data),
                    Message::Exit(_) => break,
                };
            }
        } else {
            let min = min(buf.remaining(), self.stderr.len());

            buf.put_slice(&self.stderr.split_to(min));
        }

        self.stdout.extend(stdout);
        self.stderr.extend(stderr);
        self.closed = closed;
        self.eof = eof;
        ret
    }
}

// impl<T, B> From<Address<B>> for Address<T>
// {
//     fn from(value: Address<B>) -> Self {
//         todo!()
//     }
// }

// impl<T: Into<String>> From<T> for Address {
//     fn from(value: T) -> Self {
//         Self(value.into())
//     }
// }

pub struct Channel {
    pub(crate) id: u32,
    // pub(crate) stdout: ManuallyDrop<IOReceiver>,
    // stderr: ManuallyDrop<IOReceiver>,
    recver: ManuallyDrop<mpsc::Receiver<Message>>,
    session: ManuallyDrop<mpsc::Sender<Request>>,
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.session.try_send(Request::ChannelDrop {
            id: self.id,
            sender: None,
        });
        self.manually_drop()
    }
}

use super::scp::Sender as ScpSender;
use super::sftp::{Permissions, Timestamp};

impl Channel {
    pub(crate) fn new(
        id: u32,
        channel: mpsc::Receiver<Message>,
        session: mpsc::Sender<Request>,
    ) -> Self {
        Self {
            id,
            recver: ManuallyDrop::new(channel),
            session: ManuallyDrop::new(session),
        }
    }

    fn manually_drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.recver);
            ManuallyDrop::drop(&mut self.session);
        }
    }

    pub async fn sftp(self) -> Result<SFtp> {
        let (sender, recver) = oneshot::channel();

        let session = (*self.session).clone();
        let request = Request::SFtpFromChannel {
            channel: self,
            sender,
        };

        session
            .send(request)
            .await
            .map_err(|_| Error::Disconnected)?;

        recver.await?
    }

    pub async fn flush(&self) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelFlushStdout {
            id: self.id,
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    // pub async fn is_server_closed(&self) -> bool {
    //     self.stdout.is_closed().await
    // }

    // pub async fn is_server_eof(&self) -> bool {
    //     self.stdout.is_eof().await
    // }

    pub async fn scp_sender(
        mut self,
        path: &str,
        size: usize,
        permissions: Permissions,
        time: Option<Timestamp>,
    ) -> Result<ScpSender> {
        let cmd = match time {
            Some(_) => format!("scp -pt {}", path),
            None => format!("scp -t {}", path),
        };

        self.exec(cmd).await?;

        let response = self.read().await?;

        if response.len() != 1 || response[0] != 0 {
            return Err(Error::invalid_format("invalid scp response"));
        }

        if let Some(time) = time {
            let send = format!("T{} 0 {} 0\n", time.mtime, time.atime);
            self.write(send).await?;
            let response = self.read().await?;

            if response.len() != 1 || response[0] != 0 {
                return Err(Error::invalid_format("invalid scp response"));
            }
        }

        let filename = path.split('/').last().unwrap_or(path);
        let send = format!("C0{:0o} {} {}\n", permissions.bits(), size, filename);

        self.write(send).await?;

        let response = self.read().await?;

        if response.len() != 1 || response[0] != 0 {
            return Err(Error::invalid_format("invalid scp response"));
        }

        Ok(ScpSender::new(self))
    }

    async fn close_without_drop(&self) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        self.send_request(Request::ChannelDrop {
            id: self.id,
            sender: Some(sender),
        })
        .await?;
        recver.await?
    }

    pub async fn close(mut self) -> Result<()> {
        let res = self.close_without_drop().await;
        self.manually_drop();
        std::mem::forget(self);
        res
    }

    pub async fn send_signal(&self, signal: impl Into<Signal>) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelSendSignal {
            id: self.id,
            signal: signal.into(),
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    pub async fn set_env(&self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<()> {
        let name = name.into();
        let value = value.into();
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelSetEnv {
            id: self.id,
            name,
            value,
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    pub async fn exec(&self, cmd: impl Into<String>) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelExec {
            id: self.id,
            cmd: cmd.into(),
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    // pub async fn exec_and_wait(&self, cmd: impl Into<String>) -> Result<ExitStatus> {
    //     let (sender, recver) = oneshot::channel();

    //     let request = Request::ChannelExecWait {
    //         id: self.id,
    //         cmd: cmd.into(),
    //         sender,
    //     };

    //     self.send_request(request).await?;

    //     recver.await.map_err(|_| Error::Disconnected)?
    // }

    // pub async fn exit_status(&self) -> Result<ExitStatus> {
    //     let (sender, recver) = oneshot::channel();
    //     let request = Request::ChannelGetExitStatus {
    //         id: self.id,
    //         sender,
    //     };

    //     self.send_request(request).await?;
    //     recver.await.map_err(|_| Error::Disconnected)?
    // }

    pub async fn recv(&mut self) -> Result<Message> {
        self.recver.recv().await.ok_or(Error::Disconnected)
    }

    // pub fn try_read(&mut self) -> Result<Option<Vec<u8>>> {
    //     self.stdout.try_read()
    // }

    async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            match self.recv().await? {
                Message::Close => return Err(Error::ChannelClosed),
                Message::Eof => return Err(Error::ChannelEOF),
                Message::Stdout(data) => return Ok(data),
                Message::Stderr(_) => {}
                Message::Exit(_) => {
                    return Err(Error::ProtocolError("Unexpected status".to_string()))
                }
            }
        }
    }

    // pub fn try_read_stderr(&mut self) -> Result<Option<Vec<u8>>> {
    //     self.stderr.try_read()
    // }

    // pub async fn read_stderr(&mut self) -> Result<Vec<u8>> {
    //     self.stderr.read().await
    // }

    pub async fn write(&self, data: impl Into<Vec<u8>>) -> Result<bool> {
        let data: Vec<u8> = data.into();
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelWriteStdout {
            id: self.id,
            data,
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    pub async fn eof(&self) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelEof {
            id: self.id,
            sender,
        };
        self.send_request(request).await?;

        recver.await?
    }

    pub async fn request_shell(&self) -> Result<()> {
        let (sender, recver) = oneshot::channel();
        let request = Request::ChannelReuqestShell {
            id: self.id,
            sender,
        };

        self.send_request(request).await?;

        recver.await?
    }

    async fn send_request(&self, msg: Request) -> Result<()> {
        self.session
            .send(msg)
            .await
            .map_err(|_| Error::Disconnected)
    }
}

pub(crate) struct Endpoint {
    pub(crate) id: u32,
    pub(crate) initial: u32,
    pub(crate) size: u32,
    pub(crate) maximum: u32,
    pub(crate) eof: bool,
    pub(crate) closed: bool,
}

impl Endpoint {
    pub(crate) fn new(id: u32, initial: u32, maximum: u32) -> Self {
        Self {
            id,
            initial,
            size: initial,
            maximum,
            eof: false,
            closed: false,
        }
    }
}

#[derive(new)]
pub(crate) struct ChannelInner {
    pub(crate) client: Endpoint,
    pub(crate) server: Endpoint,
    // pub(crate) stdout: IOSender,
    // pub(crate) stderr: IOSender,
    pub(crate) sender: mpsc::Sender<Message>,

    #[new(default)]
    pub(crate) stdout_buf: Vec<u8>,
    // pub(crate) exit_status: Option<ExitStatus>,
}

impl ChannelInner {
    pub(crate) async fn server_close(&mut self) {
        self.server.closed = true;
        let _ = self.sender.send(Message::Close).await;
    }

    pub(crate) async fn server_eof(&mut self) {
        self.server.eof = true;
        let _ = self.sender.send(Message::Eof).await;
    }
}
