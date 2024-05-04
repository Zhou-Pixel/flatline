use super::ssh::common::code::*;
use bytes::BytesMut;
use derive_new::new;
use tokio::sync::mpsc::error::TryRecvError;
use std::cmp::min;
use std::io;
use std::mem::transmute;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

use super::error::{Error, Result};
use super::msg::Request;
use super::{o_channel, MReceiver, MSender, BoxFuture};


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

// #[derive(Debug)]
pub enum Message {
    Close,
    Eof,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(ExitStatus),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close => write!(f, "Message::Close"),
            Self::Eof => write!(f, "Message::Eof"),
            Self::Stdout(arg0) => write!(f, "Message::Stdout {{ len: {} }}", arg0.len()),
            Self::Stderr(arg0) => write!(f, "Message::Stderr {{ len: {} }}", arg0.len()),
            Self::Exit(arg0) => write!(f, "Message::Exit ( {:?} )", arg0),
        }
    }
}

pub struct Stream {
    channel: Box<Channel>, // boxed due to self referencing

    // be careful, self referencing here
    read_future: Option<BoxFuture<'static, Result<Vec<u8>>>>,

    // be careful, self referencing here
    write_future: Option<BoxFuture<'static, Result<usize>>>,

    stdout: BytesMut,

    stderr: BytesMut,

    pub rw_stdout: bool,

    closed: bool,

    eof: bool,
}

// struct BufferChannel {

//     channel: Channel,

//     stdout: BytesMut,

//     stderr: BytesMut,

//     stdin: BytesMut,

//     closed: bool,

//     eof: bool,
// }

// impl BufferChannel {
//     async fn read_exact(&mut self, len: usize) -> Result<Vec<u8>> {
//         if self.stdout.len() < len {
//             if self.closed {
//                 return Err(Error::ChannelClosed);
//             }
//             if self.eof {
//                 return Err(Error::ChannelEof);
//             }

//         }
//         while self.stdout.len() < len {
//             let msg = self.channel.recv().await?;
//             match msg {
//                 Message::Close => {
//                     self.closed = true;
//                     return Err(Error::ChannelClosed)
//                 },
//                 Message::Eof => {
//                     self.eof = true;
//                     return Err(Error::ChannelEof)
//                 },
//                 Message::Stdout(data) => self.stdout.extend(data),
//                 Message::Stderr(data) => self.stderr.extend(data),
//                 Message::Exit(_) => continue,
//             }
//         }

//         Ok(self.stdout.split_to(len).to_vec())
//     }

// }

impl Stream {
    pub fn new(channel: Channel) -> Self {
        Self {
            channel: Box::new(channel),
            read_future: None,
            write_future: None,
            stdout: BytesMut::with_capacity(4096),
            stderr: BytesMut::with_capacity(4096),
            rw_stdout: true,
            closed: false,
            eof: false,
        }
    }

    pub async fn close(self) -> Result<()> {
        self.channel.close().await
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_future.is_none() {
            let future = self.channel.write(buf);
            let future: BoxFuture<'_, Result<usize>> = Box::pin(future);

            self.write_future = unsafe { transmute(Some(future)) };
        }
        let res = ready!(self.write_future.as_mut().unwrap().as_mut().poll(cx));
        self.write_future = None;

        Poll::Ready(match res {
            Ok(size) => Ok(size),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, Box::new(err))),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
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
        if self.read_future.is_none() {
            let f = self.read_maximum(buf.remaining());
            let f: Option<BoxFuture<'_, Result<Vec<u8>>>> = Some(Box::pin(f));

            self.read_future = unsafe { transmute(f) };
        }

        let res = ready!(self.read_future.as_mut().unwrap().as_mut().poll(cx));
        self.read_future = None;
        Poll::Ready(match res {
            Ok(data) => {
                buf.put_slice(&data);
                Ok(())
            }
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, Box::new(err))),
        })
    }
}

impl Stream {
    async fn read_maximum(&mut self, max: usize) -> Result<Vec<u8>> {
        loop {
            if self.rw_stdout {
                if self.stdout.is_empty() {
                    if self.closed {
                        return Err(Error::ChannelClosed);
                    }
                    if self.eof {
                        return Ok(vec![]);
                    }
                    let msg = self.channel.recv().await?;
                    // println!("msg from channel: {:?}", msg);
                    match msg {
                        Message::Close => {
                            self.closed = true;
                            return Err(Error::ChannelClosed);
                        }
                        Message::Eof => {
                            self.eof = true;
                            return Ok(vec![]);
                        }
                        Message::Stdout(mut data) => {
                            if data.len() <= max {
                                return Ok(data);
                            } else {
                                self.stdout.extend(&data[max..]);
                                data.truncate(max);
                                return Ok(data);
                            }
                        }
                        Message::Stderr(data) => {
                            self.stderr.extend(data);
                        }
                        Message::Exit(_) => continue,
                    }
                } else {
                    let min = min(max, self.stdout.len());
                    return Ok(self.stdout.split_to(min).to_vec());
                }
            } else if self.stderr.is_empty() {
                if self.closed {
                    return Err(Error::ChannelClosed);
                }
                if self.eof {
                    return Ok(vec![]);
                }
                let msg = self.channel.recv().await?;
                match msg {
                    Message::Close => {
                        self.closed = true;
                        return Err(Error::ChannelClosed);
                    }
                    Message::Eof => {
                        self.eof = true;
                        return Ok(vec![]);
                    }
                    Message::Stdout(data) => {
                        self.stdout.extend(data);
                    }
                    Message::Stderr(mut data) => {
                        if data.len() <= max {
                            return Ok(data);
                        } else {
                            self.stderr.extend(&data[max..]);
                            data.truncate(max);
                            return Ok(data);
                        }
                    }
                    Message::Exit(_) => continue,
                }
            } else {
                let min = min(max, self.stderr.len());
                return Ok(self.stderr.split_to(min).to_vec());
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMode {
    // #[allow(non_camel_case_types)]
    // TTY_OP_END,
    VINTR = 1,
    VQUIT = 2,
    VERASE = 3,
    VKILL = 4,
    VEOF = 5,
    VEOL = 6,
    VEOL2 = 7,
    VSTART = 8,
    VSTOP = 9,
    VSUSP = 10,
    VDSUSP = 11,
    VREPRINT = 12,
    VWERASE = 13,
    VLNEXT = 14,
    VFLUSH = 15,
    VSWTCH = 16,
    VSTATUS = 17,
    VDISCARD = 18,
    IGNPAR = 30,
    PARMRK = 31,
    INPCK = 32,
    ISTRIP = 33,
    INLCR = 34,
    IGNCR = 35,
    ICRNL = 36,
    IUCLC = 37,
    IXON = 38,
    IXANY = 39,
    IXOFF = 40,
    IMAXBEL = 41,
    ISIG = 50,
    ICANON = 51,
    XCASE = 52,
    ECHO = 53,
    ECHOE = 54,
    ECHOK = 55,
    ECHONL = 56,
    NOFLSH = 57,
    TOSTOP = 58,
    IEXTEN = 59,
    ECHOCTL = 60,
    ECHOKE = 61,
    PENDIN = 62,
    OPOST = 70,
    OLCUC = 71,
    ONLCR = 72,
    OCRNL = 73,
    ONOCR = 74,
    ONLRET = 75,
    CS7 = 90,
    CS8 = 91,
    PARENB = 92,
    PARODD = 93,
    #[allow(non_camel_case_types)]
    TTY_OP_ISPEED = 128,
    #[allow(non_camel_case_types)]
    TTY_OP_OSPEED = 129,
}

// impl ToString for TerminalMode {
//     fn to_string(&self) -> String {
//         self.to_str().to_string()
//     }
// }

// impl TerminalMode {
//     fn to_str(&self) -> &str {
//         match self {
//             // TerminalMode::TTY_OP_END => "TTY_OP_END",
//             TerminalMode::VINTR => "VINTR",
//             TerminalMode::VERASE => "VERASE",
//             TerminalMode::VKILL => "VKILL",
//             TerminalMode::VEOF => "VEOF",
//             TerminalMode::VEOL => "VEOL",
//             TerminalMode::VEOL2 => "VEOL2",
//             TerminalMode::VSTART => "VSTART",
//             TerminalMode::VSTOP => "VSTOP",
//             TerminalMode::VSUSP => "VSUSP",
//             TerminalMode::VDSUSP => "VDSUSP",
//             TerminalMode::VREPRINT => "VREPRINT",
//             TerminalMode::VWERASE => "VWERASE",
//             TerminalMode::VLNEXT => "VLNEXT",
//             TerminalMode::VFLUSH => "VFLUSH",
//             TerminalMode::VSWTCH => "VSWTCH",
//             TerminalMode::VSTATUS => "VSTATUS",
//             TerminalMode::VDISCARD => "VDISCARD",
//             TerminalMode::IGNPAR => "IGNPAR",
//             TerminalMode::PARMRK => "PARMRK",
//             TerminalMode::INPCK => "INPCK",
//             TerminalMode::ISTRIP => "ISTRIP",
//             TerminalMode::INLCR => "INLCR",
//             TerminalMode::IGNCR => "IGNCR",
//             TerminalMode::ICRNL => "ICRNL",
//             TerminalMode::IUCLC => "IUCLC",
//             TerminalMode::IXON => "IXON",
//             TerminalMode::IXANY => "IXANY",
//             TerminalMode::IXOFF => "IXOFF",
//             TerminalMode::IMAXBEL => "IMAXBEL",
//             TerminalMode::ISIG => "ISIG",
//             TerminalMode::ICANON => "ICANON",
//             TerminalMode::XCASE => "XCASE",
//             TerminalMode::ECHO => "ECHO",
//             TerminalMode::ECHOE => "ECHOE",
//             TerminalMode::ECHOK => "ECHOK",
//             TerminalMode::ECHONL => "ECHONL",
//             TerminalMode::NOFLSH => "NOFLSH",
//             TerminalMode::TOSTOP => "TOSTOP",
//             TerminalMode::IEXTEN => "IEXTEN",
//             TerminalMode::ECHOCTL => "ECHOCTL",
//             TerminalMode::ECHOKE => "ECHOKE",
//             TerminalMode::PENDIN => "PENDIN",
//             TerminalMode::OPOST => "OPOST",
//             TerminalMode::OLCUC => "OLCUC",
//             TerminalMode::ONLCR => "ONLCR",
//             TerminalMode::OCRNL => "OCRNL",
//             TerminalMode::ONOCR => "ONOCR",
//             TerminalMode::ONLRET => "ONLRET",
//             TerminalMode::CS7 => "CS7",
//             TerminalMode::CS8 => "CS8",
//             TerminalMode::PARENB => "PARENB",
//             TerminalMode::PARODD => "PARODD",
//             TerminalMode::TTY_OP_ISPEED => "TTY_OP_ISPEED",
//             TerminalMode::TTY_OP_OSPEED => "TTY_OP_OSPEED",
//         }
//     }
// }

pub struct Channel {
    pub(crate) id: u32,
    recver: ManuallyDrop<MReceiver<Message>>,
    session: ManuallyDrop<MSender<Request>>,
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.session.send(Request::ChannelDrop {
            id: self.id,
            sender: None,
        });
        self.manually_drop()
    }
}

impl Channel {
    pub(crate) fn new(id: u32, channel: MReceiver<Message>, session: MSender<Request>) -> Self {
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

    async fn close_without_drop(&self) -> Result<()> {
        let (sender, recver) = o_channel();
        self.send_request(Request::ChannelDrop {
            id: self.id,
            sender: Some(sender),
        })?;
        recver.await?
    }

    pub async fn close(mut self) -> Result<()> {
        let res = self.close_without_drop().await;
        self.manually_drop();
        std::mem::forget(self);
        res
    }

    pub async fn send_signal(&self, signal: impl Into<Signal>) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelSendSignal {
            id: self.id,
            signal: signal.into(),
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn set_env(&self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<()> {
        let name = name.into();
        let value = value.into();
        let (sender, recver) = o_channel();
        let request = Request::ChannelSetEnv {
            id: self.id,
            name,
            value,
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn exec(&self, cmd: impl Into<String>) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelExec {
            id: self.id,
            cmd: cmd.into(),
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn recv(&mut self) -> Result<Message> {
        self.recver.recv().await.ok_or(Error::Disconnected)
    }

    pub fn try_recv(&mut self) -> Result<Option<Message>> {
        match self.recver.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Disconnected)
        }
    }

    pub async fn write(&self, data: impl Into<Vec<u8>>) -> Result<usize> {
        let data: Vec<u8> = data.into();
        let (sender, recver) = o_channel();
        let request = Request::ChannelWriteStdout {
            id: self.id,
            data,
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn eof(&self) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelEof {
            id: self.id,
            sender,
        };
        self.send_request(request)?;

        recver.await?
    }

    pub async fn request_shell(&self) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelReuqestShell {
            id: self.id,
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn request_pty(
        &self,
        term: impl Into<String>,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        terimal_modes: impl Into<Vec<(TerminalMode, u32)>>,
    ) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelRequestPty {
            id: self.id,
            term: term.into(),
            columns,
            rows,
            width,
            height,
            terimal_modes: terimal_modes.into(),
            sender,
        };

        self.send_request(request)?;

        recver.await?
    }

    pub async fn pty_change_size(
        &self,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
    ) -> Result<()> {
        let (sender, recver) = o_channel();
        let request = Request::ChannelPtyChangeSize {
            id: self.id,
            columns,
            rows,
            width,
            height,
            sender,
        };

        self.send_request(request)?;
        recver.await?
    }

    fn send_request(&self, msg: Request) -> Result<()> {
        self.session.send(msg).map_err(|_| Error::Disconnected)
    }

    pub(crate) fn session(&self) -> MSender<Request> {
        (*self.session).clone()
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
    pub(crate) sender: MSender<Message>,
    // #[new(default)]
    // pub(crate) stdout_buf: Vec<u8>,
    // pub(crate) exit_status: Option<ExitStatus>,
}

impl ChannelInner {
    pub(crate) fn server_close(&mut self) {
        self.server.closed = true;
        let _ = self.sender.send(Message::Close);
    }

    pub(crate) fn server_eof(&mut self) {
        self.server.eof = true;
        let _ = self.sender.send(Message::Eof);
    }
}
