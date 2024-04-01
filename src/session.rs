use std::collections::HashMap;

use super::ssh::stream::CipherStream;

use crate::channel::ChannelInner;
use crate::channel::Endpoint as ChannelEndpoint;
use crate::channel::NormalChannel;
use crate::cipher::kex::Dependency;

use crate::cipher::sign;

use crate::error::Error;
use crate::error::Result;

use crate::sftp::SFtpSystem;
use crate::sftp::Sftp;
use crate::ssh::buffer::Buffer;
use crate::ssh::common::code::*;
use crate::ssh::common::SFTP_VERSION;

use super::channel::Channel;
use super::Request;
use crate::ssh::stream::PlainStream;
use async_channel::{Receiver, Sender};
use derive_new::new;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(new)]
struct Endpoint {
    banner: String,
}

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct ChannelOpenFailureReson(pub u32);

impl ChannelOpenFailureReson {
    pub const ADMINISTRATIVELY_PROHIBITED: Self = Self(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
    pub const CONNECT_FAILED: Self = Self(SSH_OPEN_CONNECT_FAILED);
    pub const UNKNOWN_CHANNELTYPE: Self = Self(SSH_OPEN_UNKNOWN_CHANNELTYPE);
    pub const RESOURCE_SHORTAGE: Self = Self(SSH_OPEN_RESOURCE_SHORTAGE);
}

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct DisconnectReson(pub u32);

impl DisconnectReson {
    pub const HOST_NOT_ALLOWED_TO_CONNECT: Self = Self(SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);
    pub const PROTOCOL_ERROR: Self = Self(SSH_DISCONNECT_PROTOCOL_ERROR);
    pub const KEY_EXCHANGE_FAILED: Self = Self(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
    pub const RESERVED: Self = Self(SSH_DISCONNECT_RESERVED);
    pub const MAC_ERROR: Self = Self(SSH_DISCONNECT_MAC_ERROR);
    pub const COMPRESSION_ERROR: Self = Self(SSH_DISCONNECT_COMPRESSION_ERROR);
    pub const SERVICE_NOT_AVAILABLE: Self = Self(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: Self =
        Self(SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
    pub const HOST_KEY_NOT_VERIFIABLE: Self = Self(SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
    pub const CONNECTION_LOST: Self = Self(SSH_DISCONNECT_CONNECTION_LOST);
    pub const BY_APPLICATION: Self = Self(SSH_DISCONNECT_BY_APPLICATION);
    pub const TOO_MANY_CONNECTIONS: Self = Self(SSH_DISCONNECT_TOO_MANY_CONNECTIONS);
    pub const AUTH_CANCELLED_BY_USER: Self = Self(SSH_DISCONNECT_AUTH_CANCELLED_BY_USER);
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: Self =
        Self(SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
    pub const ILLEGAL_USER_NAME: Self = Self(SSH_DISCONNECT_ILLEGAL_USER_NAME);
}

#[derive(Debug, Clone)]
pub struct Signal(pub String);

impl PartialEq<&str> for Signal {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
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

#[derive(Debug)]
pub enum ServerMessage {
    UserauthSuccess,
    UserauthFailure {
        methods: Vec<String>,
        partial: bool,
    },
    UserauthChangeReq,
    UserauthBanner {
        msg: String,
        tag: String,
    },
    // UserauthPkOk {
    //     algo: String,
    //     blob: String,
    // },
    // UserAuthInfoRequest {
    //     name: String,
    //     instruction: String,
    //     tag: String,
    //     prompts: Vec<(String, bool)>,
    // },
    HostKeysOpenSsh(Vec<u8>),
    ChannelOpenFailure {
        recipient: u32,
        reson: ChannelOpenFailureReson,
        desc: String,
        tag: String,
    },
    ChannelOpenConfirmation {
        recipient: u32,
        sender: u32,
        initial: u32,
        maximum: u32,
    },
    ChannelStdoutData {
        recipient: u32,
        data: Vec<u8>,
    },
    ChannelStderrData {
        recipient: u32,
        data: Vec<u8>,
    },
    ChannelSuccess(u32),
    ChannelFailure(u32),
    ChannelWindowAdjust {
        recipient: u32,
        count: u32,
    },
    ChannelClose(u32),
    ChannelEof(u32),
    ChannelExitStatus {
        recipient: u32,
        status: u32,
    },
    ChannelExitSignal {
        recipient: u32,
        signal: Signal,
        core_dumped: bool,
        error_msg: String,
        tag: String,
    },
    UserauthServiceAccept,
    Unimplemented(u32),
    Debug {
        always_display: bool,
        msg: String,
        tag: String,
    },
    Disconnect {
        reason: DisconnectReson,
        description: String,
        tag: String,
    },
    Ignore(Vec<u8>),
}

#[derive(Debug, Clone, new)]
pub enum ExitStatus {
    Normal(u32),
    Interrupt {
        signal: Signal,
        core_dumped: bool,
        error_msg: String,
    },
}

#[derive(Debug)]
pub enum Userauth {
    Success,
    Failure(Vec<String>),
    Expired,
}

impl ServerMessage {
    fn parse(payload: impl Into<Vec<u8>>) -> std::result::Result<Self, String> {
        let mut buffer = Buffer::from_vec(payload.into());

        let mut detail = "unable to parse a server message".to_string();

        let mut func = || {
            let mut utf8 = |data: &[u8]| {
                let str = String::from_utf8(data.to_vec());
                match str {
                    Ok(str) => Some(str),
                    Err(_) => {
                        detail = "unable to parse string as utf8".to_string();
                        None
                    }
                }
            };
            let code = buffer.take_u8()?;

            match code {
                SSH_MSG_CHANNEL_OPEN_FAILURE => {
                    let recipient = buffer.take_u32()?;
                    let reson = ChannelOpenFailureReson(buffer.take_u32()?);

                    let (_, desc) = buffer.take_one()?;
                    let (_, tag) = buffer.take_one()?;

                    let desc = utf8(&desc)?;
                    let tag = utf8(&tag)?;

                    Some(Self::ChannelOpenFailure {
                        recipient,
                        reson,
                        desc,
                        tag,
                    })
                }
                SSH_MSG_USERAUTH_SUCCESS => Some(Self::UserauthSuccess),
                SSH_MSG_USERAUTH_FAILURE => {
                    let (_, methods) = buffer.take_one()?;

                    let methods = utf8(&methods)?.split(",").map(|v| v.to_owned()).collect();

                    let partial = buffer.take_u8()? != 0;

                    Some(Self::UserauthFailure { methods, partial })
                }
                SSH_MSG_USERAUTH_PASSWD_CHANGEREQ => Some(Self::UserauthChangeReq),
                SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                    let recipient = buffer.take_u32()?;

                    let sender = buffer.take_u32()?;

                    let initial = buffer.take_u32()?;

                    let maximum = buffer.take_u32()?;

                    Some(Self::ChannelOpenConfirmation {
                        recipient,
                        sender,
                        initial,
                        maximum,
                    })
                }
                SSH_MSG_CHANNEL_SUCCESS => Some(Self::ChannelSuccess(buffer.take_u32()?)),
                SSH_MSG_CHANNEL_FAILURE => Some(Self::ChannelFailure(buffer.take_u32()?)),
                SSH_MSG_GLOBAL_REQUEST => {
                    let len = buffer.take_u32()?;

                    let line = buffer.take_bytes(len as usize)?;

                    if line == b"hostkeys-00@openssh.com" {
                        Some(Self::HostKeysOpenSsh(line))
                    } else {
                        detail = format!("unknown global reqeust: {:?}", utf8(&line)?);
                        // Err(Error::ssh_packet_parse(format!(
                        //     "unknown global reqeust: {:?}",
                        //     String::from_utf8(line)?
                        // )))
                        None
                    }
                }
                SSH_MSG_CHANNEL_DATA => {
                    let recipient = buffer.take_u32()?;

                    let (_, data) = buffer.take_one()?;

                    Some(Self::ChannelStdoutData { recipient, data })
                }
                SSH_MSG_CHANNEL_EXTENDED_DATA => {
                    let recipient = buffer.take_u32()?;
                    let code = buffer.take_u32()?;
                    let len = buffer.take_u32()?;
                    let data = buffer.take_bytes(len as usize)?;
                    if code == SSH_EXTENDED_DATA_STDERR {
                        Some(Self::ChannelStderrData { recipient, data })
                    } else {
                        detail = format!("unknow data type code: {code}");
                        // Err(Error::ssh_packet_parse(format!(
                        //     "unknow data type code: {code}"
                        // )))
                        None
                    }
                }
                SSH_MSG_CHANNEL_EOF => {
                    let recipient = buffer.take_u32()?;
                    Some(Self::ChannelEof(recipient))
                }
                SSH_MSG_UNIMPLEMENTED => Some(Self::Unimplemented(buffer.take_u32()?)),
                SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    let recipient = buffer.take_u32()?;
                    let count = buffer.take_u32()?;

                    Some(Self::ChannelWindowAdjust { recipient, count })
                }
                SSH_MSG_SERVICE_ACCEPT => {
                    // let service =
                    let len = buffer.take_u32()?;
                    let service = buffer.take_bytes(len as usize)?;

                    if service == b"ssh-userauth" {
                        Some(Self::UserauthServiceAccept)
                    } else {
                        detail = "unknown service name".to_string();
                        None
                    }
                }
                SSH_MSG_CHANNEL_REQUEST => {
                    let recipient = buffer.take_u32()?;

                    let (_, string) = buffer.take_one()?;

                    let _ = buffer.take_u8()?;

                    if string == b"exit-status" {
                        let code = buffer.take_u32()?;

                        Some(Self::ChannelExitStatus {
                            recipient,
                            status: code,
                        })
                    } else if string == b"exit-signal" {
                        let (_, signal) = buffer.take_one()?;
                        let core_dumped = buffer.take_u8()? != 0;
                        let (_, error_msg) = buffer.take_one()?;
                        let (_, tag) = buffer.take_one()?;

                        let signal = Signal(utf8(&signal)?);
                        let error_msg = utf8(&error_msg)?;
                        let tag = utf8(&tag)?;

                        Some(Self::ChannelExitSignal {
                            recipient,
                            signal,
                            core_dumped,
                            error_msg,
                            tag,
                        })
                    } else {
                        detail = "unimplemented".to_string();
                        None
                    }
                }
                SSH_MSG_CHANNEL_CLOSE => {
                    let recipient = buffer.take_u32()?;

                    Some(Self::ChannelClose(recipient))
                }
                SSH_MSG_USERAUTH_BANNER => {
                    let (_, msg) = buffer.take_one()?;
                    let (_, tag) = buffer.take_one()?;

                    let msg = utf8(&msg)?;
                    let tag = utf8(&tag)?;
                    Some(Self::UserauthBanner { msg, tag })
                }
                SSH_MSG_DEBUG => {
                    let always_display = buffer.take_u8()? != 0;
                    let (_, msg) = buffer.take_one()?;
                    let (_, tag) = buffer.take_one()?;

                    let msg = utf8(&msg)?;
                    let tag = utf8(&tag)?;

                    Some(Self::Debug {
                        always_display,
                        msg,
                        tag,
                    })
                }
                SSH_MSG_DISCONNECT => {
                    let reason = DisconnectReson(buffer.take_u32()?);

                    let (_, description) = buffer.take_one()?;

                    let (_, tag) = buffer.take_one()?;

                    let description = utf8(&description)?;
                    let tag = utf8(&tag)?;

                    Some(Self::Disconnect {
                        reason,
                        description,
                        tag,
                    })
                }
                SSH_MSG_IGNORE => Some(Self::Ignore(buffer.take_one()?.1)),
                _ => {
                    detail = format!("unknown code: {code} datalen: {}", buffer.len());
                    None
                }
            }
        };

        func().ok_or(detail)
    }
}

#[derive(new)]
pub struct Session {
    sender: Sender<Request>,
}

impl Session {
    async fn send_request(&mut self, msg: Request) -> Result<()> {
        self.sender.send(msg).await.map_err(|_| Error::Disconnect)
    }

    // pub async fn channel_stdout_read(&mut self, channel: &mut Channel) -> Result<Vec<u8>> {
    //     channel.stdout.recv().await.map_err(|_| Error::Disconnect)
    // }

    pub async fn sftp_open(&mut self) -> Result<Sftp> {
        let (sender, recver) = async_channel::bounded(1);
        self.send_request(Request::SFtpOpen {
            session: self.sender.clone(),
            sender,
        })
        .await?;

        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn channel_open_default(&mut self) -> Result<Channel> {
        self.channel_open(1024 * 1024, 32768).await
    }

    pub async fn channel_open(&mut self, initial: u32, maximum: u32) -> Result<Channel> {
        let (sender, recver) = async_channel::bounded(1);
        let msg = Request::ChannelOpenSession {
            initial,
            maximum,
            session: self.sender.clone(),
            sender,
        };

        self.send_request(msg).await?;

        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn userauth_none(&mut self, username: impl Into<String>) -> Result<Userauth> {
        let username = username.into();

        let (sender, recver) = async_channel::bounded(1);

        let requset = Request::UserauthNone { username, sender };

        self.send_request(requset).await?;

        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn userauth_publickey(
        &mut self,
        username: impl Into<String>,
        method: impl Into<String>,
        publickey: impl Into<Vec<u8>>,
        privatekey: impl Into<Vec<u8>>,
    ) -> Result<Userauth> {
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::UserauthPublickey {
            username: username.into(),
            method: method.into(),
            publickey: publickey.into(),
            privatekey: privatekey.into(),
            sender,
        };
        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn userauth_password(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Userauth> {
        let username = username.into();
        let password = password.into();

        let (sender, recver) = async_channel::bounded(1);

        let request = Request::UserAuthPassWord {
            username,
            password,
            sender,
        };

        self.sender
            .send(request)
            .await
            .map_err(|_| Error::Disconnect)?;
        let auth = recver.recv().await.map_err(|_| Error::Disconnect)?;

        auth
    }

    pub async fn handshake<T>(mut config: super::handshake::Config, socket: T) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut socket = PlainStream::new(socket);
        socket.client.ext = config.ext;
        socket.client.kex_strict = config.key_strict;

        // let (banner, _) = socket.banner_exchange(config.banner.as_str()).await?;
        // let meex = socket.method_exchange(&config).await?;

        let (banner, _) =
            super::handshake::banner_exchange(&mut socket, &config.banner.as_str()).await?;
        let meex = super::handshake::method_exchange(&mut socket, &config).await?;

        // socket.kex_strict = config.key_strict && meex.server.1.kex_strict;
        socket.server.kex_strict = meex.server.methods.kex_strict;
        socket.server.ext = meex.server.methods.ext;
        let mut algo = super::handshake::match_method(
            &meex.client.methods,
            &meex.server.methods,
            &mut config,
        )?;

        // let client_banner = self.client_info.banner.clone().unwrap();
        // let clienet_kexinit = self.client_info.kex.clone().unwrap();

        // let server_banner = self.server_info.banner.clone().unwrap();
        // let server_kexinit = self.server_info.kex.clone().unwrap();

        // let stream: Box<dyn SshStream> = Box::new(&mut socket);
        let dhconfig = Dependency::new(
            config.banner.clone(),
            meex.client.binary,
            banner.clone(),
            meex.server.binary,
            socket.client.kex_strict && socket.server.kex_strict,
        );

        let mut result = algo.kex.kex(dhconfig, &mut socket).await?;

        algo.hostkey.initialize(&result.server_hostkey)?;

        let res = algo
            .hostkey
            .verify(&result.server_signature, &result.client_signature)?;

        if !res {
            return Err(Error::HostKeyVerifyFailed);
        }
        super::handshake::new_keys(&mut socket).await?;

        algo.initialize(&mut result)?;

        let (sender, recver) = async_channel::unbounded();

        let session = Session::new(sender);

        let stream = socket.encrypt(
            (algo.client_crypt, algo.client_mac, algo.client_compress),
            (algo.server_crypt, algo.server_mac, algo.server_compress),
        );
        let mut inner = SessionInner::new(
            result.session_id,
            stream,
            Endpoint::new(config.banner),
            Endpoint::new(banner),
            recver,
            HashMap::new(),
        );
        inner.request_userauth_service().await?;
        inner.run();
        Ok(session)
    }
}

#[derive(new)]
pub struct SessionInner<T: AsyncRead + AsyncWrite + Unpin + Send> {
    session_id: Vec<u8>,
    stream: CipherStream<T>,
    _client: Endpoint,
    _server: Endpoint,
    recver: Receiver<Request>,
    channels: HashMap<u32, ChannelInner>,
}

fn parse_error<T>(opt: Option<T>) -> Result<T> {
    opt.ok_or(Error::invalid_format("unable to parse a ssh packet"))
}

impl<T> SessionInner<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn run(mut self) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    request = self.recver.recv() => {
                        let Ok(request) = request else {
                            break;
                        };
                        self.handle_request(request).await;
                    }
                    packet = self.stream.recv_packet() => {
                        let msg = ServerMessage::parse(packet?.payload).map_err(Error::invalid_format)?;
                        self.handle_msg(msg).await?;
                    }
                }
            }
            Result::Ok(())
        });
    }

    fn genarate_channel_id(&mut self) -> u32 {
        let mut next = 0;
        for (_, channel) in self.channels.iter() {
            if channel.server.closed == false || channel.client.closed == false {
                if next <= channel.client.id {
                    next = channel.client.id + 1;
                }
            }
        }

        next
    }

    async fn request_userauth_service(&mut self) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_SERVICE_REQUEST);
        buffer.put_one(b"ssh-userauth");

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            let msg = self.recv_msg().await?;
            if let ServerMessage::UserauthServiceAccept = msg {
                return Ok(());
            }

            self.handle_msg(msg).await?;
        }
    }

    async fn recv_msg(&mut self) -> Result<ServerMessage> {
        let packet = self.stream.recv_packet().await?;
        ServerMessage::parse(packet.payload).map_err(Error::invalid_format)
    }

    async fn handle_msg(&mut self, msg: ServerMessage) -> Result<()> {
        // println!("handle message: {:?}", msg);
        match msg {
            ServerMessage::ChannelStdoutData { recipient, data } => {
                self.append_channel_stdout(recipient, data).await?;
            }
            ServerMessage::ChannelWindowAdjust { recipient, count } => {
                self.add_channel_bytes_count(recipient, count);
            }
            ServerMessage::ChannelStderrData { recipient, data } => {
                self.append_channel_stderr(recipient, data).await?;
            }
            ServerMessage::ChannelEof(recipient) => {
                self.set_channel_eof(recipient, true);
            }
            ServerMessage::ChannelClose(recipient) => {
                self.handle_channel_close(recipient).await?;
            }
            ServerMessage::ChannelExitSignal {
                recipient,
                signal,
                core_dumped,
                error_msg,
                ..
            } => {
                let channel = self.get_server_channel(recipient)?;

                channel.exit_status =
                    Some(ExitStatus::new_interrupt(signal, core_dumped, error_msg));
            }
            ServerMessage::ChannelExitStatus { recipient, status } => {
                let channel = self.get_server_channel(recipient)?;
                channel.exit_status = Some(ExitStatus::new_normal(status));
            }
            _ => {}
        }

        Ok(())
    }

    fn set_channel_eof(&mut self, id: u32, eof: bool) -> bool {
        let Some(channel) = self.channels.get_mut(&id) else {
            return false;
        };

        channel.server.eof = eof;

        true
    }

    fn add_channel_bytes_count(&mut self, recipeint: u32, count: u32) -> bool {
        if let Some(channel) = self.channels.get_mut(&recipeint) {
            channel.server.size += count;
            true
        } else {
            false
        }
    }

    async fn channel_window_adjust(
        stream: &mut CipherStream<T>,
        channel: &mut ChannelInner,
        count: u32,
    ) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        buffer.put_u32(channel.server.id);
        buffer.put_u32(count);
        stream.send_payload(buffer.as_ref()).await?;
        channel.client.size += count;
        Ok(())
    }

    async fn append_channel_stderr(&mut self, recipient: u32, data: Vec<u8>) -> Result<bool> {
        if let Some(channel) = self.channels.get_mut(&recipient) {
            channel.client.size -= data.len() as u32;

            let value = channel.subsystem.append_stderr(&data).await.is_ok();
            if channel.client.size < channel.client.maximum {
                Self::channel_window_adjust(
                    &mut self.stream,
                    channel,
                    channel.client.initial - channel.client.size,
                )
                .await?;
            }
            Ok(value)
        } else {
            Ok(false)
        }
    }

    async fn append_channel_stdout(&mut self, recipient: u32, data: Vec<u8>) -> Result<bool> {
        if let Some(channel) = self.channels.get_mut(&recipient) {
            channel.client.size -= data.len() as u32;
            let value = channel.subsystem.append_stdout(&data).await.is_ok();
            if channel.client.size < channel.client.maximum {
                Self::channel_window_adjust(
                    &mut self.stream,
                    channel,
                    channel.client.initial - channel.client.size,
                )
                .await?;
            }
            Ok(value)
        } else {
            Ok(false)
        }
    }

    async fn handle_request(&mut self, request: Request) {
        match request {
            Request::UserAuthPassWord {
                username,
                password,
                sender,
            } => {
                let res = self.userauth_password(&username, &password).await;
                let _ = sender.send(res).await;
            }
            Request::ChannelOpenSession {
                initial,
                maximum,
                session,
                sender,
            } => {
                let res = self.channel_open_session(initial, maximum, session).await;

                let _ = sender.send(res).await;
            }
            Request::ChannelExec { id, cmd, sender } => {
                let res = self.channel_exec(id, &cmd).await;
                let _ = sender.send(res).await;
            }
            Request::ChannelDrop { id, sender } => {
                let res = self.channel_drop(id).await;
                let _ = sender.send(res).await;
            }
            Request::ChannelWriteStdout { id, data, sender } => {
                let res = self.channel_write_stdout(id, &data).await;

                let _ = sender.send(res).await;
            }
            Request::SFtpOpen { session, sender } => {
                let res = self.sftp_open(2 * 1024 * 1024, 32768, session).await;

                let _ = sender.send(res).await;
            }
            Request::UserauthNone { username, sender } => {
                let res = self.userauth_none(&username).await;
                let _ = sender.send(res).await;
            }
            Request::UserauthPublickey {
                username,
                method,
                publickey,
                privatekey,
                sender,
            } => {
                let res = self
                    .userauth_publickey(&username, &method, &publickey, &privatekey)
                    .await;
                let _ = sender.send(res).await;
            }
            Request::ChannelExecWait { id, cmd, sender } => {
                let res = self.channel_exec_wait(id, &cmd).await;

                let _ = sender.send(res).await;
            }
            Request::ChannelGetExitStatus { id, sender } => {
                let res = self.wait_for_finish(id).await;

                let _ = sender.send(res).await;
            }
            Request::ChannelEof { id, sender } => {
                let res = self.channel_eof(id).await;

                let _ = sender.send(res).await;
            }
            Request::ChannelSetEnv {
                id,
                name,
                value,
                sender,
            } => {
                let res = self.channel_set_env(id, &name, &value).await;
                let _ = sender.send(res).await;
            }
            Request::ChannelSendSignal { id, signal, sender } => {
                let res = self.channel_send_signal(id, &signal.0).await;
                let _ = sender.send(res).await;
            },
        }
    }

    async fn channel_send_signal(&mut self, id: u32, signal: &str) -> Result<()> {
        let mut buffer = Buffer::new();

        let server_id = self.get_server_channel_id(id)?;
        buffer.put_u32(server_id);
        buffer.put_one("signal");
        buffer.put_u8(0);
        buffer.put_one(signal);

        self.stream.send_payload(buffer.as_ref()).await
    }
    async fn channel_set_env(&mut self, id: u32, name: &str, value: &[u8]) -> Result<()> {
        let mut buffer = Buffer::new();

        let server_id = self.get_server_channel_id(id)?;
        buffer.put_u32(server_id);

        buffer.put_one("env");
        buffer.put_u8(1);
        buffer.put_one(name);
        buffer.put_one(value);

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            let msg = self.recv_msg().await?;

            return match msg {
                ServerMessage::ChannelSuccess(recipient) if recipient == id => Ok(()),
                ServerMessage::ChannelFailure(recipient) if recipient == id => {
                    Err(Error::ChannelFailure)
                }
                msg => {
                    self.handle_msg(msg).await?;
                    continue;
                }
            };
        }
    }

    async fn wait_for_finish(&mut self, id: u32) -> Result<ExitStatus> {
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("failed to find channel"))?;

        if let Some(ref exit_status) = channel.exit_status {
            return Ok(exit_status.clone());
        }

        let status = loop {
            let msg = self.recv_msg().await?;
            match msg {
                ServerMessage::ChannelExitStatus { recipient, status } if id == recipient => {
                    break ExitStatus::Normal(status);
                }
                ServerMessage::ChannelExitSignal {
                    recipient,
                    signal,
                    core_dumped,
                    error_msg,
                    ..
                } if recipient == id => {
                    break ExitStatus::Interrupt {
                        signal,
                        core_dumped,
                        error_msg,
                    };
                }

                msg => {
                    self.handle_msg(msg).await?;
                }
            }
        };

        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("failed to find channel"))?;

        channel.exit_status = Some(status.clone());

        Ok(status)
    }

    async fn channel_exec_wait(&mut self, id: u32, cmd: &str) -> Result<ExitStatus> {
        self.channel_exec(id, cmd).await?;

        loop {
            let msg = self.recv_msg().await?;
            match msg {
                ServerMessage::ChannelExitStatus { recipient, status } if id == recipient => {
                    return Ok(ExitStatus::Normal(status));
                }
                ServerMessage::ChannelExitSignal {
                    recipient,
                    signal,
                    core_dumped,
                    error_msg,
                    ..
                } if recipient == id => {
                    return Ok(ExitStatus::Interrupt {
                        signal,
                        core_dumped,
                        error_msg,
                    });
                }

                msg => {
                    self.handle_msg(msg).await?;
                }
            }
        }
    }

    async fn channel_write_stdout(&mut self, id: u32, data: &[u8]) -> Result<usize> {
        // let (channel, stream) = func(self)?;
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("failed to find channel"))?;

        if channel.client.closed || channel.server.closed {
            return Err(Error::ChannelClosed);
        }

        if channel.client.eof {
            return Err(Error::ChannelEof);
        }

        if channel.server.size == 0 || data.is_empty() {
            return Ok(0);
        }

        let mut buffer = Buffer::new();

        buffer.put_u8(SSH_MSG_CHANNEL_DATA);

        buffer.put_u32(channel.server.id);

        let len = if channel.server.size as usize >= data.len() {
            data.len()
        } else {
            channel.server.size as _
        };

        buffer.put_one(&data[..len]);

        self.stream.send_payload(buffer.as_ref()).await?;

        channel.server.size -= len as u32;

        Ok(len)
    }

    async fn channel_drop(&mut self, id: u32) -> Result<()> {
        let mut channel = self.remove_channel(id)?;
        // let channel = self.channels.get_mut(&id).ok_or(Error::ChannelNotFound)?;

        if !channel.client.closed {
            if !channel.client.eof {
                let mut buffer = Buffer::new();
                buffer.put_u8(SSH_MSG_CHANNEL_EOF);
                buffer.put_u32(channel.server.id);
                self.stream.send_payload(buffer.as_ref()).await?;
                channel.client.eof = true;
            }

            let mut buffer = Buffer::new();
            buffer.put_u8(SSH_MSG_CHANNEL_CLOSE);
            buffer.put_u32(channel.server.id);

            self.stream.send_payload(buffer.as_ref()).await?;
            channel.client.closed = true;
        }

        if !channel.server.closed {
            self.channels.insert(id, channel);
        }

        Ok(())
    }

    async fn channel_eof(&mut self, id: u32) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("failed to find channel"))?;

        if channel.client.closed {
            return Ok(());
        }
        if channel.client.eof {
            return Ok(());
        }

        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_CHANNEL_EOF);
        buffer.put_u32(channel.server.id);

        self.stream.send_payload(buffer.as_ref()).await?;

        channel.client.eof = true;
        Ok(())
    }

    async fn handle_channel_close(&mut self, id: u32) -> Result<()> {
        let mut channel = self.remove_channel(id)?;

        channel.server.closed = true;

        if !channel.client.closed {
            if !channel.client.eof {
                let mut buffer = Buffer::new();
                buffer.put_u8(SSH_MSG_CHANNEL_EOF);
                buffer.put_u32(channel.server.id);
                self.stream.send_payload(buffer.as_ref()).await?;
                channel.client.eof = true;
            }
            let mut buffer = Buffer::new();
            buffer.put_u8(SSH_MSG_CHANNEL_CLOSE);
            buffer.put_u32(channel.server.id);

            self.stream.send_payload(buffer.as_ref()).await?;

            channel.client.closed = true;
            self.channels.insert(id, channel);
        }

        Ok(())
    }

    fn remove_channel(&mut self, id: u32) -> Result<ChannelInner> {
        self.channels
            .remove(&id)
            .ok_or(Error::ub("failed to find channel"))
    }

    fn get_server_channel_id(&mut self, id: u32) -> Result<u32> {
        self.channels
            .get(&id)
            .map(|v| v.server.id)
            .ok_or(Error::ub("failed to find channel"))
    }

    fn get_server_channel(&mut self, id: u32) -> Result<&mut ChannelInner> {
        self.channels
            .get_mut(&id)
            .ok_or(Error::ub("failed to find channel"))
    }

    async fn channel_exec(&mut self, id: u32, cmd: &str) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_CHANNEL_REQUEST);
        buffer.put_u32(self.get_server_channel_id(id)?);
        buffer.put_one(b"exec");
        buffer.put_u8(1);
        buffer.put_one(cmd.as_bytes());

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            let msg = self.recv_msg().await?;
            return match msg {
                ServerMessage::ChannelSuccess(recipient) if recipient == id => Ok(()),
                ServerMessage::ChannelFailure(recipient) if recipient == id => {
                    Err(Error::ChannelFailure)
                }
                _ => {
                    self.handle_msg(msg).await?;
                    continue;
                }
            };
        }
    }

    async fn channel_open_raw(
        &mut self,
        initial: u32,
        maximum: u32,
    ) -> Result<(ChannelEndpoint, ChannelEndpoint)> {
        let mut buffer = Buffer::new();
        let client_id = self.genarate_channel_id();
        buffer.put_u8(SSH_MSG_CHANNEL_OPEN);
        buffer.put_one(b"session");
        buffer.put_u32(client_id);
        buffer.put_u32(initial);
        buffer.put_u32(maximum);

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            let msg = self.recv_msg().await?;
            return match msg {
                ServerMessage::ChannelOpenFailure {
                    recipient,
                    reson,
                    desc,
                    ..
                } if recipient == client_id => Err(Error::ChannelOpenFail(reson, desc)),
                ServerMessage::ChannelOpenConfirmation {
                    recipient,
                    sender,
                    initial: server_initial,
                    maximum: server_maximum,
                } if recipient == client_id => Ok((
                    ChannelEndpoint::new(client_id, initial, maximum),
                    ChannelEndpoint::new(sender, server_initial, server_maximum),
                )),

                _ => {
                    self.handle_msg(msg).await?;
                    continue;
                }
            };
        }
    }

    // async fn channel_open<B: SubSystem + Send + 'static>(
    //     &mut self,
    //     initial: u32,
    //     maximum: u32,
    //     subsystem: B,
    // ) -> Result<()> {
    //     let (client, server) = self.channel_open_raw(initial, maximum).await?;

    //     let inner = ChannelInner::new(client, server, Box::new(subsystem), None);

    //     self.channels.insert(inner.client.id, inner);

    //     Ok(())
    // }

    async fn channel_open_normal(
        &mut self,
        initial: u32,
        maximum: u32,
        session: Sender<Request>,
    ) -> Result<(Channel, ChannelInner)> {
        let (client, server) = self.channel_open_raw(initial, maximum).await?;

        let stdout = async_channel::unbounded();
        let stderr = async_channel::unbounded();

        let channel = Channel::new(client.id, stdout.1, stderr.1, session);

        let inner = ChannelInner::new(
            client,
            server,
            Box::new(NormalChannel::new(stdout.0, stderr.0)),
            None,
        );

        Ok((channel, inner))
    }

    async fn channel_open_session(
        &mut self,
        initial: u32,
        maximum: u32,
        session: Sender<Request>,
    ) -> Result<Channel> {
        let (channel, inner) = self.channel_open_normal(initial, maximum, session).await?;

        self.channels.insert(channel.id, inner);

        Ok(channel)
    }

    async fn userauth_none(&mut self, username: &str) -> Result<Userauth> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_USERAUTH_REQUEST);
        buffer.put_one(username);
        buffer.put_one(b"ssh-connection");
        buffer.put_one(b"none");

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            return match self.recv_msg().await? {
                ServerMessage::UserauthSuccess => {
                    self.stream.authed = true;
                    Ok(Userauth::Success)
                }
                ServerMessage::UserauthFailure { methods, .. } => Ok(Userauth::Failure(methods)),
                ServerMessage::UserauthChangeReq => Ok(Userauth::Failure(vec![])),

                msg => {
                    self.handle_msg(msg).await?;
                    continue;
                }
            };
        }
    }

    async fn userauth_password(&mut self, username: &str, password: &str) -> Result<Userauth> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_USERAUTH_REQUEST);
        buffer.put_one(username);
        buffer.put_one(b"ssh-connection");
        buffer.put_one(b"password");
        buffer.put_u8(0);
        buffer.put_one(password);

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            return match self.recv_msg().await? {
                ServerMessage::UserauthSuccess => {
                    self.stream.authed = true;
                    Ok(Userauth::Success)
                }
                ServerMessage::UserauthFailure { methods, .. } => Ok(Userauth::Failure(methods)),
                ServerMessage::UserauthChangeReq => Ok(Userauth::Expired),

                msg => {
                    self.handle_msg(msg).await?;
                    continue;
                }
            };
        }
    }

    async fn userauth_publickey(
        &mut self,
        username: &str,
        method: &str,
        publickey: &[u8],
        privatekey: &[u8],
    ) -> Result<Userauth> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_USERAUTH_REQUEST);
        buffer.put_one(username);
        buffer.put_one(b"ssh-connection");
        buffer.put_one("publickey");
        buffer.put_u8(0);
        buffer.put_one(method);
        // buffer.put_u32((4 + method.len() + 4 + publickey.len()) as u32);
        // buffer.put_one(method);
        buffer.put_one(publickey);

        self.stream.send_payload(buffer.as_ref()).await?;


        loop {
            let packet = self.stream.recv_packet().await?;
            let mut payload = Buffer::from_vec(packet.payload.clone());
            let code = payload.take_u8().ok_or(Error::invalid_format("invalid ssh packet"))?;
            match code {
                SSH_MSG_USERAUTH_FAILURE => {
                    let (_, methods) = payload.take_one().ok_or(Error::invalid_format("invalid ssh packet"))?;
                    return Ok(Userauth::Failure(
                        String::from_utf8(methods)?
                            .split(",")
                            .map(|v| v.to_string())
                            .collect(),
                    ));
                }
                SSH_MSG_USERAUTH_SUCCESS => return Ok(Userauth::Success),
                SSH_MSG_USERAUTH_PK_OK => break,
                _ => {
                    self.handle_msg(
                        ServerMessage::parse(packet.payload).map_err(Error::invalid_format)?,
                    )
                    .await?;
                }
            }
        }


        let mut buffer = Buffer::new();
        buffer.put_one(&self.session_id);
        buffer.put_u8(SSH_MSG_USERAUTH_REQUEST);
        buffer.put_one(username);
        buffer.put_one(b"ssh-connection");
        buffer.put_one("publickey");
        buffer.put_u8(1);
        buffer.put_one(method);
        // buffer.put_u32((4 + method.len() + 4 + publickey.len()) as u32);
        // buffer.put_one(method);
        buffer.put_one(publickey);

        let mut algo = sign::new_signature_by_name(method)
            .ok_or(Error::ub("unable to create cipher"))?
            .create();

        algo.initialize(privatekey.as_ref())?;
        let sign = algo.signature(buffer.as_ref())?;

        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_USERAUTH_REQUEST);
        buffer.put_one(username);
        buffer.put_one(b"ssh-connection");
        buffer.put_one("publickey");
        buffer.put_u8(1);
        buffer.put_one(method);
        // buffer.put_u32((4 + method.len() + 4 + publickey.len()) as u32);
        // buffer.put_one(method);
        buffer.put_one(publickey);

        buffer.put_u32((4 + method.len() + 4 + sign.len()) as _);

        buffer.put_one(method);
        buffer.put_one(sign);

        self.stream.send_payload(buffer.as_ref()).await?;

        loop {
            match self.recv_msg().await? {
                ServerMessage::UserauthSuccess => {
                    self.stream.authed = true;
                    break Ok(Userauth::Success);
                }
                ServerMessage::UserauthFailure { methods, .. } => {
                    break Ok(Userauth::Failure(methods));
                }
                msg => {
                    self.handle_msg(msg).await?;
                }
            }
        }
    }

    async fn sftp_open(
        &mut self,
        initial: u32,
        maximum: u32,
        session: Sender<Request>,
    ) -> Result<Sftp> {
        // let (channel, inner) = self.channel_open_normal(initial, maximum, session).await?;

        let (client, server) = self.channel_open_raw(initial, maximum).await?;

        let server_id = server.id;
        let client_id = client.id;

        // self.channels.insert(channel.id, inner);

        let (sender, recver) = async_channel::unbounded();

        let sub = SFtpSystem::new(sender);

        let inner = ChannelInner::new(client, server, Box::new(sub), None);

        self.channels.insert(client_id, inner);

        let func = async {
            let mut buffer = Buffer::new();

            buffer.put_u8(SSH_MSG_CHANNEL_REQUEST);
            buffer.put_u32(server_id);
            buffer.put_one(b"subsystem");
            buffer.put_u8(1);
            buffer.put_one(b"sftp");

            self.stream.send_payload(buffer.as_ref()).await?;

            loop {
                match self.recv_msg().await? {
                    ServerMessage::ChannelSuccess(_) => break,
                    ServerMessage::ChannelFailure(_) => return Err(Error::SubsystemFailed),
                    msg => {
                        self.handle_msg(msg).await?;
                    }
                }
            }

            let mut buffer = Buffer::new();
            // buffer.put_u8(SSH_MSG_CHANNEL_DATA);
            // buffer.put_u32(server_id);
            // buffer.put_u32(4 + 1 + 4);
            buffer.put_u32(5);
            buffer.put_u8(SSH_FXP_INIT);
            buffer.put_u32(SFTP_VERSION);

            // self.stream.send_payload(buffer.as_ref()).await?;

            let size = self
                .channel_write_stdout(client_id, buffer.as_ref())
                .await?;

            if size < buffer.len() {
                return Err(Error::TemporarilyUnavailable);
            }

            loop {
                let msg = self.recv_msg().await?;
                match msg {
                    ServerMessage::ChannelStdoutData { recipient, data }
                        if recipient == client_id =>
                    {
                        let mut data = Buffer::from_vec(data);

                        let (_, data) = parse_error(data.take_one())?;

                        let mut data = Buffer::from_vec(data);

                        let value = parse_error(data.take_u8())?;

                        if value != SSH_FXP_VERSION {
                            return Err(Error::UnexpectMsg);
                        }

                        let version = parse_error(data.take_u32())?;

                        let mut ext = || {
                            let Some((_, key)) = data.take_one() else {
                                return Ok(None);
                            };

                            let key = String::from_utf8(key)?;

                            let (_, value) = data
                                .take_one()
                                .ok_or(Error::invalid_format("could't parse value"))?;

                            Result::Ok(Some((key, value)))
                        };

                        let mut extension = HashMap::new();
                        while let Some((k, v)) = ext()? {
                            extension.insert(k, v);
                        }

                        break Ok(Sftp::new(
                            session.clone(),
                            client_id,
                            0,
                            version,
                            recver,
                            extension,
                        ));
                    }
                    msg => {
                        self.handle_msg(msg).await?;
                        continue;
                    }
                }
            }
        };

        let res = func.await;

        if res.is_err() {
            self.channels.remove(&client_id);
        }

        res

        // Ok(())
    }
}
