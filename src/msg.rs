use async_channel::Sender;
use derive_new::new;
use super::error::Result;
use crate::ssh::buffer::Buffer;
use super::sftp::SFtp;
use super::channel::Channel;
use super::ssh::common::code::*;

#[derive(Debug)]
pub enum Userauth {
    Success,
    Failure(Vec<String>),
    Expired,
}

pub(crate) enum Request {
    SessionDrop {
        reson: DisconnectReson,
        desc: String,
    },
    UserAuthPassWord {
        username: String,
        password: String,
        sender: Sender<Result<Userauth>>,
    },
    UserauthPublickey {
        username: String,
        method: String,
        publickey: Vec<u8>,
        privatekey: Vec<u8>,
        sender: Sender<Result<Userauth>>,
    },
    UserauthNone {
        username: String,
        sender: Sender<Result<Userauth>>,
    },
    ChannelOpenSession {
        initial: u32,
        maximum: u32,
        session: Sender<Request>,
        sender: Sender<Result<Channel>>,
    },
    ChannelExec {
        id: u32,
        cmd: String,
        sender: Sender<Result<()>>,
    },
    ChannelExecWait {
        id: u32,
        cmd: String,
        sender: Sender<Result<ExitStatus>>,
    },
    ChannelGetExitStatus {
        id: u32,
        sender: Sender<Result<ExitStatus>>,
    },
    ChannelDrop {
        id: u32,
        sender: Option<Sender<Result<()>>>,
    },
    ChannelWriteStdout {
        id: u32,
        data: Vec<u8>,
        sender: Sender<Result<usize>>,
    },
    ChannelSetEnv {
        id: u32,
        name: String,
        value: Vec<u8>,
        sender: Sender<Result<()>>,
    },
    ChannelSendSignal {
        id: u32,
        signal: Signal,
        sender: Sender<Result<()>>,
    },
    ChannelEof {
        id: u32,
        sender: Sender<Result<()>>
    },
    SFtpOpen {
        session: Sender<Request>,
        sender: Sender<Result<SFtp>>,
    },
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug)]
pub(crate) enum Message {
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
    Ping(Vec<u8>)
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

impl Message {
    pub fn parse(payload: impl Into<Vec<u8>>) -> std::result::Result<Self, String> {
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
                SSH2_MSG_PING => Some(Self::Ping(buffer.take_one()?.1)),
                _ => {
                    detail = format!("unknown code: {code} datalen: {}", buffer.len());
                    None
                }
            }
        };

        func().ok_or(detail)
    }
}
