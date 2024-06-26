use std::collections::HashMap;

use super::channel::{Channel, ChannelOpenFailureReson, Signal};
use super::error::Result;
use super::session::{DisconnectReson, Userauth};
use super::sftp::SFtp;
use super::ssh::common::code::*;
use super::OSender;
use crate::channel::TerminalMode;
use crate::forward::{Listener, SocketAddr};
use crate::session::Interactive;
use crate::ssh::buffer::Buffer;

#[derive(custom_debug_derive::Debug)]
pub(crate) enum Request {
    SessionDrop {
        reson: DisconnectReson,
        desc: String,
        #[debug(skip)]
        sender: Option<OSender<Result<()>>>,
    },
    UserAuthPassWord {
        username: String,
        password: String,
        #[debug(skip)]
        sender: OSender<Result<Userauth>>,
    },
    UserauthPublickey {
        username: String,
        method: String,
        publickey: Vec<u8>,
        privatekey: Vec<u8>,
        #[debug(skip)]
        sender: OSender<Result<Userauth>>,
    },
    UserauthNone {
        username: String,
        #[debug(skip)]
        sender: OSender<Result<Userauth>>,
    },
    UserauthKeyboardInteractive {
        username: String,
        submethods: Vec<String>,
        #[debug(skip)]
        cb: Box<dyn Interactive>,
        #[debug(skip)]
        sender: OSender<Result<bool>>,
    },
    ChannelOpenSession {
        initial: u32,
        maximum: u32,
        #[debug(skip)]
        sender: OSender<Result<Channel>>,
    },
    ChannelExec {
        id: u32,
        cmd: String,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    TcpipForward {
        address: SocketAddr,
        // port: u32,
        initial: u32,
        maximum: u32,
        #[debug(skip)]
        sender: OSender<Result<Listener>>,
    },
    CancelTcpipForward {
        address: SocketAddr,
        // port: u32,
        #[debug(skip)]
        sender: Option<OSender<Result<()>>>,
    },
    DirectTcpip {
        initial: u32,
        maximum: u32,
        remote: SocketAddr,
        local: SocketAddr,
        #[debug(skip)]
        sender: OSender<Result<Channel>>,
    },
    // ChannelExecWait {
    //     id: u32,
    //     cmd: String,
    //     sender: OSender<Result<ExitStatus>>,
    // },
    // ChannelGetExitStatus {
    //     id: u32,
    //     sender: OSender<Result<ExitStatus>>,
    // },
    ChannelDrop {
        id: u32,
        #[debug(skip)]
        sender: Option<OSender<Result<()>>>,
    },
    ChannelWriteStdout {
        id: u32,
        #[debug(skip)]
        data: Vec<u8>,
        #[debug(skip)]
        sender: OSender<Result<usize>>,
    },
    ChannelSetEnv {
        id: u32,
        name: String,
        value: Vec<u8>,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    ChannelSendSignal {
        id: u32,
        signal: Signal,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    ChannelEof {
        id: u32,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    ChannelReuqestShell {
        id: u32,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    ChannelRequestPty {
        id: u32,
        term: String,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        terimal_modes: Vec<(TerminalMode, u32)>,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    ChannelPtyChangeSize {
        id: u32,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    SFtpFromChannel {
        #[debug(skip)]
        channel: Channel,
        #[debug(skip)]
        sender: OSender<Result<SFtp>>,
    },
    SFtpOpen {
        initial: u32,
        maximum: u32,
        #[debug(skip)]
        sender: OSender<Result<SFtp>>,
    },
    X11Forward {
        id: u32,
        single_connection: bool,
        protocol: String,
        cookie: String,
        screen_number: u32,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    XonXoff {
        id: u32,
        allow: bool,
        #[debug(skip)]
        sender: OSender<Result<()>>,
    },
    KeyReExchange(OSender<Result<()>>),
}

#[derive(custom_debug_derive::Debug)]
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
    HostKeysOpenSSH {
        want_reply: bool,
        hostkeys: Vec<Vec<u8>>,
    },
    ChannelOpenFailure {
        recipient: u32,
        reson: ChannelOpenFailureReson,
        desc: String,
        _tag: String,
    },
    ChannelOpenConfirmation {
        recipient: u32,
        sender: u32,
        initial: u32,
        maximum: u32,
    },
    ChannelStdoutData {
        recipient: u32,
        #[debug(skip)]
        data: Vec<u8>,
    },
    ChannelStderrData {
        recipient: u32,
        #[debug(skip)]
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
    Ping(Vec<u8>),
    GlobalKeepAliveOpenSSH {
        want_reply: bool,
    },
    ChannelKeepAliveOpenSSH {
        recipient: u32,
        want_reply: bool,
    },
    ForwardTcpIp {
        sender: u32,
        initial: u32,
        maximum: u32,
        listen_address: String,     // connected address
        listen_port: u32,           // connected port
        originator_address: String, // originator IP address
        originator_port: u32,       // originator port
    },
    X11Forward {
        sender: u32,
        initial: u32,
        maximum: u32,
        address: String,
        port: u32,
    },
    ExtInfo(HashMap<String, Vec<u8>>),
    KexIntial(Vec<u8>),
}

impl Message {
    pub fn parse(payload: &[u8]) -> std::result::Result<Self, String> {
        let buffer = Buffer::from_slice(payload);

        let mut detail = "Unable to parse a server message".to_string();

        let mut func = || {
            let mut utf8 = |data: &[u8]| {
                let str = String::from_utf8(data.to_vec());
                match str {
                    Ok(str) => Some(str),
                    Err(_) => {
                        detail = "Unable to parse string as utf8".to_string();
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

                    let desc = utf8(desc)?;
                    let tag = utf8(tag)?;

                    Some(Self::ChannelOpenFailure {
                        recipient,
                        reson,
                        desc,
                        _tag: tag,
                    })
                }
                SSH_MSG_USERAUTH_SUCCESS => Some(Self::UserauthSuccess),
                SSH_MSG_USERAUTH_FAILURE => {
                    let (_, methods) = buffer.take_one()?;

                    let methods = utf8(methods)?.split(',').map(|v| v.to_owned()).collect();

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
                        let want_reply = buffer.take_u8()? != 0;

                        let mut hostkeys = vec![];
                        while buffer.len() != 0 {
                            hostkeys.push(buffer.take_one()?.1.to_vec());
                        }
                        Some(Self::HostKeysOpenSSH {
                            want_reply,
                            hostkeys,
                        })
                    } else if line == b"keepalive@openssh.com" {
                        Some(Self::GlobalKeepAliveOpenSSH {
                            want_reply: buffer.take_u8()? != 0,
                        })
                    } else {
                        detail = format!("Unknown global reqeust: {:?}", utf8(line)?);
                        // Err(Error::ssh_packet_parse(format!(
                        //     "unknown global reqeust: {:?}",
                        //     String::from_utf8(line)?
                        // )))
                        None
                    }
                }
                SSH_MSG_CHANNEL_DATA => {
                    let recipient = buffer.take_u32()?;

                    let data = buffer.take_one()?.1.to_vec();
                    Some(Self::ChannelStdoutData { recipient, data })
                }
                SSH_MSG_CHANNEL_EXTENDED_DATA => {
                    let recipient = buffer.take_u32()?;
                    let code = buffer.take_u32()?;
                    let len = buffer.take_u32()?;
                    let data = buffer.take_bytes(len as usize)?.to_vec();
                    if code == SSH_EXTENDED_DATA_STDERR {
                        Some(Self::ChannelStderrData { recipient, data })
                    } else {
                        detail = format!("Unknow data type code: {code}");
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
                        detail = "Unknown service name".to_string();
                        None
                    }
                }
                SSH_MSG_CHANNEL_REQUEST => {
                    let recipient = buffer.take_u32()?;

                    let (_, string) = buffer.take_one()?;

                    let want_reply = buffer.take_u8()? != 0;

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

                        let signal = Signal(utf8(signal)?);
                        let error_msg = utf8(error_msg)?;
                        let tag = utf8(tag)?;

                        Some(Self::ChannelExitSignal {
                            recipient,
                            signal,
                            core_dumped,
                            error_msg,
                            tag,
                        })
                    } else if string == b"keepalive@openssh.com" {
                        Some(Self::ChannelKeepAliveOpenSSH {
                            recipient,
                            want_reply,
                        })
                    } else {
                        detail = format!("Unimplement: {}", String::from_utf8_lossy(string));
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

                    let msg = utf8(msg)?;
                    let tag = utf8(tag)?;
                    Some(Self::UserauthBanner { msg, tag })
                }
                SSH_MSG_DEBUG => {
                    let always_display = buffer.take_u8()? != 0;
                    let (_, msg) = buffer.take_one()?;
                    let (_, tag) = buffer.take_one()?;

                    let msg = utf8(msg)?;
                    let tag = utf8(tag)?;

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

                    let description = utf8(description)?;
                    let tag = utf8(tag)?;

                    Some(Self::Disconnect {
                        reason,
                        description,
                        tag,
                    })
                }
                SSH_MSG_IGNORE => Some(Self::Ignore(buffer.take_one()?.1.to_vec())),
                SSH2_MSG_PING => Some(Self::Ping(buffer.take_one()?.1.to_vec())),
                SSH_MSG_CHANNEL_OPEN => {
                    let cmd = buffer.take_one()?.1;
                    if cmd == b"forwarded-tcpip" {
                        let sender = buffer.take_u32()?;
                        let initial = buffer.take_u32()?;
                        let maximum = buffer.take_u32()?;
                        let c_address = buffer.take_one()?.1;
                        let c_address = utf8(c_address)?;
                        let c_port = buffer.take_u32()?;

                        let o_address = buffer.take_one()?.1;
                        let o_address = utf8(o_address)?;
                        let o_port = buffer.take_u32()?;

                        Some(Self::ForwardTcpIp {
                            sender,
                            initial,
                            maximum,
                            listen_address: c_address,
                            listen_port: c_port,
                            originator_address: o_address,
                            originator_port: o_port,
                        })
                    } else if cmd == b"x11" {
                        let sender = buffer.take_u32()?;
                        let initial = buffer.take_u32()?;
                        let maximum = buffer.take_u32()?;
                        let address = buffer.take_one()?.1;
                        let port = buffer.take_u32()?;

                        let address = utf8(address)?;

                        Some(Self::X11Forward {
                            sender,
                            initial,
                            maximum,
                            address,
                            port,
                        })
                    } else {
                        detail = "Unimplemented".to_string();
                        None
                    }
                }
                SSH_MSG_EXT_INFO => {
                    let nr_extensions = buffer.take_u32()?;

                    let mut map = HashMap::new();
                    for _ in 0..nr_extensions {
                        let name = buffer.take_one()?.1;
                        let value = buffer.take_one()?.1;
                        map.insert(utf8(name)?, value.to_vec());
                    }

                    Some(Self::ExtInfo(map))
                }
                SSH_MSG_KEXDH_INIT => Some(Self::KexIntial(payload.to_vec())),
                _ => {
                    detail = format!("unknown code: {code} datalen: {}", buffer.len());
                    None
                }
            }
        };

        func().ok_or(detail)
    }
}
