use std::collections::HashMap;
use std::mem::ManuallyDrop;

use super::ssh::stream::CipherStream;

use crate::channel::ChannelInner;
use crate::channel::Endpoint as ChannelEndpoint;
use crate::cipher::kex::Dependency;

use crate::cipher::sign;

use crate::error::Error;
use crate::error::Result;

use crate::msg::DisconnectReson;
use crate::msg::ExitStatus;
use crate::sftp::SFtp;
use crate::ssh::buffer::Buffer;
use crate::ssh::common::code::*;
use crate::ssh::common::SFTP_VERSION;
use crate::utils::io_channel;

use super::channel::Channel;
use super::msg::Message;
use super::msg::Request;
use super::msg::Userauth;
use crate::ssh::stream::PlainStream;
use async_channel::{Receiver, Sender};
use derive_new::new;
use tokio::io::{AsyncRead, AsyncWrite};

macro_rules! channel_loop {
         ($sel:ident,$id:expr,$($e:pat $(if $c:expr )? => $h:expr,)*) => {
            loop {
                match $sel.recv_msg().await? {
                    Message::ChannelClose(recipient) if recipient == $id => {
                        $sel.handle_channel_close(recipient).await?;
                        return Err(Error::ChannelClosed);
                    }
                    $(
                        $e $( if $c )? => $h,
                    )*
                    msg => {
                        $sel.handle_msg(msg).await?;
                    }
                }
            }
        };
    }

#[derive(new)]
struct Endpoint {
    banner: String,
}

#[derive(new)]
pub struct Session {
    sender: ManuallyDrop<Sender<Request>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        let request = Request::SessionDrop {
            reson: DisconnectReson::BY_APPLICATION,
            desc: "exit".to_string(),
        };
        let _ = self.sender.send_blocking(request);
        self.manually_drop()
    }
}

impl Session {
    async fn send_request(&mut self, msg: Request) -> Result<()> {
        self.sender.send(msg).await.map_err(|_| Error::Disconnect)
    }

    fn manually_drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.sender) }
    }
    // pub async fn channel_stdout_read(&mut self, channel: &mut Channel) -> Result<Vec<u8>> {
    //     channel.stdout.recv().await.map_err(|_| Error::Disconnect)
    // }

    pub async fn disconnect_default(self) -> Result<()> {
        self.disconnect(DisconnectReson::BY_APPLICATION, "exit")
            .await
    }

    pub async fn disconnect(
        mut self,
        reson: DisconnectReson,
        desc: impl Into<String>,
    ) -> Result<()> {
        let request = Request::SessionDrop {
            reson,
            desc: desc.into(),
        };
        let res = self.send_request(request).await;

        self.manually_drop();
        std::mem::forget(self);

        res
    }

    pub async fn sftp_open(&mut self) -> Result<SFtp> {
        let (sender, recver) = async_channel::bounded(1);
        self.send_request(Request::SFtpOpen {
            session: (*self.sender).clone(),
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
            session: (*self.sender).clone(),
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
            .verify(&result.server_signature, &result.client_hash)?;

        if !res {
            return Err(Error::HostKeyVerifyFailed);
        }
        super::handshake::new_keys(&mut socket).await?;

        algo.initialize(&mut result)?;

        let (sender, recver) = async_channel::unbounded();

        let session = Session::new(ManuallyDrop::new(sender));

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
                            self.session_disconnect(DisconnectReson::BY_APPLICATION, "exit").await?;
                            break;
                        };
                        if self.handle_request(request).await {
                            break;
                        }
                    }
                    packet = self.stream.recv_packet() => {
                        let msg = Message::parse(packet?.payload).map_err(Error::invalid_format)?;
                        if self.handle_msg(msg).await? {
                            break;
                        }
                    }
                }
            }
            Result::Ok(())
        });
    }

    async fn session_disconnect(&mut self, reson: DisconnectReson, desc: &str) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_DISCONNECT);
        buffer.put_u32(reson.0);
        buffer.put_one(desc);
        buffer.put_u32(0);
        self.stream.send_payload(buffer.as_ref()).await
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
            if let Message::UserauthServiceAccept = msg {
                return Ok(());
            }

            self.handle_msg(msg).await?;
        }
    }

    async fn recv_msg(&mut self) -> Result<Message> {
        let packet = self.stream.recv_packet().await?;
        Message::parse(packet.payload).map_err(Error::invalid_format)
    }

    async fn handle_msg(&mut self, msg: Message) -> Result<bool> {
        // println!("handle message: {:?}", msg);
        match msg {
            Message::ChannelStdoutData { recipient, data } => {
                self.append_channel_stdout(recipient, data).await?;
            }
            Message::ChannelWindowAdjust { recipient, count } => {
                self.add_channel_bytes_count(recipient, count);
            }
            Message::ChannelStderrData { recipient, data } => {
                self.append_channel_stderr(recipient, data).await?;
            }
            Message::ChannelEof(recipient) => {
                self.set_channel_eof(recipient, true).await;
            }
            Message::ChannelClose(recipient) => {
                self.handle_channel_close(recipient).await?;
            }
            Message::ChannelExitSignal {
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
            Message::ChannelExitStatus { recipient, status } => {
                let channel = self.get_server_channel(recipient)?;
                channel.exit_status = Some(ExitStatus::new_normal(status));
            }
            Message::Disconnect { .. } => {
                return Ok(true);
            }
            Message::Ping(data) => {
                self.session_pong(data).await?;
            }
            _ => {}
        }

        Ok(false)
    }

    async fn session_pong(&mut self, data: Vec<u8>) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH2_MSG_PONG);
        buffer.put_one(data);

        self.stream.send_payload(buffer.as_ref()).await
    }

    async fn set_channel_eof(&mut self, id: u32, eof: bool) -> bool {
        let Some(channel) = self.channels.get_mut(&id) else {
            return false;
        };

        channel.server.eof = eof;
        channel.stderr.eof().await;
        channel.stdout.eof().await;

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

            let value = channel.stderr.write(data).await.is_ok();
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
            let value = channel.stdout.write(data).await.is_ok();
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

    async fn handle_request(&mut self, request: Request) -> bool {
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
                if let Some(sender) = sender {
                    let _ = sender.send(res).await;
                }
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
            }
            Request::SessionDrop { reson, desc } => {
                let _ = self.session_disconnect(reson, &desc).await;
                return true;
            }
        }
        false
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

        // loop {
        //     let msg = self.recv_msg().await?;

        //     return match msg {
        //         ServerMessage::ChannelSuccess(recipient) if recipient == id => Ok(()),
        //         ServerMessage::ChannelFailure(recipient) if recipient == id => {
        //             Err(Error::ChannelFailure)
        //         }
        //         msg => {
        //             self.handle_msg(msg).await?;
        //             continue;
        //         }
        //     };
        // }

        channel_loop!(
            self,
            id,
            Message::ChannelSuccess(recipient) if recipient == id => return Ok(()),
            Message::ChannelFailure(recipient) if recipient == id => {
                return Err(Error::ChannelFailure);
            },
        );
    }

    async fn wait_for_finish(&mut self, id: u32) -> Result<ExitStatus> {
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("Failed to find channel"))?;

        if let Some(ref exit_status) = channel.exit_status {
            return Ok(exit_status.clone());
        }

        let status = channel_loop!(
            self,
            id,
            Message::ChannelExitStatus { recipient, status } if id == recipient => {
                break ExitStatus::Normal(status);
            },
            Message::ChannelExitSignal {
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
            },
        );

        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("Failed to find channel"))?;

        channel.exit_status = Some(status.clone());

        Ok(status)
    }

    async fn channel_exec_wait(&mut self, id: u32, cmd: &str) -> Result<ExitStatus> {
        self.channel_exec(id, cmd).await?;

        let status = channel_loop!(
            self,
            id,
            Message::ChannelExitStatus { recipient, status } if id == recipient => {
                break ExitStatus::Normal(status);
            },
            Message::ChannelExitSignal {
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
            },
        );

        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("Failed to find channel"))?;

        channel.exit_status = Some(status.clone());

        Ok(status)
    }

    async fn channel_write_stdout(&mut self, id: u32, data: &[u8]) -> Result<usize> {
        // let (channel, stream) = func(self)?;
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or(Error::ub("Failed to find channel"))?;

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
            .ok_or(Error::ub("Failed to find channel"))?;

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
        channel.stderr.close().await;
        channel.stdout.close().await;
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
            .ok_or(Error::ub("Failed to find channel"))
    }

    fn get_server_channel_id(&mut self, id: u32) -> Result<u32> {
        self.channels
            .get(&id)
            .map(|v| v.server.id)
            .ok_or(Error::ub("Failed to find channel"))
    }

    fn get_server_channel(&mut self, id: u32) -> Result<&mut ChannelInner> {
        self.channels
            .get_mut(&id)
            .ok_or(Error::ub("Failed to find channel"))
    }

    async fn channel_exec(&mut self, id: u32, cmd: &str) -> Result<()> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_CHANNEL_REQUEST);
        buffer.put_u32(self.get_server_channel_id(id)?);
        buffer.put_one(b"exec");
        buffer.put_u8(1);
        buffer.put_one(cmd.as_bytes());

        self.stream.send_payload(buffer.as_ref()).await?;

        channel_loop!(
            self,
            id,
            Message::ChannelSuccess(recipient) if recipient == id => return Ok(()),
            Message::ChannelFailure(recipient) if recipient == id => {
                return Err(Error::ChannelFailure);
            },
        );
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
                Message::ChannelOpenFailure {
                    recipient,
                    reson,
                    desc,
                    ..
                } if recipient == client_id => Err(Error::ChannelOpenFail(reson, desc)),
                Message::ChannelOpenConfirmation {
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

        let stdout = io_channel();
        let stderr = io_channel();

        let channel = Channel::new(
            client.id,
            ManuallyDrop::new(stdout.1),
            ManuallyDrop::new(stderr.1),
            ManuallyDrop::new(session),
        );

        let inner = ChannelInner::new(
            client, server, // Box::new(NormalChannel::new(stdout.0, stderr.0)),
            stdout.0, stderr.0, None,
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
                Message::UserauthSuccess => {
                    self.stream.authed = true;
                    Ok(Userauth::Success)
                }
                Message::UserauthFailure { methods, .. } => Ok(Userauth::Failure(methods)),
                Message::UserauthChangeReq => Ok(Userauth::Failure(vec![])),

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
                Message::UserauthSuccess => {
                    self.stream.authed = true;
                    Ok(Userauth::Success)
                }
                Message::UserauthFailure { methods, .. } => Ok(Userauth::Failure(methods)),
                Message::UserauthChangeReq => Ok(Userauth::Expired),

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
            let code = payload
                .take_u8()
                .ok_or(Error::invalid_format("invalid ssh packet"))?;
            match code {
                SSH_MSG_USERAUTH_FAILURE => {
                    let (_, methods) = payload
                        .take_one()
                        .ok_or(Error::invalid_format("invalid ssh packet"))?;
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
                    self.handle_msg(Message::parse(packet.payload).map_err(Error::invalid_format)?)
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
                Message::UserauthSuccess => {
                    self.stream.authed = true;
                    break Ok(Userauth::Success);
                }
                Message::UserauthFailure { methods, .. } => {
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
    ) -> Result<SFtp> {
        let (channel, inner) = self
            .channel_open_normal(initial, maximum, session.clone())
            .await?;

        // let (client, server) = self.channel_open_raw(initial, maximum).await?;

        let server_id = inner.server.id;
        let client_id = inner.client.id;

        // self.channels.insert(channel.id, inner);

        // let (sender, recver) = async_channel::unbounded();

        // let sub = SFtpSystem::new(sender);

        // let inner = ChannelInner::new(client, server, Box::new(sub), None);

        self.channels.insert(client_id, inner);

        let func = async {
            let mut buffer = Buffer::new();

            buffer.put_u8(SSH_MSG_CHANNEL_REQUEST);
            buffer.put_u32(server_id);
            buffer.put_one(b"subsystem");
            buffer.put_u8(1);
            buffer.put_one(b"sftp");

            self.stream.send_payload(buffer.as_ref()).await?;

            // loop {
            //     match self.recv_msg().await? {
            //         ServerMessage::ChannelSuccess(_) => break,
            //         ServerMessage::ChannelFailure(_) => return Err(Error::SubsystemFailed),
            //         msg => {
            //             self.handle_msg(msg).await?;
            //         }
            //     }
            // }

            channel_loop!(
                self,
                client_id,
                Message::ChannelSuccess(recipient) if recipient == client_id => break,
                Message::ChannelFailure(recipient) if recipient == client_id => return Err(Error::SubsystemFailed),
            );

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
                    Message::ChannelClose(recipient) if recipient == client_id => {
                        break Err(Error::ChannelClosed);
                    }
                    Message::ChannelEof(recipient) if recipient == client_id => {
                        break Err(Error::ChannelEof);
                    }
                    Message::ChannelStdoutData { recipient, data } if recipient == client_id => {
                        let mut data = Buffer::from_vec(data);

                        let (_, data) = data
                            .take_one()
                            .ok_or(Error::invalid_format("Invalid ssh packet"))?;

                        let mut data = Buffer::from_vec(data);

                        let value = data
                            .take_u8()
                            .ok_or(Error::invalid_format("Invalid ssh packet"))?;

                        if value != SSH_FXP_VERSION {
                            return Err(Error::ProtocolError);
                        }

                        let version = data
                            .take_u32()
                            .ok_or(Error::invalid_format("Invalid ssh packet"))?;

                        let mut ext = || {
                            let Some((_, key)) = data.take_one() else {
                                return Ok(None);
                            };

                            let key = String::from_utf8(key)?;

                            let (_, value) = data
                                .take_one()
                                .ok_or(Error::invalid_format("Failed to parse value"))?;

                            Result::Ok(Some((key, value)))
                        };

                        let mut extension = HashMap::new();
                        while let Some((k, v)) = ext()? {
                            extension.insert(k, v);
                        }

                        break Ok(SFtp::new(channel, version, extension));
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
            let _ = session
                .send(Request::ChannelDrop {
                    id: client_id,
                    sender: None,
                })
                .await;
        }

        res

        // Ok(())
    }
}
