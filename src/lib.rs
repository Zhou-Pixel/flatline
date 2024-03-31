pub mod cipher;
pub mod error;
pub mod session;
pub mod sftp;
pub mod channel;
pub mod scp;
pub mod handshake;
mod ssh;
mod project;
mod keys;

#[cfg(test)]
mod test;


use async_channel::Sender;
use error::Result;
use session::Userauth;
use channel::Channel;
use session::ExitStatus;
use sftp::Sftp;
pub use openssl;
pub use cipher::{
    Boxtory,
    Factory,
    compress::{Decode, Encode},
    crypt::{Decrypt, Encrypt},
    hash::Hash,
    kex::KeyExChange,
    mac::Mac,
    sign::{Verify, Signature},
};



#[async_trait::async_trait]
trait SubSystem {
    async fn append_stderr(&mut self, data: &[u8]) -> Result<()>;
    async fn append_stdout(&mut self, data: &[u8]) -> Result<()>;
}

enum Request {
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
    // ChannelSftpOpen {

    // },
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
        sender: Sender<Result<()>>,
    },
    ChannelWriteStdout {
        id: u32,
        data: Vec<u8>,
        sender: Sender<Result<usize>>,
    },
    ChannelEof {
        id: u32,
        sender: Sender<Result<()>>
    },

    SFtpOpen {
        session: Sender<Request>,
        sender: Sender<Result<Sftp>>,
    },
}