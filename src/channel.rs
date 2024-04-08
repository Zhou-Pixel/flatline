

use std::mem::ManuallyDrop;

use async_channel::Sender;
use derive_new::new;

use crate::msg::Signal;
use crate::utils::{IOReceiver, IOSender};

use super::msg::ExitStatus;

use super::error::{Error, Result};
use super::msg::Request;
// use super::SubSystem;





pub struct Channel {
    id: u32,
    pub(crate) stdout: ManuallyDrop<IOReceiver>,
    stderr: ManuallyDrop<IOReceiver>,
    session: ManuallyDrop<Sender<Request>>,

}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.session.send_blocking(Request::ChannelDrop {
            id: self.id,
            sender: None,
        });
        self.manually_drop()
    }
}

use super::scp::Sender as ScpSender;
use super::sftp::{Permissions, Timestamp};

impl Channel {

    pub(crate) fn new(id: u32, stdout: IOReceiver, stderr: IOReceiver, session: Sender<Request>) -> Self {
        Self {
            id,
            stdout: ManuallyDrop::new(stdout),
            stderr: ManuallyDrop::new(stderr),
            session: ManuallyDrop::new(session)
        }
    }
    
    fn manually_drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.stdout);
            ManuallyDrop::drop(&mut self.stderr);
            ManuallyDrop::drop(&mut self.session);
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelFlushStdout { id: self.id, sender };

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

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
        let (sender, recver) = async_channel::bounded(1);
        self.send_request(Request::ChannelDrop {
            id: self.id,
            sender: Some(sender),
        })
        .await?;
        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn close(mut self) -> Result<()> {
        let res = self.close_without_drop().await;
        self.manually_drop();
        std::mem::forget(self);
        res
    }

    pub async fn send_signal(&mut self, signal: Signal) -> Result<()> {
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelSendSignal { id: self.id, signal, sender };        

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    pub async fn set_env(
        &mut self,
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Result<()> {
        let name = name.into();
        let value = value.into();
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelSetEnv {
            id: self.id,
            name,
            value,
            sender,
        };

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    pub async fn exec(&self, cmd: impl Into<String>) -> Result<()> {
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelExec {
            id: self.id,
            cmd: cmd.into(),
            sender,
        };

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    pub async fn exec_and_wait(&mut self, cmd: impl Into<String>) -> Result<ExitStatus> {
        let (sender, recver) = async_channel::bounded(1);

        let request = Request::ChannelExecWait {
            id: self.id,
            cmd: cmd.into(),
            sender,
        };

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    pub async fn exit_status(&mut self) -> Result<ExitStatus> {
        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelGetExitStatus {
            id: self.id,
            sender,
        };

        self.send_request(request).await?;
        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    pub fn try_read(&mut self) -> Result<Option<Vec<u8>>> {
        self.stdout.try_read()
    }

    pub async fn read(&mut self) -> Result<Vec<u8>> {
        self.stdout.read().await
    }

    pub fn try_read_stderr(&mut self) -> Result<Option<Vec<u8>>> {
        self.stderr.try_read()
    }

    pub async fn read_stderr(&mut self) -> Result<Vec<u8>> {
        self.stderr.read().await
    }

    pub async fn write(&mut self, data: impl Into<Vec<u8>>) -> Result<bool> {
        let data: Vec<u8> = data.into();

        let (sender, recver) = async_channel::bounded(1);
        let request = Request::ChannelWriteStdout {
            id: self.id,
            data,
            sender,
        };

        self.send_request(request).await?;

        recver.recv().await.map_err(|_| Error::ChannelClosed)?
    }

    // pub(crate) async fn send_eof(&mut self) -> Result<()> {
    //     let (sender, recver) = async_channel::bounded(1);
    //     let request = Request::ChannelEof { id: self.id, sender };
    //     self.send_request(request).await?;

    //     recver.recv().await.map_err(|_| Error::ChannelClosed)?
    // }

    async fn send_request(&self, msg: Request) -> Result<()> {
        self.session.send(msg).await.map_err(|_| Error::Disconnect)
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

// #[derive(new)]
// pub(crate) struct NormalChannel {
//     stdout: Sender<Vec<u8>>,
//     stderr: Sender<Vec<u8>>,
// }

// #[async_trait::async_trait]
// impl SubSystem for NormalChannel {
//     async fn append_stderr(&mut self, data: &[u8]) -> Result<()> {
//         let _ = self.stderr.send(data.to_vec()).await;
//         Ok(())
//     }
//     async fn append_stdout(&mut self, data: &[u8]) -> Result<()> {
//         let _ = self.stdout.send(data.to_vec()).await;
//         Ok(())
//     }
// }

#[derive(new)]
pub(crate) struct ChannelInner {
    pub(crate) client: Endpoint, 
    pub(crate) server: Endpoint,
    pub(crate) stdout: IOSender,
    pub(crate) stderr: IOSender,
    
    #[new(default)]
    pub(crate) stdout_buf: Vec<u8>,
    // #[new(default)]
    // pub(crate) stderr_buf: Vec<u8>,
    // pub(crate) subsystem: Box<dyn SubSystem + Send>,
    pub(crate) exit_status: Option<ExitStatus>,
}
