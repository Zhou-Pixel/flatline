use async_channel::{Receiver, Sender, TryRecvError};
use derive_new::new;

use super::session::ExitStatus;

use super::Request;
use super::SubSystem;
use super::error::{Result, Error};


#[derive(new)]
pub struct Channel {
    pub(crate) id: u32,
    stdout: Receiver<Vec<u8>>,
    stderr: Receiver<Vec<u8>>,
    session: Sender<Request>,

    #[new(value = "false")]
    closed: bool,
}

impl Drop for Channel {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let (sender, recver) = async_channel::bounded(1);
        let _ = self.session.send_blocking(Request::ChannelDrop {
            id: self.id,
            sender,
        });
        drop(recver);
    }
}

use super::scp::Sender as ScpSender;
use super::sftp::{Timestamp, Permissions};

impl Channel {


    // pub async fn scp_receiver(mut self, path: &str) -> Result<()> {


    //     todo!()
    // }

    pub async fn scp_sender(mut self, path: &str, size: usize, permissions: Permissions, time: Option<Timestamp>) -> Result<ScpSender> {


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

    pub async fn close(mut self) -> Result<()> {
        self.closed = true;
        let (sender, recver) = async_channel::bounded(1);
        self.send_request(Request::ChannelDrop {
            id: self.id,
            sender,
        })
        .await?;
        recver.recv().await.map_err(|_| Error::Disconnect)?
    }

    pub async fn exec(&self, cmd: impl Into<String>) -> Result<()> {
        let (sender, recver) = async_channel::bounded(1);
        let resquest = Request::ChannelExec {
            id: self.id,
            cmd: cmd.into(),
            sender,
        };

        self.send_request(resquest).await?;

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

    pub fn try_read(&self) -> Result<Option<Vec<u8>>> {
        match self.stdout.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err(Error::ChannelClosed),
        }
    }

    pub async fn read(&mut self) -> Result<Vec<u8>> {
        self.stdout.recv().await.map_err(|_| Error::ChannelClosed)
    }

    pub fn try_read_stderr(&self) -> Result<Option<Vec<u8>>> {
        match self.stderr.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err(Error::ChannelClosed),
        }
    }

    pub async fn read_stderr(&mut self) -> Result<Vec<u8>> {
        self.stderr.recv().await.map_err(|_| Error::ChannelClosed)
    }

    pub async fn write(&mut self, data: impl Into<Vec<u8>>) -> Result<usize> {
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


#[derive(new)]
pub(crate) struct NormalChannel {
    stdout: Sender<Vec<u8>>,
    stderr: Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl SubSystem for NormalChannel {
    async fn append_stderr(&mut self, data: &[u8]) -> Result<()> {
        let _ = self.stderr.send(data.to_vec()).await;
        Ok(())
    }
    async fn append_stdout(&mut self, data: &[u8]) -> Result<()> {
        let _ = self.stdout.send(data.to_vec()).await;
        Ok(())
    }
}

#[derive(new)]
pub(crate) struct ChannelInner {
    pub(crate) client: Endpoint, // 数据是server发来的, 发送数据时减少
    pub(crate) server: Endpoint, // 数据是client设定， 收到数据时减少， 发送window_adjust 调整
    // stdout: Sender<Vec<u8>>,
    // stderr: Sender<Vec<u8>>,
    pub(crate) subsystem: Box<dyn SubSystem + Send>,
    pub(crate) exit_status: Option<ExitStatus>,
}