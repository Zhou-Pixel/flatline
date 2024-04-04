use std::cmp::min;
use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};
use derive_new::new;
use num_enum::TryFromPrimitive;

use crate::channel::Channel;
use crate::error::Result;
use crate::ssh::common::PAYLOAD_MAXIMUM_SIZE;
use crate::{
    error::Error,
    ssh::{buffer::Buffer, common::code::*},
};

use bitflags::bitflags;

bitflags! {
    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-01#section-7.3
    #[derive(Clone, Copy)]
    pub struct OpenFlags: u32 {
        // Open the file for reading
        const READ                        = SSH_FXF_READ;
        // Open the file for writing.  If both this and SSH_FXF_READ are specified,
        // the file is opened for both reading and writing.
        const WRITE                       = SSH_FXF_WRITE;
        // Force all writes to append data at the end of the file.
        const APPEND                      = SSH_FXF_APPEND;
        // If this flag is specified, then a new file will be created if one
        // does not alread exist (if O_TRUNC is specified, the new file will
        // be truncated to zero length if it previously exists)
        const CREAT                       = SSH_FXF_CREAT;
        // Forces an existing file with the same name to be truncated to zero
        // length when creating a file by specifying SSH_FXF_CREAT.
        // SSH_FXF_CREAT MUST also be specified if this flag is used.
        const TRUNC                       = SSH_FXF_TRUNC;
        // Causes the request to fail if the named file already exists.
        // SSH_FXF_CREAT MUST also be specified if this flag is used.
        const EXCL                        = SSH_FXF_EXCL;
    }
}

#[derive(new)]
pub struct Sftp {
    // session: Sender<Request>,
    // id: u32,
    channel: Channel,

    #[new(default)]
    request_id: u32,
    version: u32,
    // recver: Receiver<Vec<u8>>,
    ext: HashMap<String, Vec<u8>>,
    #[new(default)]
    buf: Vec<u8>,
}

#[derive(new)]
pub struct File {
    // sftp: &'a mut Sftp,
    handle: Vec<u8>,
    #[new(value = "0")]
    pos: u64,
    // #[new(value = "false")]
    // closed: bool,
}

#[derive(new)]
pub struct Dir {
    handle: Vec<u8>,
}

// impl<'a> Drop for File<'a> {
//     fn drop(&mut self) {
//         if self.closed {
//             return;
//         }
//         let _ = tokio::runtime::Handle::current().block_on(async {
//             let request_id = self.sftp.genarate_request_id();

//             let mut buffer = Buffer::new();

//             buffer.put_u32(request_id);
//             buffer.put_one(&self.handle);

//             let mut packet = Buffer::new();

//             packet.put_u32((buffer.len() + 1) as u32);
//             packet.put_u8(SSH_FXP_CLOSE);
//             packet.put_bytes(buffer);

//             self.sftp.write_all(packet.as_ref()).await?;

//             let packet = self.sftp.wait_for_packet(request_id).await?;

//             match packet.msg {
//                 Message::Status { status, .. } if status == SSH_FX_OK => Ok(()),
//                 Message::Status { status, msg, .. } => Err(Error::SFtpRequestFailed(status, msg)),
//                 _ => Err(Error::UnexpectMsg),
//             }
//         });
//     }
// }

// impl<'a> File<'a> {
//     pub async fn close(mut self) -> Result<()> {
//         self.closed = true;
//         let request_id = self.sftp.genarate_request_id();

//         let mut buffer = Buffer::new();

//         buffer.put_u32(request_id);
//         buffer.put_one(&self.handle);

//         let mut packet = Buffer::new();

//         packet.put_u32((buffer.len() + 1) as u32);
//         packet.put_u8(SSH_FXP_CLOSE);
//         packet.put_bytes(buffer);

//         self.sftp.write_all(packet.as_ref()).await?;

//         let packet = self.sftp.wait_for_packet(request_id).await?;

//         match packet.msg {
//             Message::Status { status, .. } if status == SSH_FX_OK => Ok(()),
//             Message::Status { status, msg, .. } => Err(Error::SFtpRequestFailed(status, msg)),
//             _ => Err(Error::UnexpectMsg),
//         }
//     }

//     pub async fn read(&mut self, max: u32) -> Result<Vec<u8>> {
//         let request_id = self.sftp.genarate_request_id();

//         let mut buffer = Buffer::new();

//         buffer.put_u32(request_id);

//         buffer.put_one(&self.handle);
//         buffer.put_u64(self.pos);

//         buffer.put_u32(max);

//         let mut packet = Buffer::new();

//         packet.put_u32((buffer.len() + 1) as u32);
//         packet.put_u8(SSH_FXP_READ);
//         packet.put_bytes(buffer);

//         self.sftp.write_all(packet.as_ref()).await?;

//         let packet = self.sftp.recv().await?;

//         match packet.msg {
//             Message::Data(data) => {
//                 self.pos += data.len() as u64;
//                 Ok(data)
//             }
//             Message::Status { status, msg, .. } => Err(Error::SFtpRequestFailed(status, msg)),
//             _ => Err(Error::UnexpectMsg),
//         }
//     }

//     pub async fn write(&mut self, data: &[u8]) -> Result<()> {
//         // ssh最大数据包检查
//         let mut buffer = Buffer::new();

//         let request_id = self.sftp.genarate_request_id();

//         buffer.put_u32(request_id);
//         buffer.put_one(&self.handle);
//         buffer.put_u64(self.pos);
//         buffer.put_one(data);

//         let mut packet = Buffer::new();
//         packet.put_u32((buffer.len() + 1) as u32);
//         packet.put_u8(SSH_FXP_WRITE);
//         packet.put_bytes(buffer);

//         self.sftp.write_all(packet.as_ref()).await?;

//         let packet = self.sftp.wait_for_packet(request_id).await?;

//         match packet.msg {
//             Message::Status { status, .. } if status == SSH_FX_OK => Ok(()),
//             Message::Status { status, msg, .. } => Err(Error::SFtpRequestFailed(status, msg)),
//             _ => Err(Error::UnexpectMsg),
//         }
//     }
// }

// #[derive(new)]
// pub struct SFtpSystem {
//     sender: Sender<Vec<u8>>,
// }

// #[async_trait::async_trait]
// impl SubSystem for SFtpSystem {
//     async fn append_stderr(&mut self, _: &[u8]) -> Result<()> {
//         Ok(())
//     }
//     async fn append_stdout(&mut self, data: &[u8]) -> Result<()> {
//         let _ = self.sender.send(data.to_vec()).await;
//         Ok(())
//     }
// }

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct Permissions: u32 {
        const OTHER_EXEC                        = 1 << 0;
        const OTHER_WRITE                       = 1 << 1;
        const OTHER_READ                        = 1 << 2;

        const GROUP_EXEC                        = 1 << 0 << 4;
        const GROUP_WRITE                       = 1 << 1 << 4;
        const GROUP_READ                        = 1 << 2 << 4;

        const OWNER_EXEC                        = 1 << 0 << 8;
        const OWNER_WRITE                       = 1 << 1 << 8;
        const OWNER_READ                        = 1 << 2 << 8;
    }
}

impl Permissions {
    pub fn p0755() -> Self {
        Self::from_bits_retain(0o755)
    }
}

#[derive(new, Debug, Clone, Copy)]
pub struct Timestamp {
    pub atime: u32,
    pub mtime: u32,
}

#[derive(new, Debug, Clone, Copy)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

#[derive(new, Debug, Clone)]
pub struct Attributes {
    pub size: Option<u64>,
    pub user: Option<User>,
    pub permissions: Option<Permissions>,
    // atime mtime
    pub time: Option<Timestamp>,
    // extended_count: Option<u32>,
    pub extend: HashMap<String, Vec<u8>>,
}

impl Attributes {
    fn to_bytes(&self, buffer: &mut Buffer) {
        let mut flags = 0;
        let mut tmp = Buffer::new();
        if let Some(size) = self.size {
            flags |= SSH_FILEXFER_ATTR_SIZE;
            tmp.put_u64(size);
        }

        if let Some(user) = self.user {
            flags |= SSH_FILEXFER_ATTR_UIDGID;
            tmp.put_u32(user.uid);
            tmp.put_u32(user.gid);
        }

        if let Some(permissions) = self.permissions {
            flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
            tmp.put_u32(permissions.bits());
        }

        if let Some(time) = self.time {
            flags |= SSH_FILEXFER_ATTR_ACMODTIME;
            tmp.put_u32(time.atime);
            tmp.put_u32(time.mtime);
        }


        let count = self.extend.len() as u32;

        tmp.put_u32(count);


        for (k, v) in &self.extend {
            tmp.put_one(k);
            tmp.put_one(v);
        }
        buffer.put_u32(flags);
        buffer.put_bytes(tmp);




    }
    fn parse(buffer: &mut Buffer) -> Option<Self> {
        let flags = buffer.take_u32()?;

        let mut size = None;
        let mut user = None;
        let mut permissions = None;
        let mut time = None;

        let mut extend = HashMap::new();

        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            size = Some(buffer.take_u64()?)
        }

        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            let uid = buffer.take_u32()?;
            let gid = buffer.take_u32()?;
            user = Some(User::new(uid, gid))
        }

        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            let per = buffer.take_u32()?;
            permissions = Some(Permissions::from_bits_retain(per))
        }

        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            let atime = buffer.take_u32()?;
            let mtime = buffer.take_u32()?;

            time = Some(Timestamp::new(atime, mtime))
        }

        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let ecount = buffer.take_u32()?;

            for _ in 0..ecount {
                let (_, key) = buffer.take_one()?;
                let (_, value) = buffer.take_one()?;

                extend.insert(String::from_utf8(key).ok()?, value);
            }
        }

        Some(Self::new(size, user, permissions, time, extend))
    }
}

#[derive(new, Debug, Clone)]
pub struct FileInfo {
    pub filename: String,
    pub longname: String,
    pub attrs: Attributes,
}

struct Packet {
    id: u32,
    msg: Message,
}

impl Packet {
    fn parse(data: impl Into<Vec<u8>>) -> Option<Packet> {
        let mut data = Buffer::from_vec(data.into());
        let (_, data) = data.take_one()?;

        let mut data = Buffer::from_vec(data.into());

        let code = data.take_u8()?;
        let id = data.take_u32()?;

        let msg = match code {
            SSH_FXP_HANDLE => {
                let (_, handle) = data.take_one()?;

                Message::FileHandle(handle)
            }
            SSH_FXP_STATUS => {
                let status = data.take_u32()?;

                let (_, msg) = data.take_one()?;

                let (_, tag) = data.take_one()?;

                let msg = String::from_utf8(msg).ok()?;

                let tag = String::from_utf8(tag).ok()?;

                let status = Status::try_from(status).ok()?;
                Message::Status { status, msg, tag }
            }
            SSH_FXP_DATA => Message::Data(data.take_one()?.1),
            SSH_FXP_NAME => {
                let count = data.take_u32()?;
                let mut res = Vec::with_capacity(count as usize);

                for _ in 0..count {
                    let (_, filename) = data.take_one()?;
                    let (_, longname) = data.take_one()?;

                    let filename = String::from_utf8(filename).ok()?;

                    let longname = String::from_utf8(longname).ok()?;

                    // let flags = data.take_u32()?;

                    // let mut size = None;
                    // let mut user = None;
                    // let mut permissions = None;
                    // let mut time = None;

                    // let mut extend = HashMap::new();

                    // if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
                    //     size = Some(data.take_u64()?)
                    // }

                    // if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
                    //     let uid = data.take_u32()?;
                    //     let gid = data.take_u32()?;
                    //     user = Some(User::new(uid, gid))
                    // }

                    // if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
                    //     let per = data.take_u32()?;
                    //     permissions = Some(Permissions::from_bits_retain(per))
                    // }

                    // if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
                    //     let atime = data.take_u32()?;
                    //     let mtime = data.take_u32()?;

                    //     time = Some(Time::new(atime, mtime))
                    // }

                    // if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
                    //     let ecount = data.take_u32()?;

                    //     for _ in 0..ecount {
                    //         let (_, key) = data.take_one()?;
                    //         let (_, value) = data.take_one()?;

                    //         extend.insert(String::from_utf8(key).ok()?, value);
                    //     }
                    // }

                    res.push(FileInfo::new(
                        filename,
                        longname,
                        Attributes::parse(&mut data)?,
                    ));
                }
                Message::Name(res)
            }
            SSH_FXP_ATTRS => Message::Attributes(Attributes::parse(&mut data)?),
            _ => return None,
        };

        Some(Packet { id, msg })
    }
}

#[derive(TryFromPrimitive, Debug, PartialEq)]
#[repr(u32)]
enum Status {
    OK = SSH_FX_OK,
    EOF = SSH_FX_EOF,
    NoSuchFile = SSH_FX_NO_SUCH_FILE,
    PermissionDenied = SSH_FX_PERMISSION_DENIED,
    FAILURE = SSH_FX_FAILURE,
    BadMessage = SSH_FX_BAD_MESSAGE,
    NoConnection = SSH_FX_NO_CONNECTION,
    ConnectionLost = SSH_FX_CONNECTION_LOST,
    OpUnsupported = SSH_FX_OP_UNSUPPORTED,
}

impl Status {
    fn to_result<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Ok(Default::default()),
            Status::EOF => Ok(Default::default()),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::FAILURE => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }

    fn no_ok_and_eof<T>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Err(Error::ProtocolError),
            Status::EOF => Err(Error::ProtocolError),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::FAILURE => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }

    fn no_eof<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Ok(Default::default()),
            Status::EOF => Err(Error::ProtocolError),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::FAILURE => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }

    fn no_ok<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Err(Error::ProtocolError),
            Status::EOF => Ok(Default::default()),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::FAILURE => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }
}

// fn status_to_result<T: Default>(status: Status, msg: String) -> Result<T> {
//     match status {
//         Status::OK => Ok(Default::default()),
//         Status::EOF => Ok(Default::default()),
//         Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
//         Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
//         Status::FAILURE => Err(Error::SFtpFailure(msg)),
//         Status::BadMessage => Err(Error::BadMessage(msg)),
//         Status::NoConnection => Err(Error::NoConnection(msg)),
//         Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
//         Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
//     }
// }

enum Message {
    FileHandle(Vec<u8>),
    Status {
        status: Status,
        msg: String,
        tag: String,
    },
    Data(Vec<u8>),
    Name(Vec<FileInfo>),
    Attributes(Attributes),
}

// impl Drop for Sftp {
//     fn drop(&mut self) {
//         if self.closed {
//             return;
//         }
//         let _ = self.session.send_blocking(Request::ChannelDrop {
//             id: self.id,
//             sender: None,
//         });
//     }
// }

impl Sftp {

    pub fn extend(&self, key: &str) -> Option<&[u8]> {
        self.ext.get(key).map(|v| v.as_ref())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    // pub async fn close(mut self) -> Result<()> {
    //     self.closed = true;
    //     let (sender, recver) = async_channel::bounded(1);
    //     self.session
    //         .send(Request::ChannelDrop {
    //             id: self.id,
    //             sender: Some(sender),
    //         })
    //         .await
    //         .map_err(|_| Error::Disconnect)?;
    //     recver.recv().await.map_err(|_| Error::Disconnect)?
    // }

    pub fn seek_file(&self, file: &mut File, pos: u64) {
        file.pos = pos;
    }

    pub async fn close_file(&mut self, file: File) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();

        buffer.put_u32(request_id);
        buffer.put_one(file.handle);

        self.send(SSH_FXP_CLOSE, buffer.as_ref()).await?;
        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.to_result(msg),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn read_file(&mut self, file: &mut File, max: u32) -> Result<Vec<u8>> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();

        buffer.put_u32(request_id);

        buffer.put_one(&file.handle);
        buffer.put_u64(file.pos);

        buffer.put_u32(max);

        let mut packet = Buffer::new();

        packet.put_u32((buffer.len() + 1) as u32);
        packet.put_u8(SSH_FXP_READ);
        packet.put_bytes(buffer);

        self.write_all(packet.as_ref()).await?;

        let packet = self.recv().await?;

        match packet.msg {
            Message::Data(data) => {
                file.pos += data.len() as u64;
                Ok(data)
            }
            Message::Status { status, msg, .. } => status.to_result(msg),
            _ => Err(Error::ProtocolError),
        }
    }

    async fn send(&mut self, code: u8, bytes: &[u8]) -> Result<()> {
        let mut packet = Buffer::new();

        packet.put_u32((bytes.len() + 1) as u32);
        packet.put_u8(code);
        packet.put_bytes(bytes);

        self.write_all(packet.as_ref()).await
    }

    pub async fn write_file(&mut self, file: &mut File, data: &[u8]) -> Result<()> {


        let max = PAYLOAD_MAXIMUM_SIZE - 1 - 4 - 4 - file.handle.len() - 8 - 4 - 5;
        for i in (0..data.len()).step_by(max) {


            let left = data.len() - i;


            let min = min(left, max);

            self.write_file_unchecked(file, &data[i..i+min]).await?;



        }

        Ok(())
    }

    async fn write_file_unchecked(&mut self, file: &mut File, data: &[u8]) -> Result<()> {
        // ssh最大数据包检查
        let mut buffer = Buffer::new();

        let request_id = self.genarate_request_id();

        buffer.put_u32(request_id);
        buffer.put_one(&file.handle);
        buffer.put_u64(file.pos);
        buffer.put_one(data);

        let mut packet = Buffer::new();
        packet.put_u32((buffer.len() + 1) as u32);
        packet.put_u8(SSH_FXP_WRITE);
        packet.put_bytes(buffer);

        self.write_all(packet.as_ref()).await?;

        self.wait_for_status(request_id).await
    }

    async fn wait_for_status(&mut self, id: u32) -> Result<()> {
        let packet = self.wait_for_packet(id).await?;

        match packet.msg {
            // Message::Status { status, .. } if status == Status::OK => Ok(()),
            Message::Status { status, msg, .. } => status.to_result(msg),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn mkdir(&mut self, path: &str, permissions: Permissions) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        let flags = SSH_FILEXFER_ATTR_PERMISSIONS;

        buffer.put_u32(flags);
        buffer.put_u32(permissions.bits());

        self.send(SSH_FXP_MKDIR, buffer.as_ref()).await?;
        self.wait_for_status(request_id).await
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_RMDIR, buffer.as_ref()).await?;

        self.wait_for_status(request_id).await
    }

    pub async fn open_dir(&mut self, path: &str) -> Result<Dir> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_OPENDIR, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::FileHandle(handle) => Ok(Dir::new(handle)),
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),

            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn close_dir(&mut self, dir: Dir) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();

        buffer.put_u32(request_id);
        buffer.put_one(dir.handle);

        self.send(SSH_FXP_CLOSE, buffer.as_ref()).await?;
        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.to_result(msg),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn read_dir(&mut self, dir: &Dir) -> Result<Vec<FileInfo>> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(&dir.handle);

        self.send(SSH_FXP_READDIR, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok(msg),
            Message::Name(infos) => Ok(infos),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn stat(&mut self, path: &str) -> Result<Attributes> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_STAT, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Attributes(attrs) => Ok(attrs),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn lstat(&mut self, path: &str) -> Result<Attributes> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_LSTAT, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Attributes(attrs) => Ok(attrs),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn fstat(&mut self, file: &File) -> Result<Attributes> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(&file.handle);

        self.send(SSH_FXP_FSTAT, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Attributes(attrs) => Ok(attrs),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn set_stat(&mut self, path: &str, attrs: &Attributes) -> Result<()> {


        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        attrs.to_bytes(&mut buffer);


        self.send(SSH_FXP_SETSTAT, buffer.as_ref()).await?;


        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_eof(msg),
            _ => Err(Error::ProtocolError),
        }
        
    }

    pub async fn set_fstat(&mut self, file: &File, attrs: &Attributes) -> Result<()> {

        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(&file.handle);

        attrs.to_bytes(&mut buffer);


        self.send(SSH_FXP_FSETSTAT, buffer.as_ref()).await?;


        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_eof(msg),
            _ => Err(Error::ProtocolError),
        }
        
    }

    pub async fn read_link(&mut self, path: &str) -> Result<FileInfo> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_READLINK, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Name(mut infos) if infos.len() == 1 => Ok(infos.remove(0)),
            _ => Err(Error::ProtocolError),
        }

    }

    pub async fn symlink(&mut self, linkpath: &str, targetpath: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(linkpath);
        buffer.put_one(targetpath);

        self.send(SSH_FXP_SYMLINK, buffer.as_ref()).await?;
        let packet = self.wait_for_packet(request_id).await?;
        match packet.msg {
            Message::Status { status, msg, .. } => status.no_eof(msg),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn real_path(&mut self, path: &str) -> Result<String> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_REALPATH, buffer.as_ref()).await?;
        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Name(infos) if infos.len() == 1 => Ok(infos[0].filename.clone()),
            _ => Err(Error::ProtocolError),
        }
    }

    pub async fn rename_file_or_dir(&mut self, old: &str, new: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(old);
        buffer.put_one(new);

        self.send(SSH_FXP_RENAME, buffer.as_ref()).await?;
        self.wait_for_status(request_id).await
    }

    pub async fn remove_file(&mut self, file: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(file);

        self.send(SSH_FXP_REMOVE, buffer.as_ref()).await?;

        self.wait_for_status(request_id).await
    }

    pub async fn open_file(
        &mut self,
        filename: &str,
        flags: OpenFlags,
        permissions: Option<Permissions>,
    ) -> Result<File> {
        let mut buffer = Buffer::new();

        let request_id = self.genarate_request_id();
        buffer.put_u32(request_id);
        buffer.put_one(filename);
        buffer.put_u32(flags.bits());

        let mut flag = 0;

        let mut tmp = Buffer::new();
        if let Some(permissions) = permissions {
            flag |= SSH_FILEXFER_ATTR_PERMISSIONS;
            tmp.put_u32(permissions.bits());
        }
        buffer.put_u32(flag);
        buffer.put_bytes(tmp);

        self.send(SSH_FXP_OPEN, buffer.as_ref()).await?;
        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::FileHandle(handle) => Ok(File::new(handle)),
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),

            _ => Err(Error::ProtocolError),
        }
    }

    async fn wait_for_packet(&mut self, id: u32) -> Result<Packet> {
        loop {
            let packet = self.recv().await?;
            if packet.id == id {
                return Ok(packet);
            }
            println!("ignore packet: {}", packet.id)
        }
    }

    async fn recv(&mut self) -> Result<Packet> {
        let mut data = self.channel.stdout.read_exact(4).await?;

        let len = BigEndian::read_u32(&data);

        data.extend(self.channel.stdout.read_exact(len as usize).await?);

        Packet::parse(data).ok_or(Error::invalid_format("unable to parse sftp packet"))
    }

    fn genarate_request_id(&mut self) -> u32 {
        self.request_id = self.request_id.wrapping_add(1);
        self.request_id
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.buf.extend(data);
        while !self.buf.is_empty() {
            let size = self.write(self.buf.clone()).await?;
            self.buf.drain(0..size);
        }
        Ok(())
    }

    async fn write(&mut self, data: Vec<u8>) -> Result<usize> {
        // let (sender, recver) = async_channel::bounded(1);
        // let request = Request::ChannelWriteStdout {
        //     id: self.channel.id,
        //     data,
        //     sender,
        // };

        // self.session
        //     .send(request)
        //     .await
        //     .map_err(|_| Error::Disconnect)?;

        // let size = recver.recv().await.map_err(|_| Error::Disconnect)??;

        let size = self.channel.write(data).await?;
        Ok(size)
    }
}
