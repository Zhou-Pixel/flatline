use std::cmp::min;
use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};
use derive_new::new;

use crate::channel::Channel;
use crate::error::Result;
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
pub struct SFtp {
    // session: Sender<Request>,
    // id: u32,
    channel: Channel,

    #[new(default)]
    request_id: u32,
    version: u32,
    // recver: Receiver<Vec<u8>>,
    ext: HashMap<String, Vec<u8>>,
}

pub struct File {
    handle: Vec<u8>,
    pos: u64,
}

impl File {
    fn new(handle: Vec<u8>) -> Self {
        Self { handle, pos: 0 }
    }
}

pub struct Dir {
    handle: Vec<u8>,
}

impl Dir {
    fn new(handle: Vec<u8>) -> Self {
        Self { handle }
    }
}

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

        let mut data = Buffer::from_vec(data);

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

                let _tag = String::from_utf8(tag).ok()?;

                let status = Status::from_status(status).ok()?;
                Message::Status { status, msg, _tag }
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

#[derive(Debug, PartialEq)]
#[repr(u32)]
enum Status {
    OK = SSH_FX_OK,
    Eof = SSH_FX_EOF,
    NoSuchFile = SSH_FX_NO_SUCH_FILE,
    PermissionDenied = SSH_FX_PERMISSION_DENIED,
    Failure = SSH_FX_FAILURE,
    BadMessage = SSH_FX_BAD_MESSAGE,
    NoConnection = SSH_FX_NO_CONNECTION,
    ConnectionLost = SSH_FX_CONNECTION_LOST,
    OpUnsupported = SSH_FX_OP_UNSUPPORTED,
}

impl Status {
    fn from_status(code: u32) -> Result<Self> {
        Ok(match code {
            SSH_FX_OK => Self::OK,
            SSH_FX_EOF => Self::Eof,
            SSH_FX_NO_SUCH_FILE => Self::NoSuchFile,
            SSH_FX_PERMISSION_DENIED => Self::PermissionDenied,
            SSH_FX_FAILURE => Self::Failure,
            SSH_FX_BAD_MESSAGE => Self::BadMessage,
            SSH_FX_NO_CONNECTION => Self::NoConnection,
            SSH_FX_CONNECTION_LOST => Self::ConnectionLost,
            SSH_FX_OP_UNSUPPORTED => Self::OpUnsupported,
            _ => return Err(Error::invalid_format("Invalid Sftp status code")),
        })
    }

    // fn to_result<T: Default>(&self, msg: String) -> Result<T> {
    //     match self {
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

    fn no_ok_and_eof<T>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Err(Error::ProtocolError(
                "Unexpected Ok status received".to_string(),
            )),
            Status::Eof => Err(Error::ProtocolError(
                "Unexpected EOF status received".to_string(),
            )),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::Failure => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }

    fn no_eof<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Ok(Default::default()),
            Status::Eof => Err(Error::ProtocolError(
                "Unexpected EOF status received".to_string(),
            )),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::Failure => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }

    fn no_ok<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Err(Error::ProtocolError(
                "Unexpected Ok status received".to_string(),
            )),
            Status::Eof => Ok(Default::default()),
            Status::NoSuchFile => Err(Error::NoSuchFile(msg)),
            Status::PermissionDenied => Err(Error::PermissionDenied(msg)),
            Status::Failure => Err(Error::SFtpFailure(msg)),
            Status::BadMessage => Err(Error::BadMessage(msg)),
            Status::NoConnection => Err(Error::NoConnection(msg)),
            Status::ConnectionLost => Err(Error::ConnectionLost(msg)),
            Status::OpUnsupported => Err(Error::OpUnsupported(msg)),
        }
    }
}

enum Message {
    FileHandle(Vec<u8>),
    Status {
        status: Status,
        msg: String,
        _tag: String,
    },
    Data(Vec<u8>),
    Name(Vec<FileInfo>),
    Attributes(Attributes),
}

impl SFtp {
    const MAX_SFTP_PACKET: usize = 32000;

    pub fn extend(&self, key: &str) -> Option<&[u8]> {
        self.ext.get(key).map(|v| v.as_ref())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.channel.flush().await
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

        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn read_file(&mut self, file: &mut File, max: u32) -> Result<Vec<u8>> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();

        buffer.put_u32(request_id);

        buffer.put_one(&file.handle);
        buffer.put_u64(file.pos);

        buffer.put_u32(max);

        self.send(SSH_FXP_READ, buffer.as_ref()).await?;

        let packet = self.recv().await?;

        match packet.msg {
            Message::Data(data) => {
                file.pos += data.len() as u64;
                Ok(data)
            }
            Message::Status { status, msg, .. } => status.no_ok(msg),
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    async fn send(&mut self, code: u8, bytes: &[u8]) -> Result<()> {
        let mut packet = Buffer::new();

        packet.put_u32((bytes.len() + 1) as u32);
        packet.put_u8(code);
        packet.put_bytes(bytes);

        self.write(packet).await?;
        Ok(())
    }

    pub async fn write_file_buf(&mut self, file: &mut File, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let max = Self::MAX_SFTP_PACKET;
        let mut requests = vec![];
        let mut buffer = Buffer::new();
        for i in (0..data.len()).step_by(max) {
            let left = data.len() - i;

            let min = min(left, max);

            let request_id = self.genarate_request_id();

            buffer.put_u32(request_id);
            buffer.put_one(&file.handle);
            buffer.put_u64(file.pos);
            buffer.put_one(&data[i..i + min]);

            self.send(SSH_FXP_WRITE, buffer.as_ref()).await?;

            requests.push(request_id);
            file.pos += min as u64;
            buffer.clear();
        }

        for id in requests {
            self.wait_for_status(id, Status::no_eof).await?;
        }

        Ok(())
    }

    pub async fn write_file(&mut self, file: &mut File, data: &[u8]) -> Result<()> {
        let max = Self::MAX_SFTP_PACKET;
        for i in (0..data.len()).step_by(max) {
            let left = data.len() - i;

            let min = min(left, max);

            self.write_file_unchecked(file, &data[i..i + min]).await?;
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

        self.send(SSH_FXP_WRITE, buffer.as_ref()).await?;

        let res = self.wait_for_status(request_id, Status::no_eof).await;
        if res.is_ok() {
            file.pos += data.len() as u64;
        }
        res
    }

    async fn wait_for_status<T, B>(&mut self, id: u32, f: T) -> Result<B>
    where
        T: FnOnce(&Status, String) -> Result<B>,
    {
        let packet = self.wait_for_packet(id).await?;

        match packet.msg {
            // Message::Status { status, .. } if status == Status::OK => Ok(()),
            Message::Status { status, msg, .. } => f(&status, msg),
            _ => Err(Error::ProtocolError("Unknown msg received".to_string())),
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
        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        self.send(SSH_FXP_RMDIR, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_ok).await
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

            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    pub async fn close_dir(&mut self, dir: Dir) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();

        buffer.put_u32(request_id);
        buffer.put_one(dir.handle);

        self.send(SSH_FXP_CLOSE, buffer.as_ref()).await?;
        self.wait_for_status(request_id, Status::no_eof).await
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    pub async fn set_stat(&mut self, path: &str, attrs: &Attributes) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        attrs.to_bytes(&mut buffer);

        self.send(SSH_FXP_SETSTAT, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn set_fstat(&mut self, file: &File, attrs: &Attributes) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(&file.handle);

        attrs.to_bytes(&mut buffer);

        self.send(SSH_FXP_FSETSTAT, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    pub async fn symlink(&mut self, linkpath: &str, targetpath: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(linkpath);
        buffer.put_one(targetpath);

        self.send(SSH_FXP_SYMLINK, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
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
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    pub async fn rename_file_or_dir(&mut self, old: &str, new: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(old);
        buffer.put_one(new);

        self.send(SSH_FXP_RENAME, buffer.as_ref()).await?;
        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn remove_file(&mut self, file: &str) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(file);

        self.send(SSH_FXP_REMOVE, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
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

            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
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

    async fn write(&mut self, data: impl Into<Vec<u8>>) -> Result<bool> {
        self.channel.write(data).await
    }
}
