use std::cmp::min;
use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};
use derive_new::new;

use crate::channel::{Channel, Stream};
use crate::error::Result;
use crate::ssh::common::*;
use crate::ssh::stream::BufferStream;
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

#[derive(Debug, Clone, Copy)]
pub struct Statvfs {
    pub bsize: u64,
    pub frsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub favail: u64,
    pub fsid: u64,
    pub flag: u64,
    pub namemax: u64,
}

impl Statvfs {
    pub const FLAG_RDONLY: u64 = 0x1;
    pub const FLAG_NOSUID: u64 = 0x2;
    fn parse(data: &[u8]) -> Option<Self> {
        let mut buffer = Buffer::from_vec(data.to_vec());

        Some(Self {
            bsize: buffer.take_u64()?,
            frsize: buffer.take_u64()?,
            blocks: buffer.take_u64()?,
            bfree: buffer.take_u64()?,
            bavail: buffer.take_u64()?,
            files: buffer.take_u64()?,
            ffree: buffer.take_u64()?,
            favail: buffer.take_u64()?,
            fsid: buffer.take_u64()?,
            flag: buffer.take_u64()?,
            namemax: buffer.take_u64()?,
        })
    }
}

pub struct SFtp {
    channel: BufferStream<Stream>,
    request_id: u32,
    version: u32,
    ext: HashMap<String, Vec<u8>>,
}

impl SFtp {
    pub(crate) fn new(channel: Channel, version: u32, ext: HashMap<String, Vec<u8>>) -> Self {
        Self {
            channel: BufferStream::new(Stream::new(channel)),
            request_id: 0,
            version,
            ext,
        }
    }
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
    fn to_bytes(&self, buffer: &mut Buffer<Vec<u8>>) {
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

    fn parse(buffer: &mut Buffer<Vec<u8>>) -> Option<Self> {
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

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_packet_len: u64,
    pub max_read_len: u64,
    pub max_write_len: u64,
    pub max_open_handles: u64,
}

impl Limits {
    fn parse(data: &[u8]) -> Option<Self> {
        let mut buffer = Buffer::from_vec(data.to_vec());

        Some(Self {
            max_packet_len: buffer.take_u64()?,
            max_read_len: buffer.take_u64()?,
            max_write_len: buffer.take_u64()?,
            max_open_handles: buffer.take_u64()?,
        })
    }
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
            SSH_FXP_EXTENDED_REPLY => Message::ExtendReply(data.into_vec()),
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

    fn to_result<T: Default>(&self, msg: String) -> Result<T> {
        match self {
            Status::OK => Ok(Default::default()),
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
    ExtendReply(Vec<u8>),
}

impl SFtp {
    const MAX_SFTP_PACKET: usize = 32000;

    pub fn extend(&self, key: &str) -> Option<&[u8]> {
        self.ext.get(key).map(|v| v.as_ref())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub async fn flush(&self) -> Result<()> {
        self.channel.inner().inner().flush().await
    }

    pub fn support_posix_rename(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_POSIX_RENAME)
    }

    pub async fn posix_rename(&mut self, oldpath: &str, newpath: &str) -> Result<()> {
        let mut buffer = Buffer::new();

        let request_id = self.genarate_request_id();

        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_POSIX_RENAME.0);
        buffer.put_one(oldpath);
        buffer.put_one(newpath);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub fn support_fstatvfs(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_FSTATVFS)
    }

    pub async fn fstatvfs(&mut self, file: &File) -> Result<Statvfs> {
        debug_assert!(self.support_fstatvfs(), "Server doesn't support fstatvfs");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_FSTATVFS.0);
        buffer.put_one(&file.handle);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, _tag } => status.no_ok_and_eof(msg),
            Message::ExtendReply(data) => Statvfs::parse(&data)
                .ok_or(Error::ProtocolError("Invalid Statvfs Message".to_string())),
            _ => Err(Error::ProtocolError("Unexpected SFtp Message".to_string())),
        }
    }

    pub fn support_statvfs(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_STATVFS)
    }

    pub async fn statvfs(&mut self, path: &str) -> Result<Statvfs> {
        debug_assert!(self.support_fstatvfs(), "Server doesn't support statvfs");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_STATVFS.0);
        buffer.put_one(path);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, _tag } => status.no_ok_and_eof(msg),
            Message::ExtendReply(data) => Statvfs::parse(&data)
                .ok_or(Error::ProtocolError("Invalid Statvfs Message".to_string())),
            _ => Err(Error::ProtocolError("Unexpected SFtp Message".to_string())),
        }
    }

    pub fn support_hardlink(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_HARDLINK)
    }

    pub async fn hardlink(&mut self, oldpath: &str, newpath: &str) -> Result<()> {
        debug_assert!(self.support_hardlink(), "Server doesn't support hardlink");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_HARDLINK.0);
        buffer.put_one(oldpath);
        buffer.put_one(newpath);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;
        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub fn support_fsync(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_FSYNC)
    }

    pub async fn fsync(&mut self, file: &File) -> Result<()> {
        debug_assert!(self.support_fsync(), "Server doesn't support fsync");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_FSYNC.0);
        buffer.put_one(&file.handle);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;
        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub fn support_lsetstat(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_LSETSTAT)
    }

    pub async fn lsetstat(&mut self, path: &str, attrs: &Attributes) -> Result<()> {
        debug_assert!(self.support_lsetstat(), "Server doesn't lsetstat");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_LSETSTAT.0);
        buffer.put_one(path);
        attrs.to_bytes(&mut buffer);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;
        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub fn support_limits(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_LIMITS)
    }

    pub async fn limits(&mut self) -> Result<Limits> {
        debug_assert!(self.support_limits(), "Server doesn't support limits");
        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_one(OPENSSH_SFTP_EXT_LIMITS.0);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::ExtendReply(data) => Limits::parse(&data)
                .ok_or(Error::ProtocolError("Invalid packet format".to_string())),
            _ => Err(Error::ProtocolError(
                "Unexpect message from server".to_string(),
            )),
        }
    }

    pub fn support_expand_path(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_EXPAND_PATH)
    }

    pub async fn expand_path(&mut self, path: &str) -> Result<String> {
        debug_assert!(
            self.support_expand_path(),
            "Server doesn't support expand path"
        );

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_EXPAND_PATH.0);
        buffer.put_one(path);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, .. } => status.no_ok_and_eof(msg),
            Message::Name(infos) if infos.len() == 1 => Ok(infos[0].filename.clone()),
            _ => Err(Error::ProtocolError("Unknown msg".to_string())),
        }
    }

    pub fn support_copy_data(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_COPY_DATA)
    }

    pub async fn copy_data(&mut self, read: &mut File, len: u64, write: &mut File) -> Result<()> {
        debug_assert!(self.support_copy_data(), "Server doesn't support copy data");

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_COPY_DATA.0);
        buffer.put_one(&read.handle);
        buffer.put_u64(read.pos);
        buffer.put_u64(len);
        buffer.put_one(&write.handle);
        buffer.put_u64(write.pos);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let status = self.wait_for_status(request_id, Status::to_result).await;

        if status.is_ok() {
            read.pos += len;
            write.pos += len;
        }

        status
    }

    pub fn support_home_directory(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_HOME_DIRECTORY)
    }

    pub async fn home_directory(&mut self, username: &str) -> Result<String> {
        debug_assert!(
            self.support_home_directory(),
            "Server doesn't support home directory"
        );

        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_HOME_DIRECTORY.0);
        buffer.put_one(username);

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::Status { status, msg, _tag } => status.no_ok_and_eof(msg),
            Message::Name(infos) if infos.len() == 1 => Ok(infos[0].filename.clone()),
            _ => Err(Error::ProtocolError("Unexpected message".to_string())),
        }
    }

    pub fn support_users_groups_by_id(&self) -> bool {
        self.support(OPENSSH_SFTP_EXT_USERS_GROUPS_BY_ID)
    }

    pub async fn users_groups_by_id(
        &mut self,
        users: &[u32],
        groups: &[u32],
    ) -> Result<(Vec<String>, Vec<String>)> {
        let request_id = self.genarate_request_id();
        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(OPENSSH_SFTP_EXT_USERS_GROUPS_BY_ID.0);

        buffer.put_u32((users.len() * 4) as u32);

        users.iter().for_each(|v| {
            buffer.put_u32(*v);
        });

        buffer.put_u32((groups.len() * 4) as u32);

        groups.iter().for_each(|v| {
            buffer.put_u32(*v);
        });

        self.send(SSH_FXP_EXTENDED, buffer.as_ref()).await?;

        let packet = self.wait_for_packet(request_id).await?;

        match packet.msg {
            Message::ExtendReply(data) => {
                let mut buffer = Buffer::from_vec(data);
                let usernames = buffer
                    .take_one()
                    .ok_or(Error::ProtocolError(
                        "Invalid sftp packet format".to_string(),
                    ))?
                    .1;
                let mut usernames = Buffer::from_vec(usernames);

                let groupnames = buffer
                    .take_one()
                    .ok_or(Error::ProtocolError(
                        "Invalid sftp packet format".to_string(),
                    ))?
                    .1;
                let mut groupnames = Buffer::from_vec(groupnames);

                let mut unames = vec![];
                while let Some(user) = usernames.take_one() {
                    unames.push(String::from_utf8(user.1)?);
                }

                let mut gnames = vec![];

                while let Some(group) = groupnames.take_one() {
                    gnames.push(String::from_utf8(group.1)?)
                }

                Ok((unames, gnames))
            }
            _ => Err(Error::ProtocolError("Unexpected message".to_string())),
        }
    }

    fn support(&self, (e, v): (&str, &[u8])) -> bool {
        self.ext.get(e).map(|v| v.as_ref()) == Some(v)
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

        self.write(packet.into_vec()).await?;
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

    pub async fn setstat(&mut self, path: &str, attrs: &Attributes) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(path);

        attrs.to_bytes(&mut buffer);

        self.send(SSH_FXP_SETSTAT, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn setfstat(&mut self, file: &File, attrs: &Attributes) -> Result<()> {
        let request_id = self.genarate_request_id();

        let mut buffer = Buffer::new();
        buffer.put_u32(request_id);
        buffer.put_one(&file.handle);

        attrs.to_bytes(&mut buffer);

        self.send(SSH_FXP_FSETSTAT, buffer.as_ref()).await?;

        self.wait_for_status(request_id, Status::no_eof).await
    }

    pub async fn readlink(&mut self, path: &str) -> Result<FileInfo> {
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

    pub async fn realpath(&mut self, path: &str) -> Result<String> {
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
        let mut data = self.channel.read_exact(4).await?;

        let len = BigEndian::read_u32(&data);

        data.extend(self.channel.read_exact(len as usize).await?);
        Packet::parse(data).ok_or(Error::invalid_format("unable to parse sftp packet"))
    }

    fn genarate_request_id(&mut self) -> u32 {
        self.request_id = self.request_id.wrapping_add(1);
        self.request_id
    }

    async fn write(&mut self, data: impl Into<Vec<u8>>) -> Result<bool> {
        self.channel.inner().inner().write(data).await
    }
}
