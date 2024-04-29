use crate::sftp::{Permissions, Timestamp};

use super::channel::Channel;
use super::channel::Stream;
use super::error::{Error, Result};
use super::ssh::stream::BufferStream;
use derive_new::new;

impl BufferStream<Stream> {
    async fn check_scp_response(&mut self) -> Result<()> {
        let res = self.read_exact(1).await?;
        if res[0] != 0 {
            Err(Error::scp_error(
                Some(res[0]),
                String::from_utf8(self.read_line_lf().await?).map_err(|e| e.utf8_error())?,
            ))
        } else {
            Ok(())
        }
    }
}

fn shell_quote_filename(path: &str) -> String {
    enum State {
        None,
        Single,
        Double,
    }
    let mut state = State::None;

    let mut dest = Vec::new();
    let path = path.as_bytes();
    let len = path.len();
    let mut pos = 0;

    while pos < len {
        match path[pos] {
            b'\'' => {
                match state {
                    State::None => {
                        dest.push(b'"');
                    }
                    State::Double => {}
                    State::Single => {
                        dest.push(b'\'');
                        dest.push(b'"')
                    }
                }
                state = State::Double;
            }
            b'!' => {
                match state {
                    State::None => {
                        dest.push(b'\\');
                    }
                    State::Double => {
                        dest.push(b'"');
                        dest.push(b'\\');
                    }
                    State::Single => {
                        dest.push(b'\'');
                        dest.push(b'\\');
                    }
                }
                state = State::None;
            }
            _ => {
                match state {
                    State::None => dest.push(b'\''),
                    State::Double => {
                        dest.push(b'"');
                        dest.push(b'\'');
                    }
                    State::Single => {}
                }
                state = State::Single;
            }
        }

        dest.push(path[pos]);
        pos += 1;
    }

    match state {
        State::Double => {
            dest.push(b'"');
        }
        State::Single => dest.push(b'\''),
        _ => {}
    }

    String::from_utf8(dest).unwrap()
}

#[derive(new)]
pub struct Sender {
    channel: BufferStream<Stream>,
}

impl Sender {
    // pub fn writer(&mut self) -> (Vec<u8>, &mut impl AsyncWrite) {
    //     (self.channel.take_write_bytes(), self.channel.inner_mut())
    // }

    // pub async fn writer(&mut self) -> Result<&mut impl AsyncWrite> {
    //     self.channel.flush().await?;
    //     Ok(self.channel.inner_mut())
    // }

    pub async fn send(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        if self.channel.write(data).await? {
            self.channel.flush().await?;
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<()> {
        self.channel.write([0]).await?;
        self.channel.flush().await?;
        self.channel.into_inner().into_inner().close().await?;
        Ok(())
    }

    pub async fn from_channel(
        channel: Channel,
        path: &str,
        size: u64,
        permissions: Permissions,
        time: Option<Timestamp>,
    ) -> Result<Self> {
        let cmd = format!("scp -t {}", shell_quote_filename(path));

        channel.exec(cmd).await?;

        let mut channel = BufferStream::new(Stream::new(channel));

        channel.check_scp_response().await?;

        if let Some(time) = time {
            let send = format!("T{} 0 {} 0\n", time.mtime, time.atime);
            channel.write(send).await?;
            channel.flush().await?;
            channel.check_scp_response().await?;
        }

        let filename = path.split('/').last().unwrap_or(&path);
        let send = format!("C0{:0o} {} {}\n", permissions.bits(), size, filename);

        channel.write(send).await?;
        channel.flush().await?;
        channel.check_scp_response().await?;

        Ok(Self::new(channel))
    }
}

pub struct Receiver {
    channel: BufferStream<Stream>,
    time: Timestamp,
    permissions: Permissions,
    size: u64,
    pos: u64,
}



// impl AsyncRead for Receiver {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         cx: &mut task::Context<'_>,
//         buf: &mut tokio::io::ReadBuf<'_>,
//     ) -> Poll<io::Result<()>> {
//         let len = buf.remaining();
//         match Pin::new(self.channel.inner_mut()).poll_read(cx, buf) {
//             Poll::Ready(res) => {
//                 let read = len - buf.remaining();
//                 self.pos += read as u64;

//                 if self.pos == self.size {
//                     buf.set_filled(buf.filled().len() - 1);
//                 }
//                 Poll::Ready(res)
//             },
//             Poll::Pending => Poll::Pending,
//         }
//     }
// }

impl Receiver {
    
    // pub fn reader(&mut self) -> (Vec<u8>, &mut impl AsyncRead) {
    //     let bytes = self.channel.take_read_bytes();

    //     self.pos += bytes.len() as u64;

    //     (bytes, self)
    // }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut bytes = self.channel.read_buf().await?;

        let len = bytes.len();
        if len == 0 {
            return Ok(bytes);
        }
        self.pos += len as u64;
        if self.pos >= self.size {
            bytes.remove(len - 1);
        }
        Ok(bytes)
    }

    pub fn timestamp(&self) -> Timestamp {
        self.time
    }

    pub fn permissions(&self) -> Permissions {
        self.permissions
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub async fn from_channel(channel: Channel, path: &str) -> Result<Self> {
        let cmd = format!("scp -pf {}", shell_quote_filename(path));
        channel.exec(cmd).await?;

        let mut channel = BufferStream::new(Stream::new(channel));

        channel.write([0]).await?;

        let response = channel.read_line_lf().await?;

        if !response.starts_with(b"T") || response.len() < 7 {
            return Err(Error::scp_error(
                None,
                String::from_utf8(response).map_err(|e| e.utf8_error())?,
            ));
        }

        let len = response.len();
        let parts: Vec<_> = response[1..len - 4].split(|v| *v == b' ').collect();

        if parts.len() != 3 || parts[1] != [b'0'] {
            return Err(Error::scp_error(
                None,
                String::from_utf8(response).map_err(|e| e.utf8_error())?,
            ));
        }

        let mtime = std::str::from_utf8(parts[0])?
            .parse::<u32>()
            .map_err(|e| Error::scp_error(None, e.to_string()))?;
        let atime = std::str::from_utf8(parts[2])?
            .parse::<u32>()
            .map_err(|e| Error::scp_error(None, e.to_string()))?;

        let time = Timestamp::new(atime, mtime);

        channel.write([0]).await?;

        let response = channel.read_line_lf().await?;

        if !response.starts_with(b"C") || response.len() < 8 {
            return Err(Error::scp_error(
                None,
                String::from_utf8(response).map_err(|e| e.utf8_error())?,
            ));
        }

        let perm = std::str::from_utf8(&response[1..=4])?;

        let perm = u32::from_str_radix(perm, 8)
            .map_err(|_| Error::scp_error(None, "Invalid permission"))?;

        let permissions = Permissions::from_bits_retain(perm);

        let len = response.len();

        let mut pos = 6;

        loop {
            pos += 1;
            if pos >= len {
                return Err(Error::scp_error(None, "Invalid filesize"));
            }
            if response[pos] == b' ' {
                break;
            }
        }
        let size = std::str::from_utf8(&response[6..pos])?
            .parse::<u64>()
            .map_err(|e| Error::scp_error(None, e.to_string()))?;

        // first zero is to start reading, second one is to end reading
        channel.write([0; 2]).await?;

        Ok(Self {
            channel,
            time,
            permissions,
            size,
            pos: 0,
        })
    }
}
