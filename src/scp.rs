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
                res[0],
                String::from_utf8(self.read_line_lf().await?)?,
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
