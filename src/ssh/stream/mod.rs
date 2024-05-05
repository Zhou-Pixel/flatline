use std::fmt::Debug;
use std::io;

use super::{common::PACKET_MAXIMUM_SIZE, packet::Packet};

use crate::{cipher::compress::Encode, error::Error};
use crate::{
    cipher::{compress::Decode, crypt::Decrypt},
    error::Result,
};
use bytes::{BufMut, BytesMut};
use openssl::rand::rand_bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[async_trait::async_trait]
pub trait Stream: Send {
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()>;
    async fn recv_packet(&mut self) -> Result<Packet>;
    async fn send_new_keys(&mut self) -> Result<()>;
}

#[async_trait::async_trait]
impl<T> Stream for PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        PlainStream::send_payload(self, payload).await
    }

    async fn recv_packet(&mut self) -> Result<Packet> {
        PlainStream::recv_packet(self).await
    }

    async fn send_new_keys(&mut self) -> Result<()> {
        PlainStream::send_new_keys(self).await
    }
}

use crate::{
    cipher::{crypt::Encrypt, mac::Mac},
    ssh::buffer::Buffer,
};

use super::common::{code::*, PAYLOAD_MAXIMUM_SIZE};

pub struct BufferStream<T> {
    socket: T,
    r_buf: BytesMut,
    w_buf: BytesMut,
}

impl<T> Debug for BufferStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BufferStream {{ socket, r_buf_len: {}, w_buf_len: {} }}",
            self.r_buf.len(),
            self.w_buf.len()
        )
    }
}

// impl<T: AsyncRead + Unpin> AsyncRead for BufferStream<T> {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut ReadBuf<'_>,
//     ) -> Poll<io::Result<()>> {
//         if !self.r_buf.is_empty() {
//             let len = min(buf.remaining(), self.r_buf.len());
//             buf.put(self.r_buf.split_to(len));
//             return Poll::Ready(Ok(()));
//         }
//         Pin::new(&mut self.socket).poll_read(cx, buf)
//     }
// }

impl<T> BufferStream<T> {
    pub fn new(socket: T) -> Self {
        Self {
            socket,
            r_buf: BytesMut::with_capacity(1024 * 40),
            w_buf: BytesMut::with_capacity(1024 * 40),
        }
    }

    pub fn into_inner(self) -> T {
        self.socket
    }

    // pub fn rbuffer(&self) -> &[u8] {
    //     &self.r_buf
    // }

    pub fn consume_read_buffer(&mut self, size: usize) {
        drop(self.r_buf.split_to(size))
    }
    // pub fn inner_mut(&mut self) -> &mut T {
    //     &mut self.socket
    // }

    // pub fn take_read_bytes(&mut self) -> Vec<u8> {
    //     std::mem::take(&mut self.r_buf).to_vec()
    // }

    // pub fn take_write_bytes(&mut self) -> Vec<u8> {
    //     std::mem::take(&mut self.w_buf).to_vec()
    // }
    // pub fn inner(&self) -> &T {
    //     &self.socket
    // }
}

impl<T: AsyncWrite + Unpin> BufferStream<T> {
    pub async fn write(&mut self, data: impl AsRef<[u8]>) -> io::Result<bool> {
        self.w_buf.put(data.as_ref());
        let len = self.w_buf.len();
        self.socket
            .write_buf(&mut self.w_buf)
            .await
            .map(|write| write == len)
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        while !self.w_buf.is_empty() {
            self.socket.write_buf(&mut self.w_buf).await?;
        }
        self.socket.flush().await
    }

    #[allow(unused)]
    pub async fn write_all(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        self.w_buf.put(data.as_ref());
        while !self.w_buf.is_empty() {
            self.socket.write_buf(&mut self.w_buf).await?;
        }
        self.socket.flush().await
    }
}

impl<T: AsyncRead + Unpin> BufferStream<T> {
    async fn internal_read(&mut self) -> io::Result<usize> {
        let size = self.socket.read_buf(&mut self.r_buf).await?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed",
            ));
        }
        Ok(size)
    }

    pub async fn read_line_lf(&mut self) -> io::Result<Vec<u8>> {
        loop {
            // todo: improve performance
            let pos = self.r_buf.iter().position(|&x| x == b'\n');
            if let Some(pos) = pos {
                return Ok(self.r_buf.split_to(pos + 1).to_vec());
            }
            self.internal_read().await?;
        }
    }

    pub async fn read_line_crlf(&mut self) -> io::Result<Vec<u8>> {
        loop {
            // todo: improve performance
            for i in 0..self.r_buf.len() {
                if self.r_buf[i] == b'\r' && i < self.r_buf.len() - 1 && self.r_buf[i + 1] == b'\n'
                {
                    return Ok(self.r_buf.split_to(i + 2).to_vec());
                }
            }

            self.internal_read().await?;
        }
    }

    // pub async fn read_buf_at_least(&mut self) -> io::Result<Vec<u8>> {
    //     self.socket.read_buf(&mut self.r_buf).await?;

    //     Ok(take(&mut self.r_buf).to_vec())
    // }

    pub async fn read_buf(&mut self) -> io::Result<Vec<u8>> {
        if self.r_buf.is_empty() {
            self.socket.read_buf(&mut self.r_buf).await?;
        }
        let ret = self.r_buf.to_vec();
        self.r_buf.clear();
        Ok(ret)
    }

    pub async fn read_exact(&mut self, size: usize) -> io::Result<Vec<u8>> {
        while self.r_buf.len() < size {
            self.internal_read().await?;
        }

        Ok(self.r_buf.split_to(size).to_vec())
    }

    pub async fn fill(&mut self, len: usize) -> io::Result<&[u8]> {
        while self.r_buf.len() < len {
            self.internal_read().await?;
        }

        Ok(&self.r_buf[..len])
    }
}

#[derive(Default, Debug)]
pub struct NormalEndpoint {
    pub kex_strict: bool,
    pub ext: bool,
    pub sequence_number: u32,
}

impl NormalEndpoint {
    fn encrypt(
        &self,
        // cipher: Box<dyn Encrypt + Send>,
        mac: Box<dyn Mac + Send>,
        // compress: Option<Box<dyn Encode + Send>>,
    ) -> EncryptedEndpoint {
        EncryptedEndpoint {
            // cipher,
            mac,
            kex_strict: self.kex_strict,
            sequence_number: self.sequence_number,
            // compress,
        }
    }
}

pub struct PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    stream: BufferStream<T>,
    pub client: NormalEndpoint,
    pub server: NormalEndpoint,
}

pub struct EncryptedEndpoint {
    pub mac: Box<dyn Mac + Send>,
    pub kex_strict: bool,
    pub sequence_number: u32,
}

impl<T> PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: BufferStream<T>) -> Self {
        Self {
            stream,
            client: Default::default(),
            server: Default::default(),
        }
    }

    pub fn encrypt(
        self,
        client: (
            Box<dyn Encrypt + Send>,
            Box<dyn Mac + Send>,
            Box<dyn Encode + Send>,
        ),
        server: (
            Box<dyn Decrypt + Send>,
            Box<dyn Mac + Send>,
            Box<dyn Decode + Send>,
        ),
    ) -> CipherStream<T> {
        CipherStream {
            encrypt: client.0,
            decrypt: server.0,
            encode: client.2,
            decode: server.2,
            stream: self.stream,
            client: self.client.encrypt(client.1),
            server: self.server.encrypt(server.1),
            authed: false, // kex_strict: self.kex_strict,
            block: None,
        }
    }

    pub async fn send_new_keys(&mut self) -> Result<()> {
        self.send_payload(&[SSH_MSG_NEWKEYS]).await?;
        if self.client.kex_strict && self.server.kex_strict {
            self.server.sequence_number = 0;
            self.client.sequence_number = 0;
        }
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Result<Packet> {
        // let size = self.stream.read_exact(size_of::<u32>()).await?;
        let size = self.stream.fill(4).await?;
        let size = u32::from_be_bytes([size[0], size[1], size[2], size[3]]);
        // let mut size = Buffer::from_vec(size);
        // let size = size.take_u32().unwrap();
        if size as usize > PACKET_MAXIMUM_SIZE - 4 {
            return Err(Error::invalid_format(format!(
                "invalid packet length: {size}"
            )));
        }

        // let data = self.stream.read_exact(size as _).await?;
        let data = self.stream.fill(4 + size as usize).await?;

        let pakcet = Packet::parse(&data[4..], None)
            .ok_or(Error::invalid_format("Failed to parse packet"))?;

        self.stream.consume_read_buffer(4 + size as usize);

        self.server.sequence_number = self.server.sequence_number.wrapping_add(1);
        if !pakcet.payload.is_empty()
            && pakcet.payload[0] == SSH_MSG_NEWKEYS
            && self.client.kex_strict
            && self.server.kex_strict
        {
            self.server.sequence_number = 0;
            self.client.sequence_number = 0;
        }

        Ok(pakcet)
    }

    pub async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let payload_len = payload.len();
        if payload_len > PAYLOAD_MAXIMUM_SIZE {
            return Err(Error::ub("payload is too long"));
        }
        // ( 4 + 1 + y + x) % 8 = 0
        // x = 8 - (4 + 1 + y + x) % 8
        // (packet_length || padding_length || payload || random padding)

        /*
        There MUST be at least four bytes of padding.  The
         padding SHOULD consist of random bytes.  The maximum amount of
         padding is 255 bytes.
         */

        // let en_cts =
        // let pktlen_add = self.hostkey_cts.as_ref().map(|v| v.pktlen_aad()) == Some(true);

        // let crypt_offset = if encrypt_then_mac || pktlen_add { 4 } else { 0 };
        // let etm_offset = if encrypt_then_mac { 4 } else { 0 };
        let block_size = 8;
        // let integerated_mac = self.hostkey_cts.as_ref().map(|v| v.integrated_mac()) == Some(true);

        let mut padding_len = block_size - ((4 + 1 + payload_len) % block_size);
        if padding_len < 4 {
            padding_len += block_size;
        }

        let mut rand_padding = vec![0u8; padding_len];

        rand_bytes(&mut rand_padding)?;

        let mut packet = Buffer::new();

        let packet_len = payload_len + padding_len + 1;

        packet.put_u32(packet_len as _);

        // WriteBytesExt::write_u32::<byteorder::BigEndian>(&mut packet, packet_len as _)?;
        packet.put_u8(padding_len as u8);

        packet.extend(payload.to_vec());

        packet.extend(rand_padding);
        self.stream.write(packet).await?;
        self.stream.flush().await?;
        self.client.sequence_number = self.client.sequence_number.wrapping_add(1);
        Ok(())
    }
}

pub struct CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    stream: BufferStream<T>,
    pub encrypt: Box<dyn Encrypt + Send>,
    pub decrypt: Box<dyn Decrypt + Send>,
    pub decode: Box<dyn Decode + Send>,
    pub encode: Box<dyn Encode + Send>,
    pub client: EncryptedEndpoint,
    pub server: EncryptedEndpoint,
    pub authed: bool,

    block: Option<Vec<u8>>, // pub kex_strict: bool,
}

// impl<T> Deref for CipherStream<T>
// where
//     T: AsyncRead + AsyncWrite + Send,
// {
//     type Target = BufferStream<T>;

//     fn deref(&self) -> &Self::Target {
//         &self.stream
//     }
// }

// impl<T> DerefMut for CipherStream<T>
// where
//     T: AsyncRead + AsyncWrite + Send,
// {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.stream
//     }
// }

impl<T> CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    // pub async fn send_new_keys(&mut self) -> Result<()> {
    //     self.send_payload(&[SSH_MSG_NEWKEYS]).await?;
    //     if self.client.kex_strict && self.server.kex_strict {
    //         self.client.sequence_number = 0;
    //         self.server.sequence_number = 0;
    //     }
    //     Ok(())
    // }

    pub async fn recv_packet(&mut self) -> Result<Packet> {
        let mut func = |mut data: Buffer<Vec<u8>>, mac: Option<Vec<u8>>| {
            let (len, data) = data.take_one()?;

            let mut data = Buffer::from_vec(data);

            let padding_len = data.take_u8()?;

            let payload_len = data.len() - padding_len as usize;
            let mut payload = data.take_bytes(payload_len)?;

            let uncompress = self.authed || self.decode.compress_in_auth();

            if uncompress {
                self.decode.update(&payload).ok()?;
                // todo: change payload len ???
                payload = self.decode.finalize().ok()?;
            }

            let padding = data.take_bytes(padding_len as usize)?;
            Some(Packet {
                len,
                padding_len,
                payload,
                padding,
                mac,
            })
        };

        // let server_crypt = &mut self.decrypt;
        // let server_mac = &mut self.server.mac;
        let mac_len = self.server.mac.mac_len();
        let block_size = self.decrypt.block_size();

        // 记录密文
        let mut cipher_text = vec![];

        let (packet_size, packet, mac) = if self.decrypt.has_aad() {
            // let aad = self.stream.read_exact(4).await?;

            let aad = self.stream.fill(4).await?;

            let size = u32::from_be_bytes([aad[0], aad[1], aad[2], aad[3]]);

            if size as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "Aes: Invalid packet length: {size}"
                )));
            }

            // let left = self.stream.read_exact(size as usize).await?;

            // let left = self.stream.fill(4 + size as usize).await?;

            let mut plain_text = vec![];

            // self.decrypt.update(&add_clone, None)?;

            // self.decrypt.update(&left, Some(&mut plain_text))?;

            let mac = if self.decrypt.has_tag() {
                let tag_len = self.decrypt.tag_len();
                let total = 4 + size as usize + tag_len;
                let buf = self.stream.fill(total).await?;

                self.decrypt.update(&buf[..4], None)?;

                self.decrypt
                    .update(&buf[4..4 + size as usize], Some(&mut plain_text))?;

                self.decrypt
                    .set_authentication_tag(&buf[4 + size as usize..])?;

                self.stream.consume_read_buffer(total);
                None
            } else {
                // unreachable here
                let buf = self.stream.fill(4 + size as usize + mac_len).await?;

                self.decrypt.update(&buf[..4], None)?;

                self.decrypt
                    .update(&buf[4..4 + size as usize], Some(&mut plain_text))?;

                cipher_text.extend(&buf[..4 + size as usize]);

                let mac = buf[4 + size as usize..].to_vec();
                self.stream.consume_read_buffer(4 + size as usize + mac_len);
                Some(mac)
            };

            self.decrypt.finalize(&mut plain_text)?;

            (size, plain_text, mac)
        } else if self.server.mac.encrypt_then_mac() {
            let packet_len = self.stream.fill(4).await?;

            let packet_len =
                u32::from_be_bytes([packet_len[0], packet_len[1], packet_len[2], packet_len[3]]);

            if packet_len as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "Etm: Invalid packet length: {packet_len}"
                )));
            }

            let cipher = self.stream.fill(4 + packet_len as usize).await?;
            cipher_text.extend(&cipher[4..]);
            // cipher_text = self.stream.read_exact(packet_len as usize).await?;

            let mut plaint_text = vec![];

            let len = 4 + packet_len as usize;
            let mac = self.stream.fill(len + mac_len).await?;
            let mac = mac[len..].to_vec();

            // must after async/await function
            self.decrypt.update(&cipher_text, Some(&mut plaint_text))?;
            self.decrypt.finalize(&mut plaint_text)?;

            self.stream.consume_read_buffer(len + mac_len);

            (packet_len, plaint_text, Some(mac))
        } else {
            if self.block.is_none() {
                // 解密最少需要一个block的数据
                let size = self.stream.read_exact(block_size).await?;

                let mut out_size = vec![];
                self.decrypt.update(&size, Some(&mut out_size))?;
                self.decrypt.finalize(&mut out_size)?;

                self.block = Some(out_size);

                cipher_text.extend(size);
            }

            let block = self.block.as_ref().unwrap();

            let pakcet_size = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);

            if pakcet_size as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "Normal: Invalid packet length: {pakcet_size}"
                )));
            }

            let left_len = pakcet_size as usize - (block_size - 4);
            let left = self.stream.fill(left_len + mac_len).await?;

            cipher_text.extend(left);

            // 解密数据
            let mut plain_text = vec![];
            // self.decrypt.reset()?;
            self.decrypt
                .update(&left[..left_len], Some(&mut plain_text))?;
            self.decrypt.finalize(&mut plain_text)?;

            // let mac = self.stream.read_exact(mac_len).await?;

            // assert_eq!(mac.len(), mac_len);

            // buffer_first.extend(plain_text);
            let mut buffer = self.block.take().unwrap();
            buffer.drain(..4);
            buffer.extend(plain_text);
            let mac = left[left_len..].to_vec();

            self.stream.consume_read_buffer(left_len + mac_len);

            (pakcet_size, buffer, Some(mac))
        };

        // // 读取mac的结果，准备校验
        // let mac = self.stream.read_exact(mac_len).await?;

        // 重新拼装整一个packet
        let mut buffer = Buffer::new();
        buffer.put_u32(packet_size);
        buffer.put_bytes(packet);

        if let Some(ref mac) = mac {
            // 计算mac所需的sqno
            self.server
                .mac
                .update(&self.server.sequence_number.to_be_bytes())?;
            // 计算mac
            if self.server.mac.encrypt_then_mac() {
                self.server.mac.update(&packet_size.to_be_bytes())?;
                self.server.mac.update(&cipher_text)?;
            } else {
                self.server.mac.update(buffer.as_ref())?;
            }

            let cal = self.server.mac.finalize()?;

            // server_mac.reset()?;

            if &cal != mac {
                return Err(Error::MacVerificationFailed);
            }
        }

        self.server.sequence_number = self.server.sequence_number.wrapping_add(1);
        let packet = func(buffer, mac).ok_or(Error::invalid_format("not enough data"))?;
        if !packet.payload.is_empty()
            && packet.payload[0] == SSH_MSG_NEWKEYS
            && self.client.kex_strict
            && self.server.kex_strict
        {
            self.server.sequence_number = 0;
            self.client.sequence_number = 0;
        }
        Ok(packet)
    }

    pub async fn send_payload(&mut self, payload: impl AsRef<[u8]>) -> Result<()> {
        /*
          If compression has been negotiated, the 'payload' field (and only it)
           will be compressed using the negotiated algorithm.
        */
        let mut payload = payload.as_ref();
        let compress = self.authed || self.encode.compress_in_auth();

        // let payload = payload.to_vec();
        let out;
        if compress {
            self.encode.update(payload)?;
            out = self.encode.finalize()?;
            payload = &out;
        }

        let payload_len = payload.len();
        if payload_len > PAYLOAD_MAXIMUM_SIZE {
            return Err(Error::ub(format!("Payload is too long: {}", payload_len)));
        }
        // ( 4 + 1 + y + x) % 8 = 0
        // x = 8 - (4 + 1 + y + x) % 8
        // (packet_length || padding_length || payload || random padding)

        // let crypt_offset = if self.client.mac.encrypt_then_mac() || self.decrypt.has_aad() {
        //     4
        // } else {
        //     0
        // };

        let crypt_offset = if self.encrypt.has_aad() || self.client.mac.encrypt_then_mac() {
            4
        } else {
            0
        };

        /*
        There MUST be at least four bytes of padding.  The
         padding SHOULD consist of random bytes.  The maximum amount of
         padding is 255 bytes.
         */
        // let mac_cts = &mut self.client.mac;

        let mut block_size = self.encrypt.block_size();
        if block_size < 8 {
            block_size = 8;
        }

        let mut padding_len = block_size - ((4 + 1 + payload_len - crypt_offset) % block_size);
        if padding_len < 4 {
            padding_len += block_size;
        }

        let mut cipher_text = vec![];

        let mut rand_padding = vec![0u8; padding_len];

        // 生成随机padding
        rand_bytes(&mut rand_padding)?;

        let mut packet = Buffer::new();

        let packet_len = payload_len + padding_len + 1;

        packet.put_u32(packet_len as _);

        // 处理aes-gcm的addlen
        if self.encrypt.has_aad() {
            cipher_text.extend(packet.as_ref());
            self.encrypt.update(packet.as_ref(), None)?;
        } else if self.client.mac.encrypt_then_mac() {
            cipher_text.extend(packet.as_ref());
        }

        // WriteBytesExt::write_u32::<byteorder::BigEndian>(&mut packet, packet_len as _)?;
        packet.put_u8(padding_len as u8);

        packet.extend(payload.to_vec());

        packet.extend(rand_padding);

        let mut mac = None;

        if !self.client.mac.encrypt_then_mac() && !self.encrypt.has_tag() {
            let mut buffer = Buffer::new();
            buffer.put_u32(self.client.sequence_number);

            self.client.mac.update(buffer.as_ref())?;
            self.client.mac.update(packet.as_ref())?;
            mac = Some(self.client.mac.finalize()?);
            // println!("!en then mac");
            // self.client.mac.reset()?;
        }

        // println!("send_payload plain text==========: {:?}", payload);
        self.encrypt
            .update(packet[crypt_offset..].as_ref(), Some(&mut cipher_text))?;

        // for i in (crypt_offset..packet.len()).step_by(block_size) {
        //     let left = packet.len() - i;
        //     let bsize = min(block_size, left);
        //     self.encrypt.update(&packet.as_ref()[i..i + bsize], Some(&mut cipher_text))?;
        // }

        self.encrypt.finalize(&mut cipher_text)?;

        cipher_text.extend(mac.unwrap_or_default());

        // if self.client.mac.encrypt_then_mac() && !self.encrypt.has_mac() {
        //     let mut buffer = Buffer::new();
        //     buffer.put_u32(self.client.sequence_number);

        //     self.client.mac.update(buffer.as_ref())?;
        //     self.client.mac.update(&cipher_text)?;
        //     let mac = self.client.mac.finalize()?;

        //     // self.client.mac.reset()?;

        //     cipher_text.extend(mac);
        // }

        if self.encrypt.has_tag() {
            let tag = self.encrypt.authentication_tag()?;
            // println!("send_payload tag: {:?}", tag);
            cipher_text.extend(tag);
        } else if self.client.mac.encrypt_then_mac() {
            let mut buffer = Buffer::new();
            buffer.put_u32(self.client.sequence_number);

            self.client.mac.update(buffer.as_ref())?;
            self.client.mac.update(&cipher_text)?;
            let mac = self.client.mac.finalize()?;

            // self.client.mac.reset()?;

            cipher_text.extend(mac);
        }

        self.stream.write(cipher_text).await?;
        self.stream.flush().await?;

        self.client.sequence_number = self.client.sequence_number.wrapping_add(1);

        Ok(())
    }
}
