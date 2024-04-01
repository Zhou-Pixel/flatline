use std::{
    io,
    mem::{size_of, take},
    ops::{Deref, DerefMut},
};

// trait Stream {
//     async fn send_payload(&mut self, payload: &[u8]) -> SshResult<()>;
//     async fn recv_packet(&mut self) -> SshResult<Packet>;
// }

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
impl<T> Stream for &mut CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        CipherStream::send_payload(self, payload).await
    }
    async fn recv_packet(&mut self) -> Result<Packet> {
        CipherStream::recv_packet(self).await
    }

    async fn send_new_keys(&mut self) -> Result<()> {
        CipherStream::send_new_keys(self).await
    }
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
    ssh::{buffer::Buffer, packet},
};

use super::common::{code::*, PAYLOAD_MAXIMUM_SIZE};

pub struct BufferStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    socket: T,
    r_buf: BytesMut,
    w_buf: BytesMut,
}

impl<T: AsyncRead + AsyncWrite + Unpin> BufferStream<T> {
    pub fn new(socket: T) -> Self {
        Self {
            socket,
            r_buf: BytesMut::new(),
            w_buf: BytesMut::new(),
        }
    }

    async fn internal_read(&mut self) -> io::Result<usize> {
        let size = self.socket.read_buf(&mut self.r_buf).await?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        Ok(size)
        // self.socket.read_buf(&mut self.r_buf).await
    }

    pub async fn read_line_lf(&mut self) -> io::Result<Vec<u8>> {
        loop {
            // todo: improve performance
            let pos = self.r_buf.iter().position(|&x| x == b'\n');
            if let Some(pos) = pos {
                return Ok(self.r_buf.split_to(pos).to_vec());
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

    pub async fn read_buf_at_least(&mut self) -> io::Result<Vec<u8>> {
        self.socket.read_buf(&mut self.r_buf).await?;

        Ok(take(&mut self.r_buf).to_vec())
    }

    pub async fn read_buf(&mut self) -> io::Result<Vec<u8>> {
        if self.r_buf.is_empty() {
            self.socket.read_buf(&mut self.r_buf).await?;
        }
        Ok(take(&mut self.r_buf).to_vec())
    }

    pub async fn write(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        self.w_buf.put(data.as_ref());

        self.socket.write_buf(&mut self.w_buf).await.map(|_| ())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        while !self.w_buf.is_empty() {
            self.socket.write_buf(&mut self.w_buf).await?;
        }
        self.socket.flush().await
    }

    pub async fn read_exact(&mut self, size: usize) -> io::Result<Vec<u8>> {
        while self.r_buf.len() < size {
            self.internal_read().await?;
        }

        Ok(self.r_buf.split_to(size).to_vec())
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
    // pub kex_strict: bool
}

impl<T> Deref for PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    type Target = BufferStream<T>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<T> DerefMut for PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

// #[derive(Default)]
pub struct EncryptedEndpoint {
    // pub cipher: Box<dyn Decrypt + Send>,
    pub mac: Box<dyn Mac + Send>,
    pub kex_strict: bool,
    pub sequence_number: u32,
    // pub compress: Option<Box<dyn Encode + Send>>,
}

impl<T> PlainStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(socket: T) -> Self {
        Self {
            stream: BufferStream::new(socket),
            client: Default::default(),
            server: Default::default(),
            // kex_strict: false
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
        let size = self.stream.read_exact(size_of::<u32>()).await?;

        let mut size = Buffer::from_vec(size);
        let size = size.take_u32().unwrap();
        if size as usize > PACKET_MAXIMUM_SIZE - 4 {
            return Err(Error::invalid_format(format!(
                "invalid packet length: {size}"
            )));
        }

        let data = self.stream.read_exact(size as _).await?;

        let pakcet =
            Packet::parse(data, None).ok_or(Error::invalid_format("can't parse packet"))?;

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
        if padding_len < 4 && padding_len != 0 {
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
    // pub kex_strict: bool,
}

impl<T> Deref for CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    type Target = BufferStream<T>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<T> DerefMut for CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl<T> CipherStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn send_new_keys(&mut self) -> Result<()> {
        self.send_payload(&[SSH_MSG_NEWKEYS]).await?;
        if self.client.kex_strict && self.server.kex_strict {
            self.client.sequence_number = 0;
            self.server.sequence_number = 0;
        }
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Result<Packet> {
        let mut func = |mut data: Buffer, mac: Option<Vec<u8>>| {
            // let size = size.get_u32();
            let (len, data) = data.take_one()?;

            let mut data = Buffer::from_vec(data);

            let padding_len = data.take_u8()?;

            let payload_len = data.len() - padding_len as usize;
            let mut payload = data.take_bytes(payload_len)?;

            let uncompress = self.authed || self.decode.compress_in_auth();

            if uncompress {
                self.decode.update(&payload).unwrap();
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
            let aad = self.stream.read_exact(4).await?;

            cipher_text.extend(aad.clone());

            let mut aad = Buffer::from_vec(aad);
            let size = aad.take_u32().unwrap();

            if size as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "invalid packet length: {size}"
                )));
            }

            let left = self.stream.read_exact(size as usize).await?;
            cipher_text.extend(left.clone());

            let mut plain_text = vec![];

            aad.put_u32(size);
            self.decrypt.update(aad.as_ref(), None)?;

            self.decrypt.update(&left, Some(&mut plain_text))?;

            let mac = if self.decrypt.has_tag() {
                let tag = self.stream.read_exact(16).await?;
                self.decrypt.set_authentication_tag(&tag)?;
                None
            } else {
                let mac = self.stream.read_exact(mac_len).await?;
                Some(mac)
            };

            self.decrypt.finalize(&mut plain_text)?;

            // self.decrypt.reset()?;
            // println!("final: {res:?}");

            // panic!("");

            (size, plain_text, mac)
        } else if self.server.mac.encrypt_then_mac() {
            let packet_len = self.stream.read_exact(4).await?;
            let mut packet_len = Buffer::from_vec(packet_len);

            let packet_len = packet_len.take_u32().unwrap();

            if packet_len as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "invalid packet length: {packet_len}"
                )));
            }

            cipher_text = self.stream.read_exact(packet_len as usize).await?;

            let mut plaint_text = vec![];

            self.decrypt.update(&cipher_text, Some(&mut plaint_text))?;
            self.decrypt.finalize(&mut plaint_text)?;

            let mac = self.stream.read_exact(mac_len).await?;

            (packet_len, plaint_text, Some(mac))
        } else {
            // 解密最少需要一个block的数据
            let size = self.stream.read_exact(block_size).await?;
            cipher_text.extend(size.clone());

            let mut out_size = vec![];
            self.decrypt.update(&size, Some(&mut out_size))?;
            self.decrypt.finalize(&mut out_size)?;

            let mut buffer_first = Buffer::from_vec(out_size);

            // 所有block都大于等于8, 直接使用unwrap
            let pakcet_size = buffer_first.take_u32().unwrap() as u32;

            if pakcet_size as usize > PACKET_MAXIMUM_SIZE - 4 {
                return Err(Error::invalid_format(format!(
                    "invalid packet length: {pakcet_size}"
                )));
            }
            

            let left = self
                .stream
                .read_exact(pakcet_size as usize - (block_size - 4))
                .await?;
            cipher_text.extend(left.clone());

            // 解密数据
            let mut plain_text = vec![];
            // self.decrypt.reset()?;
            self.decrypt.update(&left, Some(&mut plain_text))?;
            self.decrypt.finalize(&mut plain_text)?;

            let mac = self.stream.read_exact(mac_len).await?;
            buffer_first.extend(plain_text);
            (pakcet_size, buffer_first.into_vec(), Some(mac))
        };

        // // 读取mac的结果，准备校验
        // let mac = self.stream.read_exact(mac_len).await?;

        // 重新拼装整一个packet
        let mut buffer = Buffer::new();
        buffer.put_u32(packet_size);
        buffer.put_bytes(packet);

        if let Some(ref mac) = mac {
            // 计算mac所需的sqno
            let mut sqnobuf = Buffer::new();
            sqnobuf.put_u32(self.server.sequence_number);
            self.server.mac.update(sqnobuf.as_ref())?;
            // 计算mac
            if self.server.mac.encrypt_then_mac() {
                let mut pbuf = Buffer::new();
                pbuf.put_u32(packet_size);
                self.server.mac.update(pbuf.as_ref())?;
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

    pub async fn send_payload(&mut self, mut payload: &[u8]) -> Result<()> {
        // let en = &mut self.encrypt;

        /*
          If compression has been negotiated, the 'payload' field (and only it)
           will be compressed using the negotiated algorithm.
        */
        let compress = self.authed || self.encode.compress_in_auth();

        // let payload = payload.to_vec();
        let out;
        if compress {
            self.encode.update(&payload)?;
            out = self.encode.finalize()?;
            payload = &out;
        }

        let payload_len = payload.len();
        if payload_len > PAYLOAD_MAXIMUM_SIZE {
            return Err(Error::ub("payload is too long"));
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
        if padding_len < 4 && padding_len != 0 {
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

        self.socket.write(cipher_text.as_ref()).await?;
        self.socket.flush().await?;

        self.client.sequence_number = self.client.sequence_number.wrapping_add(1);

        Ok(())
    }
}
