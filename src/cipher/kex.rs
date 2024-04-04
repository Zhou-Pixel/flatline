use super::*;
use crate::{
    error::{Error, Result},
    ssh::stream::Stream,
};

use derive_new::new;
use indexmap::IndexMap;
use openssl::{
    bn::{BigNum, BigNumContext, MsbOption},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    md::{Md, MdRef},
    md_ctx::MdCtx,
    nid::Nid,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
};

use super::hash::{Hash, MdWrapper};
use crate::ssh::{self, buffer::Buffer};

use ssh::common::code::*;

algo_list! (
    all,
    new_all,
    new_kex_by_name,
    dyn KeyExChange + Send,
    "curve25519-sha256@libssh.org" => Curve25519::curve25519_sha256(),
    "curve25519-sha256" => Curve25519::curve25519_sha256(),
    "ecdh-sha2-nistp256" => ECDHKexExchange::ecdh_sha2_nistp256(),
    "ecdh-sha2-nistp384" => ECDHKexExchange::ecdh_sha2_nistp384(),
    "ecdh-sha2-nistp521" => ECDHKexExchange::ecdh_sha2_nistp521(),
    "diffie-hellman-group14-sha256" => DiffieHellmanKeyExchange::dh_group14_sha256(),
    "diffie-hellman-group16-sha512" => DiffieHellmanKeyExchange::dh_group16_sha512(),
    "diffie-hellman-group16-sha256" => DiffieHellmanKeyExchange::dh_group16_sha256(),
    "diffie-hellman-group14-sha1" => DiffieHellmanKeyExchange::dh_group14_sha1(),
    "diffie-hellman-group18-sha512" => DiffieHellmanKeyExchange::dh_group18_sha512(),
    "diffie-hellman-group-exchange-sha256" => DiffieHellmanKeyExchangeX::sha256(),
    "diffie-hellman-group-exchange-sha1" => DiffieHellmanKeyExchangeX::sha1(),
    "diffie-hellman-group15-sha512" => DiffieHellmanKeyExchange::dh_group15_sha512(),
    "diffie-hellman-group17-sha512" => DiffieHellmanKeyExchange::dh_group17_sha512(),
    "diffie-hellman-group1-sha1" => DiffieHellmanKeyExchange::dh_group1_sha1(),
);

#[async_trait::async_trait]
pub trait KeyExChange {
    async fn kex(&self, config: Dependency, stream: &mut dyn Stream) -> Result<Summary>;
}

#[derive(new)]
pub struct Dependency {
    client_banner: String,
    client_kexinit: Vec<u8>,
    server_banner: String,
    server_kexinit: Vec<u8>,
    _kex_strict: bool,
}

// impl DhConfig {
//     pub fn new(
//         // stream: &'a mut dyn SshStream,
//         client_banner: Vec<u8>,
//         client_kexinit: Vec<u8>,
//         server_banner: Vec<u8>,
//         server_kexinit: Vec<u8>,
//     ) -> Self {
//         Self {
//             client_banner,
//             client_kexinit,
//             server_banner,
//             server_kexinit,
//         }
//     }
// }

#[derive(new)]
pub struct DiffieHellman {
    p: BigNum,
    g: BigNum,
    group_order: i32,
}

// dh 算法的sha是用来计算session id的
// 比如diffie-hellman-group14-sha256 是通过sha256计算session id

impl DiffieHellman {
    fn make_pri_key(&self) -> Result<BigNum> {
        let mut key = BigNum::new()?;
        key.rand(self.group_order * 8 - 1, MsbOption::TWO_ONES, true)?;
        Ok(key)
    }

    fn make_pub_key(&self, pri_key: &BigNum) -> Result<(BigNum, BigNumContext)> {
        let mut key = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        key.mod_exp(&self.g, pri_key, &self.p, &mut ctx)?;
        Ok((key, ctx))
    }

    fn secret_key(
        &self,
        pri_key: &BigNum,
        remote_pub_key: &BigNum,
        ctx: &mut BigNumContext,
    ) -> Result<BigNum> {
        let mut key = BigNum::new()?;

        key.mod_exp(remote_pub_key, pri_key, &self.p, ctx)?;

        Ok(key)
    }
}

#[derive(new)]
struct DiffieHellmanKeyExchange<'a> {
    p: &'a [u8],
    g: u32,
    hash: &'static MdRef,
    // group_order: i32,
}

#[derive(new)]
pub struct Summary {
    // pub server_hostkey_type: String,
    pub server_hostkey: Vec<u8>,
    pub server_dh_value: Vec<u8>,
    // pub server_signature_type: String,
    pub server_signature: Vec<u8>, // 服务器传过来的
    pub client_hash: Vec<u8>, // 通过算法计算出来的
    pub session_id: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub hash: Box<dyn Hash + Send>,
}

#[async_trait::async_trait]
impl<'a> KeyExChange for DiffieHellmanKeyExchange<'a> {
    async fn kex(&self, config: Dependency, stream: &mut dyn Stream) -> Result<Summary> {
        let mut sha_ctx = MdCtx::new()?;

        sha_ctx.digest_init(self.hash)?;

        let p = BigNum::from_slice(&self.p)?;
        let g = BigNum::from_u32(self.g)?;

        let group_order = self.p.len() as i32;
        let dh = DiffieHellman::new(p, g, group_order);

        let pri_key = dh.make_pri_key()?;
        let (pub_key, mut ctx) = dh.make_pub_key(&pri_key)?;

        let pub_key = if pub_key.num_bits() % 8 == 0 {
            let mut bytes = vec![0; 1];
            bytes.extend(pub_key.to_vec());
            bytes
        } else {
            pub_key.to_vec()
        };

        let mut buffer = Buffer::new();
        // let mut payload = vec![];
        // payload.push(DIFFIE_HELLMAN_KEY_EXCHANGE_INIT);
        buffer.put_u8(SSH_MSG_KEXDH_INIT);
        buffer.put_one(&pub_key);

        // let dh_client = DHKeyExInit::new(pub_key);
        // payload.extend(dh_client.to_bytes());

        // let stream = config.stream;
        // let recv = &mut config.stream;

        // session.send_payload(&payload).await?;
        // let packet = session.read_raw_packet().await?;
        stream.send_payload(buffer.as_ref()).await?;
        let packet = stream.recv_packet().await?;

        let mut payload = Buffer::from_vec(packet.payload);

        // let code = ReadBytesExt::read_u8(&mut payload)?;
        let code = payload.take_u8().unwrap();
        if code != SSH_MSG_KEXDH_REPLY {
            return Err(Error::ProtocolError);
        }

        // let hostkey_parser = |data: Vec<u8>| {

        //     let mut hostkey = Buffer::from_vec(data);

        //     let (_, keytype) = hostkey.take_one()?;

        //     // let (_, key) = hostkey.take_one()?;

        //     Some((keytype, hostkey.into_vec()))

        // };

        // let signature_parser = |data: Vec<u8>| {
        //     let mut sign = Buffer::from_vec(data);

        //     let (_, signtype) =  sign.take_one()?;
        //     let (_, signture) =  sign.take_one()?;

        //     Some((signtype, signture))
        // };

        let (_, hostkey) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse hostkey"))?;

        // let (keytype, key) = hostkey_parser(hostkey.clone()).ok_or(Error::invalid_format("unable to parse hostkey"))?;

        // let keytype = String::from_utf8(keytype)?;

        let (_, f) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse f value"))?;

        let (_, sign) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse signture"))?;

        // let (signtype, signature) = signature_parser(sign).ok_or(Error::ssh_packet_parse("unable to parse signture"))?;

        // let dh_server = DHKeyExInitReply::from_bytes(&mut payload)?;

        let bnf = BigNum::from_slice(&f)?;

        /*
        [10, 87, 66, 109, 6, 170, 208, 174, 116, 146, 15, 150, 93, 217, 154, 233, 93, 241, 37, 253, 199, 204, 219, 138, 227, 14, 228, 201, 30, 28, 20, 144]
         */

        let secret_key = dh.secret_key(&pri_key, &bnf, &mut ctx)?;

        // session.scrt = serk

        // let new_key = ssh::packet::Payload::NewKeys;

        // let new_key = new_key.to_bytes();

        // stream.send_payload(&new_key).await?;
        // session.send_payload(&new_key).await?;

        // session.secret_key = Some(secret_key.clone());

        let mut update = |bytes: &[u8]| {
            // let mut len = [0; 4];
            // WriteBytesExt::write_u32::<BigEndian>(&mut len.as_mut_slice(), bytes.len() as u32)?;

            let buffer = Buffer::from_one(bytes);

            sha_ctx.digest_update(buffer.as_ref())?;
            // sha_ctx.digest_update(&len)?;
            // sha_ctx.digest_update(bytes)?;

            Result::Ok(())
        };

        // let client_banner = session
        //     .client_info
        //     .banner
        //     .as_ref()
        //     .ok_or(anyhow::anyhow!("unreachable code"))?;

        // let client_banner = String::from_utf8(config.client_banner.to_vec())?;

        let client_banner = config.client_banner.trim_end_matches("\r\n").as_bytes();

        // let client_banner_len = client_banner.len() as u32;
        // let mut client_banner_len_bytes = [0; 4];
        // WriteBytesExt::write_u32::<BigEndian>(&mut client_banner_len_bytes.as_mut_slice(), client_banner_len)?;
        // sha_ctx.digest_update(&client_banner)?;
        update(client_banner)?;

        // 服务器的banner
        // let server_banner = session
        //     .server_info
        //     .banner
        //     .as_ref()
        //     .ok_or(anyhow::anyhow!("unreachable code"))?;
        // let server_banner = String::from_utf8(config.server_banner)?;
        let server_banner = config.server_banner.trim_end_matches("\r\n").as_bytes();

        update(server_banner)?;

        // 客户端的kex的packet
        update(&config.client_kexinit)?;

        // 服务器的kex的packet
        update(&config.server_kexinit)?;

        // 服务器公钥
        update(&hostkey)?;

        // let bytes = dh_server.key.to_bytes();
        // if bytes.len() < 4 {
        //     return Err(Error::ssh_packet_parse("host key to short"));
        // }

        // update(&bytes[4..])?;

        // let client_dh_bytes = Buffer::from_one(dh_client.e);

        update(&pub_key)?;

        // let server_dh_bytes = Buffer::from_one(&dh_server.f);
        update(&f)?;

        // let secret_key_bytes = Buffer::from_one(secret_key.to_vec());

        let secret_key = if secret_key.num_bits() % 8 == 0 {
            let mut bytes = vec![0; 1];

            bytes.extend(secret_key.to_vec());
            bytes
        } else {
            secret_key.to_vec()
        };

        update(secret_key.as_ref())?;

        let mut session_id = vec![0; sha_ctx.size()];
        sha_ctx.digest_final(&mut session_id)?;

        // stream.send_new_keys().await?;

        // let packet = stream.recv_packet().await?;

        // if !packet.payload.is_empty() && packet.payload[0] != SSH_MSG_NEWKEYS {
        //     return Err(Error::UnexpectMsg);
        // }

        let hash = MdWrapper::initialize(self.hash)?;
        Ok(Summary {
            // server_hostkey_type: keytype,
            server_hostkey: hostkey,
            server_dh_value: f,
            // server_signature_type: String::from_utf8(signtype)?,
            server_signature: sign,
            secret_key,
            client_hash: session_id.clone(),
            session_id,
            hash: Box::new(hash),
        })
    }
}

impl<'a> DiffieHellmanKeyExchange<'a> {
    const P_GROUP1_VALUE: [u8; 128] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    const P_GROUP14_VALUE: [u8; 256] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3,
        0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3,
        0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70,
        0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77,
        0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5,
        0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39,
        0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ];

    const P_GROUP15_VALUE: [u8; 384] = [
        255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98,
        139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34,
        81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242,
        95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244,
        76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90,
        137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 228, 91, 61, 194,
        0, 124, 184, 161, 99, 191, 5, 152, 218, 72, 54, 28, 85, 211, 154, 105, 22, 63, 168, 253,
        36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28, 98, 243, 86, 32, 133, 82, 187, 158,
        213, 41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116, 108, 8, 202,
        24, 33, 124, 50, 144, 94, 70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39,
        131, 162, 236, 7, 162, 143, 181, 197, 93, 240, 111, 76, 82, 201, 222, 43, 203, 246, 149,
        88, 23, 24, 57, 149, 73, 124, 234, 149, 106, 229, 21, 210, 38, 24, 152, 250, 5, 16, 21,
        114, 142, 90, 138, 170, 196, 45, 173, 51, 23, 13, 4, 80, 122, 51, 168, 85, 33, 171, 223,
        28, 186, 100, 236, 251, 133, 4, 88, 219, 239, 10, 138, 234, 113, 87, 93, 6, 12, 125, 179,
        151, 15, 133, 166, 225, 228, 199, 171, 245, 174, 140, 219, 9, 51, 215, 30, 140, 148, 224,
        74, 37, 97, 157, 206, 227, 210, 38, 26, 210, 238, 107, 241, 47, 250, 6, 217, 138, 8, 100,
        216, 118, 2, 115, 62, 200, 106, 100, 82, 31, 43, 24, 23, 123, 32, 12, 187, 225, 23, 87,
        122, 97, 93, 108, 119, 9, 136, 192, 186, 217, 70, 226, 8, 226, 79, 160, 116, 229, 171, 49,
        67, 219, 91, 252, 224, 253, 16, 142, 75, 130, 209, 32, 169, 58, 210, 202, 255, 255, 255,
        255, 255, 255, 255, 255,
    ];
    const P_GROUP16_VALUE: [u8; 512] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3,
        0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3,
        0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70,
        0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77,
        0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5,
        0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39,
        0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A,
        0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB,
        0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6,
        0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
        0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA,
        0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F,
        0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77,
        0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08,
        0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA,
        0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6,
        0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
        0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 0x28, 0x7C, 0x59,
        0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B,
        0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8,
        0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0,
        0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ];

    const P_GROUP17_VALUE: [u8; 768] = [
        255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98,
        139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34,
        81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242,
        95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244,
        76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90,
        137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 228, 91, 61, 194,
        0, 124, 184, 161, 99, 191, 5, 152, 218, 72, 54, 28, 85, 211, 154, 105, 22, 63, 168, 253,
        36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28, 98, 243, 86, 32, 133, 82, 187, 158,
        213, 41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116, 108, 8, 202,
        24, 33, 124, 50, 144, 94, 70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39,
        131, 162, 236, 7, 162, 143, 181, 197, 93, 240, 111, 76, 82, 201, 222, 43, 203, 246, 149,
        88, 23, 24, 57, 149, 73, 124, 234, 149, 106, 229, 21, 210, 38, 24, 152, 250, 5, 16, 21,
        114, 142, 90, 138, 170, 196, 45, 173, 51, 23, 13, 4, 80, 122, 51, 168, 85, 33, 171, 223,
        28, 186, 100, 236, 251, 133, 4, 88, 219, 239, 10, 138, 234, 113, 87, 93, 6, 12, 125, 179,
        151, 15, 133, 166, 225, 228, 199, 171, 245, 174, 140, 219, 9, 51, 215, 30, 140, 148, 224,
        74, 37, 97, 157, 206, 227, 210, 38, 26, 210, 238, 107, 241, 47, 250, 6, 217, 138, 8, 100,
        216, 118, 2, 115, 62, 200, 106, 100, 82, 31, 43, 24, 23, 123, 32, 12, 187, 225, 23, 87,
        122, 97, 93, 108, 119, 9, 136, 192, 186, 217, 70, 226, 8, 226, 79, 160, 116, 229, 171, 49,
        67, 219, 91, 252, 224, 253, 16, 142, 75, 130, 209, 32, 169, 33, 8, 1, 26, 114, 60, 18, 167,
        135, 230, 215, 136, 113, 154, 16, 189, 186, 91, 38, 153, 195, 39, 24, 106, 244, 226, 60,
        26, 148, 104, 52, 182, 21, 11, 218, 37, 131, 233, 202, 42, 212, 76, 232, 219, 187, 194,
        219, 4, 222, 142, 249, 46, 142, 252, 20, 31, 190, 202, 166, 40, 124, 89, 71, 78, 107, 192,
        93, 153, 178, 150, 79, 160, 144, 195, 162, 35, 59, 161, 134, 81, 91, 231, 237, 31, 97, 41,
        112, 206, 226, 215, 175, 184, 27, 221, 118, 33, 112, 72, 28, 208, 6, 145, 39, 213, 176, 90,
        169, 147, 180, 234, 152, 141, 143, 221, 193, 134, 255, 183, 220, 144, 166, 192, 143, 77,
        244, 53, 201, 52, 2, 132, 146, 54, 195, 250, 180, 210, 124, 112, 38, 193, 212, 220, 178,
        96, 38, 70, 222, 201, 117, 30, 118, 61, 186, 55, 189, 248, 255, 148, 6, 173, 158, 83, 14,
        229, 219, 56, 47, 65, 48, 1, 174, 176, 106, 83, 237, 144, 39, 216, 49, 23, 151, 39, 176,
        134, 90, 137, 24, 218, 62, 219, 235, 207, 155, 20, 237, 68, 206, 108, 186, 206, 212, 187,
        27, 219, 127, 20, 71, 230, 204, 37, 75, 51, 32, 81, 81, 43, 215, 175, 66, 111, 184, 244, 1,
        55, 140, 210, 191, 89, 131, 202, 1, 198, 75, 146, 236, 240, 50, 234, 21, 209, 114, 29, 3,
        244, 130, 215, 206, 110, 116, 254, 246, 213, 94, 112, 47, 70, 152, 12, 130, 181, 168, 64,
        49, 144, 11, 28, 158, 89, 231, 201, 127, 190, 199, 232, 243, 35, 169, 122, 126, 54, 204,
        136, 190, 15, 29, 69, 183, 255, 88, 90, 197, 75, 212, 7, 178, 43, 65, 84, 170, 204, 143,
        109, 126, 191, 72, 225, 216, 20, 204, 94, 210, 15, 128, 55, 224, 167, 151, 21, 238, 242,
        155, 227, 40, 6, 161, 213, 139, 183, 197, 218, 118, 245, 80, 170, 61, 138, 31, 191, 240,
        235, 25, 204, 177, 163, 19, 213, 92, 218, 86, 201, 236, 46, 242, 150, 50, 56, 127, 232,
        215, 110, 60, 4, 104, 4, 62, 143, 102, 63, 72, 96, 238, 18, 191, 45, 91, 11, 116, 116, 214,
        230, 148, 249, 30, 109, 204, 64, 36, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    const P_GROUP18_VALUE: [u8; 1024] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3,
        0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3,
        0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70,
        0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77,
        0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5,
        0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39,
        0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A,
        0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB,
        0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6,
        0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
        0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA,
        0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F,
        0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77,
        0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08,
        0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA,
        0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6,
        0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
        0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 0x28, 0x7C, 0x59,
        0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B,
        0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8,
        0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0,
        0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92, 0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C,
        0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D,
        0xBA, 0x37, 0xBD, 0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
        0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31, 0x17, 0x97, 0x27,
        0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE,
        0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B, 0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33,
        0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
        0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D,
        0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6, 0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98,
        0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE,
        0xC7, 0xE8, 0xF3, 0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
        0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA, 0xCC, 0x8F, 0x6D,
        0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97,
        0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28, 0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5,
        0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
        0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04,
        0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE, 0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74,
        0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12,
        0xFE, 0xE5, 0xE4, 0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0,
        0x73, 0xB9, 0x31, 0xBA, 0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00, 0x74, 0x1F, 0xA7,
        0xBF, 0x8A, 0xFC, 0x47, 0xED, 0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB,
        0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68, 0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23,
        0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D, 0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
        0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0,
        0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B, 0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83,
        0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8, 0x79, 0x68, 0x33, 0x03, 0xED,
        0x5B, 0xDD, 0x3A, 0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 0x6D, 0x2A, 0x13, 0xF8,
        0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36, 0x45, 0x97, 0xE8,
        0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D, 0xF9, 0xAB,
        0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1, 0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 0xFA,
        0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
        0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38,
        0x2B, 0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47, 0x95, 0x58, 0xE4, 0x47, 0x56, 0x77,
        0xE9, 0xAA, 0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80,
        0xB9, 0x6E, 0x71, 0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    ];
    const G_GROUP1_VALUE: u32 = 2;
    const G_GROUP14_VALUE: u32 = 2;
    const G_GROUP15_VALUE: u32 = 2;
    const G_GROUP16_VALUE: u32 = 2;
    const G_GROUP17_VALUE: u32 = 2;
    const G_GROUP18_VALUE: u32 = 2;

    // const fn new() -> Self {
    //     Self {}
    // }

    fn dh_group1_sha1() -> Self {
        Self::new(&Self::P_GROUP1_VALUE, Self::G_GROUP1_VALUE, Md::sha1())
    }

    fn dh_group14_sha1() -> Self {
        Self::new(&Self::P_GROUP14_VALUE, Self::G_GROUP14_VALUE, Md::sha1())
    }

    fn dh_group14_sha256() -> Self {
        Self::new(&Self::P_GROUP14_VALUE, Self::G_GROUP14_VALUE, Md::sha256())
    }

    fn dh_group15_sha512() -> Self {
        Self::new(&Self::P_GROUP15_VALUE, Self::G_GROUP15_VALUE, Md::sha512())
    }

    fn dh_group16_sha512() -> Self {
        Self::new(&Self::P_GROUP16_VALUE, Self::G_GROUP16_VALUE, Md::sha512())
    }

    fn dh_group16_sha256() -> Self {
        Self::new(&Self::P_GROUP16_VALUE, Self::G_GROUP16_VALUE, Md::sha256())
    }

    fn dh_group17_sha512() -> Self {
        Self::new(&Self::P_GROUP17_VALUE, Self::G_GROUP17_VALUE, Md::sha512())
    }

    fn dh_group18_sha512() -> Self {
        Self::new(&Self::P_GROUP18_VALUE, Self::G_GROUP18_VALUE, Md::sha512())
    }
}

#[derive(new)]
struct DiffieHellmanKeyExchangeX {
    hash: &'static MdRef,
    min: u32,
    prefer: u32,
    max: u32,
}

impl DiffieHellmanKeyExchangeX {
    fn sha256() -> Self {
        Self::new(Md::sha256(), 2048, 4096, 8192)
    }

    fn sha1() -> Self {
        Self::new(Md::sha1(), 2048, 4096, 8192)
    }
}

#[async_trait::async_trait]
impl KeyExChange for DiffieHellmanKeyExchangeX {
    async fn kex(&self, deps: Dependency, stream: &mut dyn Stream) -> Result<Summary> {
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH_MSG_KEX_DH_GEX_REQUEST);
        buffer.put_u32(self.min);
        buffer.put_u32(self.prefer);
        buffer.put_u32(self.max);

        stream.send_payload(buffer.as_ref()).await?;

        buffer.take_u8().unwrap();
        let hashreq = buffer.into_vec();

        let packet = stream.recv_packet().await?;

        let mut payload = Buffer::from_vec(packet.payload);

        let code = payload
            .take_u8()
            .ok_or(Error::invalid_format("unable to parse msg"))?;

        if code != SSH_MSG_KEX_DH_GEX_GROUP {
            return Err(Error::ProtocolError);
        }

        let hashpg = payload.clone().into_vec();

        let (_, mut p) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse p value"))?;

        let (_, mut g) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse g value"))?;

        let trim_zero = |data: &mut Vec<u8>| {
            while data.len() > 0 && data[0] == 0 {
                data.remove(0);
            }
        };
        trim_zero(&mut p);
        trim_zero(&mut g);

        let group_order = p.len() as i32;
        let p = BigNum::from_slice(&p)?;
        let g = BigNum::from_slice(&g)?;

        let mut sha_ctx = MdCtx::new()?;

        sha_ctx.digest_init(self.hash)?;

        // let p = BigNum::from_slice(&self.p)?;
        // let g = BigNum::from_u32(self.g)?;

        let dh = DiffieHellman::new(p, g, group_order);

        let pri_key = dh.make_pri_key()?;
        let (pub_key, mut ctx) = dh.make_pub_key(&pri_key)?;

        let pub_key = if pub_key.num_bits() % 8 == 0 {
            let mut bytes = vec![0; 1];
            bytes.extend(pub_key.to_vec());
            bytes
        } else {
            pub_key.to_vec()
        };

        let mut buffer = Buffer::new();
        // let mut payload = vec![];
        // payload.push(DIFFIE_HELLMAN_KEY_EXCHANGE_INIT);
        buffer.put_u8(SSH_MSG_KEX_DH_GEX_INIT);
        buffer.put_one(&pub_key);

        // let dh_client = DHKeyExInit::new(pub_key);
        // payload.extend(dh_client.to_bytes());

        // let stream = config.stream;
        // let recv = &mut config.stream;

        // session.send_payload(&payload).await?;
        // let packet = session.read_raw_packet().await?;
        stream.send_payload(buffer.as_ref()).await?;
        let packet = stream.recv_packet().await?;

        let mut payload = Buffer::from_vec(packet.payload);

        // let code = ReadBytesExt::read_u8(&mut payload)?;
        let code = payload.take_u8().unwrap();
        if code != SSH_MSG_KEX_DH_GEX_REPLY {
            return Err(Error::ProtocolError);
        }

        // let hostkey_parser = |data: Vec<u8>| {

        //     let mut hostkey = Buffer::from_vec(data);

        //     let (_, keytype) = hostkey.take_one()?;

        //     // let (_, key) = hostkey.take_one()?;

        //     Some((keytype, hostkey.into_vec()))

        // };

        // let signature_parser = |data: Vec<u8>| {
        //     let mut sign = Buffer::from_vec(data);

        //     let (_, signtype) =  sign.take_one()?;
        //     let (_, signture) =  sign.take_one()?;

        //     Some((signtype, signture))
        // };

        let (_, hostkey) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse hostkey"))?;

        // let (keytype, key) = hostkey_parser(hostkey.clone()).ok_or(Error::ssh_packet_parse("unable to parse hostkey"))?;

        // let keytype = String::from_utf8(keytype)?;

        let (_, f) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse f value"))?;

        let (_, sign) = payload
            .take_one()
            .ok_or(Error::invalid_format("unable to parse signture"))?;

        // let (signtype, signature) = signature_parser(sign).ok_or(Error::ssh_packet_parse("unable to parse signture"))?;

        // let dh_server = DHKeyExInitReply::from_bytes(&mut payload)?;

        let bnf = BigNum::from_slice(&f)?;

        /*
        [10, 87, 66, 109, 6, 170, 208, 174, 116, 146, 15, 150, 93, 217, 154, 233, 93, 241, 37, 253, 199, 204, 219, 138, 227, 14, 228, 201, 30, 28, 20, 144]
         */

        let secret_key = dh.secret_key(&pri_key, &bnf, &mut ctx)?;

        // session.scrt = serk

        // let new_key = ssh::packet::Payload::NewKeys;

        // let new_key = new_key.to_bytes();

        // stream.send_payload(&new_key).await?;
        // session.send_payload(&new_key).await?;

        // session.secret_key = Some(secret_key.clone());

        let mut update = |bytes: &[u8]| {
            let buffer = Buffer::from_one(bytes);

            sha_ctx.digest_update(buffer.as_ref())?;

            Result::Ok(())
        };

        // let client_banner = String::from_utf8(config.client_banner.to_vec())?;

        let client_banner = deps.client_banner.trim_end_matches("\r\n").as_bytes();

        // let client_banner_len = client_banner.len() as u32;
        // let mut client_banner_len_bytes = [0; 4];
        // WriteBytesExt::write_u32::<BigEndian>(&mut client_banner_len_bytes.as_mut_slice(), client_banner_len)?;
        // sha_ctx.digest_update(&client_banner)?;
        update(client_banner)?;

        // 服务器的banner
        // let server_banner = session
        //     .server_info
        //     .banner
        //     .as_ref()
        //     .ok_or(anyhow::anyhow!("unreachable code"))?;
        // let server_banner = String::from_utf8(config.server_banner)?;
        let server_banner = deps.server_banner.trim_end_matches("\r\n").as_bytes();

        update(server_banner)?;

        // 客户端的kex的packet
        update(&deps.client_kexinit)?;

        // 服务器的kex的packet
        update(&deps.server_kexinit)?;

        update(&hostkey)?;

        drop(update); // .............

        sha_ctx.digest_update(&hashreq)?; // can't mut twice
        sha_ctx.digest_update(&hashpg)?;

        let mut update = |bytes: &[u8]| {
            let buffer = Buffer::from_one(bytes);

            sha_ctx.digest_update(buffer.as_ref())?;

            Result::Ok(())
        };

        // // 服务器公钥
        // let bytes = dh_server.key.to_bytes();
        // if bytes.len() < 4 {
        //     return Err(Error::ssh_packet_parse("host key to short"));
        // }

        // update(&bytes[4..])?;

        // let client_dh_bytes = Buffer::from_one(dh_client.e);

        update(&pub_key)?;

        // let server_dh_bytes = Buffer::from_one(&dh_server.f);
        update(&f)?;

        // let secret_key_bytes = Buffer::from_one(secret_key.to_vec());

        let secret_key = if secret_key.num_bits() % 8 == 0 {
            let mut bytes = vec![0; 1];

            bytes.extend(secret_key.to_vec());
            bytes
        } else {
            secret_key.to_vec()
        };

        update(secret_key.as_ref())?;

        let mut session_id = vec![0; sha_ctx.size()];
        sha_ctx.digest_final(&mut session_id)?;

        // stream.send_new_keys().await?;

        // let packet = stream.recv_packet().await?;

        // if !packet.payload.is_empty() && packet.payload[0] != SSH_MSG_NEWKEYS {
        //     return Err(Error::UnexpectMsg);
        // }

        let hash = MdWrapper::initialize(self.hash)?;
        Ok(Summary {
            // server_hostkey_type: keytype,
            server_hostkey: hostkey,
            server_dh_value: f,
            // server_signature_type: String::from_utf8(signtype)?,
            server_signature: sign,
            secret_key,
            client_hash: session_id.clone(),
            session_id,
            hash: Box::new(hash),
        })
    }
}

#[derive(new)]
pub struct ECDHKexExchange {
    nid: Nid,
    hash: &'static MdRef,
}

impl ECDHKexExchange {
    fn ecdh_sha2_nistp256() -> Self {
        Self::new(Nid::X9_62_PRIME256V1, Md::sha256())
    }

    fn ecdh_sha2_nistp384() -> Self {
        Self::new(Nid::SECP384R1, Md::sha384())
    }

    fn ecdh_sha2_nistp521() -> Self {
        Self::new(Nid::SECP521R1, Md::sha512())
    }
}

#[async_trait::async_trait]
impl KeyExChange for ECDHKexExchange {
    async fn kex(&self, config: Dependency, stream: &mut dyn Stream) -> Result<Summary> {
        let group = EcGroup::from_curve_name(self.nid)?;

        let private_key = EcKey::generate(&group)?;

        let public_key = private_key.public_key();

        let mut ctx = BigNumContext::new()?;
        let pkey = public_key.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        let private_key: PKey<_> = private_key.try_into()?;

        // send client public key to server
        let mut buffer = Buffer::new();
        buffer.put_u8(SSH2_MSG_KEX_ECDH_INIT);
        buffer.put_one(&pkey);

        stream.send_payload(buffer.as_ref()).await?;

        // recv server public key
        let packet = stream.recv_packet().await?;

        let mut payload = Buffer::from_vec(packet.payload);

        let code = payload
            .take_u8()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        if code != SSH2_MSG_KEX_ECDH_REPLY {
            return Err(Error::ProtocolError);
        }

        // hostkey
        let (_, hostkey) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        // server public key
        let (_, keyqs) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        // server signature
        let (_, signature) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        // let mut ctx = BigNumContext::new()?;
        let server_pk = EcPoint::from_bytes(&group, &keyqs, &mut ctx)?;

        let server_pk = EcKey::from_public_key(&group, &server_pk)?;

        let server_pk: PKey<_> = server_pk.try_into()?;

        let mut deriver = Deriver::new(&private_key)?;

        deriver.set_peer(&server_pk)?;

        // the server key is exactly the same as this one
        let secret_key = deriver.derive_to_vec()?;

        let mut hash = MdWrapper::initialize(self.hash)?;

        let mut update = |data: &[u8]| {
            let buffer = Buffer::from_one(data);
            hash.update(buffer.as_ref())?;
            Result::Ok(())
        };

        fn check(data: &[u8]) -> Vec<u8> {
            let bn = BigNum::from_slice(data).unwrap();
            let mut bndata = bn.to_vec();

            if bn.num_bits() % 8 == 0 {
                bndata.insert(0, 0);
            }

            bndata
        }

        let secret_key = check(&secret_key);
        // check(&pkey);

        update(config.client_banner.trim_end_matches("\r\n").as_bytes())?;
        update(config.server_banner.trim_end_matches("\r\n").as_bytes())?;
        update(&config.client_kexinit)?;
        update(&config.server_kexinit)?;
        update(&hostkey)?;
        update(&pkey)?;
        update(&keyqs)?;
        update(&secret_key)?;

        let client_signature = hash.finalize()?;

        let sum = Summary::new(
            hostkey,
            keyqs,
            signature,
            client_signature.clone(),
            client_signature,
            secret_key,
            Box::new(hash),
        );

        Ok(sum)
    }
}

#[derive(new)]
struct Curve25519 {
    hash: &'static MdRef,
}

impl Curve25519 {
    fn curve25519_sha256() -> Self {
        Self::new(Md::sha256())
    }
}


#[async_trait::async_trait]
impl KeyExChange for Curve25519 {
    async fn kex(&self, config: Dependency, stream: &mut dyn Stream) -> Result<Summary> {
        let mut ctx = PkeyCtx::new_id(Id::X25519)?;

        ctx.keygen_init()?;

        let private = ctx.keygen()?;


        let public_bytes = private.raw_public_key()?;

        let mut buffer = Buffer::new();

        buffer.put_u8(SSH2_MSG_KEX_ECDH_INIT);
        buffer.put_one(&public_bytes);

        stream.send_payload(buffer.as_ref()).await?;

        let packet = stream.recv_packet().await?;

        let mut payload = Buffer::from_vec(packet.payload);

        if payload.take_u8() != Some(SSH2_MSG_KEX_ECDH_REPLY) {
            return Err(Error::ProtocolError);
        }

        // hostkey
        let (_, hostkey) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        // server public key
        let (_, keyqs) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        // server signature
        let (_, signature) = payload
            .take_one()
            .ok_or(Error::invalid_format("invalid packet format"))?;

        let server_public = PKey::public_key_from_raw_bytes(&keyqs, Id::X25519)?;

        let mut server_ctx = PkeyCtx::new(&private)?;

        server_ctx.derive_init()?;
        server_ctx.derive_set_peer(&server_public)?;
        let size = server_ctx.derive(None)?;

        let mut secret_key = vec![0; size];

        server_ctx.derive(Some(&mut secret_key))?;

        
        let mut hash = MdWrapper::initialize(self.hash)?;

        let mut update = |data: &[u8]| {
            let buffer = Buffer::from_one(data);
            hash.update(buffer.as_ref())?;
            Result::Ok(())
        };

        fn check(data: &[u8]) -> Vec<u8> {
            let bn = BigNum::from_slice(data).unwrap();
            let mut bndata = bn.to_vec();

            if bn.num_bits() % 8 == 0 {
                bndata.insert(0, 0);
            }

            bndata
        }

        let secret_key = check(&secret_key);
        // check(&pkey);

        update(config.client_banner.trim_end_matches("\r\n").as_bytes())?;
        update(config.server_banner.trim_end_matches("\r\n").as_bytes())?;
        update(&config.client_kexinit)?;
        update(&config.server_kexinit)?;
        update(&hostkey)?;
        update(&public_bytes)?;
        update(&keyqs)?;
        update(&secret_key)?;

        let client_signature = hash.finalize()?;

        let sum = Summary::new(
            hostkey,
            keyqs,
            signature,
            client_signature.clone(),
            client_signature,
            secret_key,
            Box::new(hash),
        );

        Ok(sum)

    }
}