use crate::error::{Error, Result};
use derive_new::new;
use indexmap::IndexMap;
use openssl::{
    md::{Md, MdRef},
    md_ctx::MdCtx,
    pkey::{PKey, Private},
};
use super::*;

pub trait Mac {
    fn encrypt_then_mac(&self) -> bool;
    fn key_len(&self) -> usize;
    fn mac_len(&self) -> usize;
    fn initialize(&mut self, key: &[u8]) -> Result<()>;
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(&mut self) -> Result<Vec<u8>>;
}

#[derive(new)]
pub struct HMac {
    mac_len: usize,
    key_len: usize,
    ctx: Option<MdCtx>,
    key: Option<PKey<Private>>,
    encrypt_then_mac: bool,
    digest: &'static MdRef,
}

impl HMac {
    fn get_ctx_mut(&mut self) -> Result<&mut MdCtx> {
        match self.ctx {
            Some(ref mut ctx) => Ok(ctx),
            None => Err(crate::error::Error::ub("uninitilze")),
        }
    }
}

impl Mac for HMac {
    fn encrypt_then_mac(&self) -> bool {
        self.encrypt_then_mac
    }
    fn key_len(&self) -> usize {
        self.key_len
    }

    fn mac_len(&self) -> usize {
        self.mac_len
    }

    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let pkey = PKey::hmac(key)?;

        let mut ctx = MdCtx::new()?;
        ctx.digest_sign_init(Some(self.digest), &pkey)?;
        
        self.ctx = Some(ctx);
        self.key = Some(pkey);
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        self.get_ctx_mut()?.digest_sign_update(data).map_err(|e| e.into())
    }

    fn finalize(&mut self) -> Result<Vec<u8>> {
        let ctx = self.ctx.as_mut().ok_or(Error::ub("uninitilize"))?;

        let size = ctx.digest_sign_final(None)?;
        let mut buf = vec![0; size];
        ctx.digest_sign_final(Some(&mut buf))?;
        buf.truncate(self.mac_len);

        // self.ctx = MdCtx::new()?;

        ctx.reset()?;
        if let Some(ref pkey) = self.key {
            ctx.digest_sign_init(Some(self.digest), pkey)?;
        }
        Ok(buf)
    }


}



algo_list!(
    all,
    new_all,
    new_mac_by_name,
    dyn Mac + Send,
    "hmac-sha1" => HMac {
        mac_len: 20,
        key_len: 20,
        ctx: None,
        key: None,
        encrypt_then_mac: false,
        digest: Md::sha1(),
    },
    "hmac-sha1-etm@openssh.com" => HMac {
        mac_len: 20,
        key_len: 20,
        ctx: None,
        key: None,
        encrypt_then_mac: true,
        digest: Md::sha1(),
    },
    "hmac-sha1-96" => HMac::new(
        12,
        20,
        None,
        None,
        false,
        Md::sha1(),
    ),
    "hmac-sha1-96-etm@openssh.com" => HMac::new(
        12,
        20,
        None,
        None,
        true,
        Md::sha1(),
    ),
    "hmac-md5" => HMac::new(
        16,
        16,
        None,
        None,
        false,
        Md::md5(),
    ),
    "hmac-md5-etm@openssh.com" => HMac::new(
        16,
        16,
        None,
        None,
        false,
        Md::md5(),
    ),
    "hmac-md5-96" => HMac::new(
        12,
        16,
        None,
        None,
        false,
        Md::md5(),
    ),
    "hmac-md5-96-etm@openssh.com" => HMac::new(
        12,
        16,
        None,
        None,
        true,
        Md::md5(),
    ),
    "hmac-sha2-512" => HMac::new(
        64,
        64,
        None,
        None,
        false,
        Md::sha512(),
    ),
    "hmac-sha2-512-etm@openssh.com" => HMac::new(
        64,
        64,
        None,
        None,
        true,
        Md::sha512(),
    ),
    "hmac-sha2-256" => HMac::new(
        32,
        32,
        None,
        None,
        false,
        Md::sha256(),
    ),
    "hmac-sha2-256-etm@openssh.com" => HMac::new(
        32,
        32,
        None,
        None,
        true,
        Md::sha256(),
    ),
    "hmac-ripemd160" => HMac::new(
        20,
        20,
        None,
        None,
        false,
        Md::ripemd160(),
    ),
    "hmac-ripemd160@openssh.com" => HMac::new(
        20,
        20,
        None,
        None,
        false,
        Md::ripemd160(),
    ),
    "hmac-ripemd160-etm@openssh.com" => HMac::new(
        20,
        20,
        None,
        None,
        true,
        Md::ripemd160(),
    ),   
);


