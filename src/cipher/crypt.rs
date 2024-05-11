use super::*;
use crate::error::{Error, Result};
use derive_new::new;
use indexmap::IndexMap;
use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
    md_ctx::MdCtx,
    pkey::{Id, PKey},
    symm::{self, Crypter},
};

algo_list!(
    encrypt_all,
    new_encrypt_all,
    new_encrypt_by_name,
    dyn Encrypt + Send,
    "chacha20-poly1305@openssh.com" => Chacha20Poly1205::new(),
    "aes256-gcm@openssh.com" => Gcm::aes256_gcm_openssh(),
    "aes128-gcm@openssh.com" => Gcm::aes128_gcm_openssh(),
    "aes256-ctr" => CbcCtr::aes256_ctr(),
    "aes128-cbc" => CbcCtr::aes128_cbc(),
    "aes192-cbc" => CbcCtr::aes192_cbc(),
    "aes256-cbc" => CbcCtr::aes256_cbc(),
    "aes128-ctr" => CbcCtr::aes128_ctr(),
    "aes192-ctr" => CbcCtr::aes192_ctr(),
    "rijndael-cbc@lysator.liu.se" => CbcCtr::aes256_cbc(),
    "3des-cbc" => CbcCtr::des_ede3_cbc(),
);

algo_list!(
    decrypt_all,
    new_decrypt_all,
    new_decrypt_by_name,
    dyn Decrypt + Send,
    "chacha20-poly1305@openssh.com" => Chacha20Poly1205::new(),
    "aes256-gcm@openssh.com" => Gcm::aes256_gcm_openssh(),
    "aes128-gcm@openssh.com" => Gcm::aes128_gcm_openssh(),
    "aes256-ctr" => CbcCtr::aes256_ctr(),
    "aes128-cbc" => CbcCtr::aes128_cbc(),
    "aes192-cbc" => CbcCtr::aes192_cbc(),
    "aes256-cbc" => CbcCtr::aes256_cbc(),
    "aes128-ctr" => CbcCtr::aes128_ctr(),
    "aes192-ctr" => CbcCtr::aes192_ctr(),
    "rijndael-cbc@lysator.liu.se" => CbcCtr::aes256_cbc(),
    "3des-cbc" => CbcCtr::des_ede3_cbc(),
);

#[derive(new)]
struct Gcm {
    name: String,
    cipher: symm::Cipher,
    block_size: usize,
    key_len: usize,
    iv_len: usize,

    #[new(value = "16")]
    tag_len: usize,
    #[new(value = "true")]
    increase_iv: bool,
    #[new(default)]
    iv: Option<Vec<u8>>,
    #[new(default)]
    key: Option<Vec<u8>>,
    #[new(default)]
    ctx: Option<Crypter>,
}

impl Gcm {
    fn aes128_gcm_openssh() -> Self {
        Self::new(
            "aes128-gcm@openssh.com".to_string(),
            symm::Cipher::aes_128_gcm(),
            16,
            16,
            12,
        )
    }
    fn aes256_gcm_openssh() -> Self {
        Self::new(
            "aes256-gcm@openssh.com".to_string(),
            symm::Cipher::aes_256_gcm(),
            16,
            32,
            12,
        )
    }
}

impl Gcm {
    fn get_ctx(&mut self) -> Result<&mut Crypter> {
        self.ctx.as_mut().ok_or(Error::ub("Uninitialized"))
    }

    fn reset(&mut self, mode: symm::Mode) -> Result<()> {
        match (&self.key, &mut self.iv) {
            /*
                   With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
                   fixed field and an 8-octet invocation counter field.  The invocation
                   field is treated as a 64-bit integer and is incremented after each
                   invocation of AES-GCM to process a binary packet.
            */
            (Some(key), Some(iv)) => {
                assert_eq!(iv.len(), 12);
                if self.increase_iv {
                    // let u64 = BigEndian::read_u64(&iv[4..]).wrapping_add(1);
                    for i in (4..12).rev() {
                        iv[i] = iv[i].wrapping_add(1);
                        if iv[i] != 0 {
                            break;
                        }
                    }
                }
                let ctx = Crypter::new(self.cipher, mode, key, Some(iv))?;
                self.ctx = Some(ctx);
                Ok(())
            }
            _ => Err(Error::ub("Uninitlized")),
        }
    }
}

impl Encrypt for Gcm {
    fn name(&self) -> &str {
        &self.name
    }

    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
    }

    fn enable_increase_iv(&mut self, enable: bool) {
        self.increase_iv = enable;
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn iv_len(&self) -> usize {
        self.iv_len
    }

    fn key_len(&self) -> usize {
        self.key_len
    }

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()> {
        let mut ctx = Crypter::new(self.cipher, symm::Mode::Encrypt, key, Some(iv))?;
        ctx.pad(false);
        self.ctx = Some(ctx);
        self.iv = Some(iv.to_vec());
        self.key = Some(key.to_vec());
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> Result<usize> {
        let base = buf.len();
        buf.resize(base + data.len() + self.block_size, 0);
        let len = self.get_ctx()?.update(data, &mut buf[base..])?;
        buf.truncate(base + len);
        Ok(len)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let base = buf.len();
        buf.resize(base + self.block_size, 0);
        let len = self.get_ctx()?.finalize(&mut buf[base..])?;
        buf.truncate(base + len);
        Ok(len)
    }

    fn authentication_tag(&mut self) -> Result<Vec<u8>> {
        let mut tag = vec![0; 16];
        self.get_ctx()?.get_tag(&mut tag)?;
        self.reset(symm::Mode::Encrypt)?;
        Ok(tag)
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn update_sequence_number(&mut self, _: u32) -> Result<()> {
        Ok(())
    }

    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()> {
        self.get_ctx()?.aad_update(aad).map_err(|e| e.into())
    }
}

impl Decrypt for Gcm {
    fn name(&self) -> &str {
        &self.name
    }

    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn enable_increase_iv(&mut self, enable: bool) {
        self.increase_iv = enable;
    }

    fn iv_len(&self) -> usize {
        self.iv_len
    }

    fn key_len(&self) -> usize {
        self.key_len
    }

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()> {
        let mut ctx = Crypter::new(self.cipher, symm::Mode::Decrypt, key, Some(iv))?;
        ctx.pad(false);
        self.ctx = Some(ctx);
        self.key = Some(key.to_vec());
        self.iv = Some(iv.to_vec());
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> Result<usize> {
        let base = buf.len();
        buf.resize(base + data.len() + self.block_size, 0);
        let len = self.get_ctx()?.update(data, &mut buf[base..])?;
        buf.truncate(base + len);
        Ok(len)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let base = buf.len();
        buf.resize(base + self.block_size, 0);
        let len = self.get_ctx()?.finalize(&mut buf[base..])?;
        buf.truncate(base + len);
        self.reset(symm::Mode::Decrypt)?;
        Ok(len)
    }

    fn set_authentication_tag(&mut self, data: &[u8]) -> Result<()> {
        self.get_ctx()?.set_tag(data)?;
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn update_sequence_number(&mut self, _: u32) -> Result<()> {
        Ok(())
    }

    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()> {
        self.get_ctx()?.aad_update(aad)?;
        Ok(())
    }
}

pub trait Encrypt {
    fn name(&self) -> &str;
    fn has_tag(&self) -> bool;
    fn has_aad(&self) -> bool;
    fn enable_increase_iv(&mut self, enable: bool);
    fn block_size(&self) -> usize;
    fn iv_len(&self) -> usize;
    fn key_len(&self) -> usize;
    fn tag_len(&self) -> usize;

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()>;
    fn update_sequence_number(&mut self, number: u32) -> Result<()>;
    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()>;
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<usize>;
    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize>;
    fn authentication_tag(&mut self) -> Result<Vec<u8>>;
    // fn reset(&mut self) -> Result<()>;
    // fn decrypt_init(&mut self, iv: &[u8], key: &[u8]) -> Result<()>;
    // fn decrypt_update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> Result<usize>;
    // fn decrypt_final(&mut self, buf: &mut Vec<u8>) -> Result<usize>;
}

pub trait Decrypt {
    fn name(&self) -> &str;
    fn has_tag(&self) -> bool;
    fn has_aad(&self) -> bool;
    fn block_size(&self) -> usize;
    fn enable_increase_iv(&mut self, enable: bool);
    fn iv_len(&self) -> usize;
    fn key_len(&self) -> usize;
    fn tag_len(&self) -> usize;

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()>;
    fn update_sequence_number(&mut self, number: u32) -> Result<()>;
    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()>;
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<usize>;
    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize>;
    fn set_authentication_tag(&mut self, data: &[u8]) -> Result<()>;

    // must return a object that is uninitialzed;
    // fn copy(&self) -> Result<Box<dyn Decrypt>>;
    // fn reset(&mut self) -> Result<()>;
}

impl Encrypt for CbcCtr {
    fn has_tag(&self) -> bool {
        self.has_tag
    }

    fn has_aad(&self) -> bool {
        self.has_aad
    }

    fn block_size(&self) -> usize {
        self.args.block_size
    }

    fn iv_len(&self) -> usize {
        self.args.iv_len
    }

    fn key_len(&self) -> usize {
        self.args.key_len
    }

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()> {
        let mut cipher = CipherCtx::new()?;
        cipher.encrypt_init(Some(self.args.cipher), Some(key), Some(iv))?;
        cipher.set_padding(false);
        self.ctx = Some(cipher);
        // self.iv = Some(iv.to_vec());
        // self.key = Some(key.to_vec());
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> Result<usize> {
        self.get_ctx_mut()?
            .cipher_update_vec(data, buf)
            .map_err(|e| e.into())
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let size = self.get_ctx_mut()?.cipher_final_vec(buf)?;

        Ok(size)
    }

    fn authentication_tag(&mut self) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn enable_increase_iv(&mut self, _: bool) {}

    fn name(&self) -> &str {
        &self.name
    }

    fn tag_len(&self) -> usize {
        0
    }

    fn update_sequence_number(&mut self, _: u32) -> Result<()> {
        Ok(())
    }

    fn aad_update(&mut self, _: &mut [u8]) -> Result<()> {
        Ok(())
    }
}

#[derive(new)]
struct CbcCtr {
    name: String,
    #[new(default)]
    ctx: Option<CipherCtx>,
    has_tag: bool,
    has_aad: bool,
    // iv: Option<Vec<u8>>,
    // key: Option<Vec<u8>>,
    args: CipherArgs,
}

impl CbcCtr {
    fn get_ctx_mut(&mut self) -> Result<&mut CipherCtx> {
        match self.ctx {
            Some(ref mut ctx) => Ok(ctx),
            None => Err(Error::ub("uninitilize")),
        }
    }

    fn aes256_ctr() -> Self {
        Self {
            name: "aes256-ctr".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_256_ctr(), 16, 32, 16),
        }
    }

    fn aes128_cbc() -> Self {
        Self {
            name: "aes128-cbc".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_128_cbc(), 16, 16, 16),
        }
    }

    fn aes192_cbc() -> Self {
        Self {
            name: "aes192-cbc".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_192_cbc(), 16, 24, 16),
        }
    }

    fn aes256_cbc() -> Self {
        Self {
            name: "aes256-cbc".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_256_cbc(), 16, 32, 16),
        }
    }

    fn aes128_ctr() -> Self {
        Self {
            name: "aes128-ctr".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_128_ctr(), 16, 16, 16),
        }
    }

    fn aes192_ctr() -> Self {
        Self {
            name: "aes192-ctr".to_string(),
            ctx: None,
            has_tag: false,
            has_aad: false,
            // iv: None,
            // key: None,
            args: CipherArgs::new(Cipher::aes_192_ctr(), 16, 24, 16),
        }
    }

    fn des_ede3_cbc() -> Self {
        Self::new(
            "3des-cbc".to_string(),
            false,
            false,
            CipherArgs::new(Cipher::des_ede3_cbc(), 8, 24, 8),
        )
    }
}

impl Decrypt for CbcCtr {
    fn has_tag(&self) -> bool {
        self.has_tag
    }

    fn has_aad(&self) -> bool {
        self.has_aad
    }

    fn block_size(&self) -> usize {
        self.args.block_size
    }

    fn iv_len(&self) -> usize {
        self.args.iv_len
    }

    fn key_len(&self) -> usize {
        self.args.key_len
    }

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()> {
        let mut cipher = CipherCtx::new()?;
        cipher.decrypt_init(Some(self.args.cipher), Some(key), Some(iv))?;
        cipher.set_padding(false);
        self.ctx = Some(cipher);
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> Result<usize> {
        let len = self.get_ctx_mut()?.cipher_update_vec(data, buf)?;
        Ok(len)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let size = self.get_ctx_mut()?.cipher_final_vec(buf)?;

        Ok(size)
    }

    fn set_authentication_tag(&mut self, tag: &[u8]) -> Result<()> {
        self.get_ctx_mut()?.set_tag(tag).map_err(|e| e.into())
    }

    fn enable_increase_iv(&mut self, _: bool) {}

    fn name(&self) -> &str {
        &self.name
    }

    fn tag_len(&self) -> usize {
        0
    }

    fn update_sequence_number(&mut self, _: u32) -> Result<()> {
        Ok(())
    }

    fn aad_update(&mut self, _: &mut [u8]) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, new)]
struct CipherArgs {
    cipher: &'static CipherRef,
    block_size: usize,
    key_len: usize,
    iv_len: usize,
}

#[derive(new)]
struct Chacha20Poly1205 {
    #[new(default)]
    main_ctx: Option<CipherCtx>,

    #[new(default)]
    header_ctx: Option<CipherCtx>,

    #[new(default)]
    mac_ctx: Option<MdCtx>,

    #[new(default)]
    mac: Option<Vec<u8>>,
}

impl Encrypt for Chacha20Poly1205 {
    fn name(&self) -> &str {
        "chacha20-poly1305@openssh.com"
    }

    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
    }

    fn enable_increase_iv(&mut self, _: bool) {}

    fn block_size(&self) -> usize {
        8
    }

    fn iv_len(&self) -> usize {
        0
    }

    fn key_len(&self) -> usize {
        64
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn initialize(&mut self, _: &[u8], key: &[u8]) -> Result<()> {
        let mut main_ctx = CipherCtx::new()?;

        main_ctx.encrypt_init(Some(Cipher::chacha20()), Some(&key[0..32]), None)?;

        self.main_ctx = Some(main_ctx);

        let mut header_ctx = CipherCtx::new()?;

        header_ctx.encrypt_init(Some(Cipher::chacha20()), Some(&key[32..]), None)?;

        self.header_ctx = Some(header_ctx);

        Ok(())
    }

    fn update_sequence_number(&mut self, number: u32) -> Result<()> {
        let bytes = u64::from(number).to_be_bytes();

        let mut iv = [0; 16];

        iv[8..].copy_from_slice(&bytes);

        let header_ctx = self.get_header_ctx()?;

        header_ctx.encrypt_init(None, None, Some(&iv))?;

        let main_ctx = self.get_main_ctx()?;

        main_ctx.encrypt_init(None, None, Some(&iv))?;

        let mut poly_key = [0; 64];

        main_ctx.cipher_update(&[0; 64], Some(&mut poly_key))?;

        let pkey = PKey::private_key_from_raw_bytes(&poly_key[..32], Id::POLY1305)?;

        let mut mac_ctx = MdCtx::new()?;

        mac_ctx.digest_sign_init(None, &pkey)?;

        self.mac_ctx = Some(mac_ctx);

        Ok(())
    }

    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()> {
        let header_ctx = self.get_header_ctx()?;

        let input = aad.to_vec();

        header_ctx.cipher_update(&input, Some(aad))?;

        header_ctx.cipher_final(aad)?;

        self.get_mac_ctx()?.digest_sign_update(aad)?;

        Ok(())
    }

    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<usize> {
        let pos = out.len();
        let len = self.get_main_ctx()?.cipher_update_vec(data, out)?;

        self.get_mac_ctx()?
            .digest_sign_update(&out[pos..pos + len])?;

        Ok(len)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        self.get_main_ctx()?
            .cipher_final_vec(buf)
            .map_err(|e| e.into())
    }

    fn authentication_tag(&mut self) -> Result<Vec<u8>> {
        let mut tag = vec![];
        self.get_mac_ctx()?.digest_sign_final_to_vec(&mut tag)?;
        Ok(tag)
    }
}


impl Decrypt for Chacha20Poly1205 {
    fn name(&self) -> &str {
        "chacha20-poly1305@openssh.com"
    }

    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
    }

    fn block_size(&self) -> usize {
        8
    }

    fn enable_increase_iv(&mut self, _: bool) {}

    fn iv_len(&self) -> usize {
        0
    }

    fn key_len(&self) -> usize {
        64
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn initialize(&mut self, _: &[u8], key: &[u8]) -> Result<()> {
        let mut main_ctx = CipherCtx::new()?;

        main_ctx.decrypt_init(Some(Cipher::chacha20()), Some(&key[0..32]), None)?;

        self.main_ctx = Some(main_ctx);

        let mut header_ctx = CipherCtx::new()?;

        header_ctx.decrypt_init(Some(Cipher::chacha20()), Some(&key[32..]), None)?;

        self.header_ctx = Some(header_ctx);

        Ok(())
    }

    fn update_sequence_number(&mut self, number: u32) -> Result<()> {
        let bytes = u64::from(number).to_be_bytes();

        let mut iv = [0; 16];

        iv[8..].copy_from_slice(&bytes);

        let header_ctx = self.get_header_ctx()?;

        header_ctx.decrypt_init(None, None, Some(&iv))?;

        let main_ctx = self.get_main_ctx()?;

        main_ctx.decrypt_init(None, None, Some(&iv))?;

        let mut poly_key = [0; 64];

        main_ctx.cipher_update(&[0; 64], Some(&mut poly_key))?;

        let pkey = PKey::private_key_from_raw_bytes(&poly_key[..32], Id::POLY1305)?;

        let mut mac_ctx = MdCtx::new()?;

        mac_ctx.digest_sign_init(None, &pkey)?;

        self.mac_ctx = Some(mac_ctx);

        Ok(())
    }

    fn aad_update(&mut self, aad: &mut [u8]) -> Result<()> {
        let input = aad.to_vec();
        self.get_mac_ctx()?.digest_sign_update(&input)?;

        let header_ctx = self.get_header_ctx()?;

        header_ctx.cipher_update(&input, Some(aad))?;

        header_ctx.cipher_final(aad)?;

        Ok(())
    }

    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<usize> {
        self.get_mac_ctx()?.digest_sign_update(data)?;
        let len = self.get_main_ctx()?.cipher_update_vec(data, out)?;
        Ok(len)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let len = self.get_main_ctx()?.cipher_final_vec(buf)?;

        let mut tag = vec![];
        self.get_mac_ctx()?.digest_sign_final_to_vec(&mut tag)?;

        if self.mac != Some(tag) {
            return Err(Error::MacVerificationFailed);
        }

        self.mac = None;

        Ok(len)
    }

    fn set_authentication_tag(&mut self, data: &[u8]) -> Result<()> {
        self.mac = Some(data.to_vec());
        Ok(())
    }
}

impl Chacha20Poly1205 {
    fn get_main_ctx(&mut self) -> Result<&mut CipherCtx> {
        self.main_ctx.as_mut().ok_or(Error::ub("Uninitlized"))
    }

    fn get_header_ctx(&mut self) -> Result<&mut CipherCtx> {
        self.header_ctx.as_mut().ok_or(Error::ub("Uninitlized"))
    }

    fn get_mac_ctx(&mut self) -> Result<&mut MdCtx> {
        self.mac_ctx
            .as_mut()
            .ok_or(Error::ub("call update_sequence_number first"))
    }

}
