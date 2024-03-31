use super::*;
use derive_new::new;
use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
};
use std::ffi::c_int;

use crate::error::{Error, Result};
use indexmap::IndexMap;

mod ffi {
    use std::ffi::{c_int, c_uchar, c_void};

    use openssl::error::ErrorStack;

    #[repr(C)]
    pub struct CipherCtx {
        _data: [u8; 0],
    }

    #[repr(C)]
    pub struct Cipher {
        _data: [u8; 0],
    }
    pub const EVP_CTRL_AEAD_SET_IV_FIXED: c_int = 0x12;
    pub const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
    pub const EVP_CTRL_GCM_IV_GEN: c_int = 0x13;
    pub const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;
    extern "C" {
        pub fn EVP_CIPHER_CTX_free(c: *mut CipherCtx);
        pub fn EVP_aes_128_gcm() -> *const Cipher;
        pub fn EVP_aes_256_gcm() -> *const Cipher;
        pub fn EVP_EncryptInit(
            cxt: *mut CipherCtx,
            cipher: *const Cipher,
            key: *const c_uchar,
            iv: *const c_uchar,
        ) -> c_int;
        pub fn EVP_DecryptInit(
            cxt: *mut CipherCtx,
            cipher: *const Cipher,
            key: *const c_uchar,
            iv: *const c_uchar,
        ) -> c_int;
        pub fn EVP_CIPHER_CTX_ctrl(
            ctx: *mut CipherCtx,
            t: c_int,
            arg: c_int,
            ptr: *mut c_void,
        ) -> c_int;
        pub fn EVP_CipherUpdate(
            ctx: *mut CipherCtx,
            outbuf: *mut c_uchar,
            outl: *mut c_int,
            inbuf: *const c_uchar,
            inl: c_int,
        ) -> c_int;
        pub fn EVP_CipherFinal(ctx: *mut CipherCtx, outm: *mut c_uchar, outl: *mut c_int) -> c_int;
        pub fn EVP_CIPHER_CTX_new() -> *mut CipherCtx;
        pub fn EVP_CIPHER_CTX_get_tag_length(ctx: *const CipherCtx) -> c_int;
    }
    pub fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
        if r <= 0 {
            Err(ErrorStack::get())
        } else {
            Ok(r)
        }
    }
    pub fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
        if r.is_null() {
            Err(ErrorStack::get())
        } else {
            Ok(r)
        }
    }
}

#[derive(new)]
pub struct Gcm {
    name: String,
    ctx: *mut ffi::CipherCtx,
    cipher: *const ffi::Cipher,
    iv_len: usize,
    key_len: usize,
    block_size: usize,
    idle: bool,
    increase_iv: bool,
}

unsafe impl Send for Gcm {}
unsafe impl Sync for Gcm {}

impl Drop for Gcm {
    fn drop(&mut self) {
        unsafe { ffi::EVP_CIPHER_CTX_free(self.ctx) }
    }
}

impl Gcm {

    fn get_ctx_mut(&mut self) -> Result<*mut ffi::CipherCtx> {
        if self.ctx.is_null() {
            return Err(Error::ub("uninitlize"));
        }
        Ok(self.ctx)
    }

    fn aes256_gcm_openssh() -> Self {
        unsafe {
            let name = "aes256-gcm@openssh.com".to_string();
            // let ctx = ffi::EVP_CIPHER_CTX_new();
            let ctx = std::ptr::null_mut();

            // ffi::cvt_p(ctx)?;

            let cipher = ffi::EVP_aes_256_gcm();

            let iv_len = 12;
            let key_len = 32;
            let block_size = 16;
            let idle = true;
            let increase_iv = true;

            Self {
                name,
                ctx,
                cipher,
                iv_len,
                key_len,
                block_size,
                idle,
                increase_iv,
            }
        }
    }

    fn aes128_gcm_openssh() -> Self {
        unsafe {
            let name = "aes128-gcm@openssh.com".to_string();
            // let ctx = ffi::EVP_CIPHER_CTX_new();

            // ffi::cvt_p(ctx)?;
            let ctx = std::ptr::null_mut();

            let cipher = ffi::EVP_aes_128_gcm();

            let iv_len = 12;
            let key_len = 16;
            let block_size = 16;
            let idle = true;
            let increase_iv = true;

            Self {
                name,
                ctx,
                cipher,
                iv_len,
                key_len,
                block_size,
                idle,
                increase_iv,
            }
        }
    }
    fn increase(&mut self) -> Result<()> {
        unsafe {
            let mut last = 0u8;
            let res = ffi::EVP_CIPHER_CTX_ctrl(
                self.ctx,
                ffi::EVP_CTRL_GCM_IV_GEN,
                -1,
                &mut last as *mut u8 as _,
            );
            ffi::cvt(res)?;
        }

        Ok(())
    }
}

impl Decrypt for Gcm {
    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
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
        unsafe {
            let ctx = ffi::EVP_CIPHER_CTX_new();
            ffi::cvt_p(ctx)?;

            let res = ffi::EVP_DecryptInit(ctx, self.cipher, key.as_ptr(), iv.as_ptr());

            ffi::cvt(res)?;

            let res = ffi::EVP_CIPHER_CTX_ctrl(
                ctx,
                ffi::EVP_CTRL_AEAD_SET_IV_FIXED,
                -1,
                iv.as_ptr() as _,
            );
            ffi::cvt(res)?;

            self.ctx = ctx;
            // let mut last = 0u8;
            // let res = ffi::EVP_CIPHER_CTX_ctrl(
            //     self.ctx,
            //     ffi::EVP_CTRL_GCM_IV_GEN,
            //     1,
            //     &mut last as *mut u8 as _,
            // );
            // ffi::cvt(res)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize> {
        if self.increase_iv && self.idle {
            self.idle = false;
            self.increase()?;
        }

        let mut outlen = 0;
        match buf {
            Some(buf) => {
                let base = buf.len();
                buf.resize(base + data.len() + self.block_size, 0);
                let res = unsafe {
                    ffi::EVP_CipherUpdate(
                        self.get_ctx_mut()?,
                        buf[base..].as_mut_ptr(),
                        &mut outlen as *mut _,
                        data.as_ptr(),
                        data.len() as _,
                    )
                };
                ffi::cvt(res)?;
                buf.truncate(base + outlen as usize);
            }
            None => {
                let res = unsafe {
                    ffi::EVP_CipherUpdate(
                        self.get_ctx_mut()?,
                        std::ptr::null_mut(),
                        &mut outlen as *mut _,
                        data.as_ptr(),
                        data.len() as _,
                    )
                };

                ffi::cvt(res)?;
            }
        }

        Ok(outlen as usize)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        unsafe {
            self.idle = true;
            let base = buf.len();
            buf.resize(base + self.block_size, 0);

            let mut outlen: c_int = 0;
            let res =
                ffi::EVP_CipherFinal(self.get_ctx_mut()?, buf[base..].as_mut_ptr(), &mut outlen as *mut _);

            ffi::cvt(res)?;
            buf.truncate(base + outlen as usize);
            Ok(outlen as usize)
        }
    }

    fn set_authentication_tag(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let res = ffi::EVP_CIPHER_CTX_ctrl(
                self.get_ctx_mut()?,
                ffi::EVP_CTRL_GCM_SET_TAG,
                data.len() as _,
                data.as_ptr() as *mut _,
            );
            ffi::cvt(res)?;
        }
        Ok(())
    }


    fn enable_increase_iv(&mut self, enable: bool) {
        self.increase_iv = enable;
    }

    fn name(&self) -> &str {
        &self.name
    }


}

impl Encrypt for Gcm {
    fn has_tag(&self) -> bool {
        true
    }

    fn has_aad(&self) -> bool {
        true
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
        unsafe {

            let ctx = ffi::EVP_CIPHER_CTX_new();
            ffi::cvt_p(ctx)?;

            let res = ffi::EVP_EncryptInit(ctx, self.cipher, key.as_ptr(), iv.as_ptr());

            ffi::cvt(res)?;

            let res = ffi::EVP_CIPHER_CTX_ctrl(
                ctx,
                ffi::EVP_CTRL_AEAD_SET_IV_FIXED,
                -1,
                iv.as_ptr() as _,
            );
            ffi::cvt(res)?;
            self.ctx = ctx;
            // Encrypt::reset(self)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize> {
        if self.increase_iv && self.idle {
            self.idle = false;
            self.increase()?;
        }

        let mut outlen = 0;
        match buf {
            Some(buf) => {
                let base = buf.len();
                buf.resize(base + data.len() + self.block_size, 0);
                let res = unsafe {
                    ffi::EVP_CipherUpdate(
                        self.get_ctx_mut()?,
                        buf[base..].as_mut_ptr(),
                        &mut outlen as *mut _,
                        data.as_ptr(),
                        data.len() as _,
                    )
                };
                ffi::cvt(res)?;
                buf.truncate(base + outlen as usize);
            }
            None => {
                let res = unsafe {
                    ffi::EVP_CipherUpdate(
                        self.get_ctx_mut()?,
                        std::ptr::null_mut(),
                        &mut outlen as *mut _,
                        data.as_ptr(),
                        data.len() as _,
                    )
                };

                ffi::cvt(res)?;
            }
        }

        Ok(outlen as usize)
    }

    fn finalize(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        unsafe {
            self.idle = true;
            let base = buf.len();
            buf.resize(base + self.block_size, 0);

            let mut outlen: i32 = 0;
            let res =
                ffi::EVP_CipherFinal(self.get_ctx_mut()?, buf[base..].as_mut_ptr(), &mut outlen as *mut _);

            ffi::cvt(res)?;

            buf.truncate(base + outlen as usize);
            Ok(outlen as usize)
        }
    }

    fn authentication_tag(&mut self) -> Result<Vec<u8>> {
        unsafe {
            let ctx = self.get_ctx_mut()?;
            let tag_len = ffi::EVP_CIPHER_CTX_get_tag_length(ctx);

            let mut tag = vec![0; tag_len as usize];

            let res = ffi::EVP_CIPHER_CTX_ctrl(
                ctx,
                ffi::EVP_CTRL_GCM_GET_TAG,
                tag_len,
                tag.as_mut_ptr() as _,
            );
            ffi::cvt(res)?;

            Ok(tag)
        }
    }

    fn enable_increase_iv(&mut self, enable: bool) {
        self.increase_iv = enable;
    }

    fn name(&self) -> &str {
        &self.name
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

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()>;
    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize>;
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

    fn initialize(&mut self, iv: &[u8], key: &[u8]) -> Result<()>;
    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize>;
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

    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize> {
        if let Some(buf) = buf {
            self.get_ctx_mut()?.cipher_update_vec(data, buf)
        } else {
            self.get_ctx_mut()?.cipher_update(data, None)
        }
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
}

#[derive(new)]
pub struct CbcCtr {
    name: String,
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

    fn update(&mut self, data: &[u8], buf: Option<&mut Vec<u8>>) -> Result<usize> {
        if let Some(buf) = buf {
            self.get_ctx_mut()?.cipher_update_vec(data, buf)
        } else {
            self.get_ctx_mut()?.cipher_update(data, None)
        }
        .map_err(|e| e.into())
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
}

#[derive(Clone, Copy, new)]
pub struct CipherArgs {
    cipher: &'static CipherRef,
    block_size: usize,
    key_len: usize,
    iv_len: usize,
}


algo_list!(
    encrypt_all,
    new_encrypt_all,
    new_encrypt_by_name,
    dyn Encrypt + Send,
    "aes256-gcm@openssh.com" => Gcm::aes256_gcm_openssh(),
    "aes128-gcm@openssh.com" => Gcm::aes128_gcm_openssh(),
    "aes256-ctr" => CbcCtr::aes256_ctr(),
    "aes128-cbc" => CbcCtr::aes128_cbc(),
    "aes192-cbc" => CbcCtr::aes192_cbc(),
    "aes256-cbc" => CbcCtr::aes256_cbc(),
    "aes128-ctr" => CbcCtr::aes128_ctr(),
    "aes192-ctr" => CbcCtr::aes192_ctr(),
);

algo_list!(
    decrypt_all,
    new_decrypt_all,
    new_decrypt_by_name,
    dyn Decrypt + Send,
    "aes256-gcm@openssh.com" => Gcm::aes256_gcm_openssh(),
    "aes128-gcm@openssh.com" => Gcm::aes128_gcm_openssh(),
    "aes256-ctr" => CbcCtr::aes256_ctr(),
    "aes128-cbc" => CbcCtr::aes128_cbc(),
    "aes192-cbc" => CbcCtr::aes192_cbc(),
    "aes256-cbc" => CbcCtr::aes256_cbc(),
    "aes128-ctr" => CbcCtr::aes128_ctr(),
    "aes192-ctr" => CbcCtr::aes192_ctr(),
);

