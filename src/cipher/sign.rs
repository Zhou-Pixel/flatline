use derive_new::new;
use indexmap::IndexMap;
use openssl::{
    bn::BigNum,
    md::{Md, MdRef},
    md_ctx::MdCtx,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
    rsa::{self, Padding},
};

use crate::{
    error::{Error, Result},
    ssh::buffer::Buffer,
};

use super::*;

pub trait Signature {
    fn initialize(&mut self, key: &[u8]) -> Result<()>;
    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(new)]
struct Ed25519 {
    ctx: Option<MdCtx>,
}

impl Ed25519 {
    fn get_ctx_mut(&mut self) -> Result<&mut MdCtx> {
        match self.ctx {
            Some(ref mut ctx) => Ok(ctx),
            None => Err(Error::ub("uninitilize")),
        }
    }
}

impl Signature for Ed25519 {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let pkey = PKey::private_key_from_raw_bytes(key, Id::ED25519)?;

        let mut ctx = MdCtx::new()?;
        ctx.digest_sign_init(None, &pkey)?;
        self.ctx = Some(ctx);

        Ok(())
    }

    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.get_ctx_mut()?;
        
        let len = ctx.digest_sign(data, None)?;

        let mut buffer = vec![0; len];

        ctx.digest_sign(data, Some(&mut buffer))?;
        Ok(buffer)
    }
}


algo_list!(
    signature_all,
    new_signature_all,
    new_signature_by_name,
    dyn Signature + Send,
    "ssh-ed25519" => Ed25519::new(None),
);



algo_list!(
    verify_all,
    new_verify_all,
    new_verify_by_name,
    dyn Verify + Send,
    "ssh-ed25519" => Ed25519::new(None),
    "rsa-sha2-256" => Rsa::rsa_sha2_256(),
    "rsa-sha2-512" => Rsa::rsa_sha2_512(),
);


pub trait Verify {
    fn initialize(&mut self, key: &[u8]) -> Result<()>;
    fn verify(&mut self, sigature: &[u8], data: &[u8]) -> Result<bool>;
}

impl Verify for Ed25519 {
    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        let mut signature = Buffer::from_vec(signature.to_vec());
        let Some((_, keytype)) = signature.take_one() else {
            return Err(Error::invalid_format("invalid signature format"));
        };
        if keytype != b"ssh-ed25519" {
            return Ok(false);
        }
        let (_, signature) = signature
            .take_one()
            .ok_or(Error::invalid_format("invalid format"))?;

        let res = self.get_ctx_mut()?.digest_verify(data, &signature).unwrap_or(false);
        Ok(res)
    }

    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let mut key = Buffer::from_vec(key.to_vec());
        let (_, keytype) = key
            .take_one()
            .ok_or(Error::invalid_format("invalid ed25519 key"))?;

        if keytype != b"ssh-ed25519" {
            return Err(Error::invalid_format("invalid ssh-ed25519 key"));
        }

        let (_, key) = key
            .take_one()
            .ok_or(Error::invalid_format("invalid ed25519 key"))?;

        let key = PKey::public_key_from_raw_bytes(&key, Id::ED25519)?;

        let mut ctx = MdCtx::new()?;



        ctx.digest_verify_init(None, &key)?;

        self.ctx = Some(ctx);

        Ok(())
    }
}

#[derive(new)]
struct Rsa {
    name: String,
    hash: &'static MdRef,
    #[new(default)]
    e: Option<Vec<u8>>,
    #[new(default)]
    n: Option<Vec<u8>>,
}

impl Rsa {
    fn rsa_sha2_256() -> Self {
        Self::new("rsa-sha2-256".to_string(), Md::sha256())
    }

    fn rsa_sha2_512() -> Self {
        Self::new("rsa-sha2-512".to_string(), Md::sha512())
    }

    fn calculate_hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0; self.hash.size()];

        let mut ctx = MdCtx::new()?;

        ctx.digest_init(self.hash)?;

        ctx.digest_update(data)?;

        ctx.digest_final(&mut out)?;

        Ok(out)
    }
}

impl Verify for Rsa {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let mut buffer = Buffer::from_vec(key.to_vec());

        let (_, keytype) = buffer.take_one().ok_or(Error::ub("invalid key"))?;
        if keytype != b"ssh-rsa" {
            return Err(Error::ub("invalid key"));
        }

        let (_, e) = buffer.take_one().ok_or(Error::ub("invalid key"))?;

        let (_, n) = buffer.take_one().ok_or(Error::ub("invalid key"))?;

        self.e = Some(e);
        self.n = Some(n);

        Ok(())
    }

    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        match (&self.e, &self.n) {
            (Some(e), Some(n)) => {
                let e = BigNum::from_slice(e)?;
                let n = BigNum::from_slice(n)?;

                let key = rsa::Rsa::from_public_components(n, e)?;

                let pkey = PKey::from_rsa(key)?;

                let mut ctx = PkeyCtx::new(&pkey)?;

                ctx.verify_init()?;
                ctx.set_rsa_padding(Padding::PKCS1)?;
                ctx.set_signature_md(self.hash)?;

                let mut signature = Buffer::from_vec(signature.to_vec());

                let (_, signtype) = signature
                    .take_one()
                    .ok_or(Error::invalid_format("invalid key"))?;
                if signtype != self.name.as_bytes() {
                    return Err(Error::invalid_format("not signature doesn't match"));
                }

                let (_, signature) = signature
                    .take_one()
                    .ok_or(Error::invalid_format("invalid signature"))?;


                let out = self.calculate_hash(data)?;

                Ok(ctx.verify(&out, &signature).unwrap_or(false))
            }

            _ => Err(Error::ub("it must be initilized before verify")),
        }
    }
}
