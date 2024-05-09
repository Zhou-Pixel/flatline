use derive_new::new;
use indexmap::IndexMap;
use openssl::{
    bn::{BigNum, BigNumContext},
    dsa::{self, DsaSig},
    ec::{EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    md::{Md, MdRef},
    md_ctx::MdCtx,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    rsa::{self, Padding, RsaPrivateKeyBuilder},
    sign::{Signer, Verifier},
};

use crate::{
    error::{Error, Result},
    ssh::buffer::Buffer,
    BigNumExt,
};

use super::*;
macro_rules! invalid_key_format {
    () => {
        Error::invalid_format(format!("{}:{} invalid key format", file!(), line!()))
    };
}

algo_list!(
    signature_all,
    new_signature_all,
    new_signature_by_name,
    dyn Signature + Send,
    "ssh-ed25519" => Ed25519::new(),
    "rsa-sha2-256" => Rsa::rsa_sha2_256(),
    "rsa-sha2-512" => Rsa::rsa_sha2_512(),
    "ssh-rsa" => Rsa::ssh_rsa(),
    "ssh-dss" => Dsa::ssh_dss(),
    "ecdsa-sha2-nistp521" => Ecdsa::ecdsa_sha2_nistp521(),
    "ecdsa-sha2-nistp256" => Ecdsa::ecdsa_sha2_nistp256(),
    "ecdsa-sha2-nistp384" => Ecdsa::ecdsa_sha2_nistp384(),
);

algo_list!(
    verify_all,
    new_verify_all,
    new_verify_by_name,
    dyn Verify + Send,
    "ssh-ed25519" => Ed25519::new(),
    "rsa-sha2-256" => Rsa::rsa_sha2_256(),
    "rsa-sha2-512" => Rsa::rsa_sha2_512(),
    "ssh-rsa" => Rsa::ssh_rsa(),
    "ssh-dss" => Dsa::ssh_dss(),
    "ecdsa-sha2-nistp521" => Ecdsa::ecdsa_sha2_nistp521(),
    "ecdsa-sha2-nistp256" => Ecdsa::ecdsa_sha2_nistp256(),
    "ecdsa-sha2-nistp384" => Ecdsa::ecdsa_sha2_nistp384(),
);

pub trait Signature {
    fn name(&self) -> &str;
    fn initialize(&mut self, key: &[u8]) -> Result<()>;
    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(new)]
struct Ed25519 {
    #[new(default)]
    ctx: Option<MdCtx>,
}

impl Ed25519 {
    fn get_ctx_mut(&mut self) -> Result<&mut MdCtx> {
        match self.ctx {
            Some(ref mut ctx) => Ok(ctx),
            None => Err(Error::ub("Uninitilize")),
        }
    }
}

impl Signature for Ed25519 {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);

        // let invalid_format_key = || Error::invalid_format("invalid key format");

        if key.take_one().ok_or(invalid_key_format!())?.1 != b"ssh-ed25519" {
            return Err(invalid_key_format!());
        }

        let key = key.take_one().ok_or(invalid_key_format!())?.1;

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

    fn name(&self) -> &str {
        "ssh-ed25519"
    }
}

pub trait Verify {
    fn name(&self) -> &str;
    fn initialize(&mut self, key: &[u8]) -> Result<()>;
    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool>;
}

impl Verify for Ed25519 {
    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        let signature = Buffer::from_slice(signature);
        let Some((_, keytype)) = signature.take_one() else {
            return Err(Error::invalid_format("invalid signature format"));
        };
        if keytype != b"ssh-ed25519" {
            return Ok(false);
        }
        let (_, signature) = signature
            .take_one()
            .ok_or(Error::invalid_format("invalid format"))?;

        let res = self
            .get_ctx_mut()?
            .digest_verify(data, signature)
            .unwrap_or(false);
        Ok(res)
    }

    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);
        let (_, keytype) = key
            .take_one()
            .ok_or(Error::invalid_format("invalid ed25519 key"))?;

        if keytype != b"ssh-ed25519" {
            return Err(Error::invalid_format("invalid ssh-ed25519 key"));
        }

        let (_, key) = key
            .take_one()
            .ok_or(Error::invalid_format("invalid ed25519 key"))?;

        let key = PKey::public_key_from_raw_bytes(key, Id::ED25519)?;

        let mut ctx = MdCtx::new()?;

        ctx.digest_verify_init(None, &key)?;

        self.ctx = Some(ctx);

        Ok(())
    }

    fn name(&self) -> &str {
        "ssh-ed25519"
    }
}

#[derive(new)]
struct Rsa<T> {
    name: String,
    hash: &'static MdRef,
    // #[new(default)]
    // e: Option<Vec<u8>>,
    // #[new(default)]
    // n: Option<Vec<u8>>,
    #[new(default)]
    ctx: Option<PkeyCtx<T>>,
}

impl<T> Rsa<T> {
    fn rsa_sha2_256() -> Self {
        Self::new("rsa-sha2-256".to_string(), Md::sha256())
    }

    fn rsa_sha2_512() -> Self {
        Self::new("rsa-sha2-512".to_string(), Md::sha512())
    }

    fn ssh_rsa() -> Self {
        Self::new("ssh-rsa".to_string(), Md::sha1())
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

impl Verify for Rsa<Public> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let buffer = Buffer::from_slice(key);

        let (_, keytype) = buffer.take_one().ok_or(Error::ub("invalid key"))?;
        if keytype != b"ssh-rsa" {
            return Err(Error::ub("invalid key"));
        }

        let (_, e) = buffer.take_one().ok_or(Error::ub("invalid key"))?;

        let (_, n) = buffer.take_one().ok_or(Error::ub("invalid key"))?;

        // self.e = Some(e);
        // self.n = Some(n);

        let n = BigNum::from_slice(n)?;
        let e = BigNum::from_slice(e)?;
        let key = rsa::Rsa::from_public_components(n, e)?;

        let pkey = PKey::from_rsa(key)?;

        let mut ctx = PkeyCtx::new(&pkey)?;

        ctx.verify_init()?;
        ctx.set_rsa_padding(Padding::PKCS1)?;
        ctx.set_signature_md(self.hash)?;

        self.ctx = Some(ctx);

        Ok(())
    }

    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        let hash = self.calculate_hash(data)?;
        match self.ctx {
            Some(ref mut ctx) => {
                let signature = Buffer::from_slice(signature);

                let (_, signtype) = signature
                    .take_one()
                    .ok_or(Error::invalid_format("invalid signature"))?;
                if signtype != self.name.as_bytes() {
                    return Err(Error::invalid_format("signature type doesn't match"));
                }

                let (_, signature) = signature
                    .take_one()
                    .ok_or(Error::invalid_format("invalid signature format"))?;

                Ok(ctx.verify(&hash, signature).unwrap_or(false))
            }

            _ => Err(Error::ub("it must be initilized before verify")),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Signature for Rsa<Private> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let buffer = Buffer::from_slice(key);

        if buffer
            .take_one()
            .ok_or(Error::invalid_format("invalid key format"))?
            .1
            != b"ssh-rsa"
        {
            return Err(Error::invalid_format("key type doesn't match"));
        }

        let func = || {
            let one = || Some(buffer.take_one()?.1);

            let n = one()?;
            let e = one()?;
            let d = one()?;
            let iqmp = one()?;
            let p = one()?;
            let q = one()?;

            Some((n, e, d, iqmp, p, q))
        };

        let (n, e, d, iqmp, p, q) = func().ok_or(Error::invalid_format("invalid key format"))?;

        let n = BigNum::from_slice(n)?;
        let e = BigNum::from_slice(e)?;
        let d = BigNum::from_slice(d)?;
        let iqmp = BigNum::from_slice(iqmp)?;
        let p = BigNum::from_slice(p)?;
        let q = BigNum::from_slice(q)?;
        let dmp1 = BigNum::new()?;
        let dmq1 = BigNum::new()?;

        let key = RsaPrivateKeyBuilder::new(n, e, d)?
            .set_crt_params(dmp1, dmq1, iqmp)?
            .set_factors(p, q)?
            .build();
        // let key = rsa::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;

        let pkey = PKey::from_rsa(key)?;

        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.sign_init()?;
        ctx.set_rsa_padding(Padding::PKCS1)?;
        ctx.set_signature_md(self.hash)?;

        self.ctx = Some(ctx);

        Ok(())
    }

    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let hash = self.calculate_hash(data)?;

        let ctx = self.ctx.as_mut().ok_or(Error::ub("uninitlize"))?;

        let len = ctx.sign(&hash, None)?;

        let mut vec = vec![0; len];

        ctx.sign(&hash, Some(&mut vec))?;

        Ok(vec)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(new)]
struct Dsa<T> {
    #[new(default)]
    key: Option<PKey<T>>,
}

impl<T> Dsa<T> {
    fn ssh_dss() -> Self {
        Self::new()
    }
}

impl Verify for Dsa<Public> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);
        // let invalid_key_format = || Error::invalid_format("invalid key format");

        let take_one = || Result::Ok(key.take_one().ok_or(invalid_key_format!())?.1);

        if take_one()? != b"ssh-dss" {
            return Err(invalid_key_format!());
        }

        let p = take_one()?;
        let q = take_one()?;
        let g = take_one()?;
        let y = take_one()?;

        let p = BigNum::from_slice(p)?;
        let q = BigNum::from_slice(q)?;
        let g = BigNum::from_slice(g)?;
        let y = BigNum::from_slice(y)?;

        let key = dsa::Dsa::from_public_components(p, q, g, y)?;

        let key = PKey::from_dsa(key)?;

        self.key = Some(key);

        Ok(())
    }

    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        let signature = Buffer::from_slice(signature);

        let (_, signtype) = signature
            .take_one()
            .ok_or(Error::invalid_format("invalid signature"))?;
        if signtype != b"ssh-dss" {
            return Err(Error::invalid_format("signature type doesn't match"));
        }

        let (_, signature) = signature
            .take_one()
            .ok_or(Error::invalid_format("invalid signature format"))?;

        if signature.len() != 40 {
            return Err(Error::invalid_format("invalid signature lenght"));
        }

        let r = BigNum::from_slice(&signature[0..20])?;
        let s = BigNum::from_slice(&signature[20..])?;

        let signature = DsaSig::from_private_components(r, s)?;

        // Serialize DSA signature to DER
        let signature = signature.to_der()?;

        let key = self.key.as_ref().ok_or(Error::ub("Uninitializedd"))?;
        let mut verifier = Verifier::new(MessageDigest::sha1(), key).unwrap();
        verifier.update(data)?;

        Ok(verifier.verify(&signature[..]).unwrap_or(false))
    }

    fn name(&self) -> &str {
        todo!()
    }
}

impl Signature for Dsa<Private> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);
        // let invalid_key_format = || Error::invalid_format("invalid key format");

        let take_one = || Result::Ok(key.take_one().ok_or(invalid_key_format!())?.1);

        if take_one()? != b"ssh-dss" {
            return Err(invalid_key_format!());
        }

        let p = take_one()?;
        let q = take_one()?;
        let g = take_one()?;
        let y = take_one()?;
        let x = take_one()?;

        let p = BigNum::from_slice(p)?;
        let q = BigNum::from_slice(q)?;
        let g = BigNum::from_slice(g)?;
        let y = BigNum::from_slice(y)?;
        let x = BigNum::from_slice(x)?;

        let key = dsa::Dsa::from_private_components(p, q, g, x, y)?;

        self.key = Some(PKey::from_dsa(key)?);

        Ok(())
    }

    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.as_ref().ok_or(Error::ub("uninitlize"))?;

        let mut signer = Signer::new(MessageDigest::sha1(), key)?;

        signer.update(data)?;

        Ok(signer.sign_to_vec()?)
    }

    fn name(&self) -> &str {
        "ssh-dss"
    }
}

// fn invalid_key_format() -> Error {
//     Error::invalid_format("invalid key format")
// }

#[derive(new)]
struct Ecdsa<T> {
    name: String,
    nid: Nid,
    hash: &'static MdRef,
    #[new(default)]
    key: Option<PKey<T>>,
}

impl<T> Ecdsa<T> {
    fn calculate_hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = MdCtx::new()?;
        ctx.digest_init(self.hash)?;

        ctx.digest_update(data)?;

        let mut out = vec![0; ctx.size()];

        ctx.digest_final(&mut out)?;

        Ok(out)
    }

    fn get_key(&self) -> Result<&PKey<T>> {
        self.key.as_ref().ok_or(Error::ub("Uninitialized"))
    }
}

impl<T> Ecdsa<T> {
    fn ecdsa_sha2_nistp256() -> Self {
        Self::new(
            "ecdsa-sha2-nistp256".to_string(),
            Nid::X9_62_PRIME256V1,
            Md::sha256(),
        )
    }

    fn ecdsa_sha2_nistp384() -> Self {
        Self::new(
            "ecdsa-sha2-nistp384".to_string(),
            Nid::SECP384R1,
            Md::sha384(),
        )
    }

    fn ecdsa_sha2_nistp521() -> Self {
        Self::new(
            "ecdsa-sha2-nistp521".to_string(),
            Nid::SECP521R1,
            Md::sha512(),
        )
    }
}

impl Signature for Ecdsa<Private> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);

        let keytype = key.take_one().ok_or(invalid_key_format!())?.1;
        if keytype != self.name.as_bytes() {
            return Err(invalid_key_format!());
        }

        let nid = key.take_one().ok_or(invalid_key_format!())?.1;
        if !self.name.ends_with(std::str::from_utf8(nid)?) {
            return Err(invalid_key_format!());
        }

        let public_key = key.take_one().ok_or(invalid_key_format!())?.1;
        let e = key.take_one().ok_or(invalid_key_format!())?.1;

        let eckey = EcKey::from_curve_name(self.nid)?;
        let group = eckey.group();

        let mut bnctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(group, public_key, &mut bnctx)?;
        // let point = EcKey::from_public_key(group, &point)?;

        let e = BigNum::from_slice(e)?;
        let private = EcKey::from_private_components(group, &e, &point)?;

        let pkey = PKey::from_ec_key(private)?;

        self.key = Some(pkey);

        Ok(())
    }

    fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let hash = self.calculate_hash(data)?;
        let key = self.get_key()?;

        let ec = key.ec_key()?;

        let sign = EcdsaSig::sign(&hash, &ec)?;

        let r = sign.r().to_ssh_bytes();
        let s = sign.s().to_ssh_bytes();

        let out = make_buffer_without_header! {
            one: r,
            one: s,
        };

        Ok(out.into_vec())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Verify for Ecdsa<Public> {
    fn initialize(&mut self, key: &[u8]) -> Result<()> {
        let key = Buffer::from_slice(key);

        let keytype = key.take_one().ok_or(invalid_key_format!())?.1;
        if self.name.as_bytes() != keytype {
            return Err(invalid_key_format!());
        }

        let id = key.take_one().ok_or(invalid_key_format!())?.1;

        if !self.name.ends_with(std::str::from_utf8(id)?) {
            return Err(invalid_key_format!());
        }

        let public_key = key.take_one().ok_or(invalid_key_format!())?.1;

        let eckey = EcKey::from_curve_name(self.nid)?;
        let group = eckey.group();

        let mut bnctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(group, public_key, &mut bnctx)?;
        let point = EcKey::from_public_key(group, &point)?;

        point.check_key()?;

        let pkey = PKey::from_ec_key(point)?;

        self.key = Some(pkey);
        Ok(())
    }

    fn verify(&mut self, signature: &[u8], data: &[u8]) -> Result<bool> {
        let signature = Buffer::from_slice(signature);
        if signature.take_one().ok_or(invalid_key_format!())?.1 != self.name.as_bytes() {
            return Err(invalid_key_format!());
        }

        let signature = signature.take_one().ok_or(invalid_key_format!())?.1;

        let signature = Buffer::from_slice(signature);
        let r = signature.take_one().ok_or(invalid_key_format!())?.1;
        let s = signature.take_one().ok_or(invalid_key_format!())?.1;

        let ecsig =
            EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;

        let signature = ecsig.to_der()?;

        let hash = self.calculate_hash(data)?;

        let key = self.get_key()?;

        let mut ctx = PkeyCtx::new(key)?;

        ctx.verify_init()?;
        Ok(ctx.verify(&hash, &signature)?)
    }

    fn name(&self) -> &str {
        &self.name
    }
}
