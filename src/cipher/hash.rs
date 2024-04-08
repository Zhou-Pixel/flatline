use openssl::{md::MdRef, md_ctx::MdCtx};

use crate::error::Result;

pub trait Hash {
    fn hash_len(&self) -> usize;
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(&mut self) -> Result<Vec<u8>>;
}

pub(crate) struct MdWrapper {
    ctx: MdCtx,
    ctxref: &'static MdRef,
}

impl MdWrapper {
    pub fn initialize(ctxref: &'static MdRef) -> Result<MdWrapper> {
        let mut ctx = MdCtx::new()?;

        ctx.digest_init(ctxref)?;

        Ok(MdWrapper { ctx, ctxref })
    }
}

impl Hash for MdWrapper {
    fn hash_len(&self) -> usize {
        self.ctx.size()
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        self.ctx.digest_update(data)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<u8>> {
        let mut out = vec![0; self.ctx.size()];
        self.ctx.digest_final(&mut out)?;

        self.ctx = MdCtx::new()?;
        self.ctx.digest_init(self.ctxref)?;

        Ok(out)
    }
}

