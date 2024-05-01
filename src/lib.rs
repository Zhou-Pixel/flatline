pub mod channel;
pub mod cipher;
pub mod error;
pub mod forward;
pub mod handshake;
pub mod keys;
mod msg;
mod project;
pub mod scp;
pub mod session;
pub mod sftp;
mod ssh;

pub(crate) type KMSender<T> = kanal::AsyncSender<T>;
pub(crate) type KMReceiver<T> = kanal::AsyncReceiver<T>;
pub(crate) type KOSender<T> = kanal::OneshotAsyncSender<T>;
pub(crate) type KOReceiver<T> = kanal::OneshotAsyncReceiver<T>;

#[cfg(test)]
mod test;

pub use cipher::{
    compress::{Decode, Encode},
    crypt::{Decrypt, Encrypt},
    hash::Hash,
    kex::KeyExChange,
    mac::Mac,
    sign::{Signature, Verify},
    Boxtory, Factory,
};
pub use openssl;
