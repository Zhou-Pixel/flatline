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

#[cfg(test)]
mod test;

type MSender<T> = mpsc::UnboundedSender<T>;
type MReceiver<T> = mpsc::UnboundedReceiver<T>;
type OSender<T> = oneshot::Sender<T>;
type OReceiver<T> = oneshot::Receiver<T>;
type MWSender<T> = mpsc::WeakUnboundedSender<T>;

fn m_channel<T>() -> (MSender<T>, MReceiver<T>) {
    mpsc::unbounded_channel()
}

fn o_channel<T>() -> (OSender<T>, OReceiver<T>) {
    oneshot::channel()
}

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
use tokio::sync::{mpsc, oneshot};
