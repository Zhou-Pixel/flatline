pub mod openssh;
use derive_new::new;

use crate::{cipher::crypt::Decrypt, error::Result, Boxtory};

#[derive(new)]
pub struct PrivateKey {
    pub key_type: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub comment: String,
}

#[derive(new)]
pub struct PublicKey {
    pub key_type: String,
    pub key: Vec<u8>,
}

pub trait KeyParser {
    fn parse_publickey(&self, binary: &[u8]) -> Result<PublicKey>;
    fn parse_privatekey(&self, binary: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey>;
    fn add_cipher(&mut self, name: &str, cipher: Boxtory<dyn Decrypt + Send>);
}
