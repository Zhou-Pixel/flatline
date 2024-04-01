pub mod openssh;
use crate::{cipher::crypt::Decrypt, error::Result, Boxtory};


pub trait KeyParser {
    fn parse_publickey(&self, binary: &[u8]) -> Result<(String, Vec<u8>)>;
    fn parse_privatekey(&self, binary: &[u8], passphrase: Option<&[u8]>) -> Result<(String, Vec<u8>, Vec<u8>)>;
    fn add_cipher(&mut self, name: &str, cipher: Boxtory<dyn Decrypt + Send>);
}