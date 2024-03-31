mod openssh;
use crate::{cipher::crypt::Decrypt, error::Result};


pub trait KeyParser {
    fn parse_publickey(&mut self, binary: &[u8]) -> Result<(String, Vec<u8>)>;
    fn parse_privatekey(&mut self, binary: &[u8], passphrase: Option<&[u8]>) -> Result<(String, Vec<u8>, Vec<u8>)>;
    // fn parse_both(&mut self, private: &[u8], public: &[u8]) -> Result<(String, Vec<u8>, Vec<u8>)>;
    fn add_cipher(&mut self, name: &str, cipher: Box<dyn Decrypt>);
}