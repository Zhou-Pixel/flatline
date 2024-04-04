use crate::cipher::crypt;
use crate::cipher::crypt::Decrypt;
use crate::error::Error;
use crate::error::Result;
use crate::ssh::buffer::Buffer;
use crate::Boxtory;
use openssl::base64::decode_block;
use std::collections::HashMap;

use super::PrivateKey;
use super::PublicKey;

pub struct OpenSSH {
    cipher: HashMap<String, Boxtory<dyn Decrypt + Send>>,
}

impl Default for OpenSSH {
    fn default() -> Self {
        let cipher = crypt::new_decrypt_all();
        let cipher = cipher
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<HashMap<_, _>>();
        Self { cipher }
    }
}

impl super::KeyParser for OpenSSH {
    fn parse_publickey(&self, binary: &[u8]) -> Result<PublicKey> {
        let content = String::from_utf8(binary.to_vec())?;

        let parts: Vec<_> = content.trim().split(' ').collect();

        if parts.len() != 3 {
            return Err(Error::invalid_format("invaild key format"));
        }
        // let mut decode = Buffer::from_vec(decode_block(parts[1])?);
        // let (_, keytype) = decode
        //     .take_one()
        //     .ok_or(Error::invalid_format("invaild key format"))?;

        // if keytype != parts[0].as_bytes() {
        //     return Err(Error::invalid_format("keytype doesn't match"));
        // }

        // let key = if keytype == b"ssh-ed25519" {
        //     let (_, key) = decode
        //         .take_one()
        //         .ok_or(Error::invalid_format("invaild key format"))?;
        //     key
        // } else if keytype == b"ssh-rsa" {
        //     decode.into_vec()
        // } else {
        //     return Err(Error::invalid_format("unsupport key type"));
        // };

        Ok(PublicKey::new(parts[0].to_string(), decode_block(parts[1])?))
    }

    fn parse_privatekey(
        &self,
        binary: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<PrivateKey> {
        let invalid_key_format = || Error::invalid_format("invalid public key format");
        let content =
            std::str::from_utf8(binary).map_err(|_| Error::invalid_format("not uft-8 string"))?;
        let mut content = content.trim().to_string();

        content.retain(|v| v != '\r' && v != '\n');

        let content = content
            .trim_start_matches("-----BEGIN OPENSSH PRIVATE KEY-----")
            .trim_end_matches("-----END OPENSSH PRIVATE KEY-----");

        let mut decode = Buffer::from_vec(decode_block(content)?);

        let key = b"openssh-key-v1\0";

        let auth_magic = decode
            .take_bytes(key.len())
            .ok_or(Error::invalid_format("invalid binary format"))?;
        if auth_magic != key {
            return Err(Error::invalid_format("unsupport key file type"));
        }

        let (_, cipher) = decode
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        let (_, kdfname) = decode
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;


        let (_, kdfopts) = decode
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;


        let numofkeys = decode
            .take_u32()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        if numofkeys != 1 {
            return Err(Error::invalid_format("num for keys must be 1"));
        }

        let (_, pbuf) = decode
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        let public_key = pbuf.clone();
        let mut pbuf = Buffer::from_vec(pbuf);

        let (_, keytype) = pbuf
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        let (_, mut section) = decode
            .take_one()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        match passphrase {
            Some(passphrase) => {
                if cipher != b"none" {
                    if kdfname != b"bcrypt" {
                        // In the current version only bcrtypt is legal
                        return Err(Error::invalid_format("invalid kdfname"));
                    }
                    let mut kdfopts = Buffer::from_vec(kdfopts);
                    let (_, salt) = kdfopts
                        .take_one()
                        .ok_or(Error::invalid_format("invalid binary format"))?;
                    let rounds = kdfopts
                        .take_u32()
                        .ok_or(Error::invalid_format("invalid binary format"))?;

                    let mut cipher = self
                        .cipher
                        .get(String::from_utf8(cipher)?.as_str())
                        .ok_or(Error::invalid_format("unsupport cipher type"))?
                        .create();

                    cipher.enable_increase_iv(false);

                    let mut key_and_iv = vec![0; cipher.key_len() + cipher.iv_len()];
                    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, &salt, rounds, &mut key_and_iv)
                        .map_err(|e| Error::invalid_format(e.to_string()))?;

                    cipher.initialize(
                        &key_and_iv[cipher.key_len()..],
                        &key_and_iv[..cipher.key_len()],
                    )?;

                    if section.len() % cipher.block_size() != 0 {
                        return Err(Error::invalid_format("invalid binary format"));
                    }

                    let mut plain_text = vec![];

                    cipher.update(&section, Some(&mut plain_text))?;

                    if cipher.has_tag() {
                        let tag = decode
                            .take_bytes(cipher.tag_len())
                            .ok_or(Error::invalid_format("invalid binary format"))?;

                        cipher.set_authentication_tag(&tag)?;
                    }

                    cipher.finalize(&mut plain_text)?;

                    section = plain_text;

                    // bcrypt_pbkdf::bcrypt_pbkdf_with_memory(passphrase, &salt, rounds, &mut [], &mut []);
                }
            }
            None => {
                if cipher != b"none" {
                    return Err(Error::invalid_format("passphrase was required"));
                }
            }
        }

        let mut section = Buffer::from_vec(section);

        let checkint1 = section
            .take_u32()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        let checkint2 = section
            .take_u32()
            .ok_or(Error::invalid_format("invalid binary format"))?;

        if checkint1 != checkint2 {
            return Err(Error::invalid_format("checkint1 != checkint2"));
        }
        let (private, public) = if keytype == b"ssh-ed25519" {
            let (_, pubkey1) = pbuf
                .take_one()
                .ok_or(Error::invalid_format("invalid binary format"))?;



            let (_, keytype2) = section
                .take_one()
                .ok_or(Error::invalid_format("invalid binary format"))?;

            if keytype != keytype2 {
                return Err(Error::invalid_format("invalid key format"));
            }

            let (_, pubkey2) = section
                .take_one()
                .ok_or(Error::invalid_format("invalid binary format"))?;

            if pubkey1 != pubkey2 {
                return Err(Error::invalid_format("pubkey1 != pubkey2"));
            }

            let (secret_len, secret) = section
                .take_one()
                .ok_or(Error::invalid_format("invalid binary format"))?;

            if secret_len != 64 {
                return Err(Error::invalid_format("invalid binary format"));
            }
            let pubkey3 = secret[32..].to_vec();
            if pubkey1 != pubkey3 {
                return Err(Error::invalid_format("pubkey1 != pubkey3"));
            }

            let prikey = secret[..32].to_vec();

            let (_, _comment) = section
                .take_one()
                .ok_or(Error::invalid_format("invalid binary format"))?;

            let mut private_key = Buffer::new();
            private_key.put_one(&keytype);
            private_key.put_one(prikey);

            (
                private_key.into_vec(),
                public_key,
            )
        } else if keytype == b"ssh-rsa" {

            let mut take_one =
                || Result::Ok(section.take_one().ok_or_else(invalid_key_format)?.1);

            if take_one()? != keytype {
                return Err(invalid_key_format());
            }

            let n = take_one()?;
            let e = take_one()?;

            // if e1 != e2 || n1 != n2 {
            //     return Err(Error::invalid_format("invalid public key"));
            // }

            let d = take_one()?;
            let iqmp = take_one()?;
            let p = take_one()?;
            let q = take_one()?;

            let mut prikey = Buffer::new();

            prikey.put_one(&keytype);
            prikey.put_one(&n);
            prikey.put_one(&e);
            prikey.put_one(d);
            prikey.put_one(iqmp);
            prikey.put_one(p);
            prikey.put_one(q);

            (prikey.into_vec(), public_key)
        } else if keytype == b"ssh-dss" {

            let mut take_one =
                || Result::Ok(section.take_one().ok_or_else(invalid_key_format)?.1);

            if take_one()? != keytype {
                return Err(invalid_key_format());
            }

            let p = take_one()?;
            let q = take_one()?;
            let g = take_one()?;
            let y = take_one()?;
            let x = take_one()?;

            let mut private_key = Buffer::new();
            private_key.put_one(p);
            private_key.put_one(q);
            private_key.put_one(g);
            private_key.put_one(y);
            private_key.put_one(x);

            (private_key.into_vec(), public_key)
        } else if keytype.starts_with(b"ecdsa-sha2-nistp") {

            let curve = section.take_one().ok_or(Error::invalid_format("invalid binary format"))?.1;

            let nid = section.take_one().ok_or(Error::invalid_format("invalid binary format"))?.1;

            let point = section.take_one().ok_or(Error::invalid_format("invalid binary format"))?.1;
            let e= section.take_one().ok_or(Error::invalid_format("invalid binary format"))?.1;

            let mut private_key = Buffer::new();

            private_key.put_one(curve);
            private_key.put_one(nid);
            private_key.put_one(point);
            private_key.put_one(e);


           (private_key.into_vec(), public_key)
        } else {
            return Err(Error::invalid_format(format!(
                "unsupport key type => {}",
                String::from_utf8(keytype)?
            )));
        };

        let comment = section.take_one().ok_or_else(invalid_key_format)?.1;
        let comment = String::from_utf8(comment)?;


        Ok(PrivateKey::new(String::from_utf8(keytype)?, public, private, comment))
        
    }

    fn add_cipher(&mut self, name: &str, cipher: Boxtory<dyn Decrypt + Send>) {
        self.cipher.insert(name.to_string(), cipher);
    }
}

// async fn parse_publickey_from_file(path: impl AsRef<Path>) -> Result<(String, Vec<u8>)> {
//     let content = tokio::fs::read(path).await?;

//     let content = String::from_utf8(content)?;

//     let parts: Vec<_> = content.trim().split(' ').collect();

//     if parts.len() != 3 {
//         // anyhow::bail!("invalid key");
//         return Err(Error::invalid_format("invalid key format"));
//     }
//     let mut decode = Buffer::from_vec(decode_block(parts[1])?);
//     let (_, keytype) = decode.take_one().unwrap();

//     if keytype != parts[0].as_bytes() {
//         // anyhow::bail!("keytype doesn't match");
//         return Err(Error::invalid_format("invalid binary format"));
//     }

//     let (_, key) = decode.take_one().unwrap();

//     Ok((parts[0].to_string(), key))
// }

// async fn parse_privatekey_from_mem(
//     content: &str,
//     passphrase: Option<&[u8]>,
// ) -> Result<(String, Vec<u8>, Vec<u8>)> {
//     let mut content = content.trim().to_string();

//     content.retain(|v| v != '\r' || v != '\n');

//     let content = content
//         .trim_start_matches("-----BEGIN OPENSSH PRIVATE KEY-----")
//         .trim_end_matches("-----END OPENSSH PRIVATE KEY-----");

//     let mut decode = Buffer::from_vec(decode_block(content)?);

//     let key = b"openssh-key-v1\0";

//     let auth_magic = decode
//         .take_bytes(key.len())
//         .ok_or(Error::invalid_format("invalid binary format"))?;
//     if auth_magic != key {
//         return Err(Error::invalid_format("unsupport key file type"));
//     }

//     let (_, cipher) = decode
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     let (_, kdfname) = decode
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     let (_, kdfopts) = decode
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     let numofkeys = decode
//         .take_u32()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     if numofkeys != 1 {
//         return Err(Error::invalid_format("num for keys must be 1"));
//     }

//     let (_, pbuf) = decode
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     let mut pbuf = Buffer::from_vec(pbuf);

//     let (_, keytype) = pbuf
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     let (_, mut encrypted) = decode
//         .take_one()
//         .ok_or(Error::invalid_format("invalid binary format"))?;

//     match passphrase {
//         Some(passphrase) => {
//             if cipher != b"none" {
//                 if kdfname != b"bcrypt" {
//                     return Err(Error::invalid_format("invalid kdfname"));
//                 }
//                 let mut kdfopts = Buffer::from_vec(kdfopts);
//                 let (_, salt) = kdfopts
//                     .take_one()
//                     .ok_or(Error::invalid_format("invalid binary format"))?;
//                 let rounds = kdfopts
//                     .take_u32()
//                     .ok_or(Error::invalid_format("invalid binary format"))?;

//                 let mut cipher = crypt::new_decrypt_by_name(String::from_utf8(cipher)?.as_str())
//                     .ok_or(Error::invalid_format("unsupport cipher type"))?.create();
//                 cipher.enable_increase_iv(false);

//                 let mut key_and_iv = vec![0; cipher.key_len() + cipher.iv_len()];
//                 bcrypt_pbkdf::bcrypt_pbkdf(passphrase, &salt, rounds, &mut key_and_iv)
//                     .map_err(|e| Error::invalid_format(e.to_string()))?;

//                 cipher.initialize(
//                     &key_and_iv[cipher.key_len()..],
//                     &key_and_iv[..cipher.key_len()],
//                 )?;

//                 if encrypted.len() % cipher.block_size() != 0 {
//                     return Err(Error::invalid_format("invalid binary format"));
//                 }

//                 let mut plain_text = vec![];

//                 cipher.update(&encrypted, Some(&mut plain_text))?;

//                 let tag = decode
//                     .take_bytes(16)
//                     .ok_or(Error::invalid_format("invalid binary format"))?;

//                 cipher.set_authentication_tag(&tag)?;

//                 cipher.finalize(&mut plain_text)?;

//                 encrypted = plain_text;

//                 // bcrypt_pbkdf::bcrypt_pbkdf_with_memory(passphrase, &salt, rounds, &mut [], &mut []);
//             }
//         }
//         None => {
//             if cipher != b"none" {
//                 return Err(Error::invalid_format("passphrase was required"));
//             }
//         }
//     }

//     if keytype == b"ssh-ed25519" {
//         let (_, pubkey1) = pbuf
//             .take_one()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         println!("pubkey: {}", pubkey1.len());

//         println!("encrypted: {}", encrypted.len());

//         let mut encrypted = Buffer::from_vec(encrypted);

//         let checkint1 = encrypted
//             .take_u32()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         let checkint2 = encrypted
//             .take_u32()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         if checkint1 != checkint2 {
//             return Err(Error::invalid_format("checkint1 != checkint2"));
//         }

//         let (_, keytype) = encrypted
//             .take_one()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         println!("keytype again: {}", String::from_utf8(keytype).unwrap());

//         let (_, pubkey2) = encrypted
//             .take_one()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         if pubkey1 != pubkey2 {
//             return Err(Error::invalid_format("pubkey1 != pubkey2"));
//         }

//         println!("publickey content: {:?}", pubkey1);

//         let (secret_len, secret) = encrypted
//             .take_one()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         if secret_len != 64 {
//             return Err(Error::invalid_format("invalid binary format"));
//         }
//         let pubkey3 = secret[32..].to_vec();
//         if pubkey1 != pubkey3 {
//             return Err(Error::invalid_format("pubkey1 != pubkey3"));
//         }

//         let prikey = secret[..32].to_vec();

//         let (_, comment) = encrypted
//             .take_one()
//             .ok_or(Error::invalid_format("invalid binary format"))?;

//         println!("comment: {}", String::from_utf8(comment).unwrap());

//         println!("padding: {} {}", encrypted.len(), decode.len());
//         Ok(("ssh-ed25519".to_string(), prikey, pubkey3))
//     } else {
//         Err(Error::invalid_format(format!(
//             "unsupport key type => {}",
//             String::from_utf8(keytype)?
//         )))
//     }
// }

// async fn parse_privatekey_from_file(
//     path: impl AsRef<Path>,
//     passphrase: Option<&[u8]>,
// ) -> Result<(String, Vec<u8>, Vec<u8>)> {
//     let content = tokio::fs::read(path).await?;
//     let content = String::from_utf8(content)?;

//     parse_privatekey_from_mem(&content, passphrase).await
// }
