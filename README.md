SSH-2.0 client library
=====

[![Latest version](https://img.shields.io/crates/v/flatline.svg)](https://crates.io/crates/flatline)  ![License](https://img.shields.io/crates/l/flatline.svg)

### Algorithms in flatline
- **kex**
    - `curve25519-sha256@libssh.org`
    - `curve25519-sha256`
    - `ecdh-sha2-nistp256`
    - `ecdh-sha2-nistp384`
    - `ecdh-sha2-nistp521`
    - `diffie-hellman-group14-sha256`
    - `diffie-hellman-group16-sha512`
    - `diffie-hellman-group16-sha256`
    - `diffie-hellman-group14-sha1`
    - `diffie-hellman-group18-sha512`
    - `diffie-hellman-group-exchange-sha256`
    - `diffie-hellman-group-exchange-sha1`
    - `diffie-hellman-group15-sha512`
    - `diffie-hellman-group17-sha512`
    - `diffie-hellman-group1-sha1`
- **hostkey**
    - `ssh-ed25519`
    - `rsa-sha2-256`
    - `rsa-sha2-512`
    - `ssh-rsa`
    - `ssh-dss`
    - `ecdsa-sha2-nistp521`
    - `ecdsa-sha2-nistp256`
    - `ecdsa-sha2-nistp384`
- **encryption**
    - `aes256-gcm@openssh.com`
    - `aes128-gcm@openssh.com`
    - `aes256-ctr`
    - `aes128-cbc`
    - `aes192-cbc`
    - `aes256-cbc`
    - `aes128-ctr`
    - `aes192-ctr`
    - `rijndael-cbc@lysator.liu.se`
    - `3des-cbc`
- **mac**
    - `hmac-sha1`
    - `hmac-sha1-etm@openssh.com`
    - `hmac-sha1-96`
    - `hmac-sha1-96-etm@openssh.com`
    - `hmac-md5`
    - `hmac-md5-etm@openssh.com`
    - `hmac-md5-96`
    - `hmac-md5-96-etm@openssh.com`
    - `hmac-sha2-512`
    - `hmac-sha2-512-etm@openssh.com`
    - `hmac-sha2-256`
    - `hmac-sha2-256-etm@openssh.com`
    - `hmac-ripemd160`
    - `hmac-ripemd160@openssh.com`
    - `hmac-ripemd160-etm@openssh.com`
- **compress**
    - `zlib`
    - `zlib@openssh.com`

### Example
1. echo hello
```rust
#[tokio::main]
async fn main() {
    use flatline::session::Session;
    use flatline::handshake::Config;
    use tokio::net::TcpStream;
    use flatline::msg::{Userauth, ExitStatus};
    let socket = TcpStream::connect("192.168.8.190:22").await.unwrap();
    let config = Config::deafult_with_behavior();
    let mut session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password("zhou", "123456").await.unwrap();

    assert!(matches!(status, Userauth::Success));

    let mut channel = session.channel_open_default().await.unwrap();
    let status = channel.exec_and_wait("echo \"hello\"").await.unwrap();
    assert!(matches!(status, ExitStatus::Normal(0)));
    let buf = channel.read().await.unwrap();
    assert_eq!(buf, b"hello\n");
}
```

<font size=5>:exclamation:__flatline is beta now and can contain breaking changes!__</font>