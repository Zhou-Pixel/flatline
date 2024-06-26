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
    - `chacha20-poly1305@openssh.com`
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
    use flatline::session::Userauth;
    use flatline::channel::ExitStatus;
    let socket = TcpStream::connect("192.168.8.190:22").await.unwrap();
    let config = Config::deafult_with_behavior();
    let session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password("zhou", "123456").await.unwrap();

    assert!(matches!(status, Userauth::Success));

    let mut channel = session.channel_open_default().await.unwrap();
    channel.exec("echo \"hello\"").await.unwrap();
    loop {
        let msg = channel.recv().await.unwrap();
        match msg {
            flatline::channel::Message::Close => break,
            flatline::channel::Message::Eof => break,
            flatline::channel::Message::Stdout(data) => assert_eq!(data, b"hello\n"),
            flatline::channel::Message::Stderr(_) => unreachable!(),
            flatline::channel::Message::Exit(status) => assert!(matches!(status, ExitStatus::Normal(0))),
        }
    }
}
```

> [!WARNING]
> flatline is beta now and can contain breaking changes!
>