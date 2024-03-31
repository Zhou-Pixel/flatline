# SSH-2.0 client library

# example
1. echo hello
```rust
#[tokio::main]
async fn main() {
    use flatline::session::{Session, Userauth};
    use flatline::handshake::Config;
    use tokio::net::TcpStream;
    let socket = TcpStream::connect("192.168.8.190:22").await.unwrap();
    let config = Config::default();
    let mut session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password("zhou", "123456").await.unwrap();

    assert!(matches!(status, Userauth::Success));

    let mut channel = session.channel_open_default().await.unwrap();
    let status = channel.exec_and_wait("echo \"hello\"").await.unwrap();
    assert!(matches!(status, flatline::session::ExitStatus::Normal(0)));
    let buf = channel.read().await.unwrap();
    assert_eq!(buf, b"hello\n");
}
```

<font size=5>:exclamation:__flatline is beta now and can contain breaking changes!__</font>