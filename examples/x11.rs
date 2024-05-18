use std::env;

use flatline::error::Result;
use flatline::forward::Stream;
use flatline::handshake::Behavior;
use flatline::handshake::Config;
use flatline::session::DisconnectReson;
use flatline::session::Session;
use flatline::session::Userauth;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::net::UnixStream;
use tokio::process::Command;

include!("./user.conf");

struct User;

#[flatline::async_trait]
impl Behavior for User {
    async fn openssh_hostkeys(&mut self, _: bool, _: &[&[u8]]) -> Result<()> {
        Ok(())
    }

    async fn debug(&mut self, _: bool, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    async fn ignore(&mut self, _: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn useauth_banner(&mut self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&mut self, _: DisconnectReson, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    async fn verify_server_hostkey(&mut self, _: &str, _: &[u8]) -> Result<bool> {
        Ok(true)
    }

    async fn server_signature_algorithms(&mut self, _: &[&str]) -> Result<()> {
        Ok(())
    }

    async fn x11_forward(&mut self, mut stream: Stream) -> Result<()> {
        let display = env::var("DISPLAY").unwrap_or(":0".to_string());
        let screen_number = display
            .split(':')
            .collect::<Vec<_>>()
            .get(1)
            .map(|v| v.parse().unwrap())
            .unwrap_or(0);

        let x11 = format!("/tmp/.X11-unix/X{}", screen_number);

        let mut socket = UnixStream::connect(x11).await?;

        tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut stream, &mut socket)
                .await
                .unwrap();
        });

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        panic!("This example use local linux x11 protocol")
    }
    let socket = TcpStream::connect(HOST).await.unwrap();
    let config = Config::new(User {});

    let session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password(USERNAME, PASSWORD).await.unwrap();

    assert!(matches!(status, Userauth::Success));

    let mut channel = session.channel_open_default().await.unwrap();

    let (protocol, cookie, screen_number) = system_x11_protocol_cookie().await;

    channel
        .request_pty("xterm", 80, 60, 800, 480, &[])
        .await
        .unwrap();

    channel
        .request_x11_forward(false, protocol, cookie, screen_number)
        .await
        .unwrap();

    channel.request_shell().await.unwrap();

    channel.write("gedit\n").await.unwrap();

    println!("press enter to exit");
    tokio::io::stdin().read_u8().await.unwrap();
}

async fn system_x11_protocol_cookie() -> (String, String, u32) {
    let display = env::var("DISPLAY").unwrap_or(":0".to_string());
    let screen_number = display
        .split(':')
        .collect::<Vec<_>>()
        .get(1)
        .map(|v| v.parse().unwrap())
        .unwrap_or(0);
    let mut cmd = Command::new("/usr/bin/xauth");
    cmd.arg("list");
    cmd.arg(display);

    let output = cmd.output().await.unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();

    let lines: Vec<_> = stdout.lines().collect();

    // use my local cookie as a fake random cookie
    let mut cookie = "396d4663579aa232088631bcf8b9588b";
    let mut procotol = "MIT-MAGIC-COOKIE-1";

    if let Some(line) = lines.get(0) {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() == 3 {
            procotol = parts[1];
            cookie = parts[2];
        }
    }

    (procotol.to_string(), cookie.to_string(), screen_number)
}
