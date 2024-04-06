use indexmap::IndexMap;
use rand::thread_rng;
use rand::Rng;
use tokio::net::TcpStream;

use crate::handshake::Config;
use crate::keys::{self, KeyParser};
use crate::session::Session;
use crate::msg::Userauth;
use crate::sftp::Permissions;

// const IP: &str = "127.0.0.1:22";
const IP: &str = "192.168.8.190:22";
const USER: &str = "zhou";
const PASS: &str = "123456";

async fn open_session(config: Config) -> Session {
    let socket = TcpStream::connect(IP).await.unwrap();
    let mut session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password(USER, PASS).await.unwrap();

    assert!(matches!(status, Userauth::Success));

    session
}



#[tokio::test]
async fn userauth_publickey() {
    let openssh = keys::openssh::OpenSSH::default();

    let private_key_file = tokio::fs::read("/home/zhou/.ssh/id_ecdsa256").await.unwrap();
    let public_key_file = tokio::fs::read("/home/zhou/.ssh/id_ecdsa256.pub").await.unwrap();

    let key = openssh.parse_privatekey(&private_key_file, Some(b"123456")).unwrap();
    let _ = openssh.parse_publickey(&public_key_file).unwrap();

    let config = Config::default();

    let mut session = Session::handshake(config, TcpStream::connect(IP).await.unwrap())
        .await
        .unwrap();


    let status = session.userauth_publickey(USER, key.key_type, key.public_key, key.private_key).await.unwrap();

    println!("{:?}", status);

}

#[tokio::test]
async fn random() {
    for _ in 0..100 {
        echo_hello(rand_config(), 10).await
    }
}

fn rand_config() -> Config {

    let mut config = Config::default();

    rand_map(&mut config.compress_client_to_server);
    rand_map(&mut config.compress_server_to_client);
    rand_map(&mut config.crypt_client_to_server);
    rand_map(&mut config.crypt_server_to_client);
    rand_map(&mut config.hostkey);
    rand_map(&mut config.key_exchange);
    rand_map(&mut config.mac_client_to_server);
    rand_map(&mut config.mac_server_to_client);

    config.key_strict = thread_rng().gen();
    config
}

fn rand_map<K, V>(map: &mut IndexMap<K, V>) {

    map.sort_by_cached_key(|_, _| thread_rng().gen::<usize>());

}

#[tokio::test]
async fn open_sftp() {
    let mut session = open_session(Default::default()).await;

    let mut sftp = session.sftp_open().await.unwrap();

    let dir = sftp.open_dir("/usr/lib/aarch64-linux-gnu").await.unwrap();

    let path = sftp.real_path("./Documents").await.unwrap();

    println!("real path: {}", path);

    loop {
        let infos = sftp.read_dir(&dir).await.unwrap();

        if infos.is_empty() {
            break;
        }


    }

    let channel = session.channel_open_default().await.unwrap();

    let content = "123456789\n";
    let mut sender = channel.scp_sender("./Documents/test1.scp.txt", content.len(), Permissions::p0755(), None).await.unwrap();

    let im = sender.send(content).await.unwrap();

    assert!(im);

    sender.finish().await.unwrap();
}

async fn echo_hello(config: Config, times: usize) {

    let socket = TcpStream::connect(IP).await.unwrap();
    let mut session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password(USER, PASS).await.unwrap();

    assert!(matches!(status, Userauth::Success));

    for _ in 0..times {

        let mut channel = session.channel_open_default().await.unwrap();
        let status = channel.exec_and_wait("echo \"hello\"").await.unwrap();
        assert!(matches!(status, crate::msg::ExitStatus::Normal(0)));
        let buf = channel.read().await.unwrap();
        channel.close().await.unwrap();
        assert_eq!(buf, b"hello\n");
    }

    session.disconnect_default().await.unwrap();
    // channel.close().await.unwrap();

}
