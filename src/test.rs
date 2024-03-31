use indexmap::IndexMap;
use rand::Rng;
use tokio::net::TcpStream;
    use rand::thread_rng;

use crate::session::{Session, Userauth};
use crate::handshake::Config;
use crate::sftp::Permissions;




const IP: &str = "192.168.8.190:22";
const USER: &str = "zhou";
const PASS: &str = "123456";


#[tokio::test]
async fn random() {

    for _ in 0..100 {
        echo_hello(rand_config(), 1).await;
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

async fn open_session(config: Config) -> Session {

    let socket = TcpStream::connect(IP).await.unwrap();
    let mut session = Session::handshake(config, socket).await.unwrap();

    let status = session.userauth_password(USER, PASS).await.unwrap();

    assert!(matches!(status, Userauth::Success));

    session
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

        println!("{}", infos.len());
        println!("{:?}", infos.iter().map(|v| v.filename.clone()).collect::<Vec<String>>())
        
    }


    let channel = session.channel_open_default().await.unwrap();

    let content = "123456789\n";
    let mut sender = channel.scp_sender("./Documents/test1.scp.txt", content.len(), Permissions::p0755(), None).await.unwrap();
    

    let size = sender.write(content).await.unwrap();

    assert_eq!(size, content.len());

    // println!("sender finish: {}", size);
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
        assert!(matches!(status, crate::session::ExitStatus::Normal(0)));
        let buf = channel.read().await.unwrap();
        assert_eq!(buf, b"hello\n");
    }



    
    // channel.close().await.unwrap();
    
}
