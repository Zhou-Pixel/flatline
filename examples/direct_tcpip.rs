use flatline::handshake::Config;
use flatline::session::Session;
use flatline::session::Userauth;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

include!("./user.conf");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket = TcpStream::connect(HOST).await.unwrap();
    let config = Config::deafult_with_behavior();
    let session = Session::handshake(config, socket).await.unwrap();

    let private = fs::read(PRI_KEY_FILE).await.unwrap();
    let public = fs::read(PUB_KEY_FILE).await.unwrap();
    let status = session
        .userauth_publickey_from_file(USERNAME, private, Some(&public), None)
        .await
        .unwrap();

    assert!(matches!(status, Userauth::Success));

    let listener = TcpListener::bind("127.0.0.1:5000").await.unwrap();

    loop {
        let mut local = listener.accept().await.unwrap().0;
        let local_addr = local.peer_addr().unwrap();
        let mut remote = session
            .direct_tcpip_default(
                ("127.0.0.1", 5000),
                (local_addr.ip().to_string(), local_addr.port() as u32),
            )
            .await
            .unwrap();

        tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut local, &mut remote)
                .await
                .unwrap();
        });
    }

    session.disconnect_default().await.unwrap();
}
